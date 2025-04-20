#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import os
import argparse
import hmac
import hashlib
import secrets
import threading
import time
import base64
from cryptography.fernet import Fernet

# -----------------------
# Global Configuration
# -----------------------
SHARED_SECRET = b"SuperSecretKeyUsedForHMAC"
used_nonces = set()      # to detect nonce reuse
used_hmacs = set()       # to detect HMAC reuse (replay)
LOG_FILE = "attack.log"

# Derive a Fernet key from the shared secret
fernet_key = base64.urlsafe_b64encode(hashlib.sha256(SHARED_SECRET).digest())
fernet = Fernet(fernet_key)


def log_alert(message: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{ts}] ALERT: {message}\n")


def generate_nonce():
    return secrets.token_hex(16)


def compute_hmac(message: bytes, key: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


##################################################################
# 1. Defended RFID Tag (Server): Authentication + Encryption
##################################################################

def run_defended_tag(host='127.0.0.1', port=9999):
    print(f"[Defended Tag] Listening on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_tag_connection, args=(conn, addr), daemon=True).start()


def handle_tag_connection(conn: socket.socket, addr):
    with conn:
        # 1) Send fresh nonce
        nonce = generate_nonce().encode('utf-8')
        conn.sendall(nonce + b"\n")

        # 2) Receive Reader's HMAC
        data = conn.recv(2048)
        if not data:
            return
        client_hmac = data.strip()

        # 3) Replay protection: nonce reuse or HMAC reuse
        if nonce in used_nonces or client_hmac in used_hmacs:
            conn.sendall(b"ERROR: REPLAY DETECTED\n")
            log_alert(f"Replay attack detected from {addr}")
            return
        used_nonces.add(nonce)

        # 4) Verify HMAC
        expected_hmac = compute_hmac(nonce, SHARED_SECRET).encode('utf-8')
        if not hmac.compare_digest(client_hmac, expected_hmac):
            conn.sendall(b"ERROR: INVALID HMAC\n")
            log_alert(f"Invalid HMAC detected from {addr}")
            return
        used_hmacs.add(client_hmac)

        # 5) Prepare and encrypt response payload
        payload = (
            "PRODUCT_ID=ABC123;INVENTORY=50;USER_BEHAVIOR=BrowsingTime=300s;"
            "SECURITY_LEVEL=STRONGER_HMAC"
        ).encode('utf-8')
        encrypted = fernet.encrypt(payload)

        # 6) Compute integrity HMAC over nonce + encrypted
        resp_hmac = compute_hmac(nonce + encrypted, SHARED_SECRET).encode('utf-8')

        # 7) Send encrypted response and its HMAC
        conn.sendall(b"ENC_RESPONSE:" + encrypted + b"\n")
        conn.sendall(b"RESPONSE_HMAC:" + resp_hmac + b"\n")
        print(f"[Defended Tag] Sent encrypted payload to {addr}")


##################################################################
# 2. Defended RFID Reader (Client): Decrypt + Verify
##################################################################

def run_defended_reader(host='127.0.0.1', port=9999):
    print(f"[Defended Reader] Connecting to {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        try:
            cli.connect((host, port))
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return

        # Receive nonce
        nonce = cli.recv(1024).strip()
        print(f"[Defended Reader] Received nonce: {nonce.decode()}")

        # Send HMAC over nonce
        reader_hmac = compute_hmac(nonce, SHARED_SECRET).encode('utf-8')
        cli.sendall(reader_hmac + b"\n")

        # Receive encrypted response and its HMAC
        line1 = cli.recv(4096).strip()
        line2 = cli.recv(4096).strip()
        if not line1 or not line2:
            print("[Defended Reader] Incomplete response.")
            return
        if line1.startswith(b"ERROR"):
            print(f"[Defended Reader] {line1.decode()}")
            log_alert(f"Server error response received: {line1.decode()} from {host}:{port}")
            return
        # Parse ciphertext and HMAC
        _, encrypted = line1.split(b":", 1)
        _, received_hmac = line2.split(b":", 1)

        # Verify integrity
        expected_hmac = compute_hmac(nonce + encrypted, SHARED_SECRET).encode('utf-8')
        if not hmac.compare_digest(received_hmac, expected_hmac):
            print("[Defended Reader] ALERT: RESPONSE HMAC INVALID. Potential tampering detected.")
            log_alert(f"Response HMAC invalid from {host}:{port}")
            return
        # Decrypt payload
        try:
            plaintext = fernet.decrypt(encrypted)
            print(f"[Defended Reader] Decrypted payload: {plaintext.decode()}")
        except Exception:
            print("[Defended Reader] ALERT: Decryption failed.")
            log_alert(f"Decryption failed for response from {host}:{port}")
            return


##################################################################
# 3. Automated Attack Tests
##################################################################

def test_eavesdrop(tag_host, tag_port):
    print("[Test] Eavesdrop Attack vs Defense Tag")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((tag_host, tag_port))
        _ = s.recv(1024)
        s.sendall(b"CHALLENGE:EAVESDROP\n")
        try:
            data = s.recv(1024).decode('utf-8').strip()
        except:
            data = None
    if data and data.startswith("ENC_RESPONSE"):
        print("[Test Result] FAILURE: ciphertext leaked (", data, ")")
    else:
        print("[Test Result] SUCCESS: no ciphertext leaked (got:", data, ")")
        log_alert("Eavesdrop attack detected: invalid HMAC attempt")


def test_replay(tag_host, tag_port):
    print("[Test] Replay Attack vs Defense Tag")
    # First handshake
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((tag_host, tag_port))
        nonce = s.recv(1024).strip()
        valid_hmac = compute_hmac(nonce, SHARED_SECRET).encode('utf-8')
        s.sendall(valid_hmac + b"\n")
        _ = s.recv(4096)
    time.sleep(0.2)
    # Replay old HMAC
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
        s2.connect((tag_host, tag_port))
        _ = s2.recv(1024)
        s2.sendall(valid_hmac + b"\n")
        data = s2.recv(1024).decode('utf-8').strip()
    if data.startswith("ERROR:"):
        print("[Test Result] SUCCESS: replay blocked (", data, ")")
        log_alert("Replay attack test detected: old HMAC reuse")
    else:
        print("[Test Result] FAILURE: replay succeeded (", data, ")")


def test_clone(tag_host, tag_port, clone_port=8888):
    print("[Test] Clone Attack vs Defense Tag")

    def proxy():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ps:
            ps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ps.bind(('0.0.0.0', clone_port))
            ps.listen(1)
            conn, _ = ps.accept()
            with conn, socket.socket() as real_s:
                real_s.connect((tag_host, tag_port))
                nonce = real_s.recv(1024)
                conn.sendall(nonce)
                hmac_line = conn.recv(1024)
                real_s.sendall(hmac_line)
                enc_line = real_s.recv(4096)
                hmac_resp = real_s.recv(4096)
                # Tamper ciphertext but keep format
                prefix, ct = enc_line.split(b":", 1)
                tampered = bytearray(ct.strip())
                tampered[0] ^= 0xFF  # flip first byte
                conn.sendall(prefix + b":" + bytes(tampered) + b"\n")
                conn.sendall(hmac_resp)

    t = threading.Thread(target=proxy, daemon=True)
    t.start()
    time.sleep(0.2)

    print(f"[Test] Running reader via clone proxy on port {clone_port}")
    run_defended_reader(host='127.0.0.1', port=clone_port)
    print("[Test] Clone test completed.")
    log_alert("Clone attack test detected: tampered ciphertext")


##################################################################
# CLI Entry Point
##################################################################

def main():
    parser = argparse.ArgumentParser(description="Defended RFID Demo with Encryption & Monitoring")
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_tag = sub.add_parser('tag', help='Run secured Tag')
    p_tag.add_argument('--host', default='127.0.0.1')
    p_tag.add_argument('--port', type=int, default=9999)

    p_reader = sub.add_parser('reader', help='Run secured Reader')
    p_reader.add_argument('--host', default='127.0.0.1')
    p_reader.add_argument('--port', type=int, default=9999)

    p_e = sub.add_parser('test-eavesdrop', help='Test eavesdrop attack')
    p_e.add_argument('--host', default='127.0.0.1')
    p_e.add_argument('--port', type=int, default=9999)

    p_r = sub.add_parser('test-replay', help='Test replay attack')
    p_r.add_argument('--host', default='127.0.0.1')
    p_r.add_argument('--port', type=int, default=9999)

    p_c = sub.add_parser('test-clone', help='Test clone attack')
    p_c.add_argument('--host', default='127.0.0.1')
    p_c.add_argument('--port', type=int, default=9999)
    p_c.add_argument('--clone-port', type=int, default=8888)

    args = parser.parse_args()
    os.system("sudo ifconfig lo0 alias 127.0.0.2 2>/dev/null")

    if args.cmd == 'tag':
        run_defended_tag(host=args.host, port=args.port)
    elif args.cmd == 'reader':
        run_defended_reader(host=args.host, port=args.port)
    elif args.cmd == 'test-eavesdrop':
        test_eavesdrop(args.host, args.port)
    elif args.cmd == 'test-replay':
        test_replay(args.host, args.port)
    elif args.cmd == 'test-clone':
        test_clone(args.host, args.port, args.clone_port)

if __name__ == '__main__':
    main()
