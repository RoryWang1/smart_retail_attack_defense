#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import argparse
import os
import re

RESPONSE_LOG = "response.log"

##################################################################
# 1. RFID Tag (Server)
##################################################################
def run_rfid_tag(host='127.0.0.2', port=9999):
    """
    Simulated RFID Tag:
    - Listens on (host:port)
    - Waits for the Reader to connect
    - Receives a single challenge and returns a static response containing
      product ID, inventory, user behavior, etc.
    """
    print(f"[RFID Tag] Starting on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(5)
        print("[RFID Tag] Waiting for Reader connection...")

        while True:
            conn, addr = server_sock.accept()
            print(f"[RFID Tag] Connected by {addr}")

            with conn:
                data = conn.recv(1024)
                if not data:
                    print("[RFID Tag] No data received, closing connection.")
                    continue

                challenge_str = data.decode().strip()
                print(f"[RFID Tag] Received challenge: {challenge_str}")

                # Static response (potentially sensitive info)
                response_data = (
                    "RFID_STATIC_RESPONSE: "
                    "PRODUCT_ID=ABC123, "
                    "INVENTORY=50, "
                    "USER_BEHAVIOR=BrowsingTime=300s, "
                    "SECURITY_LEVEL=WEAK_ENCRYPTION\n"
                )
                conn.sendall(response_data.encode('utf-8'))
                print("[RFID Tag] Sent response:", response_data.strip())


##################################################################
# 2. RFID Reader (Client)
##################################################################
def rfid_reader(tag_host='127.0.0.2', tag_port=9999):
    """
    Simulated RFID Reader:
    - Connects to the specified RFID Tag (or a fake/clone server)
    - Sends one CHALLENGE and prints out the single RESPONSE
    """
    print(f"[RFID Reader] Connecting to {tag_host}:{tag_port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reader_sock:
        try:
            reader_sock.connect((tag_host, tag_port))
        except Exception as e:
            print(f"[!] Failed to connect {tag_host}:{tag_port}: {e}")
            return

        # Send one challenge
        challenge = f"CHALLENGE:REQ_TIME_{int(time.time())}\n"
        print(f"[RFID Reader] Sending: {challenge.strip()}")
        try:
            reader_sock.sendall(challenge.encode())
        except Exception as e:
            print(f"[!] Failed to send challenge: {e}")
            return

        # Receive one response
        try:
            data = reader_sock.recv(1024)
        except Exception as e:
            print(f"[!] Failed to receive response: {e}")
            return

        if not data:
            print("[!] No response received.")
            return

        response = data.decode('utf-8', errors='ignore').strip()
        print(f"[RFID Reader] Received response: {response}")

    print("[RFID Reader] Done.")


##################################################################
# 3. Eavesdropping Attack
##################################################################
def eavesdropping_attack(host='127.0.0.2', port=9999):
    """
    Eavesdropping Attack:
    1. Connect to the real RFID Tag
    2. Send one CHALLENGE, capture the response
    3. Save the captured response to response.log for later Replay
    """
    print(f"[Eavesdrop] Connecting to real tag: {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
        except Exception as e:
            print(f"[!] Failed to connect to the real tag: {e}")
            return

        # Send a single challenge
        challenge = f"CHALLENGE:EAVESDROP_{int(time.time())}\n"
        print(f"[Eavesdrop] Sending challenge: {challenge.strip()}")
        s.sendall(challenge.encode())

        # Receive one response
        data = s.recv(1024)
        if not data:
            print("[!] No response received.")
            return

        response = data.decode().strip()
        print(f"[Eavesdrop] Captured response: {response}")

    # Write to log
    try:
        with open(RESPONSE_LOG, "w", encoding="utf-8") as f:
            f.write(response)
        print(f"[Eavesdrop] Saved response to {RESPONSE_LOG}")
    except Exception as e:
        print(f"[!] Failed to write log: {e}")


##################################################################
# 4. Replay Attack
##################################################################
def replay_attack(port=8888):
    """
    Replay Attack:
    1. Load the previously captured response from response.log
    2. Listen on the given port (default 8888) to fake an RFID Tag
    3. Each time a client connects, send the same captured data
    4. replay_count increments every time we serve a replay
    """
    if not os.path.exists(RESPONSE_LOG):
        print(f"[!] {RESPONSE_LOG} not found, run 'eavesdrop' first.")
        return

    with open(RESPONSE_LOG, "r", encoding="utf-8") as f:
        recorded_response = f.read().strip()

    replay_count = 0

    print(f"[Replay] Loaded recorded response: {recorded_response}")
    print(f"[Replay] Starting fake tag on 0.0.0.0:{port} (replay_count starts at 0)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', port))
        server_sock.listen(5)

        while True:
            conn, addr = server_sock.accept()
            replay_count += 1
            print(f"\n[Replay] Connection #{replay_count} from {addr}")

            with conn:
                try:
                    data = conn.recv(1024)
                    if not data:
                        print("[Replay] No data received from reader.")
                        continue

                    print(f"[Replay] Reader sent: {data.decode().strip()}")
                    # Attach replay count info to the response
                    response = f"{recorded_response} (Replayed #{replay_count})\n"
                    conn.sendall(response.encode('utf-8'))
                    print(f"[Replay] Sent replay response: {response.strip()}")

                except Exception as e:
                    print(f"[Replay] Error: {e}")


##################################################################
# 5. Clone Attack (Data Tampering)
##################################################################
def clone_attack(listen_port=8888, real_host='127.0.0.2', real_port=9999):
    """
    Clone Attack:
    1. Listens on (listen_port)
    2. Forwards incoming requests to the real Tag (real_host:real_port)
    3. Receives real Tag's response and modifies it (multiplies INVENTORY by 10)
    4. Sends the tampered response back to the Reader
    """
    print(f"[Clone] Listening on 0.0.0.0:{listen_port}, forwarding to {real_host}:{real_port}")
    print("[Clone] Will tamper the returned data by multiplying INVENTORY=XX by 10.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clone_sock:
        clone_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        clone_sock.bind(('0.0.0.0', listen_port))
        clone_sock.listen(5)

        while True:
            conn, addr = clone_sock.accept()
            print(f"[Clone] Reader connected from {addr}")

            with conn, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as real_sock:
                try:
                    real_sock.connect((real_host, real_port))
                except Exception as e:
                    print(f"[!] Cannot connect to the real tag: {e}")
                    continue

                try:
                    data_from_reader = conn.recv(1024)
                    if not data_from_reader:
                        print("[Clone] Reader sent empty data, closing connection.")
                        continue

                    reader_str = data_from_reader.decode().strip()
                    print(f"[Clone] Received from Reader: {reader_str}")
                    real_sock.sendall(data_from_reader)

                    data_from_real_tag = real_sock.recv(1024)
                    if not data_from_real_tag:
                        print("[Clone] No response from the real tag.")
                        continue

                    response_str = data_from_real_tag.decode().strip()
                    print(f"[Clone] Original response from real tag: {response_str}")

                    # Tamper the response
                    tampered_str = tamper_inventory(response_str)
                    print(f"[Clone] Tampered response: {tampered_str.strip()}")

                    conn.sendall(tampered_str.encode('utf-8'))

                except Exception as e:
                    print(f"[Clone] Error during clone process: {e}")


def tamper_inventory(response_str: str) -> str:
    """
    Tampering function:
    If INVENTORY=someNumber is found, multiply it by 10.
    We use a regex callback to avoid any escaping problems.
    """
    pattern = r"(INVENTORY\s*=\s*)(\d+)"

    def replacer(match_obj):
        prefix = match_obj.group(1)     # e.g. "INVENTORY= "
        original_value = int(match_obj.group(2))  # e.g. 50
        modified_value = original_value * 10       # e.g. 500
        return prefix + str(modified_value)

    tampered = re.sub(pattern, replacer, response_str)
    return tampered


##################################################################
# Main CLI
##################################################################
def main():
    parser = argparse.ArgumentParser(description="RFID Attack Demo (Tag, Reader, Eavesdrop, Replay, Clone)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # RFID Tag
    tag_parser = subparsers.add_parser("tag", help="Run a simulated RFID Tag (Server)")
    tag_parser.add_argument("--host", default="127.0.0.2", help="Server listen address")
    tag_parser.add_argument("--port", type=int, default=9999, help="Server listen port")

    # RFID Reader
    reader_parser = subparsers.add_parser("reader", help="Run a simulated RFID Reader (Client) sending only one challenge")
    reader_parser.add_argument("--tag-host", default="127.0.0.2", help="RFID Tag address")
    reader_parser.add_argument("--tag-port", type=int, default=9999, help="RFID Tag port")

    # Eavesdrop
    eavesdrop_parser = subparsers.add_parser("eavesdrop", help="Eavesdropping attack: capture the real tag's response once")
    eavesdrop_parser.add_argument("--host", default="127.0.0.2", help="Real tag address")
    eavesdrop_parser.add_argument("--port", type=int, default=9999, help="Real tag port")

    # Replay
    replay_parser = subparsers.add_parser("replay", help="Replay attack, serve the captured data as a fake tag")
    replay_parser.add_argument("--port", type=int, default=8888, help="Fake tag listen port")

    # Clone
    clone_parser = subparsers.add_parser("clone", help="Clone attack, forward requests to real tag and tamper the response")
    clone_parser.add_argument("--listen-port", type=int, default=8888, help="Clone server listen port")
    clone_parser.add_argument("--real-host", default="127.0.0.2", help="Real tag IP address")
    clone_parser.add_argument("--real-port", type=int, default=9999, help="Real tag port")

    args = parser.parse_args()

    # On macOS, add an alias to lo0 for 127.0.0.2 if needed
    try:
        os.system("sudo ifconfig lo0 alias 127.0.0.2 2>/dev/null")
    except:
        pass

    if args.command == "tag":
        run_rfid_tag(host=args.host, port=args.port)
    elif args.command == "reader":
        rfid_reader(tag_host=args.tag_host, tag_port=args.tag_port)
    elif args.command == "eavesdrop":
        eavesdropping_attack(host=args.host, port=args.port)
    elif args.command == "replay":
        replay_attack(port=args.port)
    elif args.command == "clone":
        clone_attack(listen_port=args.listen_port, real_host=args.real_host, real_port=args.real_port)


if __name__ == '__main__':
    main()
