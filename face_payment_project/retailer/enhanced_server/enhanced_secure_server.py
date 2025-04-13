#!/usr/bin/env python3

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional, Tuple, Set
import cv2
import jwt
import numpy as np
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature
from flask import Flask, Response, jsonify, request, abort
from werkzeug.utils import secure_filename

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False



class ServerConfig:
    """Server configuration and directory setup"""
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_SECONDS = 900
    HEARTBEAT_INTERVAL_SECONDS = 5
    MAX_CONTENT_LENGTH_BYTES = 16 * 1024 * 1024  # 16 MB
    CERT_VALIDITY_DAYS = 365
    RSA_KEY_SIZE = 2048
    NETWORK_CHECK_INTERVAL_SECONDS = 5
    NETWORK_BASELINE_UPDATE_INTERVAL_SECONDS = 1800
    RATE_LIMIT_WINDOW_SECONDS = 60
    RATE_LIMIT_MAX_REQUESTS = 60
    SESSION_CLEANUP_INTERVAL_SECONDS = 60
    CHALLENGE_EXPIRY_SECONDS = 30
    FRAME_SIGNATURE_EXPIRY_SECONDS = 60

    def __init__(self):
        self.app_root: str = os.path.dirname(os.path.abspath(__file__))
        self.log_dir: str = os.path.join(self.app_root, "logs")
        self.cert_dir: str = os.path.join(self.app_root, "certs")
        self.client_cert_dir: str = os.path.join(self.cert_dir, "clients")
        self.config_dir: str = os.path.join(self.app_root, "config")
        self.cache_dir: str = os.path.join(self.app_root, "cache")
        # Configure logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(self.log_dir, "server.log")),
                logging.StreamHandler()
            ]
        )
        self.logger: logging.Logger = logging.getLogger('EnhancedSecureServer')
        self.jwt_secret: str = secrets.token_hex(32)

config = ServerConfig()
logger = config.logger

class ServerState:
    """Server global state"""
    def __init__(self):
        self.camera: Optional[cv2.VideoCapture] = None
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.frame_signatures: Dict[str, Dict[str, Any]] = {}
        self.trusted_clients: Dict[str, Dict[str, Any]] = {}
        self.security_challenges: Dict[str, Dict[str, Any]] = {}
        self.server_private_key: Optional[rsa.RSAPrivateKey] = None
        self.server_certificate: Optional[x509.Certificate] = None
        self.blacklisted_ips: Set[str] = set()
        self.suspicious_activities: Dict[str, int] = {}
        self.last_arp_check_time: float = 0
        self.frame_counter: int = 0
        self.network_baseline: Dict[str, Any] = {}
        self.device_fingerprints: Dict[str, str] = {}
        self.cert_fingerprints: Dict[str, str] = {}
        self.network_status: Dict[str, Any] = {
            'arp_spoof_detected': False,
            'last_check_time': time.time(),
            'suspicious_macs': set(),
            'connection_attempts': {},
            'error_count': 0
        }

state = ServerState()

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH_BYTES



class DummyCamera:
    """A simulated camera for testing when no physical camera is available."""
    def __init__(self, width=640, height=480):
        self.width = width
        self.height = height
        self.counter = 0
        self.opened = True

    def read(self) -> Tuple[bool, np.ndarray]:
        """Generate a test image with dynamic content."""
        img = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        self.counter += 1
        cv2.putText(img, f"Simulated Camera - Frame {self.counter}",
                    (50, 70), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        cv2.putText(img, time_str,
                    (50, 120), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        radius = 30
        center_x = int(self.width / 2 + radius * np.sin(self.counter / 10))
        center_y = int(self.height / 2 + radius * np.cos(self.counter / 10))
        cv2.circle(img, (center_x, center_y), 50, (0, 0, 255), -1)
        return True, img

    def isOpened(self) -> bool:
        return self.opened

    def release(self) -> None:
        self.opened = False

    def set(self, propId, value) -> bool:
        return True

class CameraManager:
    """Manages camera operations and video frame generation"""

    @staticmethod
    def get_camera() -> Optional[cv2.VideoCapture]:
        """Initialize camera with fallback options if hardware camera is unavailable"""
        if state.camera is None or not state.camera.isOpened():
            opened_camera = None
            for index in [1, 0, 2]:
                try:
                    logger.info(f"Try camera {index}")
                    test_cam = cv2.VideoCapture(index)
                    if test_cam.isOpened():
                        logger.info(f"Camera {index} opened")
                        opened_camera = test_cam
                        opened_camera.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
                        opened_camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
                        time.sleep(1)
                        break
                    else:
                        test_cam.release()
                except Exception as e:
                    logger.error(f"Failed open camera {index}: {e}")

            if opened_camera is None:
                if platform.system() == 'Darwin':
                    try:
                        logger.info("Try camera with AVFoundation")
                        av_cam = cv2.VideoCapture(0, cv2.CAP_AVFOUNDATION)
                        if av_cam.isOpened():
                            logger.info("AVFoundation camera opened")
                            opened_camera = av_cam
                        else:
                           av_cam.release()
                    except Exception as e:
                        logger.error(f"Failed open AVFoundation camera: {e}")

            if opened_camera is None:
                logger.warning("No physical camera, using simulated.")
                state.camera = DummyCamera()
            else:
                 state.camera = opened_camera

        return state.camera


class SecurityManager:
    """Handles security operations including tokens, certificates, and encryption"""

    @staticmethod
    def generate_token(client_id: str, device_fingerprint: str) -> str:
        """Generate a JWT authentication token"""
        payload = {
            'client_id': client_id,
            'device_fingerprint': device_fingerprint,
            'exp': datetime.utcnow() + timedelta(seconds=config.JWT_EXPIRATION_SECONDS),
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16)
        }
        return jwt.encode(payload, config.jwt_secret, algorithm=config.JWT_ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """Verify a JWT token"""
        try:
            payload = jwt.decode(token, config.jwt_secret, algorithms=[config.JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token received")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None

    @staticmethod
    def token_required(f):
        """Decorator for endpoints that require valid token"""
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

            if not token:
                logger.warning(f"Missing token for: {request.path}")
                return jsonify({'message': 'Token is missing'}), 401

            payload = SecurityManager.verify_token(token)
            if not payload:
                logger.warning(f"Invalid token for: {request.path}")
                return jsonify({'message': 'Invalid or expired token'}), 401

            request.client_info = payload
            return f(*args, **kwargs)
        return decorated

    @staticmethod
    def generate_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair for the server"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config.RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_self_signed_cert(private_key: rsa.RSAPrivateKey, common_name: str) -> x509.Certificate:
        """Generate self-signed certificate with enhanced security properties"""
        hostname = socket.gethostname()
        ip_addresses = set()
        
        try:
            hostname_ip = socket.gethostbyname(hostname)
            ip_addresses.add(hostname_ip)
        except socket.gaierror:
            logger.warning(f"Could not resolve hostname {hostname} to IP.")
            
        # Get additional IPs from network interfaces
        if NETIFACES_AVAILABLE:
            try:
                for interface in netifaces.interfaces():
                    if netifaces.AF_INET in netifaces.ifaddresses(interface):
                        for addr_info in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                            ip_addresses.add(addr_info['addr'])
            except Exception as e:
                logger.warning(f"Could not get IPs via netifaces: {e}")
                
        mac_addresses = set()
        if NETIFACES_AVAILABLE:
            try:
                for interface in netifaces.interfaces():
                    if netifaces.AF_LINK in netifaces.ifaddresses(interface):
                        mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0].get('addr')
                        if mac: 
                            mac_addresses.add(mac.lower())
            except Exception as e:
                logger.warning(f"Could not get MACs via netifaces: {e}")
        else:
            cmd = []
            if platform.system() == "Linux":
                cmd = ['ip', 'link']
            elif platform.system() == "Darwin":
                cmd = ['ifconfig']
            elif platform.system() == "Windows":
                cmd = ['getmac', '/v', '/fo', 'list']
                
            if cmd:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=2, check=False)
                    mac_pattern = re.compile(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', re.IGNORECASE)
                    found_macs = mac_pattern.findall(result.stdout)
                    if found_macs:
                        for match in found_macs:
                            if isinstance(match, tuple):
                                mac_addresses.add(match[0] + match[1])
                except Exception as e:
                    logger.warning(f"Could not get MACs via cmd '{' '.join(cmd)}': {e}")
        # Current time for certificate validity
        now = datetime.utcnow()
        
        # Create subject name with common name
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"FacialPaymentSystem-{hostname}"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
        ])
        # Start certificate builder
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=config.CERT_VALIDITY_DAYS))
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.public_key(private_key.public_key())
        # Add alternative names (SANs)
        san_list = []
        # Add DNS name
        san_list.append(x509.DNSName(hostname))
        san_list.append(x509.DNSName("localhost"))
        # Add IP addresses
        for ip in ip_addresses:
            try:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                logger.warning(f"Invalid IP address for SAN: {ip}")
        # Add SAN extension to certificate
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        # Add Basic Constraints
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        # Add Key Usage
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        # Add Extended Key Usage
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )
        # Add custom extension with system fingerprint for enhanced security
        system_info = {
            'hostname': hostname,
            'machine': platform.machine(),
            'processor': platform.processor(),
            'system': platform.system(),
            'version': platform.version(),
            'python_version': platform.python_version(),
            'mac_addresses': sorted(list(mac_addresses))
        }
        
        fingerprint_data = json.dumps(system_info, sort_keys=True).encode('utf-8')
        fingerprint = hashlib.sha256(fingerprint_data).hexdigest()
        # Log the certificate information
        logger.info(f"Creating certificate for CN={common_name}, IPs={ip_addresses}, FP={fingerprint[:16]}...")
        # Sign the certificate with the private key
        certificate = cert_builder.sign(
            private_key, 
            hashes.SHA256(),
            default_backend()
        )
        
        return certificate

    @staticmethod
    def save_key_and_cert(private_key: rsa.RSAPrivateKey, cert: x509.Certificate) -> Tuple[str, str]:
        """Save private key and certificate to files"""
        key_path = os.path.join(config.cert_dir, "server.key")
        cert_path = os.path.join(config.cert_dir, "server.crt")

        try:
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(key_path, 0o600)
            logger.info(f"Server key saved: {key_path}")

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            logger.info(f"Server cert saved: {cert_path}")

        except IOError as e:
             logger.error(f"Failed save key/cert: {e}")
             raise

        return key_path, cert_path

    @staticmethod
    def initialize_certificates() -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str, str]:
        """Initialize or load server certificates"""
        key_path = os.path.join(config.cert_dir, "server.key")
        cert_path = os.path.join(config.cert_dir, "server.crt")

        if os.path.exists(key_path) and os.path.exists(cert_path):
            try:
                with open(key_path, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(), password=None, backend=default_backend()
                    )
                with open(cert_path, "rb") as cert_file:
                    certificate = x509.load_pem_x509_certificate(
                        cert_file.read(), default_backend()
                    )

                if certificate.not_valid_after < datetime.utcnow():
                    logger.warning("Existing cert expired.")
                    raise ValueError("Certificate expired")
                if certificate.not_valid_before > datetime.utcnow():
                     logger.warning("Existing cert not yet valid.")
                     raise ValueError("Certificate not yet valid")

                cert_public_key = certificate.public_key()
                private_key_public_key = private_key.public_key()

                if (cert_public_key.public_numbers().n != private_key_public_key.public_numbers().n or
                    cert_public_key.public_numbers().e != private_key_public_key.public_numbers().e):
                     logger.error("Cert public key does not match private key.")
                     raise ValueError("Key mismatch")

                fingerprint = SecurityManager.get_fingerprint(certificate)
                state.cert_fingerprints['server'] = fingerprint
                logger.info(f"Using existing valid cert (FP: {fingerprint[:16]}...)")
                return private_key, certificate, key_path, cert_path

            except (ValueError, TypeError, IOError, ssl.SSLError, InvalidSignature) as e:
                logger.error(f"Error loading/validating cert: {e}. Regenerating...")
                for f_path in [key_path, cert_path]:
                    if os.path.exists(f_path):
                        try:
                            os.remove(f_path)
                        except OSError as rm_err:
                            logger.error(f"Could not remove file {f_path}: {rm_err}")

        logger.info("Generating new server key/cert...")
        private_key, _ = SecurityManager.generate_key_pair()
        common_name = f"FacialPaymentServer-{socket.gethostname()}"
        certificate = SecurityManager.generate_self_signed_cert(private_key, common_name)
        key_path, cert_path = SecurityManager.save_key_and_cert(private_key, certificate)

        fingerprint = SecurityManager.get_fingerprint(certificate)
        state.cert_fingerprints['server'] = fingerprint
        logger.info(f"Generated new cert (FP: {fingerprint[:16]}...)")
        return private_key, certificate, key_path, cert_path

    @staticmethod
    def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> str:
        """Sign data with RSA private key using PSS padding."""
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(data: bytes, signature: str, public_key: rsa.RSAPublicKey) -> bool:
        """Verify signature with public key using PSS padding."""
        try:
            decoded_signature = base64.b64decode(signature)
            public_key.verify(
                decoded_signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (ValueError, TypeError, InvalidSignature) as e:
            logger.error(f"Signature verify failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected sig verify error: {e}")
            return False

    @staticmethod
    def generate_hmac(data: bytes, key: bytes) -> str:
        """Generate HMAC-SHA256 signature."""
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_hmac(data: bytes, signature: str, key: bytes) -> bool:
        """Verify HMAC-SHA256 signature using a constant-time comparison."""
        expected_signature = SecurityManager.generate_hmac(data, key)
        return hmac.compare_digest(expected_signature, signature)

    @staticmethod
    def generate_challenge() -> Dict[str, str]:
        """Generate a cryptographic challenge for client authentication."""
        challenge_id = str(uuid.uuid4())
        challenge_data = secrets.token_hex(32)
        expiry = time.time() + config.CHALLENGE_EXPIRY_SECONDS

        state.security_challenges[challenge_id] = {
            'data': challenge_data,
            'expiry': expiry,
            'used': False
        }
        logger.debug(f"Generated challenge {challenge_id}")
        return {
            'challenge_id': challenge_id,
            'challenge_data': challenge_data
        }

    @staticmethod
    def verify_challenge_response(challenge_id: str, response: str, client_id: str) -> bool:
        """Verify a challenge response."""
        logger.debug(f"Verify challenge resp for {challenge_id} from {client_id}")
        challenge = state.security_challenges.get(challenge_id)
        if not challenge:
            logger.warning(f"Challenge ID not found/cleaned: {challenge_id}")
            return False
        if challenge['expiry'] < time.time():
            logger.warning(f"Challenge expired: {challenge_id}")
            state.security_challenges.pop(challenge_id, None)
            return False
        if challenge['used']:
            logger.warning(f"Challenge already used: {challenge_id}")
            return False
        session = state.active_sessions.get(client_id)
        if not session or 'session_key' not in session:
            logger.warning(f"No active session/key for client: {client_id}")
            return False
        session_key = session['session_key'].encode('utf-8')
        challenge_data = challenge['data'].encode('utf-8')
        is_valid = SecurityManager.verify_hmac(challenge_data, response, session_key)

        if is_valid:
            logger.info(f"Challenge {challenge_id} OK for {client_id}")
            challenge['used'] = True
            return True
        else:
            logger.warning(f"Challenge resp FAILED for client: {client_id}, challenge: {challenge_id}")
            state.suspicious_activities[client_id] = state.suspicious_activities.get(client_id, 0) + 1
            return False

    @staticmethod
    def get_fingerprint(certificate: x509.Certificate) -> str:
        """Get SHA-256 fingerprint of a certificate."""
        fingerprint = certificate.fingerprint(hashes.SHA256())
        return fingerprint.hex()

    @staticmethod
    def get_system_fingerprint() -> str:
        """Get a unique fingerprint for this server system."""
        try:
            system_info = {
                'hostname': socket.gethostname(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'system': platform.system(),
                'version': platform.version(),
                 'python_version': platform.python_version()
            }

            mac_addresses = set()
            if NETIFACES_AVAILABLE:
                try:
                    for interface in netifaces.interfaces():
                         if netifaces.AF_LINK in netifaces.ifaddresses(interface):
                              mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0].get('addr')
                              if mac: mac_addresses.add(mac.lower())
                except Exception as e:
                     logger.warning(f"Could not get MACs via netifaces: {e}")
            else:
                 cmd = []
                 if platform.system() == "Linux":
                     cmd = ['ip', 'link']
                 elif platform.system() == "Darwin":
                     cmd = ['ifconfig']
                 elif platform.system() == "Windows":
                     cmd = ['getmac', '/v', '/fo', 'list']

                 if cmd:
                     try:
                         result = subprocess.run(cmd, capture_output=True, text=True, timeout=2, check=False)
                         mac_pattern = re.compile(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', re.IGNORECASE)
                         found_macs = mac_pattern.findall(result.stdout)
                         mac_addresses.update(m[0]+m[1] for m in found_macs)
                     except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                         logger.warning(f"Could not get MACs via cmd '{' '.join(cmd)}': {e}")

            system_info['mac_addresses'] = sorted(list(mac_addresses))

            fingerprint_data = json.dumps(system_info, sort_keys=True).encode('utf-8')
            fingerprint = hashlib.sha256(fingerprint_data).hexdigest()
            return fingerprint

        except Exception as e:
            logger.error(f"Error generating system fingerprint: {e}", exc_info=True)
            return hashlib.sha256(socket.gethostname().encode('utf-8')).hexdigest()


class FrameSecurityManager:
    """Handles video frame security operations like watermarking and signing."""

    @staticmethod
    def secure_frame(frame: np.ndarray, client_id: str, timestamp: Optional[str] = None) -> Tuple[np.ndarray, str, str, bytes]:
        """Adds security features (watermark/timestamp, signs) to a video frame."""
        secured_frame = frame.copy()

        if timestamp is None:
            timestamp = datetime.now().isoformat()

        frame_count = state.frame_counter
        state.frame_counter += 1
        unique_id = f"{client_id}:{frame_count}:{timestamp}"

        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale_small = 0.4
        font_scale_medium = 0.5
        thickness = 1
        text_color = (200, 200, 200)
        bg_color = (0, 0, 0)

        time_text = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        (tw, th), _ = cv2.getTextSize(time_text, font, font_scale_medium, thickness)
        cv2.rectangle(secured_frame, (5, 5), (10 + tw, 10 + th + 5), bg_color, -1)
        cv2.putText(secured_frame, time_text, (10, 10 + th), font, font_scale_medium, text_color, thickness, cv2.LINE_AA)

        frame_data_text = f"F:{frame_count}"
        (fw, fh), _ = cv2.getTextSize(frame_data_text, font, font_scale_small, thickness)
        pos_x = secured_frame.shape[1] - fw - 15
        pos_y = secured_frame.shape[0] - 10
        cv2.putText(secured_frame, frame_data_text, (pos_x, pos_y), font, font_scale_small, (150, 150, 150), thickness, cv2.LINE_AA)

        ret, buffer = cv2.imencode('.jpg', secured_frame)
        if not ret:
             logger.error("Failed encode frame for signing.")
             _, plain_buffer = cv2.imencode('.jpg', frame)
             return frame, unique_id, "", plain_buffer.tobytes()

        frame_bytes = buffer.tobytes()
        frame_hash = hashlib.sha256(frame_bytes).hexdigest()

        signature_payload = f"{unique_id}:{frame_hash}".encode('utf-8')
        signature_payload_bytes = signature_payload

        signature = ""
        session = state.active_sessions.get(client_id)
        if session and 'session_key' in session:
            session_key = session['session_key'].encode('utf-8')
            signature = SecurityManager.generate_hmac(signature_payload_bytes, session_key)

            state.frame_signatures[unique_id] = {
                'hash': frame_hash,
                'timestamp': timestamp,
                'signature': signature,
                'expiry': time.time() + config.FRAME_SIGNATURE_EXPIRY_SECONDS
            }
        else:
            logger.warning(f"No session/key for {client_id}. Cannot generate frame HMAC.")

        return secured_frame, unique_id, signature, frame_bytes


class NetworkSecurityManager:
    """Manages network security monitoring (ARP) and utility functions."""

    @staticmethod
    def _parse_arp_table(arp_output: str) -> Dict[str, str]:
        """Parses ARP command output based on platform."""
        entries = {}
        if platform.system() == 'Darwin':
            arp_pattern = re.compile(r'\? \((?P<ip>\d+\.\d+\.\d+\.\d+)\) at (?P<mac>([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})')
            for match in arp_pattern.finditer(arp_output):
                entries[match.group('ip')] = match.group('mac').lower()
        elif platform.system() == 'Linux':
             arp_pattern = re.compile(r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(?P<mac>([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})')
             for line in arp_output.splitlines():
                 match = arp_pattern.match(line)
                 if match:
                     entries[match.group('ip')] = match.group('mac').lower()
        elif platform.system() == 'Windows':
             arp_pattern = re.compile(r'^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})')
             for line in arp_output.splitlines():
                  match = arp_pattern.match(line)
                  if match:
                      entries[match.group('ip')] = match.group('mac').lower().replace('-', ':')
        else:
            logger.warning(f"Unsupported platform for ARP parsing: {platform.system()}")

        return entries


    @staticmethod
    def check_network_security() -> Dict[str, Any]:
        """Checks for network security issues like ARP spoofing."""
        current_time = time.time()
        if current_time - state.last_arp_check_time < config.NETWORK_CHECK_INTERVAL_SECONDS:
            return state.network_status

        logger.debug("Performing network security check (ARP)...")
        state.last_arp_check_time = current_time
        state.network_status['last_check_time'] = current_time

        cmd = []
        if platform.system() == 'Darwin': cmd = ['arp', '-an']
        elif platform.system() == 'Linux': cmd = ['ip', 'neighbor', 'show']
        elif platform.system() == 'Windows': cmd = ['arp', '-a']
        else:
            logger.error(f"ARP check not supported on platform: {platform.system()}")
            return state.network_status

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2, check=False)
            if result.returncode != 0:
                 logger.warning(f"ARP cmd '{' '.join(cmd)}' failed (Code {result.returncode}). Stderr: {result.stderr}")
                 state.network_status['error_count'] += 1
                 return state.network_status

            current_arp_entries = NetworkSecurityManager._parse_arp_table(result.stdout)
            if not current_arp_entries:
                 logger.warning(f"Could not parse ARP output.")

            if 'arp' not in state.network_baseline or not state.network_baseline['arp']:
                state.network_baseline = {'arp': current_arp_entries, 'timestamp': current_time}
                logger.info(f"Established ARP baseline ({len(current_arp_entries)} entries).")
                state.network_status['arp_spoof_detected'] = False
                state.network_status['suspicious_macs'].clear()
            else:
                baseline_arp = state.network_baseline['arp']
                suspicious_changes_detected = 0
                current_suspicious_macs = set()

                for ip, current_mac in current_arp_entries.items():
                    if ip in baseline_arp and baseline_arp[ip] != current_mac:
                        logger.warning(f"ARP Change: IP {ip} MAC {baseline_arp[ip]} -> {current_mac}")
                        suspicious_changes_detected += 1
                        current_suspicious_macs.add(current_mac)
                        for base_ip, base_mac in baseline_arp.items():
                             if base_ip != ip and base_mac == current_mac:
                                  logger.error(f"Duplicate MAC: IP {ip} now has MAC {current_mac} (was {base_ip}). Potential Spoofing!")
                                  suspicious_changes_detected += 5

                state.network_status['suspicious_macs'].update(current_suspicious_macs)

                spoof_threshold = 2
                if suspicious_changes_detected >= spoof_threshold:
                    if not state.network_status['arp_spoof_detected']:
                         logger.error(f"ARP Spoof Detected! ({suspicious_changes_detected} changes/duplicates). Suspicious MACs: {current_suspicious_macs}")
                    state.network_status['arp_spoof_detected'] = True
                else:
                     if state.network_status['arp_spoof_detected']:
                          logger.info("ARP status normal again.")
                     state.network_status['arp_spoof_detected'] = False

                baseline_age = current_time - state.network_baseline.get('timestamp', 0)
                if baseline_age > config.NETWORK_BASELINE_UPDATE_INTERVAL_SECONDS and not state.network_status['arp_spoof_detected']:
                    state.network_baseline = {'arp': current_arp_entries, 'timestamp': current_time}
                    logger.info(f"Refreshed ARP baseline ({len(current_arp_entries)} entries).")

            state.network_status['error_count'] = 0

        except subprocess.TimeoutExpired:
            logger.warning(f"ARP cmd '{' '.join(cmd)}' timed out.")
            state.network_status['error_count'] += 1
        except FileNotFoundError:
             logger.error(f"ARP cmd not found: {' '.join(cmd)}. Check installation.")
             state.network_status['error_count'] += 1
        except Exception as e:
            logger.error(f"Unexpected ARP check error: {e}", exc_info=True)
            state.network_status['error_count'] += 1

        return state.network_status

    @staticmethod
    def check_ip_reputation(ip: str) -> bool:
        """Checks if an IP is blacklisted (basic implementation)."""
        if ip in state.blacklisted_ips:
            logger.warning(f"IP {ip} is blacklisted.")
            return False
        return True

    @staticmethod
    def rate_limit_check(ip: str) -> bool:
        """Checks if an IP is exceeding defined rate limits."""
        current_time = time.time()
        limit = config.RATE_LIMIT_MAX_REQUESTS
        window = config.RATE_LIMIT_WINDOW_SECONDS

        ip_data = state.network_status['connection_attempts'].setdefault(
            ip, {'count': 0, 'first_attempt': current_time, 'last_attempt': current_time}
        )

        time_since_first = current_time - ip_data['first_attempt']
        if time_since_first > window:
            ip_data['count'] = 1
            ip_data['first_attempt'] = current_time
            ip_data['last_attempt'] = current_time
            return True
        else:
            ip_data['count'] += 1
            ip_data['last_attempt'] = current_time
            if ip_data['count'] > limit:
                logger.warning(f"Rate limit exceeded for {ip}: {ip_data['count']}/{limit} in {time_since_first:.2f}s")
                return False
            else:
                 logger.debug(f"Rate limit check {ip}: {ip_data['count']}/{limit}")
                 return True


    @staticmethod
    def cleanup_expired_data():
        """Cleans up expired data from server state."""
        current_time = time.time()
        logger.debug("Running cleanup task...")

        expired_sessions = [
            client_id for client_id, session in state.active_sessions.items()
            if session.get('expiry', 0) < current_time
        ]
        if expired_sessions:
            logger.info(f"Cleaned {len(expired_sessions)} expired sessions: {expired_sessions}")
            for client_id in expired_sessions:
                state.active_sessions.pop(client_id, None)
                state.trusted_clients.pop(client_id, None)
                state.suspicious_activities.pop(client_id, None)

        expired_signatures = [
            frame_id for frame_id, sig_data in state.frame_signatures.items()
            if sig_data.get('expiry', 0) < current_time
        ]
        if expired_signatures:
             logger.debug(f"Cleaned {len(expired_signatures)} expired frame signatures.")
             for frame_id in expired_signatures:
                 state.frame_signatures.pop(frame_id, None)

        expired_challenges = [
            challenge_id for challenge_id, challenge in state.security_challenges.items()
            if challenge.get('expiry', 0) < current_time
        ]
        if expired_challenges:
            logger.debug(f"Cleaned {len(expired_challenges)} expired challenges.")
            for challenge_id in expired_challenges:
                state.security_challenges.pop(challenge_id, None)

        cleanup_threshold = current_time - (config.RATE_LIMIT_WINDOW_SECONDS * 5)
        stale_ips = [
            ip for ip, data in state.network_status['connection_attempts'].items()
            if data.get('last_attempt', 0) < cleanup_threshold
        ]
        if stale_ips:
            logger.debug(f"Cleaned rate limit data for {len(stale_ips)} stale IPs.")
            for ip in stale_ips:
                 state.network_status['connection_attempts'].pop(ip, None)

        logger.debug("Cleanup task finished.")



def _get_display_ip() -> str:
     """Helper to get a displayable IP address for HTML pages."""
     hostname = socket.gethostname()
     try:
         local_ip = socket.gethostbyname(hostname)
         if local_ip == '127.0.0.1' and NETIFACES_AVAILABLE:
              for iface in netifaces.interfaces():
                   if netifaces.AF_INET in netifaces.ifaddresses(iface):
                        for addr_info in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                             if addr_info['addr'] != '127.0.0.1':
                                  return addr_info['addr']
         return local_ip
     except socket.gaierror:
         return "localhost"
     except Exception:
          return "localhost"

@app.route('/')
def index():
    """Provides a simple HTML status page."""
    client_ip = request.remote_addr
    logger.info(f"Index request from: {client_ip}")

    if not NetworkSecurityManager.check_ip_reputation(client_ip) or \
       not NetworkSecurityManager.rate_limit_check(client_ip):
        logger.warning(f"Blocked index access from suspicious IP: {client_ip}")
        abort(403)

    network_status = state.network_status
    security_alert = network_status.get('arp_spoof_detected', False)
    status_text = "ALERT: Possible Network Attack" if security_alert else "System Normal"
    status_color = "red" if security_alert else "green"
    display_ip = _get_display_ip()
    server_fingerprint_short = state.cert_fingerprints.get('server', 'N/A')[:16]

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Secure Camera Server Status</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body {{ font-family: sans-serif; margin: 20px; background-color: #f4f4f4; }}
        .container {{ max-width: 700px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; text-align: center; }}
        p {{ color: #555; }}
        strong {{ color: #000; }}
        .status {{ padding: 10px; border-radius: 4px; font-weight: bold; text-align: center; margin-bottom: 15px; color: white; }}
        .status.normal {{ background-color: {status_color}; }}
        .status.alert {{ background-color: {status_color}; }}
        .info {{ background-color: #e7f3fe; border-left: 6px solid #2196F3; padding: 10px; margin-top: 15px; font-size: 0.9em}}
        .footer {{ font-size: 0.8em; text-align: center; margin-top: 20px; color: #777; }}
        ul {{ list-style-type: disc; padding-left: 20px; }}
        li {{ margin-bottom: 5px;}}
    </style>
</head>
<body>
    <div class="container">
        <h1>Enhanced Secure Camera Server</h1>
        <div class="status {'alert' if security_alert else 'normal'}">{status_text}</div>
        <p>Server is running and ready to accept secure client connections.</p>
        <p>Stream URL: <strong>https://{display_ip}:5443/video_feed</strong></p>
         <div class="info">
             <strong>Security Features Enabled:</strong>
             <ul>
                 <li>Mutual TLS Authentication (via SSL context setup)</li>
                 <li>Frame Signing (HMAC per frame)</li>
                 <li>Challenge-Response Authentication</li>
                 <li>ARP Spoofing Detection</li>
                 <li>Device Fingerprinting</li>
                 <li>Rate Limiting & IP Reputation (Basic)</li>
             </ul>
        </div>
        <div class="footer">
            Server Fingerprint (SHA-256): {server_fingerprint_short}... <br/>
            &copy; {datetime.now().year} Secure Systems Inc.
        </div>
    </div>
</body>
</html>
"""

def gen_frames(client_id: str):
    """Generator function for MJPEG video stream with security headers."""
    logger.info(f"Start frame gen for client: {client_id}")
    cam = CameraManager.get_camera()
    if cam is None or not cam.isOpened():
        logger.error(f"Camera N/A for client {client_id}")
        return

    target_fps = 15
    frame_interval = 1.0 / target_fps
    last_frame_time = time.time()

    try:
        while True:
            current_time = time.time()
            elapsed = current_time - last_frame_time
            if elapsed < frame_interval:
                sleep_duration = frame_interval - elapsed
                time.sleep(sleep_duration)
            last_frame_time = time.time()

            if client_id not in state.active_sessions:
                 logger.warning(f"Client session ended {client_id}. Stop stream.")
                 break

            success, frame = cam.read()
            if not success:
                logger.warning(f"Failed read frame for {client_id}. Retrying...")
                time.sleep(0.5)
                continue

            secured_frame, frame_id, signature, frame_bytes = FrameSecurityManager.secure_frame(
                frame, client_id
            )

            frame_id_bytes = f'X-Frame-ID: {frame_id}\r\n'.encode('utf-8')
            signature_bytes = f'X-Frame-Signature: {signature}\r\n\r\n'.encode('utf-8')
            headers = (
                b'--frame\r\n' +
                b'Content-Type: image/jpeg\r\n' +
                frame_id_bytes +
                signature_bytes
            )
            frame_part = headers + frame_bytes + b'\r\n'

            yield frame_part

    except GeneratorExit:
         logger.info(f"Client {client_id} disconnected stream.")
    except Exception as e:
        logger.error(f"Frame gen error for {client_id}: {e}", exc_info=True)
    finally:
         logger.info(f"Finished frame gen for {client_id}")


@app.route('/video_feed')
def video_feed():
    """Provides the secure MJPEG video stream, requires authentication."""
    client_ip = request.remote_addr
    logger.info(f"Video stream request from: {client_ip}")

    if not NetworkSecurityManager.check_ip_reputation(client_ip) or \
       not NetworkSecurityManager.rate_limit_check(client_ip):
        logger.warning(f"Blocked stream access for suspicious IP: {client_ip}")
        abort(403)

    auth_header = request.headers.get('Authorization')
    client_id_header = request.headers.get('X-Client-ID')
    token = None

    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]

    if not token or not client_id_header:
        logger.warning(f"Stream request missing Token/Client-ID from {client_ip}")
        return Response("Auth required: Token & X-Client-ID mandatory.", 401, {'WWW-Authenticate': 'Bearer'})

    payload = SecurityManager.verify_token(token)
    if not payload:
        logger.warning(f"Invalid token for stream from {client_ip}")
        return Response("Invalid or expired token.", 401)

    token_client_id = payload.get('client_id')
    if token_client_id != client_id_header:
        logger.error(f"Client ID mismatch! Header='{client_id_header}', Token='{token_client_id}'. IP: {client_ip}")
        return Response("Client ID mismatch.", 401)

    session = state.active_sessions.get(token_client_id)
    if not session:
        logger.warning(f"No active session for client {token_client_id}")
        return Response("Session not found. Re-authenticate.", 401)

    if session.get('token') != token:
         logger.warning(f"Token mismatch for active session {token_client_id}")
         return Response("Invalid session token.", 401)

    if session.get('expiry', 0) < time.time():
        logger.warning(f"Session expired for {token_client_id}")
        state.active_sessions.pop(token_client_id, None)
        return Response("Session expired. Re-authenticate.", 401)

    token_device_fp = payload.get('device_fingerprint')
    session_device_fp = session.get('device_fingerprint')
    if session_device_fp and token_device_fp != session_device_fp:
         logger.error(f"Device FP Mismatch for client {token_client_id}")
         state.suspicious_activities[token_client_id] = state.suspicious_activities.get(token_client_id, 0) + 5
         state.active_sessions.pop(token_client_id, None)
         return Response("Device fingerprint mismatch. Session terminated.", 403)

    logger.info(f"Client {token_client_id} auth OK for video stream.")
    session['last_activity'] = time.time()

    return Response(gen_frames(token_client_id),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Handles client authentication, session creation, and challenge generation."""
    client_ip = request.remote_addr
    logger.info(f"Auth request from: {client_ip}")

    if not NetworkSecurityManager.check_ip_reputation(client_ip) or \
       not NetworkSecurityManager.rate_limit_check(client_ip):
        logger.warning(f"Blocked auth from suspicious IP: {client_ip}")
        abort(403)

    if not request.is_json:
         return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 415

    auth_data = request.get_json()
    if not auth_data:
        return jsonify({'status': 'error', 'message': 'Missing JSON data'}), 400

    client_id = auth_data.get('client_id')
    device_fingerprint = auth_data.get('device_fingerprint')
    client_cert_fingerprint = auth_data.get('certificate_fingerprint')

    if not client_id or not device_fingerprint:
        logger.warning(f"Auth request {client_ip} missing client_id/device_fingerprint.")
        return jsonify({'status': 'error', 'message': 'Missing client_id, device_fingerprint'}), 400

    is_existing_client = client_id in state.trusted_clients
    stored_fingerprint = state.trusted_clients.get(client_id, {}).get('device_fingerprint')

    if is_existing_client and stored_fingerprint != device_fingerprint:
        logger.error(f"Device FP mismatch for client: {client_id}! Stored={stored_fingerprint[:8]}..., Provided={device_fingerprint[:8]}... IP: {client_ip}")
        state.suspicious_activities[client_id] = state.suspicious_activities.get(client_id, 0) + 1
        if state.suspicious_activities[client_id] > 3:
             logger.error(f"Blocking client {client_id} due to repeated device FP mismatches.")
             return jsonify({'status': 'error', 'message': 'Auth failed: device mismatch.'}), 401

    session_key = secrets.token_hex(32)
    token = SecurityManager.generate_token(client_id, device_fingerprint)
    expiry_time = time.time() + config.JWT_EXPIRATION_SECONDS

    state.active_sessions[client_id] = {
        'token': token,
        'session_key': session_key,
        'client_ip': client_ip,
        'expiry': expiry_time,
        'device_fingerprint': device_fingerprint,
        'last_activity': time.time()
    }

    state.trusted_clients[client_id] = {
        'device_fingerprint': device_fingerprint,
        'first_seen': state.trusted_clients.get(client_id, {}).get('first_seen', datetime.now().isoformat()),
        'last_seen': datetime.now().isoformat(),
        'certificate_fingerprint': client_cert_fingerprint
    }

    if not is_existing_client:
        logger.info(f"New client registered/authed: {client_id} from {client_ip}")
    else:
        logger.info(f"Client re-authed: {client_id} from {client_ip}")

    challenge = SecurityManager.generate_challenge()

    server_info = {
        'hostname': socket.gethostname(),
        'fingerprint': state.cert_fingerprints.get('server', 'N/A'),
        'version': '2.1'
    }

    return jsonify({
        'status': 'success',
        'token': token,
        'session_key': session_key,
        'expires': int(expiry_time),
        'challenge': challenge,
        'server_info': server_info
    }), 200


@app.route('/api/challenge', methods=['POST'])
@SecurityManager.token_required
def challenge_response():
    """Handles client's response to a security challenge."""
    client_info = request.client_info
    client_id = client_info.get('client_id')
    client_ip = request.remote_addr

    logger.info(f"Challenge resp from client: {client_id} ({client_ip})")

    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 415

    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Missing JSON data'}), 400

    challenge_id = data.get('challenge_id')
    response = data.get('response')

    if not challenge_id or not response:
        return jsonify({'status': 'error', 'message': 'Missing challenge_id or response'}), 400

    is_valid = SecurityManager.verify_challenge_response(challenge_id, response, client_id)

    if is_valid:
        new_challenge = SecurityManager.generate_challenge()
        return jsonify({
            'status': 'success',
            'verified': True,
            'new_challenge': new_challenge
        }), 200
    else:
        logger.warning(f"Challenge verify FAILED for {client_id}, challenge: {challenge_id}")
        return jsonify({
            'status': 'error',
            'verified': False,
            'message': 'Challenge response incorrect.'
        }), 401


@app.route('/api/verify', methods=['POST'])
def verify_frame():
    """Verifies the signature of a specific frame (for external audit/verification)."""
    client_ip = request.remote_addr
    logger.info(f"External frame verify request from: {client_ip}")

    if not request.is_json:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 415

    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Missing JSON data'}), 400

    frame_id = data.get('frame_id')
    signature_to_verify = data.get('signature')
    client_id_from_frame = frame_id.split(':')[0] if frame_id and ':' in frame_id else None


    if not frame_id or not signature_to_verify or not client_id_from_frame:
        return jsonify({'status': 'error', 'message': 'Missing frame_id or signature'}), 400

    stored_data = state.frame_signatures.get(frame_id)
    if not stored_data:
        logger.warning(f"Frame ID '{frame_id}' not found/expired for verify request from {client_ip}.")
        return jsonify({'status': 'error', 'valid': False, 'message': 'Frame ID not found/expired'}), 404

    stored_hash = stored_data.get('hash')
    if not stored_hash:
         logger.error(f"Stored data for frame {frame_id} missing hash!")
         return jsonify({'status': 'error', 'valid': False, 'message': 'Internal error: Missing frame hash'}), 500

    signature_payload = f"{frame_id}:{stored_hash}".encode('utf-8')

    session = state.active_sessions.get(client_id_from_frame)
    if not session or 'session_key' not in session:
         logger.warning(f"No active session/key for client: {client_id_from_frame}")
         return jsonify({'status': 'error', 'valid': False, 'message': 'Cannot verify: Client session invalid'}), 400

    session_key = session['session_key'].encode('utf-8')

    is_valid = SecurityManager.verify_hmac(signature_payload, signature_to_verify, session_key)

    logger.info(f"Frame verify result for {frame_id}: {'Valid' if is_valid else 'Invalid'}")

    return jsonify({
        'status': 'success',
        'valid': is_valid,
        'frame_id': frame_id
    }), 200


@app.route('/api/heartbeat', methods=['POST'])
@SecurityManager.token_required
def heartbeat():
    """Handles client heartbeats to keep sessions alive and potentially refresh tokens."""
    client_info = request.client_info
    client_id = client_info.get('client_id')
    client_ip = request.remote_addr

    logger.debug(f"Heartbeat from client: {client_id} ({client_ip})")

    session = state.active_sessions.get(client_id)
    if not session:
        logger.warning(f"Heartbeat for non-existent session: {client_id}")
        return jsonify({'status': 'error', 'message': 'Session not found'}), 404

    session['last_activity'] = time.time()

    current_expiry = session.get('expiry', 0)
    time_to_expiry = current_expiry - time.time()
    refresh_threshold = config.JWT_EXPIRATION_SECONDS * 0.25

    if time_to_expiry < refresh_threshold:
        logger.info(f"Token expiring for {client_id} ({time_to_expiry:.0f}s left). Refreshing.")
        device_fingerprint = session.get('device_fingerprint', client_info.get('device_fingerprint'))
        new_token = SecurityManager.generate_token(client_id, device_fingerprint)
        new_expiry = time.time() + config.JWT_EXPIRATION_SECONDS

        session['token'] = new_token
        session['expiry'] = new_expiry
        session['last_activity'] = time.time()

        logger.info(f"Refreshed token for: {client_id}")
        return jsonify({
            'status': 'success',
            'server_time': datetime.now().isoformat(),
            'token_refreshed': True,
            'new_token': new_token,
            'expires': int(new_expiry)
        }), 200
    else:
        return jsonify({
            'status': 'success',
            'server_time': datetime.now().isoformat(),
            'token_refreshed': False
        }), 200


@app.route('/api/security/status', methods=['GET'])
@SecurityManager.token_required
def security_status():
    """Provides a summary of the server's current security status."""
    client_info = request.client_info
    client_id = client_info.get('client_id')
    logger.info(f"Security status request from: {client_id}")

    network_status = state.network_status

    active_session_count = len(state.active_sessions)
    server_fingerprint = SecurityManager.get_system_fingerprint()

    status_data = {
        'status': 'success',
        'network_status': {
            'arp_spoof_detected': network_status.get('arp_spoof_detected', False),
            'last_check': datetime.fromtimestamp(network_status.get('last_check_time', 0)).isoformat(),
            'suspicious_macs': list(network_status.get('suspicious_macs', set())),
            'error_count': network_status.get('error_count', 0)
        },
        'server_info': {
            'system_fingerprint_sha256': server_fingerprint,
            'active_sessions': active_session_count,
        },
        'active_sessions_summary': [
            {
                'client_id_partial': cid[:8]+"...",
                'ip_address': sess.get('client_ip', 'N/A'),
                'last_activity_ago_s': int(time.time() - sess.get('last_activity', 0))
            }
            for cid, sess in state.active_sessions.items()
        ]
    }

    return jsonify(status_data), 200


def initialize_background_tasks():
    """Initializes and starts background monitoring threads."""
    logger.info("Init background tasks...")

    network_thread = threading.Thread(target=network_monitor_thread, name="NetworkMonitorThread", daemon=True)
    network_thread.start()

    cleanup_thread = threading.Thread(target=session_cleanup_thread, name="SessionCleanupThread", daemon=True)
    cleanup_thread.start()

    logger.info("Background tasks started.")

def network_monitor_thread():
    """Background thread to periodically monitor network security (ARP)."""
    logger.info("Network monitor thread started.")
    while True:
        try:
            NetworkSecurityManager.check_network_security()
            time.sleep(config.NETWORK_CHECK_INTERVAL_SECONDS)
        except Exception as e:
            logger.error(f"Network monitor thread error: {e}", exc_info=True)
            time.sleep(config.NETWORK_CHECK_INTERVAL_SECONDS * 2)


def session_cleanup_thread():
    """Background thread to periodically clean up expired sessions and other data."""
    logger.info("Session cleanup thread started.")
    while True:
        try:
            NetworkSecurityManager.cleanup_expired_data()
            time.sleep(config.SESSION_CLEANUP_INTERVAL_SECONDS)
        except Exception as e:
            logger.error(f"Session cleanup thread error: {e}", exc_info=True)
            time.sleep(config.SESSION_CLEANUP_INTERVAL_SECONDS * 2)


def main():
    """Main application entry point."""
    logger.info("--- Starting Enhanced Secure Camera Server ---")

    try:
        private_key, certificate, key_path, cert_path = SecurityManager.initialize_certificates()
        state.server_private_key = private_key
        state.server_certificate = certificate
        logger.info("Server certs initialized OK.")
    except Exception as e:
         logger.critical(f"FATAL: Failed init certs: {e}", exc_info=True)
         return

    initialize_background_tasks()

    system_fingerprint = SecurityManager.get_system_fingerprint()
    logger.info(f"Server System FP (SHA-256): {system_fingerprint}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert_path, key_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    except ssl.SSLError as e:
         logger.critical(f"FATAL: Failed to create SSL context: {e}", exc_info=True)
         return
    except FileNotFoundError:
          logger.critical(f"FATAL: Certificate or key file not found ({cert_path}, {key_path})")
          return

    display_ip = _get_display_ip()

    logger.info("=" * 50)
    logger.info(f"Enhanced Secure Server Ready!")
    logger.info(f"Listening on: https://{display_ip}:5443")
    logger.info(f"Stream URL:   https://{display_ip}:5443/video_feed")
    logger.info(f"Server Fingerprint (SHA-256): {state.cert_fingerprints.get('server', 'N/A')[:16]}...")
    logger.info("Press Ctrl+C to stop the server.")
    logger.info("=" * 50)

    try:
        app.run(host='0.0.0.0', port=5443, ssl_context=context, threaded=True)
    except Exception as e:
        logger.critical(f"Server exited with error: {e}", exc_info=True)
    finally:
         logger.info("--- Server shutting down ---")

if __name__ == '__main__':
    import sys
    main()
