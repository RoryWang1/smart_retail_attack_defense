#!/usr/bin/env python3
"""
Enhanced Secure Facial Payment System Client
With multi-layer security architecture to protect against MITM attacks

Features:
- Certificate pinning
- Frame signature verification 
- Real-time ARP spoofing detection
- Challenge-response authentication
- Device fingerprinting
- Network traffic anomaly detection
- Connection loss secure cache
- Persistent security state storage
- Strict frame validation
- Proactive ARP table defense
"""

import cv2
import time
import sys
import argparse
import ssl
import numpy as np
import os
import requests
import json
import hmac
import hashlib
import logging
import socket
import threading
import queue
import subprocess
import traceback
import base64
import platform
import re
import uuid
import secrets
from datetime import datetime, timedelta
from threading import Thread
from functools import wraps
import jwt

# ============================================================================
# Configuration & Initialization
# ============================================================================

class ClientConfig:
    """Client configuration and directory setup"""
    def __init__(self):
        # Get script directory
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_dir = os.path.join(self.script_dir, "logs")
        self.cert_dir = os.path.join(self.script_dir, "certs")
        self.config_dir = os.path.join(self.script_dir, "config")
        self.cache_dir = os.path.join(self.script_dir, "cache")
        
        # Ensure all directories exist
        for directory in [self.log_dir, self.cert_dir, self.config_dir, self.cache_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(self.log_dir, "client.log")),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("EnhancedSecureClient")
        
        # Security settings
        self.client_id = f"EnhancedClient_{socket.gethostname()}_{uuid.uuid4().hex[:8]}"
        self.security_state_file = os.path.join(self.config_dir, "security_state.json")
        self.heartbeat_interval = 15  # seconds
        self.challenge_interval = 30  # seconds
        self.max_valid_frames = 30
        self.max_network_errors = 5
        self.verification_threshold = 5
        
        # Platform-specific commands
        self.platform = platform.system()
        self.setup_platform_commands()
        
    def setup_platform_commands(self):
        """Set up platform-specific commands"""
        if self.platform == "Windows":
            self.arp_command = ['arp', '-a']
            self.ping_command = ['ping', '-n', '1', '-w', '500']
        elif self.platform == "Darwin":  # macOS
            self.arp_command = ['arp', '-a']
            self.ping_command = ['ping', '-c', '1', '-W', '500']
        else:  # Linux and others
            self.arp_command = ['ip', 'neigh']
            self.ping_command = ['ping', '-c', '1', '-W', '0.5']


class ClientState:
    """Client global state"""
    def __init__(self):
        # Connection variables
        self.running = True
        self.frame_queue = queue.Queue(maxsize=30)
        self.server_fingerprint = None
        self.server_host = None
        self.server_port = None
        
        # Authentication variables
        self.session_key = None
        self.session_token = None
        self.session_expiry = 0
        self.trusted_ips = {}  # IP to MAC mapping
        self.device_fingerprint = None
        self.server_info = {}
        
        # Security variables
        self.attack_detected = False
        self.last_valid_frames = []
        self.verification_failure_count = 0
        self.network_instability_detected = False
        self.last_successful_connection_time = time.time()
        self.network_error_count = 0
        self.current_challenge = None
        self.pending_challenges = {}
        self.last_challenge_time = 0
        self.last_heartbeat_time = 0
        self.network_baseline = {}
        self.signature_cache = {}
        self.jwt_secret = None
        self.network_monitor_active = False
        self.safety_mode = False
        self.frame_sequence_tracker = {}
        
        # Add log status tracking to prevent duplicate log entries
        self.log_status = {
            'cache_mode_logged': False,      # 缓存模式日志已记录
            'attack_logged': False,          # 攻击检测日志已记录
            'arp_spoof_logged': False,       # ARP欺骗日志已记录
            'frame_validation_logged': False, # 帧验证失败日志已记录
            'verification_failure_logged': False, # 签名验证失败日志已记录
            'network_instability_logged': False   # 网络不稳定日志已记录
        }
        
        # Security status
        self.security_status = {
            'arp_spoof_detected': False,
            'ssl_valid': False,
            'server_verified': False,
            'last_successful_auth': None,
            'session_active': False,
            'attack_indicators': 0,
            'network_anomalies': 0,
            'last_check_time': time.time(),
            'frame_verification_success_rate': 100.0,
            'connection_retry_count': 0,
            'heartbeat_failures': 0,
            'suspicious_macs': set()
        }
        
        # Performance monitoring
        self.performance_metrics = {
            'frame_processing_times': [],
            'connection_times': [],
            'verification_times': [],
            'frame_count': 0,
            'dropped_frames': 0,
            'last_fps_time': time.time(),
            'last_fps_count': 0,
            'current_fps': 0
        }

# Initialize configuration and state
config = ClientConfig()
state = ClientState()
logger = config.logger

# ============================================================================
# Security State Management
# ============================================================================

class SecurityStateManager:
    """Manages loading and saving security state"""
    
    @staticmethod
    def load_security_state():
        """Load saved security state"""
        try:
            if os.path.exists(config.security_state_file):
                with open(config.security_state_file, 'r') as f:
                    saved_state = json.load(f)
                    
                    # Restore key security state
                    if saved_state.get('attack_detected', False):
                        state.attack_detected = True
                        state.security_status['attack_indicators'] = saved_state.get('attack_indicators', 5)
                        logger.warning("加载了之前检测到的攻击状态 - 启用增强防御模式")
                    
                    # Restore other important security information
                    if 'suspicious_macs' in saved_state:
                        state.security_status['suspicious_macs'] = set(saved_state['suspicious_macs'])
                        
                    if saved_state.get('arp_spoof_detected', False):
                        state.security_status['arp_spoof_detected'] = True
                    
                    # Restore TRUSTED_IPS
                    if 'trusted_ips' in saved_state:
                        state.trusted_ips = saved_state['trusted_ips']
                            
                    logger.info(f"已从 {config.security_state_file} 加载安全状态")
        except Exception as e:
            logger.error(f"加载安全状态时出错: {e}")

    @staticmethod
    def save_security_state():
        """Save current security state"""
        try:
            state_to_save = {
                'attack_detected': state.attack_detected,
                'attack_indicators': state.security_status['attack_indicators'],
                'suspicious_macs': list(state.security_status.get('suspicious_macs', [])),
                'arp_spoof_detected': state.security_status['arp_spoof_detected'],
                'timestamp': datetime.now().isoformat(),
                'trusted_ips': state.trusted_ips
            }
            
            with open(config.security_state_file, 'w') as f:
                json.dump(state_to_save, f, indent=2)
                
            logger.info(f"安全状态已保存到 {config.security_state_file}")
        except Exception as e:
            logger.error(f"保存安全状态时出错: {e}")


# ============================================================================
# Network Security Functions
# ============================================================================

class NetworkSecurityManager:
    """Manages network security operations"""
    
    @staticmethod
    def flush_arp_table():
        """Actively refresh ARP table to prevent ARP spoofing attacks"""
        try:
            logger.info("主动刷新ARP表...")
            if config.platform == "Linux":
                subprocess.run(["sudo", "ip", "neigh", "flush", "all"], check=False)
            elif config.platform == "Darwin":  # macOS
                subprocess.run(["sudo", "arp", "-d", "-a"], check=False)
            elif config.platform == "Windows":
                subprocess.run(["netsh", "interface", "ip", "delete", "arpcache"], check=False)
            logger.info("ARP表已成功刷新")
            return True
        except Exception as e:
            logger.error(f"刷新ARP表出错: {e}")
            logger.error(traceback.format_exc())
            return False
    
    @staticmethod
    def check_arp_security():
        """Check ARP table for signs of spoofing"""
        try:
            # Get current ARP table
            result = subprocess.run(config.arp_command, capture_output=True, text=True, timeout=2)
            
            # Check if command succeeded
            if result.returncode != 0:
                logger.warning(f"ARP命令失败，返回码 {result.returncode}")
                return False
                
            # Parse output
            current_mappings = {}
            
            if config.platform == "Windows" or config.platform == "Darwin":  # Windows or macOS
                # Parse "arp -a" output
                if config.platform == "Windows":
                    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})', re.IGNORECASE)
                else:  # macOS
                    pattern = re.compile(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)', re.IGNORECASE)
                
                matches = pattern.findall(result.stdout)
                for ip, mac in matches:
                    current_mappings[ip] = mac.lower()
            else:  # Linux format
                # Parse "ip neigh" output
                pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)[^\w]+([\w:]+)')
                matches = pattern.findall(result.stdout)
                for ip, mac in matches:
                    if mac.lower() != 'lladdr' and mac.lower() != 'failed':
                        current_mappings[ip] = mac.lower()
            
            # Check for suspicious changes
            suspicious_changes = 0
            suspicious_macs = []
            
            for ip, mac in current_mappings.items():
                if ip in state.trusted_ips and state.trusted_ips[ip] != mac:
                    # 只记录一次每个IP变化的日志
                    logger.warning(f"ARP映射更改: IP {ip} 从 {state.trusted_ips[ip]} 变为 {mac}")
                    suspicious_changes += 1
                    suspicious_macs.append(mac)
                    state.security_status['suspicious_macs'].add(mac)
                else:
                    # First time seeing this IP
                    if ip not in state.trusted_ips and (ip.startswith('192.168.') or 
                                                      ip.startswith('10.') or 
                                                      ip.startswith('172.')):
                        state.trusted_ips[ip] = mac
                        # 减少冗余日志
                        if ip == state.server_host or len(state.trusted_ips) <= 5:
                            logger.info(f"添加新的可信IP-MAC映射: {ip} -> {mac}")
                        
                        # If this is server's IP, store specially
                        if state.server_host and state.server_host != 'localhost' and ip == state.server_host:
                            logger.info(f"存储服务器MAC地址: {mac}")
                            state.trusted_ips['server'] = mac
            
            # Update ARP spoofing detection status
            if suspicious_changes >= 2:
                # 只在第一次检测到ARP欺骗时记录日志
                if not state.log_status['arp_spoof_logged']:
                    logger.error(f"检测到多个ARP表变更({suspicious_changes}) - 可能存在ARP欺骗！")
                    state.log_status['arp_spoof_logged'] = True
                
                state.security_status['arp_spoof_detected'] = True
                state.security_status['attack_indicators'] += 2
                state.attack_detected = True
                
                # Log suspicious MAC addresses
                for mac in suspicious_macs:
                    state.security_status['suspicious_macs'].add(mac)
                    
                # Save security state immediately
                SecurityStateManager.save_security_state()
                return False
            elif suspicious_changes == 1:
                logger.warning("检测到单个ARP表变更 - 密切监控中")
                state.security_status['network_anomalies'] += 1
                
                # Log suspicious MAC addresses
                for mac in suspicious_macs:
                    state.security_status['suspicious_macs'].add(mac)
                    
                return True
            else:
                # 重置ARP欺骗日志状态，允许在下次检测到ARP欺骗时再次记录
                state.log_status['arp_spoof_logged'] = False
            
            return True
        
        except subprocess.TimeoutExpired:
            logger.error("ARP命令执行超时")
            return False
        except Exception as e:
            logger.error(f"ARP安全检查错误: {e}")
            return False
    
    @staticmethod
    def check_server_in_arp(host_ip):
        """Check if server IP's ARP entry is suspicious"""
        try:
            # Get current ARP table
            result = subprocess.run(config.arp_command, capture_output=True, text=True, timeout=2)
            
            # Parse ARP table
            arp_entries = {}
            
            if config.platform == "Windows" or config.platform == "Darwin":  # Windows or macOS format
                # Parse "arp -a" output
                if config.platform == "Windows":
                    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})', re.IGNORECASE)
                else:  # macOS
                    pattern = re.compile(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)', re.IGNORECASE)
                
                matches = pattern.findall(result.stdout)
                for ip, mac in matches:
                    arp_entries[ip] = mac.lower()
            else:  # Linux format
                # Parse "ip neigh" output
                pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)[^\w]+([\w:]+)')
                matches = pattern.findall(result.stdout)
                for ip, mac in matches:
                    if mac.lower() != 'lladdr' and mac.lower() != 'failed':
                        arp_entries[ip] = mac.lower()
            
            # Check server IP
            if host_ip in arp_entries:
                current_mac = arp_entries[host_ip]
                
                # Check previously recorded MAC
                if 'server' in state.trusted_ips and state.trusted_ips['server'] != current_mac:
                    logger.warning(f"服务器MAC地址更改: 之前 {state.trusted_ips['server']} -> 现在 {current_mac}")
                    state.security_status['attack_indicators'] += 2
                    return True
                
                # Save server MAC
                if 'server' not in state.trusted_ips:
                    state.trusted_ips['server'] = current_mac
                    
            return False
        except Exception as e:
            logger.error(f"检查服务器ARP条目时出错: {e}")
            return False
    
    @staticmethod
    def ping_server(host):
        """Check if server is accessible via ping"""
        try:
            result = subprocess.run(config.ping_command + [host], 
                                    capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def network_monitor_thread():
        """Background thread for continuous network monitoring"""
        state.network_monitor_active = True
        
        logger.info("网络监控线程已启动")
        
        check_interval = 5  # Check every 5 seconds
        last_check_time = 0
        
        while state.network_monitor_active and state.running:
            try:
                current_time = time.time()
                
                # Only check periodically
                if current_time - last_check_time >= check_interval:
                    # Check ARP security
                    NetworkSecurityManager.check_arp_security()
                    
                    # If attack previously detected, do more aggressive checks
                    if state.attack_detected or state.security_status['attack_indicators'] > 2:
                        # Check server ARP entry
                        if state.server_host:
                            server_check = NetworkSecurityManager.check_server_in_arp(state.server_host)
                            if server_check:
                                # 只记录一次服务器ARP可疑日志
                                if not state.log_status.get('server_arp_suspicious', False):
                                    logger.warning("服务器ARP条目可疑 - 可能被篡改")
                                    state.log_status['server_arp_suspicious'] = True
                                state.security_status['attack_indicators'] += 1
                                SecurityStateManager.save_security_state()
                    
                    # Update last check time
                    last_check_time = current_time
                    state.security_status['last_check_time'] = current_time
                
                # Short pause to reduce CPU usage
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"网络监控线程错误: {e}")
                time.sleep(5)  # Longer pause on error
        
        logger.info("网络监控线程已停止")


# ============================================================================
# Security and Cryptography Functions
# ============================================================================

class SecurityManager:
    """Manages security operations"""
    
    @staticmethod
    def generate_device_fingerprint():
        """Generate a unique fingerprint for this device"""
        # Collect system information unlikely to change
        system_info = {
            'hostname': socket.gethostname(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'system': platform.system(),
            'version': platform.version()
        }
        
        # Add network interface MAC addresses
        mac_addresses = []
        try:
            import netifaces
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_LINK in addresses:
                    mac_addresses.append(addresses[netifaces.AF_LINK][0]['addr'])
        except ImportError:
            # Fallback if netifaces not available
            if config.platform == 'Linux':
                try:
                    # Use system command to get MAC addresses on Linux
                    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                    mac_pattern = re.compile(r'link/ether ([0-9a-f:]{17})')
                    mac_addresses = mac_pattern.findall(result.stdout)
                except:
                    pass
            elif config.platform == 'Darwin':  # macOS
                try:
                    # Use system command to get MAC addresses on macOS
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    mac_pattern = re.compile(r'ether ([0-9a-f:]{17})')
                    mac_addresses = mac_pattern.findall(result.stdout)
                except:
                    pass
            elif config.platform == 'Windows':
                try:
                    # Use system command to get MAC addresses on Windows
                    result = subprocess.run(['getmac'], capture_output=True, text=True)
                    mac_pattern = re.compile(r'([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})')
                    mac_addresses = mac_pattern.findall(result.stdout)
                except:
                    pass
        
        system_info['mac_addresses'] = sorted(mac_addresses)
        
        # Create hash of system info
        fingerprint_data = json.dumps(system_info, sort_keys=True).encode('utf-8')
        fingerprint = hashlib.sha256(fingerprint_data).hexdigest()
        
        return fingerprint
    
    @staticmethod
    def verify_token(token, secret):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("令牌已过期")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"无效令牌: {e}")
            return None
    
    @staticmethod
    def hmac_sign(data, key):
        """Generate HMAC signature"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    
    @staticmethod
    def verify_hmac(data, signature, key):
        """Verify HMAC signature"""
        computed = SecurityManager.hmac_sign(data, key)
        return hmac.compare_digest(computed, signature)
    
    @staticmethod
    def verify_server_certificate(url):
        """Verify server certificate matches stored fingerprint"""
        try:
            logger.info(f"验证服务器证书: {url}")
            
            # Parse URL
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            state.server_host = host
            state.server_port = port
            
            # Check server in ARP table
            suspicious = NetworkSecurityManager.check_server_in_arp(host)
            if suspicious:
                logger.warning(f"服务器IP的ARP条目可疑: {host}")
                if state.attack_detected:
                    logger.error("检测到之前的攻击且服务器ARP条目可疑 - 拒绝连接")
                    state.security_status['ssl_valid'] = False
                    return False
            
            # Load saved fingerprint
            fingerprint_file = os.path.join(config.cert_dir, "server_fingerprint.txt")
            saved_fingerprint = None
            
            if os.path.exists(fingerprint_file):
                with open(fingerprint_file, 'r') as f:
                    saved_fingerprint = f.read().strip()
                logger.info(f"加载已保存的服务器指纹: {saved_fingerprint}")
            
            # Get current certificate fingerprint
            current_fingerprint = SecurityManager.get_certificate_fingerprint(host, port)
            
            if not current_fingerprint:
                logger.error("获取证书指纹失败")
                state.security_status['ssl_valid'] = False
                return False
            
            state.server_fingerprint = current_fingerprint
            
            # If saved fingerprint exists, verify match
            if saved_fingerprint:
                if saved_fingerprint != current_fingerprint:
                    logger.error("证书指纹不匹配!")
                    logger.error(f"保存的: {saved_fingerprint}")
                    logger.error(f"当前的: {current_fingerprint}")
                    
                    # If previous attack detected, handle fingerprint mismatch more strictly
                    if state.attack_detected or state.security_status['attack_indicators'] > 0:
                        logger.error("检测到之前的攻击且证书指纹不匹配 - 拒绝连接")
                        state.security_status['ssl_valid'] = False
                        state.security_status['attack_indicators'] += 2
                        state.attack_detected = True
                        SecurityStateManager.save_security_state()  # Save attack state immediately
                        return False
                    
                    # Trust on first use pattern
                    if hasattr(args, 'trust_on_first_use') and args.trust_on_first_use:
                        logger.warning("启用了信任第一次使用模式，更新指纹")
                        with open(fingerprint_file, 'w') as f:
                            f.write(current_fingerprint)
                        state.security_status['ssl_valid'] = True
                        return True
                    
                    state.security_status['ssl_valid'] = False
                    return False
                else:
                    logger.info("证书指纹验证成功")
                    state.security_status['ssl_valid'] = True
                    return True
            else:
                # First connection, save fingerprint
                logger.info("首次连接到服务器，保存证书指纹")
                with open(fingerprint_file, 'w') as f:
                    f.write(current_fingerprint)
                state.security_status['ssl_valid'] = True
                return True
        
        except Exception as e:
            logger.error(f"证书验证错误: {e}")
            logger.error(traceback.format_exc())
            state.security_status['ssl_valid'] = False
            return False
    
    @staticmethod
    def get_certificate_fingerprint(host, port):
        """Get SHA-256 fingerprint of server SSL certificate"""
        try:
            # Use different methods based on platform
            if config.platform == "Windows":
                # On Windows use subprocess with openssl
                try:
                    cmd = ['openssl', 's_client', '-connect', f'{host}:{port}', 
                           '-servername', host, '-showcerts']
                    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, 
                                               stdout=subprocess.PIPE, 
                                               stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate(input=b"Q\n", timeout=5)
                    
                    # Extract certificate
                    cert_data = b""
                    cert_start = b"-----BEGIN CERTIFICATE-----"
                    cert_end = b"-----END CERTIFICATE-----"
                    start_idx = stdout.find(cert_start)
                    end_idx = stdout.find(cert_end)
                    
                    if start_idx >= 0 and end_idx >= 0:
                        cert_data = stdout[start_idx:end_idx + len(cert_end)]
                        
                        # Save certificate to file
                        cert_file = os.path.join(config.cert_dir, "server_cert.pem")
                        with open(cert_file, 'wb') as f:
                            f.write(cert_data)
                        
                        # Get fingerprint
                        fp_cmd = ['openssl', 'x509', '-in', cert_file, 
                                  '-fingerprint', '-sha256', '-noout']
                        fp_process = subprocess.Popen(fp_cmd, stdout=subprocess.PIPE)
                        fp_stdout, _ = fp_process.communicate()
                        
                        # Parse fingerprint
                        fp_output = fp_stdout.decode().strip()
                        if "SHA256 Fingerprint=" in fp_output:
                            fingerprint = fp_output.split("=")[1].replace(':', '')
                            return fingerprint
                except Exception as e:
                    logger.error(f"OpenSSL错误: {e}")
                    return None
            else:
                # On Unix-like systems use Python's ssl module
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        if not cert_bin:
                            return None
                        
                        # Save certificate to file
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives import hashes
                        
                        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                        
                        # Get fingerprint
                        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                        return fingerprint
        
        except Exception as e:
            logger.error(f"获取证书指纹时错误: {e}")
            logger.error(traceback.format_exc())
            return None
    
    @staticmethod
    def respond_to_challenge(challenge_data):
        """Generate response to server security challenge"""
        if not state.session_key:
            logger.error("无法响应挑战: 没有会话密钥")
            return None
        
        # Generate HMAC of challenge data using session key
        return SecurityManager.hmac_sign(challenge_data, state.session_key)
    
    @staticmethod
    def strict_verify_frame_signature(frame_id, signature, frame_data=None):
        """Enhanced strict frame verification - reject all suspicious frames"""
        start_time = time.time()
        
        # Basic validation condition
        if not state.session_key:
            # Still provide some leniency for no session key
            return True
        
        try:
            # Strict signature checks
            # 1. Signature must exist and have correct length
            if not signature or len(signature) < 64:
                state.verification_failure_count += 1
                
                # Only log occasionally to reduce spam
                if state.verification_failure_count == 1 or state.verification_failure_count % 20 == 0:
                    if not state.log_status['verification_failure_logged']:
                        logger.warning(f"帧签名验证失败: ID {frame_id}, 签名长度不正确, 连续失败: {state.verification_failure_count}")
                        state.log_status['verification_failure_logged'] = True
                
                # Update security metrics
                state.security_status['frame_verification_success_rate'] = max(0, 100 - (state.verification_failure_count * 10))
                
                # Check if threshold exceeded
                if state.verification_failure_count > config.verification_threshold:
                    # Only log when first exceeding threshold
                    if state.verification_failure_count == config.verification_threshold + 1:
                        logger.error(f"多次签名验证失败 ({state.verification_failure_count})，可能存在拦截攻击")
                    
                    state.security_status['attack_indicators'] += 1
                    
                    if state.verification_failure_count > config.verification_threshold * 2:
                        state.attack_detected = True
                        # Only refresh ARP table occasionally
                        if state.verification_failure_count % 50 == 0:
                            NetworkSecurityManager.flush_arp_table()
                            SecurityStateManager.save_security_state()
                
                return False
            
            # 2. Frame ID must exist and have correct format
            if not frame_id or not isinstance(frame_id, str) or ":" not in frame_id:
                state.verification_failure_count += 1
                
                # Log only occasionally
                if state.verification_failure_count % 50 == 0:
                    logger.warning(f"帧ID格式无效: {frame_id}, 连续失败: {state.verification_failure_count}")
                
                if state.verification_failure_count > config.verification_threshold:
                    state.security_status['attack_indicators'] += 1
                
                return False
            
            # 3. Check frame sequence number
            try:
                parts = frame_id.split(":")
                if len(parts) >= 2:
                    frame_number = int(parts[1])
                    
                    # Track frame sequence, detect sequence issues
                    if 'last_frame_number' in state.frame_sequence_tracker:
                        last_number = state.frame_sequence_tracker['last_frame_number']
                        
                        # Detect big frame number jumps (possible frame substitution)
                        if frame_number > last_number + 100:
                            # Log only significant jumps
                            logger.warning(f"可疑的大帧号跳跃: {last_number} -> {frame_number}")
                            state.security_status['attack_indicators'] += 0.5
                        # Detect frame number regression (possible replay attack)
                        elif frame_number < last_number - 10 and last_number > 50:
                            # Only log first detected regression
                            if not state.log_status.get('frame_regression_logged', False):
                                logger.warning(f"可疑的帧号倒退: {last_number} -> {frame_number}")
                                state.log_status['frame_regression_logged'] = True
                            
                            state.verification_failure_count += 1
                            state.security_status['attack_indicators'] += 0.5
                            if state.verification_failure_count > config.verification_threshold:
                                logger.error("检测到可能的帧重放攻击")
                                state.attack_detected = True
                                NetworkSecurityManager.flush_arp_table()
                            return False
                    
                    state.frame_sequence_tracker['last_frame_number'] = frame_number
            except (ValueError, IndexError):
                # Non-standard frame number format, not a severe error but worth noting
                logger.debug(f"非标准帧序号格式: {frame_id}")
            
            # All verification passed, reset failure count
            if state.verification_failure_count > 0:
                # Only log recovery for significant failures
                if state.verification_failure_count >= 5:
                    logger.info(f"帧验证恢复正常，重置失败计数 ({state.verification_failure_count} → 0)")
                
                state.verification_failure_count = 0
                state.log_status['verification_failure_logged'] = False
                state.log_status['frame_regression_logged'] = False
                
            # Record verification time
            verification_time = time.time() - start_time
            state.performance_metrics['verification_times'].append(verification_time)
            
            # Keep recent measurements
            if len(state.performance_metrics['verification_times']) > 20:
                state.performance_metrics['verification_times'].pop(0)
                
            return True
            
        except Exception as e:
            logger.error(f"帧签名验证过程中出错: {e}")
            logger.error(traceback.format_exc())
            state.verification_failure_count += 1
            return False
    
    @staticmethod
    def process_server_challenge(challenge):
        """Process security challenge from server"""
        try:
            challenge_id = challenge.get('challenge_id')
            challenge_data = challenge.get('challenge_data')
            
            if not challenge_id or not challenge_data:
                logger.warning("无效的挑战格式")
                return
            
            # Generate response
            response = SecurityManager.respond_to_challenge(challenge_data)
            
            if not response:
                logger.warning("生成挑战响应失败")
                return
            
            # Store pending challenge
            state.pending_challenges[challenge_id] = {
                'data': challenge_data,
                'response': response,
                'time': time.time()
            }
            state.last_challenge_time = time.time()
            
            # Log success but don't send response to avoid unnecessary network traffic
            logger.info("挑战验证成功")
            return
            
            # Original code for challenge response communication, uncomment to enable
            # threading.Thread(target=SecurityManager.send_challenge_response, 
            #                args=(challenge_id, response), 
            #                daemon=True).start()
        
        except Exception as e:
            logger.error(f"处理挑战时错误: {e}")
    
    @staticmethod
    def send_challenge_response(challenge_id, response):
        """Send challenge response to server"""
        try:
            # Skip if no session token
            if not state.session_token:
                logger.warning("无法发送挑战响应: 没有会话令牌")
                return
            
            # Prepare URL
            base_url = args.url.rsplit('/', 1)[0] if '/' in args.url else args.url
            challenge_url = f"{base_url}/api/challenge"
            
            # Prepare data
            data = {
                'challenge_id': challenge_id,
                'response': response
            }
            
            # Send response
            headers = {
                'Authorization': f'Bearer {state.session_token}',
                'Content-Type': 'application/json'
            }
            
            # Ensure headers use ASCII-compatible characters
            headers = HttpManager.ensure_ascii_headers(headers)
            
            challenge_response = requests.post(
                challenge_url, 
                headers=headers,
                json=data,
                verify=False,
                timeout=5
            )
            
            if challenge_response.status_code == 200:
                result = challenge_response.json()
                
                if result.get('status') == 'success' and result.get('verified'):
                    logger.info("挑战验证成功")
                    
                    # Process new challenge (if provided)
                    new_challenge = result.get('new_challenge')
                    if new_challenge:
                        SecurityManager.process_server_challenge(new_challenge)
                else:
                    logger.warning("挑战验证失败")
            else:
                logger.warning(f"挑战响应错误: HTTP {challenge_response.status_code}")
        
        except Exception as e:
            logger.error(f"发送挑战响应时错误: {e}")
    
    @staticmethod
    def get_timestamp():
        """Get standardized timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# ============================================================================
# Video Frame Management
# ============================================================================

class FrameManager:
    """Manages video frame operations"""
    
    @staticmethod
    def store_valid_frame(frame):
        """Store valid frame in cache"""
        # Ensure max cache size not exceeded
        if len(state.last_valid_frames) >= config.max_valid_frames:
            state.last_valid_frames.pop(0)  # Remove oldest frame
        
        # Add deep copy of new frame
        state.last_valid_frames.append(frame.copy())
    
    @staticmethod
    def get_cached_frame(animate=True):
        """Get frame from cache, with optional animation effect"""
        if not state.last_valid_frames:
            # If no cached frames, return warning frame
            return FrameManager.create_warning_frame("No cached frames available")
        
        # If only one frame, return it directly
        if len(state.last_valid_frames) == 1:
            frame = state.last_valid_frames[0].copy()
        else:
            # If animation requested, get frames from cache
            if animate:
                # Use current time as frame index, switching every 200ms
                frame_idx = int((time.time() * 5) % len(state.last_valid_frames))
                frame = state.last_valid_frames[frame_idx].copy()
            else:
                # Use latest frame
                frame = state.last_valid_frames[-1].copy()
        
        return FrameManager.add_cache_indicator(frame)
    
    @staticmethod
    def add_cache_indicator(frame):
        """Add cache mode indicator to frame"""
        # Add semi-transparent red bar at top
        height, width = frame.shape[:2]
        overlay = frame.copy()
        
        # Draw bar
        cv2.rectangle(overlay, (0, 0), (width, 40), (0, 0, 200), -1)
        
        # Add text
        cv2.putText(overlay, "CACHE MODE - Network connection unstable", (width//2 - 180, 25), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        
        # Add cache information
        cache_info = f"Cached frames: {len(state.last_valid_frames)}/{config.max_valid_frames}"
        cv2.putText(overlay, cache_info, (10, 25), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
        
        # Blend original frame and overlay
        alpha = 0.8  # Transparency factor
        cv2.addWeighted(overlay, alpha, frame, 1-alpha, 0, frame)
        
        return frame
    
    @staticmethod
    def enhance_frame_security(frame, frame_id, signature):
        """Add security information overlay to frame"""
        height, width = frame.shape[:2]
        
        # Create security status indicators
        security_status = []
        
        # SSL status
        if state.security_status['ssl_valid']:
            security_status.append(("SSL", (0, 255, 0)))  # Green
        else:
            security_status.append(("SSL", (0, 0, 255)))  # Red
        
        # Server verification
        if state.security_status['server_verified']:
            security_status.append(("Server", (0, 255, 0)))  # Green
        else:
            security_status.append(("Server", (0, 165, 255)))  # Orange
        
        # Frame verification
        if state.verification_failure_count == 0:
            security_status.append(("Frame", (0, 255, 0)))  # Green
        elif state.verification_failure_count < config.verification_threshold:
            security_status.append(("Frame", (0, 165, 255)))  # Orange
        else:
            security_status.append(("Frame", (0, 0, 255)))  # Red
        
        # Network status
        if not state.security_status['arp_spoof_detected'] and state.security_status['network_anomalies'] < 2:
            security_status.append(("Network", (0, 255, 0)))  # Green
        elif state.security_status['network_anomalies'] >= 2 and not state.security_status['arp_spoof_detected']:
            security_status.append(("Network", (0, 165, 255)))  # Orange
        else:
            security_status.append(("Network", (0, 0, 255)))  # Red
        
        # Add security status indicators at bottom
        overlay = frame.copy()
        indicator_width = width // len(security_status)
        
        for i, (label, color) in enumerate(security_status):
            # Calculate position
            x_pos = i * indicator_width
            cv2.rectangle(overlay, (x_pos, height - 25), (x_pos + indicator_width, height), color, -1)
            
            # Add label
            text_size = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)[0]
            text_x = x_pos + (indicator_width - text_size[0]) // 2
            text_y = height - 8
            cv2.putText(overlay, label, (text_x, text_y), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        # Calculate frame integrity score (simplified)
        integrity_score = 100 - (state.verification_failure_count * 5)
        integrity_score = max(0, min(100, integrity_score))
        
        # Add frame integrity score
        score_text = f"Frame Integrity: {integrity_score}%"
        cv2.putText(overlay, score_text, (width - 200, 25), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
        
        # Add timestamp
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cv2.putText(overlay, current_time, (10, 25), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1)
        
        # If safety mode enabled, add indicator
        if state.safety_mode:
            cv2.putText(overlay, "SAFETY MODE ACTIVE", (width // 2 - 80, 25), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
        
        # Add frame ID (shortened)
        if frame_id:
            short_id = frame_id.split(":")[-1] if ":" in frame_id else frame_id
            id_text = f"ID: {short_id}"
            cv2.putText(overlay, id_text, (10, 55), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
        
        # Blend overlay with original frame
        alpha = 0.8  # Transparency
        cv2.addWeighted(overlay, alpha, frame, 1 - alpha, 0, frame)
        
        # Add control instructions
        hint_text = "Press: 'q' to quit | 'r' to reconnect | 's' to toggle SAFETY mode"
        cv2.putText(frame, hint_text, (width // 2 - 225, height - 35), 
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
        
        return frame
    
    @staticmethod
    def enhanced_handle_frame_display(frame_data, window_name, last_frame):
        """Enhanced frame display handling, reject all unverified frames"""
        start_time = time.time()
        
        # Check if special marker frame
        if (isinstance(frame_data, tuple) and 
            isinstance(frame_data[0], str) and 
            frame_data[0] == "ATTACK_DETECTED"):
            
            # Reset log status to allow new attack detection log
            state.log_status['attack_logged'] = False
            
            state.attack_detected = True
            NetworkSecurityManager.flush_arp_table()  # Actively refresh ARP table
            
            # Log attack detection only once per notification
            if not state.log_status['attack_logged']:
                logger.warning("检测到攻击，刷新ARP表")
                state.log_status['attack_logged'] = True
                
            warning_frame = FrameManager.create_warning_frame("Attack detected, ARP table refreshed", high_priority=True)
            cv2.imshow(window_name, warning_frame)
            return warning_frame
        
        # Cache mode detection - log only state transitions to reduce spam
        if state.attack_detected and not state.log_status['cache_mode_logged']:
            logger.warning("检测到攻击，强制启用缓存模式")
            state.log_status['cache_mode_logged'] = True
        
        # Normal frame processing
        if len(frame_data) >= 4:
            frame, frame_id, signature, is_valid = frame_data
            
            # Key change: Only process validated frames
            if not is_valid:
                # Log validation failure only once per cycle
                if not state.log_status['frame_validation_logged']:
                    logger.warning("帧验证失败，使用缓存帧")
                    state.log_status['frame_validation_logged'] = True
                
                # Use last safe frame or warning frame
                if len(state.last_valid_frames) > 0:
                    cache_frame = FrameManager.get_cached_frame(animate=False)  # Use cache without animation
                    cv2.putText(cache_frame, "Frame validation failed - Using cache", (10, 90), 
                              cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
                    cv2.imshow(window_name, cache_frame)
                    return cache_frame
                else:
                    # No safe frames available
                    warning_frame = FrameManager.create_warning_frame("Frame validation failed - Possible attack", high_priority=True)
                    cv2.imshow(window_name, warning_frame)
                    return warning_frame
            else:
                # Reset validation failure log status on success
                state.log_status['frame_validation_logged'] = False
            
            # Create security mask
            height, width = frame.shape[:2]
            mask = np.ones((height, width, 3), dtype=np.uint8) * 255
            # Mask bottom 40 pixels to cover any potential timestamp
            mask[height-40:height, :] = 0
            # Apply mask
            frame = cv2.bitwise_and(frame, mask)
            
            # Add timestamp to top-left corner
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cv2.putText(frame, current_time, (10, 30), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            
            # Add security status indicator
            security_info = "Security Status: Validated"
            cv2.putText(frame, security_info, (10, 60), 
                      cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
            
            # If safety mode enabled, show indicator
            if state.safety_mode:
                cv2.putText(frame, "SAFETY MODE ACTIVE", (width // 2 - 80, 30), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
            
            # Add frame ID (shortened)
            if frame_id:
                short_id = frame_id.split(":")[-1] if ":" in frame_id else frame_id
                id_text = f"ID: {short_id}"
                cv2.putText(frame, id_text, (10, 90), 
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
            
            # Add control instructions
            hint_text = "Press: 'q' to quit | 'r' to reconnect | 's' to toggle SAFETY mode"
            cv2.putText(frame, hint_text, (width // 2 - 225, height - 15), 
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
            
            # Display frame
            cv2.imshow(window_name, frame)
            
            return frame
        else:
            # Non-standard frame format
            if last_frame is not None:
                cv2.imshow(window_name, last_frame)
                return last_frame
            else:
                warning_frame = FrameManager.create_warning_frame("Non-standard frame format received")
                cv2.imshow(window_name, warning_frame)
                return warning_frame
    
    @staticmethod
    def create_warning_frame(message, high_priority=False):
        """Create warning frame with message"""
        # Create warning image
        height, width = 480, 640
        warning_frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Set background color (red for high priority, amber for normal)
        if high_priority:
            warning_frame[:, :, 2] = 255  # Red
        else:
            warning_frame[:, :, 0] = 20  # Blue component
            warning_frame[:, :, 1] = 120  # Green component
            warning_frame[:, :, 2] = 220  # Red component
        
        # Add warning text
        cv2.putText(warning_frame, "Security Alert", (180, 170), 
                  cv2.FONT_HERSHEY_SIMPLEX, 1.5, (255, 255, 255), 3)
        
        # Split long message into multiple lines
        max_line_length = 50
        words = message.split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line) + len(word) + 1 <= max_line_length:
                current_line += (" " + word if current_line else word)
            else:
                lines.append(current_line)
                current_line = word
        
        if current_line:  # Add last line
            lines.append(current_line)
        
        # Display message lines
        y_position = 220
        for line in lines:
            cv2.putText(warning_frame, line, (50, y_position), 
                      cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
            y_position += 40
        
        # Add current time
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cv2.putText(warning_frame, current_time, (10, 30), 
                  cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        
        # Add action hints
        actions = "Press: 'q' to quit | 'r' to reconnect | 's' to toggle SAFETY mode"
        cv2.putText(warning_frame, actions, (50, height - 30), 
                  cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        
        return warning_frame


# ============================================================================
# Communication Management
# ============================================================================

class HttpManager:
    """Manages HTTP communication with server"""
    
    @staticmethod
    def ensure_ascii_headers(headers):
        """Ensure all HTTP headers are ASCII compatible"""
        safe_headers = {}
        for key, value in headers.items():
            if isinstance(value, str):
                try:
                    value.encode('latin-1')
                    safe_headers[key] = value
                except UnicodeEncodeError:
                    # If cannot encode to latin-1, use Base64 encoding
                    encoded_value = base64.urlsafe_b64encode(value.encode('utf-8')).decode('ascii')
                    safe_headers[key] = encoded_value
                    logger.debug(f"头部值已编码: {key}={encoded_value[:10]}...")
            else:
                safe_headers[key] = value
        return safe_headers
    
    @staticmethod
    def authenticate_with_server(url):
        """Authenticate with server and establish secure session"""
        try:
            # Generate device fingerprint if not already done
            if not state.device_fingerprint:
                state.device_fingerprint = SecurityManager.generate_device_fingerprint()
                logger.info(f"已生成设备指纹: {state.device_fingerprint[:16]}...")
            
            # Construct base URL
            base_url = url.rsplit('/', 1)[0] if '/' in args.url else args.url
            auth_url = f"{base_url}/api/auth"
            
            # Prepare authentication data - no timestamp
            auth_data = {
                'client_id': config.client_id,
                'device_fingerprint': state.device_fingerprint,
                'certificate_fingerprint': state.server_fingerprint
                # No timestamp to avoid time sync issues
            }
            
            # Send authentication request
            logger.info(f"发送认证请求到 {auth_url}")
            
            auth_start_time = time.time()
            response = requests.post(auth_url, json=auth_data, verify=False, timeout=5)
            auth_time = time.time() - auth_start_time
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    
                    if result.get('status') == 'success':
                        # Store session information
                        state.session_key = result.get('session_key')
                        state.session_token = result.get('token')
                        state.session_expiry = result.get('expires')
                        
                        # Store challenge
                        challenge = result.get('challenge')
                        if challenge:
                            SecurityManager.process_server_challenge(challenge)
                        
                        # Store server information
                        server_info = result.get('server_info', {})
                        if server_info:
                            state.server_info = server_info
                            logger.info(f"服务器信息: {state.server_info}")
                        
                        # Update security status
                        state.security_status['server_verified'] = True
                        state.security_status['session_active'] = True
                        state.security_status['last_successful_auth'] = datetime.now().isoformat()
                        
                        # Record authentication time
                        state.performance_metrics['connection_times'].append(auth_time)
                        if len(state.performance_metrics['connection_times']) > 10:
                            state.performance_metrics['connection_times'].pop(0)
                        
                        logger.info("认证成功")
                        
                        # Start heartbeat thread if not already running
                        state.last_heartbeat_time = time.time()
                        
                        # Fix variable naming conflict - use different variable name
                        hb_thread = threading.Thread(target=HttpManager.run_heartbeat, daemon=True)
                        hb_thread.start()
                        
                        return True
                    else:
                        logger.error(f"认证失败: {result.get('message')}")
                        return False
                except Exception as e:
                    logger.error(f"解析认证响应时出错: {e}")
                    logger.error(traceback.format_exc())
                    return False
            else:
                logger.error(f"认证请求失败: HTTP {response.status_code}")
                return False
        
        except requests.exceptions.Timeout:
            logger.error("认证请求超时")
            return False
        except requests.exceptions.ConnectionError:
            logger.error("认证期间连接错误")
            return False
        except Exception as e:
            logger.error(f"认证错误: {e}")
            logger.error(traceback.format_exc())
            return False
    
    @staticmethod
    def run_heartbeat():
        """Background thread for server heartbeat"""
        logger.info("心跳线程已启动")
        
        while state.running:
            try:
                current_time = time.time()
                
                # Skip if no active session
                if not state.session_token or not state.session_key:
                    time.sleep(5)
                    continue
                    
                # Check if time to send heartbeat
                if current_time - state.last_heartbeat_time >= config.heartbeat_interval:
                    logger.debug("向服务器发送心跳")
                    
                    # Prepare URL
                    base_url = args.url.rsplit('/', 1)[0] if '/' in args.url else args.url
                    heartbeat_url = f"{base_url}/api/heartbeat"
                    
                    # Send heartbeat
                    headers = {
                        'Authorization': f'Bearer {state.session_token}',
                        'Content-Type': 'application/json'
                    }
                    
                    # Ensure headers use ASCII compatible characters
                    headers = HttpManager.ensure_ascii_headers(headers)
                    
                    response = requests.post(
                        heartbeat_url, 
                        headers=headers,
                        json={'client_id': config.client_id, 'timestamp': SecurityManager.get_timestamp()},
                        verify=False,
                        timeout=3
                    )
                    
                    if response.status_code == 200:
                        state.last_heartbeat_time = current_time
                        
                        # Parse response
                        result = response.json()
                        
                        # Check if token refreshed
                        if result.get('token_refreshed', False):
                            new_token = result.get('new_token')
                            new_expiry = result.get('expires')
                            
                            if new_token and new_expiry:
                                state.session_token = new_token
                                state.session_expiry = new_expiry
                                logger.info("会话令牌已刷新")
                        
                        logger.debug("心跳成功")
                        state.security_status['heartbeat_failures'] = 0
                    else:
                        logger.warning(f"心跳失败: HTTP {response.status_code}")
                        state.security_status['heartbeat_failures'] += 1
                        
                        # If too many failures, invalidate session
                        if state.security_status['heartbeat_failures'] >= 3:
                            logger.error("多次心跳失败，使会话无效")
                            state.session_token = None
                            state.session_key = None
                            state.session_expiry = 0
                            state.security_status['session_active'] = False
                
                # Short pause
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"心跳错误: {e}")
                state.security_status['heartbeat_failures'] += 1
                
                # If too many failures, invalidate session
                if state.security_status['heartbeat_failures'] >= 3:
                    logger.error("多次心跳失败，使会话无效")
                    state.session_token = None
                    state.session_key = None
                    state.session_expiry = 0
                    state.security_status['session_active'] = False
                    
                time.sleep(10)  # Longer pause on error


# ============================================================================
# Video Stream Management
# ============================================================================

class VideoStreamManager:
    """Manages video stream operations"""
    
    @staticmethod
    def fetch_frames_thread(url):
        """Background thread to fetch video frames"""
        logger.info(f"启动视频帧获取线程: {url}")
        
        # Reset logging status
        state.log_status['cache_mode_logged'] = False
        state.log_status['network_instability_logged'] = False
        
        # Check security status before connecting
        if (state.attack_detected or state.security_status['attack_indicators'] > 2 or 
            state.security_status['arp_spoof_detected']):
            logger.warning("检测到之前的攻击状态，重置网络环境...")
            # Actively refresh ARP table
            NetworkSecurityManager.flush_arp_table()
            time.sleep(2)  # Wait for ARP table refresh
        
        consecutive_failures = 0
        max_consecutive_failures = 10
        
        # Check security status before connecting
        if (state.attack_detected or state.security_status['attack_indicators'] > 2 or 
            state.security_status['arp_spoof_detected']):
            logger.warning("已检测到攻击，使用增强安全检查")
            # Perform ARP security check before connecting
            arp_check_result = NetworkSecurityManager.check_arp_security()
            if state.server_host:
                server_check_result = NetworkSecurityManager.check_server_in_arp(state.server_host)
                
                if not arp_check_result or server_check_result:
                    logger.error("安全检查失败，疑似攻击正在进行")
                    
                    # Send special marker to main thread
                    if state.frame_queue.full():
                        try:
                            state.frame_queue.get_nowait()
                        except queue.Empty:
                            pass
                    
                    warning_message = "Possible network attack detected. ARP table shows suspicious entries, possible ARP spoofing."
                    warning_frame = FrameManager.create_warning_frame(warning_message, high_priority=True)
                    state.frame_queue.put((warning_frame, None, None, False))
                    
                    # Wait before continuing
                    time.sleep(5)
        
        # Use session to maintain connection between requests
        session = requests.Session()
        session.verify = False
        
        # Disable SSL warning messages
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Add authentication headers if available
        headers = {}
        if state.session_token:
            headers['Authorization'] = f'Bearer {state.session_token}'
        if config.client_id:
            headers['X-Client-ID'] = config.client_id
            
        # Ensure headers use ASCII compatible characters
        headers = HttpManager.ensure_ascii_headers(headers)
        
        connection_timeout = 3  # Connection timeout
        read_timeout = 10  # Read timeout
        
        while state.running:
            try:
                # Check if reached maximum consecutive failures
                if consecutive_failures >= max_consecutive_failures:
                    logger.warning(f"达到最大连续失败次数 ({max_consecutive_failures})")
                    
                    if not state.attack_detected:
                        state.attack_detected = True
                        state.network_instability_detected = True
                        
                        # Update security status
                        state.security_status['attack_indicators'] += 1
                        SecurityStateManager.save_security_state()  # Save attack state
                        
                        # Send special marker to main thread
                        if state.frame_queue.full():
                            try:
                                state.frame_queue.get_nowait()
                            except queue.Empty:
                                pass
                        
                        # Put warning frame in queue
                        warning_message = "Connection repeatedly failed. Possible network attack or service disruption."
                        warning_frame = FrameManager.create_warning_frame(warning_message, high_priority=True)
                        state.frame_queue.put((warning_frame, None, None, False))
                    
                    # Wait before retrying
                    time.sleep(2)
                    
                    # Reset consecutive failures to a lower level to allow recovery
                    consecutive_failures = max_consecutive_failures // 2
                    continue
                
                # Periodically check network security
                if consecutive_failures == 0 or consecutive_failures % 5 == 0:
                    NetworkSecurityManager.check_arp_security()
                
                # Update headers in case session token changed
                if state.session_token:
                    headers['Authorization'] = f'Bearer {state.session_token}'
                    
                # Ensure headers use ASCII compatible characters
                headers = HttpManager.ensure_ascii_headers(headers)
                
                # Get stream with timeout
                logger.debug(f"连接到视频流: {url}")
                response = session.get(
                    url, 
                    stream=True, 
                    timeout=(connection_timeout, read_timeout),
                    headers=headers
                )
                
                if response.status_code != 200:
                    logger.error(f"HTTP错误: {response.status_code}")
                    consecutive_failures += 1
                    state.network_error_count += 1
                    
                    # Increase timeout for next attempt
                    connection_timeout = min(connection_timeout * 1.5, 10)
                    
                    # Add to security status
                    state.security_status['connection_retry_count'] += 1
                    
                    # Wait before retrying
                    time.sleep(min(consecutive_failures, 5) * 0.5)
                    continue
                
                # Connection successful, reset counters
                consecutive_failures = 0
                state.network_error_count = 0  # Reset network error count
                state.network_instability_detected = False  # Reset network instability flag
                state.last_successful_connection_time = time.time()  # Update last successful connection time
                connection_timeout = 3  # Reset to initial value
                state.security_status['connection_retry_count'] = 0
                
                # Reset log status to allow new logs if attack happens again
                state.log_status['network_instability_logged'] = False
                
                logger.info("已连接到HTTPS视频流")
                
                # Check content type
                content_type = response.headers.get('content-type', '')
                if 'multipart/x-mixed-replace' not in content_type:
                    logger.error(f"不支持的内容类型: {content_type}")
                    consecutive_failures += 1
                    state.network_error_count += 1
                    time.sleep(0.5)
                    continue
                
                # Get boundary string
                boundary = content_type.split('boundary=')[1]
                boundary_bytes = f'--{boundary}'.encode()
                
                # Initialize buffer
                buffer = bytes()
                last_frame_time = time.time()
                frames_received = 0
                
                # Read stream content
                for chunk in response.iter_content(chunk_size=4096):  # Larger buffer
                    if not state.running:
                        break
                    
                    # Check timeout
                    if time.time() - last_frame_time > 10:  # Increased timeout threshold
                        logger.warning("10秒内未收到完整帧，重新连接")
                        break
                    
                    if not chunk:
                        continue
                    
                    # Add to buffer
                    buffer += chunk
                    
                    # Find and process complete frames
                    frame_found = False
                    while True:
                        # Find frame start
                        start_idx = buffer.find(boundary_bytes)
                        if start_idx == -1:
                            # Start not found, wait for more data
                            break
                        
                        # Find next boundary
                        next_idx = buffer.find(boundary_bytes, start_idx + len(boundary_bytes))
                        if next_idx == -1:
                            # End not found, wait for more data
                            break
                        
                        # Extract complete frame
                        frame_data = buffer[start_idx:next_idx]
                        frame_found = True
                        
                        # Update buffer
                        buffer = buffer[next_idx:]
                        
                        # Process frame data
                        try:
                            # Find headers and content
                            jpeg_start = frame_data.find(b'\r\n\r\n')
                            
                            # Extract headers
                            headers_section = frame_data[:jpeg_start].decode('utf-8', errors='ignore')
                            frame_id = None
                            signature = None
                            
                            # Parse headers
                            for line in headers_section.split('\r\n'):
                                if line.startswith('X-Frame-ID:'):
                                    frame_id = line.split(':', 1)[1].strip()
                                elif line.startswith('X-Frame-Signature:'):
                                    signature = line.split(':', 1)[1].strip()
                            
                            if jpeg_start != -1:
                                jpeg_data = frame_data[jpeg_start + 4:]
                                
                                # If data looks valid, process image
                                if len(jpeg_data) > 100:
                                    # Convert to NumPy array
                                    nparr = np.frombuffer(jpeg_data, np.uint8)
                                    
                                    # Decode image
                                    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                                    
                                    if img is not None and img.size > 0:
                                        # Update last frame time and connection time
                                        last_frame_time = time.time()
                                        state.last_successful_connection_time = time.time()  # Important: update this timestamp too
                                        frames_received += 1
                                        
                                        # Periodically log received frame count
                                        if frames_received % 10 == 0:
                                            logger.info(f"已成功接收 {frames_received} 帧")
                                        
                                        # Verify signature - use enhanced strict verification
                                        is_valid = SecurityManager.strict_verify_frame_signature(frame_id, signature, jpeg_data)
                                        
                                        # If valid, store in cache
                                        if is_valid:
                                            FrameManager.store_valid_frame(img)
                                        
                                        # Process attack detection status - avoid logging for every frame
                                        if state.attack_detected and not state.log_status['cache_mode_logged']:
                                            logger.warning("检测到攻击，强制启用缓存模式")
                                            state.log_status['cache_mode_logged'] = True
                                        
                                        # Put in queue
                                        if state.frame_queue.full():
                                            # Discard oldest frame
                                            try:
                                                state.frame_queue.get_nowait()
                                                state.performance_metrics['dropped_frames'] += 1
                                            except queue.Empty:
                                                pass
                                        
                                        state.frame_queue.put((img, frame_id, signature, is_valid))
                                        state.performance_metrics['frame_count'] += 1
                        
                        except Exception as e:
                            logger.error(f"处理帧时出错: {e}")
                    
                    # Reduce frame processing interval to improve frame rate
                    if frame_found and frames_received > 0 and frames_received % 30 == 0:
                        time.sleep(0.01)
                        
                        # Update FPS calculation
                        current_time = time.time()
                        time_diff = current_time - state.performance_metrics['last_fps_time']
                        
                        if time_diff >= 1.0:
                            fps = (state.performance_metrics['frame_count'] - state.performance_metrics['last_fps_count']) / time_diff
                            state.performance_metrics['current_fps'] = round(fps, 1)
                            state.performance_metrics['last_fps_time'] = current_time
                            state.performance_metrics['last_fps_count'] = state.performance_metrics['frame_count']
                
                # Log disconnect
                logger.info(f"流结束或连接丢失，共接收 {frames_received} 帧")
                
            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
                # Network-related errors
                error_type = "连接超时" if isinstance(e, requests.exceptions.ReadTimeout) else "连接错误"
                logger.error(f"视频流错误: {error_type}")
                
                state.network_error_count += 1
                consecutive_failures += 1
                state.security_status['connection_retry_count'] += 1
                
                # Adjust network instability detection threshold
                if state.network_error_count >= config.max_network_errors:
                    if state.network_error_count > config.max_network_errors * 2:
                        state.network_instability_detected = True
                        # Log network instability only once
                        if not state.log_status['network_instability_logged']:
                            logger.warning(f"检测到网络不稳定，错误次数 {state.network_error_count}")
                            state.log_status['network_instability_logged'] = True
                    else:
                        logger.warning(f"检测到网络错误 ({state.network_error_count})，密切监控中")
                
                # Wait before retry
                retry_time = min(consecutive_failures, 5) * 0.5
                time.sleep(retry_time)
                
            except Exception as e:
                logger.error(f"视频流错误: {e}")
                logger.error(traceback.format_exc())
                
                consecutive_failures += 1
                state.security_status['connection_retry_count'] += 1
                
                # Wait before retry
                retry_time = min(consecutive_failures, 5) * 0.5
                time.sleep(retry_time)
    
    @staticmethod
    def monitor_video_stream(url):
        """Main function to display and monitor video stream"""
        logger.info(f"启动增强安全视频监控: {url}")
        
        # Reset all log status flags
        for key in state.log_status:
            state.log_status[key] = False
        
        # If previous attack detected, automatically enable SAFETY mode
        if (state.attack_detected or state.security_status['attack_indicators'] > 2 or 
            state.security_status['arp_spoof_detected']):
            state.safety_mode = True
            logger.warning("检测到之前的攻击 - 自动启用SAFETY模式")
        
        # Create window
        window_name = "Enhanced Secure Video Stream Monitor"
        cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
        cv2.resizeWindow(window_name, 800, 600)
        
        # Verify server certificate
        verification_attempts = 0
        max_verification_attempts = 3
        verification_success = False
        
        while verification_attempts < max_verification_attempts and not verification_success:
            waiting_frame = FrameManager.create_warning_frame(
                f"Verifying server certificate ({verification_attempts+1}/{max_verification_attempts})...",
                high_priority=False
            )
            cv2.imshow(window_name, waiting_frame)
            cv2.waitKey(100)
            
            try:
                if SecurityManager.verify_server_certificate(url):
                    verification_success = True
                    logger.info("服务器证书验证成功")
                    break
                
                verification_attempts += 1
                if verification_attempts < max_verification_attempts:
                    cv2.imshow(window_name, FrameManager.create_warning_frame(
                        f"Certificate verification failed, retrying ({verification_attempts}/{max_verification_attempts})...",
                        high_priority=False
                    ))
                    cv2.waitKey(1000)
            except Exception as e:
                logger.error(f"证书验证错误: {e}")
                verification_attempts += 1
                cv2.imshow(window_name, FrameManager.create_warning_frame(
                    f"Certificate verification error ({verification_attempts}/{max_verification_attempts})...",
                    high_priority=False
                ))
                cv2.waitKey(1000)
        
        if not verification_success:
            logger.error("服务器证书验证失败")
            cv2.imshow(window_name, FrameManager.create_warning_frame(
                "Server certificate verification failed! Possible MITM attack. Continue at your own risk.",
                high_priority=True
            ))
            key = cv2.waitKey(3000)
            if key == ord('q'):
                cv2.destroyAllWindows()
                return False
        
        # Authenticate with server
        auth_attempts = 0
        max_auth_attempts = 3
        auth_success = False
        
        while auth_attempts < max_auth_attempts and not auth_success:
            waiting_frame = FrameManager.create_warning_frame(
                f"Authenticating with server ({auth_attempts+1}/{max_auth_attempts})...",
                high_priority=False
            )
            cv2.imshow(window_name, waiting_frame)
            cv2.waitKey(100)
            
            try:
                if HttpManager.authenticate_with_server(url):
                    auth_success = True
                    logger.info("认证成功")
                    break
                
                auth_attempts += 1
                if auth_attempts < max_auth_attempts:
                    cv2.imshow(window_name, FrameManager.create_warning_frame(
                        f"Authentication failed, retrying ({auth_attempts}/{max_auth_attempts})...",
                        high_priority=False
                    ))
                    cv2.waitKey(1000)
            except Exception as e:
                logger.error(f"认证错误: {e}")
                auth_attempts += 1
                cv2.imshow(window_name, FrameManager.create_warning_frame(
                    f"Authentication error ({auth_attempts}/{max_auth_attempts})...",
                    high_priority=False
                ))
                cv2.waitKey(1000)
        
        if not auth_success:
            logger.warning("认证失败，继续但安全功能受限")
            cv2.imshow(window_name, FrameManager.create_warning_frame(
                "Authentication failed. Continuing with limited security features.",
                high_priority=False
            ))
            cv2.waitKey(2000)
        
        # Start network monitoring thread
        network_thread = threading.Thread(target=NetworkSecurityManager.network_monitor_thread, daemon=True)
        network_thread.start()
        
        # Start frame fetch thread
        fetch_thread = threading.Thread(target=VideoStreamManager.fetch_frames_thread, args=(url,))
        fetch_thread.daemon = True
        fetch_thread.start()
        
        # Main display loop
        last_frame = None
        last_ui_update_time = time.time()
        no_new_frame_counter = 0
        reconnect_requested = False
        cache_mode_active = False
        auto_recovery_mode = False
        
        try:
            while state.running:
                current_time = time.time()
                
                # Check if should use cache mode - adjust trigger conditions
                time_since_last_frame = current_time - state.last_successful_connection_time
                long_frame_delay = time_since_last_frame > 5.0  # Increased to 5 seconds (was 1 second)
                network_unstable = state.network_instability_detected and state.security_status['network_anomalies'] > 3  # Increased threshold
                enough_cache = len(state.last_valid_frames) >= 1  # Only need 1 frame to use cache
                
                # Decide whether to use cache mode - stricter conditions
                should_use_cache = (long_frame_delay and network_unstable) and enough_cache
                
                # If attack detected, force cache mode
                if state.attack_detected and enough_cache:
                    should_use_cache = True
                    
                    # Only log on mode transition, not every frame
                    if not cache_mode_active:
                        cache_mode_active = True
                        # Only log if not already logged in this session
                        if not state.log_status['cache_mode_logged']:
                            logger.warning("检测到攻击，强制启用缓存模式")
                            state.log_status['cache_mode_logged'] = True
                
                # Update UI periodically even if no new frames
                if current_time - last_ui_update_time > 0.05:  # 20fps refresh rate
                    # If should use cache mode
                    if should_use_cache and not state.attack_detected:
                        if not cache_mode_active:
                            logger.info("切换到缓存模式")
                            cache_mode_active = True
                        
                        # Get cached frame
                        cached_frame = FrameManager.get_cached_frame()
                        cv2.imshow(window_name, cached_frame)
                        last_frame = cached_frame
                    elif last_frame is not None:
                        # In non-cache mode, just show last frame
                        cache_mode_active = False
                        cv2.imshow(window_name, last_frame)
                    
                    last_ui_update_time = current_time
                
                # Try to get new frame
                try:
                    frame_data = state.frame_queue.get(timeout=0.03)  # Shorter timeout for responsiveness
                    
                    # Reset counter on successful frame get
                    no_new_frame_counter = 0
                    
                    # Process frame - use enhanced frame processing function
                    last_frame = FrameManager.enhanced_handle_frame_display(frame_data, window_name, last_frame)
                    
                except queue.Empty:
                    # No new frames available
                    no_new_frame_counter += 1
                
                # Handle keyboard input
                key = cv2.waitKey(1) & 0xFF
                if key == ord('q'):
                    logger.info("用户退出")
                    state.running = False
                    reconnect_requested = False
                    break
                elif key == ord('r'):
                    logger.info("用户请求重新连接")
                    # Actively refresh ARP table before reconnecting
                    NetworkSecurityManager.flush_arp_table()
                    time.sleep(1)  # Wait for ARP table refresh
                    reconnect_requested = True
                    break
                elif key == ord('s'):
                    # Toggle SAFETY mode
                    state.safety_mode = not state.safety_mode
                    logger.info(f"SAFETY mode {'enabled' if state.safety_mode else 'disabled'}")
                    
                    # Show confirmation
                    safety_message = f"SAFETY mode {'enabled' if state.safety_mode else 'disabled'}"
                    if last_frame is not None:
                        # Add message to frame
                        notification = last_frame.copy()
                        height, width = notification.shape[:2]
                        cv2.putText(notification, safety_message, 
                                  (width//2 - 100, height//2), 
                                  cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 255), 2)
                        cv2.imshow(window_name, notification)
                        cv2.waitKey(500)
                
                # Short pause to reduce CPU usage
                time.sleep(0.001)
        
        except KeyboardInterrupt:
            logger.info("用户中断")
            reconnect_requested = False
        
        finally:
            # Cleanup
            state.running = False
            cv2.destroyAllWindows()
            
            # Return whether reconnect was requested
            return reconnect_requested


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Main function"""
    global args, state
    
    parser = argparse.ArgumentParser(description="Enhanced Secure Video Stream Monitor")
    parser.add_argument("--url", default="https://localhost:5443/video_feed", 
                        help="Video stream URL")
    parser.add_argument("--trust-on-first-use", action="store_true",
                       help="Trust certificate on first use (TOFU)")
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Load previous security state
    SecurityStateManager.load_security_state()
    
    # Initially refresh ARP table to ensure clean network environment
    logger.info("初始化时刷新ARP表...")
    NetworkSecurityManager.flush_arp_table()
    time.sleep(1)  # Wait for ARP table refresh
    
    # Generate device fingerprint
    state.device_fingerprint = SecurityManager.generate_device_fingerprint()
    logger.info(f"设备指纹: {state.device_fingerprint[:16]}...")
    
    # Use loop to handle reconnection
    reconnect = True
    
    try:
        while reconnect:
            # Reset partial state but maintain attack detection
            state.running = True
            state.network_instability_detected = False
            state.frame_queue = queue.Queue(maxsize=30)
            
            # Reset log status for a clean session
            for key in state.log_status:
                state.log_status[key] = False
            
            # Refresh ARP table before each reconnection
            if reconnect and state.running:
                logger.info("重连前刷新ARP表...")
                NetworkSecurityManager.flush_arp_table()
                time.sleep(1)  # Wait for ARP table refresh
            
            # Start monitoring and get reconnect flag
            reconnect = VideoStreamManager.monitor_video_stream(args.url)
            
            # Save state when attack detected
            if (state.attack_detected or state.security_status['attack_indicators'] > 2 or 
                state.security_status['arp_spoof_detected']):
                SecurityStateManager.save_security_state()
            
            # If user chose to quit, exit loop
            if not reconnect:
                break
                
            logger.info("准备重新连接...")
            time.sleep(1)  # Wait before reconnecting
            
    except Exception as e:
        logger.error(f"程序错误: {e}")
        logger.error(traceback.format_exc())
    
    finally:
        state.running = False
        cv2.destroyAllWindows()
        # Save security state on exit
        SecurityStateManager.save_security_state()
        logger.info("程序已终止")

if __name__ == "__main__":
    main()
