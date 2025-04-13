#!/bin/bash

# Enhanced secure facial payment system client launch script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
CERT_DIR="$SCRIPT_DIR/certs"
CONFIG_DIR="$SCRIPT_DIR/config"
CACHE_DIR="$SCRIPT_DIR/cache"

# Create required directories
mkdir -p "$LOG_DIR" "$CERT_DIR" "$CONFIG_DIR" "$CACHE_DIR"

# Set default server URL
DEFAULT_SERVER="https://192.168.164.128:5443/video_feed"
SERVER_URL=${1:-$DEFAULT_SERVER}

echo "===================================================="
echo "    Enhanced Secure Facial Payment Client"
echo "===================================================="
echo "Client Directory: $SCRIPT_DIR"
echo "Log Directory:    $LOG_DIR"
echo "Cert Directory:   $CERT_DIR"
echo "Server URL:       $SERVER_URL"
echo "===================================================="

# Actively refresh ARP table before startup to ensure secure network environment
echo "Flushing ARP table for clean start..."
if [ "$(uname)" == "Darwin" ]; then
    sudo arp -ad # macOS requires -ad
elif [ "$(uname)" == "Linux" ]; then
    sudo ip -s -s neigh flush all # Linux
fi
echo "ARP table flushed."

# Run Python script
python3 enhanced_secure_client.py --url "$SERVER_URL"
