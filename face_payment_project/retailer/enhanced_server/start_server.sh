#!/bin/bash

# Enhanced Secure Facial Payment System Startup Script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
CERT_DIR="$SCRIPT_DIR/certs"
CONFIG_DIR="$SCRIPT_DIR/config"
CACHE_DIR="$SCRIPT_DIR/cache"


# Create required directories
mkdir -p "$LOG_DIR" "$CERT_DIR" "$CONFIG_DIR" "$CACHE_DIR"

# Set high-entropy server secret for enhanced security
export SERVER_SECRET="$(openssl rand -hex 32)"

echo "===================================================="
echo "    Enhanced Secure Facial Payment System Server"
echo "===================================================="
echo "Server directory: $SCRIPT_DIR"
echo "Log directory: $LOG_DIR"
echo "Certificate directory: $CERT_DIR"
echo "Server secret set successfully"
echo "===================================================="

# Ensure conda environment is activated and run the python script
python enhanced_secure_server.py
