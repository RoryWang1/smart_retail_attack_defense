#!/bin/bash

# 增强安全面部支付系统客户端启动脚本
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
CERT_DIR="$SCRIPT_DIR/certs"
CONFIG_DIR="$SCRIPT_DIR/config"
CACHE_DIR="$SCRIPT_DIR/cache"

# 创建所需目录
mkdir -p "$LOG_DIR" "$CERT_DIR" "$CONFIG_DIR" "$CACHE_DIR"

# 设置默认服务器URL
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

# 在启动前主动刷新ARP表，确保安全的网络环境
echo "Flushing ARP table for clean start..."
if [ "$(uname)" == "Darwin" ]; then
    sudo arp -ad # macOS requires -ad
elif [ "$(uname)" == "Linux" ]; then
    sudo ip -s -s neigh flush all # Linux
fi
echo "ARP table flushed."

# 运行Python脚本
python3 enhanced_secure_client.py --url "$SERVER_URL"
