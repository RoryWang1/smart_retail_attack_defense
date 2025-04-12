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
DEFAULT_SERVER="https://172.20.10.7:5443/video_feed"
SERVER_URL=${1:-$DEFAULT_SERVER}

echo "===================================================="
echo "    增强安全面部支付系统客户端"
echo "===================================================="
echo "客户端目录: $SCRIPT_DIR"
echo "日志目录: $LOG_DIR"
echo "证书目录: $CERT_DIR"
echo "服务器URL: $SERVER_URL"
echo "===================================================="

# 在启动前主动刷新ARP表，确保安全的网络环境
echo "刷新ARP表以确保安全..."
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    sudo arp -d -a
elif [ "$(uname)" == "Linux" ]; then
    # Linux
    sudo ip neigh flush all
fi
echo "ARP表已刷新，准备启动客户端..."

# 运行Python脚本
python3 enhanced_secure_client.py --url "$SERVER_URL"
