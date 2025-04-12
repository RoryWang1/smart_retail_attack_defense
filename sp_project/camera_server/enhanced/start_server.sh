#!/bin/bash

# Enhanced Secure Facial Payment System Startup Script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
CERT_DIR="$SCRIPT_DIR/certs"
CONFIG_DIR="$SCRIPT_DIR/config"
CACHE_DIR="$SCRIPT_DIR/cache"

# 激活conda环境
source $(conda info --base)/etc/profile.d/conda.sh
conda activate spstudy

# 创建所需目录
mkdir -p "$LOG_DIR" "$CERT_DIR" "$CONFIG_DIR" "$CACHE_DIR"

# 设置高熵服务器密钥增强安全性
export SERVER_SECRET="$(openssl rand -hex 32)"

echo "===================================================="
echo "    Enhanced Secure Facial Payment System Server"
echo "===================================================="
echo "Server directory: $SCRIPT_DIR"
echo "Log directory: $LOG_DIR"
echo "Certificate directory: $CERT_DIR"
echo "Server secret set successfully"
echo "===================================================="

# 确保conda环境激活，直接运行python脚本
python enhanced_secure_server.py