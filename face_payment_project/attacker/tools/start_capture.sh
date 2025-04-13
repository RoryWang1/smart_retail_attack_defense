#!/bin/bash
# start_capture.sh - 启动视频流捕获

SERVER_IP="192.168.164.128"  # 默认服务器IP
SAVE_DIR="media"            # 默认保存目录
VIDEO_INTERVAL=10           # 固定为10秒的视频片段

# 颜色设置
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

# 显示帮助
show_help() {
  echo "用法: $0 [选项]"
  echo
  echo "选项:"
  echo "  -h, --help                显示此帮助"
  echo "  -s, --server IP           设置服务器IP (默认: $SERVER_IP)"
  echo "  -d, --dir 目录            设置保存目录 (默认: $SAVE_DIR)"
  echo
}

# 处理命令行参数
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      show_help
      exit 0
      ;;
    -s|--server)
      SERVER_IP="$2"
      shift 2
      ;;
    -d|--dir)
      SAVE_DIR="$2"
      shift 2
      ;;
    *)
      log_error "未知选项: $1"
      show_help
      exit 1
      ;;
  esac
done

# 检查Python3
log "检查必要的依赖..."
if ! command -v python3 &> /dev/null; then
  log_error "未找到python3，请安装"
  exit 1
fi

# 使用apt安装所需的系统包
log "检查并安装必要的Python库..."
PACKAGES="python3-opencv python3-numpy python3-requests python3-urllib3"
MISSING_PACKAGES=""

for pkg in $PACKAGES; do
  if ! dpkg -l | grep -q $pkg; then
    MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
  fi
done

if [ ! -z "$MISSING_PACKAGES" ]; then
  log_warn "需要安装以下包:$MISSING_PACKAGES"
  log_info "正在使用apt安装..."
  sudo apt update
  sudo apt install -y $MISSING_PACKAGES || { log_error "安装依赖包失败"; exit 1; }
fi

# 确保capture_stream.py存在
SCRIPT_DIR="$(dirname "$0")"
CAPTURE_SCRIPT="$SCRIPT_DIR/capture_stream.py"

if [ ! -f "$CAPTURE_SCRIPT" ]; then
  log_error "未找到捕获脚本: $CAPTURE_SCRIPT"
  exit 1
fi

# 确保脚本有执行权限
chmod +x "$CAPTURE_SCRIPT"

# 创建保存目录
mkdir -p "$SAVE_DIR/videos"
log "使用保存目录: $SAVE_DIR"

# 构建视频流URL
STREAM_URL="https://$SERVER_IP:5443/video_feed"
log "目标视频流: $STREAM_URL"

# 启动捕获 (不再使用image-interval参数)
log "开始捕获视频流..."
python3 "$CAPTURE_SCRIPT" "$STREAM_URL" --save-dir "$SAVE_DIR" --interval "$VIDEO_INTERVAL" --no-images
