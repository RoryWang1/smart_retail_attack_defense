#!/bin/bash

SERVER_IP="192.168.164.128"  # Default server IP
SAVE_DIR="media"            # Default save directory
VIDEO_INTERVAL=10           # Fixed 10 second video clips

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

show_help() {
  echo "Usage: $0 [options]"
  echo
  echo "Options:"
  echo "  -h, --help                Show this help"
  echo "  -s, --server IP           Set server IP (default: $SERVER_IP)"
  echo "  -d, --dir directory       Set save directory (default: $SAVE_DIR)"
  echo
}

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
      log_error "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

log "Checking dependencies..."
if ! command -v python3 &> /dev/null; then
  log_error "Python3 not found, please install"
  exit 1
fi

log "Checking and installing necessary Python libraries..."
PACKAGES="python3-opencv python3-numpy python3-requests python3-urllib3"
MISSING_PACKAGES=""

for pkg in $PACKAGES; do
  if ! dpkg -l | grep -q $pkg; then
    MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
  fi
done

if [ ! -z "$MISSING_PACKAGES" ]; then
  log_warn "Need to install the following packages:$MISSING_PACKAGES"
  log_info "Installing with apt..."
  sudo apt update
  sudo apt install -y $MISSING_PACKAGES || { log_error "Failed to install dependencies"; exit 1; }
fi

SCRIPT_DIR="$(dirname "$0")"
CAPTURE_SCRIPT="$SCRIPT_DIR/capture_stream.py"

if [ ! -f "$CAPTURE_SCRIPT" ]; then
  log_error "Capture script not found: $CAPTURE_SCRIPT"
  exit 1
fi

chmod +x "$CAPTURE_SCRIPT"

mkdir -p "$SAVE_DIR/videos"
log "Using save directory: $SAVE_DIR"

STREAM_URL="https://$SERVER_IP:5443/video_feed"
log "Target video stream: $STREAM_URL"

log "Starting video stream capture..."
python3 "$CAPTURE_SCRIPT" "$STREAM_URL" --save-dir "$SAVE_DIR" --interval "$VIDEO_INTERVAL" --no-images
