# smart_retail_attack_defense

## face payment attack

### usage of face payment attack

#### original server establishment /client subscription

./https_camera_server.py # start face payment server #venv

./https-client-monitor.py # start to face payment #venv

#### attack command

./start_capture.sh # get the face information of other customer 

sudo bash ./coordinator.sh [client_ip] [server_ip] [attacker_ip] # replace face information

#sudo bash ./coordinator.sh 192.168.164.129 192.168.164.128 192.168.164.130 

#### enhanced server establishment /client subscription

bash ./start_server.sh #venv

bash ./start_client.sh #venv

### attack chain analysis

#### 1. Acquiring Customer's Facial Payment Data

Attackers use the `start_capture.sh` script to initiate facial data collection:

##### Technical Methods:
* **Automated Environment Preparation**
  - Script automatically creates necessary directory structures
  - Sets appropriate access permissions
  - Automatically determines local network parameters
  - Lowers attack barrier, allowing quick deployment without manual configuration

* **Bypassing HTTPS Security Mechanisms**
  - Disables SSL certificate validation
  - Connects directly to the retailer's encrypted video stream
  - Accesses HTTPS content that should be protected
  - Does not trigger obvious security alerts

* **Video Capture and Storage**
  - Saves video streams as standard MP4 files
  - Creates a fixed reference named `latest.mp4`
  - Always points to the most recently recorded data
  - Simplifies configuration work for subsequent spoofing stages

* **Stealthy Operation**
  - Adopts a passive data reception approach
  - Does not send abnormal requests
  - Leaves no suspicious records in server logs
  - Extends the attacker's window of activity

##### Achieved Objectives:
- Successfully acquires complete video data of real customers during facial payment
- Captures all biometric features required for payment authentication
- Standardizes and stores facial data for use in the next stage
- Process is completely undetectable to the target system, equivalent to "digital voyeurism"

#### 2. Replacing Facial Payment Information

Attackers continue using the latter part of the `start_capture.sh` script, coordinating `fake_https.py` and `coordinator.sh` to implement facial information replacement attack:

##### Technical Methods:
* **Man-in-the-Middle Attack Deployment**
  - First launches the fake HTTPS server
  - Then starts the network coordinator
  - Forms a complete attack chain
  - Ensures the fake service is fully ready before traffic redirection

* **Network Traffic Hijacking**
  - Uses carefully designed ARP spoofing techniques
  - Simultaneously deceives both client and server
  - Makes both parties mistake the attacker's machine for the other
  - Creates a perfect man-in-the-middle position

* **Precise Traffic Redirection**
  - Uses iptables NAT rules
  - Targets HTTPS traffic on specific ports (443 and 5443)
  - Seamlessly redirects to local fake server
  - Only affects facial payment-related traffic, other network activities remain normal

* **Seamless Video Stream Replacement**
  - Reads previously recorded customer facial video
  - Provides it in exactly the same format as the original server
  - Causes payment system to receive pre-recorded facial data of others
  - Results in identity verification mismatch

* **Continuous Attack Maintenance**
  - Continuously monitors status of all attack components
  - Detects if ARP spoofing processes are terminated
  - Immediately takes remedial measures when anomalies are found
  - Automatically restarts relevant processes, ensuring long-term stable operation

* **Graceful Exit Strategy**
  - Orderly stops each attack component
  - Restores original network configuration
  - Clears all iptables rules
  - Leaves no abnormal network state, making tracking difficult

##### Achieved Objectives:
- Successfully injects pre-captured facial data into current payment process
- Tricks retail system into associating wrong identity with current transaction
- Enables attackers to use others' biometric features for unauthorized payments
- Real transaction requests are dropped or redirected, victims remain completely unaware
- Visually undetectable, with no change in system response time or user experience
