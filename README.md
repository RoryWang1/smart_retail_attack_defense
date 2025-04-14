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

Attackers continue using the latter part of the `coordinator.sh` script, coordinating `fake_https.py` to implement facial information replacement attack:

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

### security upgrade analysis

#### Multi-layered Defense Architecture Implementation

##### 1. Access Controls & Authentication

**Weaknesses in Original System:**
* **Server side**:
  - No client authentication mechanism
  - Any client able to connect to the port can access video stream
  - No session management or access control

* **Client side**:
  - Provides no client identity information
  - Unable to distinguish between legitimate and malicious servers

**Enhanced Version Implementation:**

* **Zero Trust Authentication Framework**:
  - JWT-based client identity token authentication containing client ID, device fingerprint, and expiration time
  - Device fingerprint verification ensures requests come from registered legitimate devices
  - Session keys dynamically generated for subsequent communication encryption
  - Complete verification required for each API access, including video stream endpoints

* **Multi-factor Authentication**:
  - Client generates unique device fingerprint based on hardware, operating system, and network characteristics
  - Device fingerprint serves as second authentication factor, preventing token theft
  - Multi-dimensional authentication reduces risk of single credential exposure

* **Continuous Verification Mechanism**:
  - Real-time challenge-response system ensures ongoing connection security
  - Server periodically sends random challenge codes; client must calculate correct response using session key
  - Each challenge has unique ID and expiration time; used challenges are invalidated to prevent replay attacks

##### 2. Data Security & Encryption Mechanisms

**Weaknesses in Original System:**
* **Server side**:
  - Only provides basic HTTPS encryption with self-signed certificates
  - No data integrity verification mechanism
  - Video stream can be replaced by man-in-the-middle without detection

* **Client side**:
  - Completely disables SSL verification (`verify=False`)
  - Does not verify server identity
  - No integrity verification for received video frames

**Enhanced Version Implementation:**

* **End-to-End Data Integrity Protection**:
  - Server adds HMAC-SHA256 digital signature to each video frame
  - Signatures generated using session key, including frame hash and timestamp
  - Client verifies each frame's signature, ensuring source authenticity and data integrity
  - Attackers cannot generate valid signatures without access to session key

* **High-Strength Key Management**:
  - Session keys use 256-bit random values, generated only after successful authentication
  - Keys bound to specific client and device, preventing cross-session use
  - Short-lifetime tokens require periodic updates, reducing theft risk
  - Layered key architecture ensures that even partial compromise doesn't endanger entire system

* **Advanced Certificate Management**:
  - Client implements Certificate Pinning technique
  - Stores and verifies SHA-256 fingerprint of server's SSL certificate
  - Any certificate changes trigger alerts, effectively preventing certificate replacement in MITM attacks
  - Attacker's fake server cannot provide matching certificate fingerprint

##### 3. Network Protection & Monitoring

**Weaknesses in Original System:**
* **Server side**:
  - Basic error logging without anomaly detection
  - No monitoring of client connection patterns or behavior
  
* **Client side**:
  - No network anomaly detection capability
  - Unable to detect network layer attacks such as ARP spoofing
  - Complete trust in network environment

**Enhanced Version Implementation:**

* **Proactive Network Defense**:
  - Client actively refreshes ARP table at startup, preventing pre-existing ARP cache poisoning
  - Periodically verifies ARP entries for server IP, detecting potential ARP spoofing
  - Triggers security response when abnormal changes in server MAC address are detected
  - Directly blocks ARP spoofing implemented through attacker's `coordinator.sh`

* **Advanced Anomaly Detection**:
  - Server monitors client connection patterns, request frequency, and network latency anomalies
  - IP reputation evaluation system filters suspicious source addresses
  - Suspicious activity counters track abnormal behavior, triggering security alerts when thresholds are exceeded
  - Adaptive baseline analysis distinguishes normal fluctuations from malicious interference

* **Network Traffic Analysis**:
  - Identifies unusual network behavior and traffic patterns
  - Monitors connection establishment time and video stream transmission characteristics
  - Detects signs of possible proxying or traffic redirection
  - Identifies man-in-the-middle attacks through multi-dimensional feature analysis

##### 4. Resilience Against Emerging Threats

**Weaknesses in Original System:**
* No protection against advanced attacks
* No anomaly detection or response mechanisms
* Lack of security incident response plan

**Enhanced Version Implementation:**

* **Multi-level Anomaly Response**:
  - Security anomalies (signature failures, latency anomalies, etc.) automatically trigger responses
  - Client enters security mode, stops displaying suspicious frames, preventing deception by fake video
  - Server logs suspicious activities, implementing access restrictions for persistent abnormal behavior
  - Tiered response mechanism balances security requirements with user experience

* **Anti-Tampering and Anti-Replay Design**:
  - Each video frame has unique ID, timestamp, and sequence number
  - Client tracks frame sequence continuity and time validity
  - Even if attacker uses `capture_stream.py` to capture old video
  - Replay attempts are detected due to expired timestamps or sequence anomalies

* **Automatic Recovery and Isolation Mechanisms**:
  - Security isolation of affected sessions when attacks are detected
  - Preserves suspicious event evidence for later analysis
  - Supports secure reconnection and session reconstruction
  - Minimizes attack impact scope, preventing system-wide crashes

#### Secure Interaction Process

##### Complete Secure Communication Lifecycle

1. **Initial Connection and Verification**
   * Client refreshes ARP table at startup, preventing ARP cache poisoning before launch
   * Client connects to server, retrieves certificate and verifies fingerprint
   * Immediately disconnects and issues warning if certificate mismatch is detected

2. **Authentication Phase**
   * Client sends authentication request containing client ID, device fingerprint, and server certificate fingerprint
   * Server verifies client identity, generates session key, JWT token, and initial security challenge
   * Server returns authentication information, client verifies and stores it

3. **Secure Video Stream Transmission**
   * Client includes Authorization token and client ID when requesting video stream
   * Server verifies token validity and client ID match
   * Each video frame gets unique ID, hash value, and HMAC signature
   * Client verifies signature and sequence validity of each frame

4. **Continuous Security Monitoring**
   * Server periodically sends security challenges, client must respond correctly
   * Client monitors network characteristics and frame processing metrics
   * Both parties simultaneously detect potential attack signs
   * Appropriate security measures implemented when anomalies are discovered

#### Defense Effectiveness Analysis

##### Complete Protection Against Attack Chain

1. **Blocking ARP Spoofing**
   * **Defense Technology**: Proactive ARP cache monitoring and refreshing
   * **Implementation Effect**: Attacker's `coordinator.sh` cannot successfully execute ARP spoofing
   * **Defense Validation**: Client detects server MAC address changes, immediately terminates connection

2. **Preventing Video Stream Replacement**
   * **Defense Technology**: HMAC frame signatures based on session key
   * **Implementation Effect**: Attackers cannot generate valid signatures for fake video
   * **Defense Validation**: Client rejects display when frame signatures are invalid, preventing fake video deception

3. **Detecting Certificate Forgery**
   * **Defense Technology**: Certificate pinning and fingerprint verification
   * **Implementation Effect**: Attacker's fake server certificate doesn't match stored fingerprint
   * **Defense Validation**: Client immediately refuses connection when certificate change is detected

4. **Preventing Session Hijacking**
   * **Defense Technology**: Challenge-response mechanism and continuous session verification
   * **Implementation Effect**: Even if initial connection is hijacked, valid session cannot be maintained
   * **Defense Validation**: Inability to respond to session key-based challenges leads to session termination

5. **Defending Against Replay Attacks**
   * **Defense Technology**: Timestamps, sequence numbers, and validity period management
   * **Implementation Effect**: Pre-recorded video frames are detected as invalid
   * **Defense Validation**: Client refuses to display frames with expired timestamps or sequence anomalies

#### Comprehensive Evaluation

The enhanced facial payment system implements a comprehensive multi-layered security architecture covering authentication, data integrity, network protection, and threat response. Its innovation lies in extending security verification from relying solely on network layer (HTTPS) to application layer (frame signatures, challenge-response), while introducing proactive defense and anomaly detection mechanisms.

The core advantage of this security architecture is its defense-in-depth strategy - even if attackers breach one security layer, they still face multiple additional defense lines, ultimately preventing completion of the full attack chain. The system not only effectively counters current man-in-the-middle attacks but also provides an extensible foundation framework for addressing more complex future threats.
