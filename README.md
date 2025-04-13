# smart_retail_attack_defense
## test of face payment attack
### original server establishment /client subscription
./https_camera_server.py # start face payment server 
./https-client-monitor.py # start to face payment
### attack command
./start_capture.sh # get the face information of other customer 
sudo bash ./coordinator.sh [client_ip] [server_ip] [attacker_ip] # replace face information
#sudo bash ./coordinator.sh 192.168.164.129 192.168.164.128 192.168.164.130 
### enhanced server establishment /client subscription
bash ./start_server.sh #venv
bash ./start_client.sh #venv
