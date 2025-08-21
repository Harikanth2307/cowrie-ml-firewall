# Cowrie ML Firewall 
This repository contains the implementation of a **honeypot-based intrusion detection and automated response system** designed for **MikroTik networks**.  
It integrates **Cowrie honeypot logs**, **machine learning detection**, and **automated firewall rules** to block malicious IPs in real-time.

---

## Structure
cowrie-ml-firewall/
src -> parse_and_detect.py, send_alert_email.py, update_mikrotik.py
dashboard -> dashboard.py

## Cowrie Honeypot Installation

The honeypot runs on a Linux VM and captures SSH/Telnet traffic.  
Below are the simplified installation steps:

# 1. Install dependencies
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip libssl-dev libffi-dev build-essential

# 2. Add a cowrie user
sudo adduser --disabled-password cowrie
sudo su - cowrie

# 3. Clone Cowrie repository
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# 4. Setup virtual environment
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# 5. Install requirements
pip install --upgrade pip
pip install -r requirements.txt

# 6. Copy default configuration
cp cowrie.cfg.dist cowrie.cfg

# 7. Start Cowrie
bin/cowrie start

# 8. Status Cowrie
bin/cowrie status

#9. Stop Cowrie
bin/cowrie stop

## MikroTik Firewall Rules

The MikroTik router detects suspicious traffic (like port scans or brute-force attempts) and redirects it to the Cowrie honeypot.
Netmiko scripts then automatically block attackers in the firewall.

1. Redirect suspicious traffic (e.g., port 22 → honeypot VM):
/ip firewall nat add chain=dstnat protocol=tcp dst-port=22 action=dst-nat to-addresses=192.160.00.00 to-ports=2222

2. Add address list for malicious IPs:
/ip firewall address-list add list=malicious address=1.2.3.4 timeout=1d

3. Drop rule for malicious IPs:
/ip firewall filter add chain=input src-address-list=malicious action=drop comment="Block malicious IPs"

4. Log suspicious scans:
/ip firewall filter add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list address-list=malicious address-list-timeout=1d comment="Port scan detection"

## Workflow Summary

MikroTik Router

Detects port scans/brute force attempts

Redirects suspicious traffic to Cowrie Honeypot

Cowrie Honeypot

Captures attacker sessions

Logs saved in cowrie.json

Detection Scripts

parse_and_detect.py analyzes logs

Hybrid detection (Random Forest + keyword rules)

Automated Response

update_mikrotik.py adds drop rules for attacker IPs

Block duration = 1 day

Alerts & Monitoring

send_alert_email.py notifies admin

streamlit_dashboard.py shows live results
