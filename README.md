# Cowrie ML Firewall 
This repository contains the implementation of a **honeypot-based intrusion detection and automated response system** designed for **MikroTik networks**.  
It integrates **Cowrie honeypot logs**, **machine learning detection**, and **automated firewall rules** to block malicious IPs in real-time.

---

## 📂 Project Structure
cowrie-ml-firewall/
│
├── src/ # Core scripts
│ ├── parse_and_detect.py # Parses Cowrie logs & ML detection
│ ├── update_mikrotik.py # Pushes block rules to MikroTik
│ └── send_alert_email.py # Sends email alerts
│
├── dashboard/ # Streamlit dashboard
│ └── dashboard.py
│
├── README.md # Project documentation
└── requirements.txt # Python dependencies
