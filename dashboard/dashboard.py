import streamlit as st
import pandas as pd
import os
from datetime import datetime

# === Config ===
st.set_page_config(page_title="Cowrie ML Firewall Dashboard", layout="wide")
st.title("Cowrie Honeypot - ML Intrusion Detection Dashboard")

# === 1. Live Logs View ===
st.header("Live Logs View")
if os.path.exists("cron_output.log"):
    with open("cron_output.log", "r") as f:
        logs = f.read()
    st.text_area("Cron Job Output", logs, height=250)
else:
    st.warning("cron_output.log not found.")

# === 2. Model Results Summary ===
st.header("Model Results Summary")
if os.path.exists("malicious_ips.txt"):
    with open("malicious_ips.txt", "r") as f:
        malicious_ips = [line.strip() for line in f if line.strip()]
    st.metric("Detected Malicious IPs", len(malicious_ips))
else:
    st.warning("malicious_ips.txt not found.")

# === 3. Show Malicious IPs List ===
st.header("Malicious IPs List")
if "malicious_ips" in locals() and malicious_ips:
    st.dataframe(pd.DataFrame(malicious_ips, columns=["Blocked IPs"]))
else:
    st.info("No malicious IPs detected yet.")

# === 4. Firewall Status ===
st.header("Firewall Status")
if os.path.exists("mikrotik_log.txt"):
    with open("mikrotik_log.txt", "r") as f:
        lines = f.readlines()
        last_update = lines[-1] if lines else "No updates yet."
    st.text(f"Last Rule Triggered:\n{last_update}")
else:
    st.warning("mikrotik_log.txt not found.")

# === 5. Send Email Alert Manually ===
st.header("Manual Email Alert")
if st.button("Send Test Alert Email"):
    from send_alert_email import send_email_alert
    if "malicious_ips" in locals() and malicious_ips:
        send_email_alert(malicious_ips)
        st.success("Email sent!")
    else:
        st.error("No malicious IPs available to send.")

# === 6. Upload New Cowrie Log File ===
st.header("Upload New Cowrie Log")
uploaded = st.file_uploader("Upload cowrie.json", type="json")
if uploaded:
    with open("cowrie.json", "wb") as f:
        f.write(uploaded.getvalue())
    st.success("Uploaded and replaced cowrie.json!")

# === 7. Manual Session Test ===
st.header("Test Single Session")
test_cmd = st.text_input("Enter Command Sequence (e.g. wget http://...)", "")
if st.button("Predict"):
    if any(kw in test_cmd.lower() for kw in ["wget", "curl", "nc", "ftp", "payload"]):
        st.error("Detected as Malicious")
    else:
        st.success("Detected as Benign")
