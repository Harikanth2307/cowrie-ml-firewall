import pandas as pd
import json
import re

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# === 1. Parse Cowrie JSON to DataFrame ===
def load_sessions_from_json(json_path):
    sessions = []
    with open(json_path, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("eventid") == "cowrie.session.connect":
                    session = {
                        "session": data["session"],
                        "src_ip": data["src_ip"],
                        "start_time": data["timestamp"]
                    }
                    sessions.append(session)
                elif data.get("eventid") == "cowrie.session.closed":
                    for s in sessions:
                        if s["session"] == data["session"]:
                            s["end_time"] = data["timestamp"]
                elif data.get("eventid") == "cowrie.command.input":
                    for s in sessions:
                        if s["session"] == data["session"]:
                            s.setdefault("commands", []).append(data["input"])
            except json.JSONDecodeError:
                continue
    return pd.DataFrame(sessions)

# Load Cowrie directory
df = load_sessions_from_json("cowrie.json")

# === 2. Feature Engineering ===
df["commands"] = df["commands"].apply(lambda x: x if isinstance(x, list) else [])
df["command_sequence"] = df["commands"].apply(lambda cmds: " && ".join(cmds))
df["command_count"] = df["commands"].apply(len)
df["input_token_count"] = df["commands"].apply(lambda cmds: sum(len(c.split()) for c in cmds))
df["unique_commands"] = df["commands"].apply(lambda cmds: len(set(cmds)))
df["end_time"] = pd.to_datetime(df["end_time"])
df["start_time"] = pd.to_datetime(df["start_time"])
df["duration"] = (df["end_time"] - df["start_time"]).dt.total_seconds().fillna(0)
df["has_malicious_keyword"] = df["command_sequence"].str.contains(
    "wget|curl|nc|ftp|tftp|payload", case=False, na=False
).astype(int)
df["label"] = ((df["command_count"] > 0) & (df["has_malicious_keyword"] == 1)).astype(int)

# === 3. ML Model Training + Detection ===
df["original_index"] = df.index
df.dropna(subset=["src_ip", "duration"], inplace=True)
df["protocol"] = "ssh"  # Placeholder if not captured

# Define features (X) and target (y)
X = df[["duration", "input_token_count", "unique_commands",
        "has_malicious_keyword", "original_index"]].copy()
y = df["label"]

# Handle the case of an empty DataFrame after filtering
if X.empty:
    print("Warning: No data available for model training after preprocessing. Exiting.")
    exit()

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X.drop(columns=["original_index"]), y, test_size=0.2, random_state=42
)

# Train the RandomForestClassifier model
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

# Make predictions on the test set
y_pred = rf.predict(X_test)

# Map predictions back to the original DataFrame
test_indices = X_test.index
X_test_with_meta = df.loc[test_indices].copy()
X_test_with_meta["predicted_label"] = y_pred

# === 4. Hybrid IP Detection ===
# Get IPs identified as malicious by the ML model
ml_ips = set(X_test_with_meta[X_test_with_meta["predicted_label"] == 1]["src_ip"])
# Get IPs identified by the simple keyword-based approach
keyword_ips = set(df[df["has_malicious_keyword"] == 1]["src_ip"])
# Combine both sets to get all detected malicious IPs
all_malicious_ips = sorted(ml_ips.union(keyword_ips))

# === 5. Save output ===
with open("malicious_ips.txt", "w") as f:
    for ip in all_malicious_ips:
        f.write(ip + "\n")

print(f"Detected and saved {len(all_malicious_ips)} malicious IPs.")

# === 6. Send Email Alert ===
from send_alert_email import send_email_alert

with open("malicious_ips.txt") as f:
    ip_list = [line.strip() for line in f if line.strip()]

if ip_list:
    send_email_alert(ip_list)
else:
    print("No malicious IPs to alert on.")
