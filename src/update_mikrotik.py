from netmiko import ConnectHandler
from datetime import datetime

# MikroTik device configuration
MIKROTIK = {
    "device_type": "mikrotik_routeros",
    "host": "",       # MikroTik IP
    "username": "",   # MikroTik username
    "password": ""    # MikroTik password
}

# Address list name and log file
address_list_name = "ML_BLOCKED"
log_file = "mikrotik_log.txt"

# === Get already blocked IPs ===
def get_blocked_ips(conn):
    output = conn.send_command(f"/ip firewall address-list print where list={address_list_name}")
    blocked = []
    for line in output.splitlines():
        if "address=" in line:
            parts = line.split()
            for part in parts:
                if part.startswith("address="):
                    blocked.append(part.split("=")[1])
    return set(blocked)

# === Block a new IP ===
def block_ip(conn, ip):
    timeout = "1d"  # MikroTik format for 1 day
    cmd = f"/ip firewall address-list add list={address_list_name} address={ip} comment=Blocked_by_ML timeout={timeout}"
    conn.send_command(cmd)
    log(f"Blocked IP {ip} for 1 day")

# === Logging helper ===
def log(message):
    with open(log_file, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# === Main function ===
def main():
    try:
        with open("malicious_ips.txt") as f:
            malicious_ips = [line.strip() for line in f if line.strip()]

        if not malicious_ips:
            log("No IPs to block.")
            return

        conn = ConnectHandler(**MIKROTIK)
        blocked = get_blocked_ips(conn)

        for ip in malicious_ips:
            if ip not in blocked:
                block_ip(conn, ip)
            else:
                log(f"Skipped already-blocked IP {ip}")

        conn.disconnect()

    except Exception as e:
        log(f"ERROR: {e}")

if __name__ == "__main__":
    main()
