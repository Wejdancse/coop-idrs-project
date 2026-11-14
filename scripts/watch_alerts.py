import json
import sqlite3
import time
import os

DB_PATH = "/home/wejdan/idrs/db/idrs.db"
LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
OFFSET_FILE = "/home/wejdan/idrs/scripts/.alerts_offset"

NORMAL_SOURCE_IP = "192.168.56.105"
EXCLUDED_IPS = {"192.168.56.1", "192.168.56.10"}  # Windows host and defender itself - not attack traffic

def split_ap(ap_string):
    if ap_string and ":" in ap_string:
        ip, port = ap_string.rsplit(":", 1)
        return ip, int(port)
    return ap_string, None

def get_last_offset():
    if os.path.exists(OFFSET_FILE):
        with open(OFFSET_FILE, "r") as f:
            saved_offset = int(f.read().strip())
        current_size = os.path.getsize(LOG_PATH)
        if saved_offset > current_size:
            print(f"Offset ({saved_offset}) exceeds file size ({current_size}) - log was rotated. Resetting to 0.")
            return 0
        return saved_offset
    return 0

def save_offset(offset):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))

def extract_sid(signature):
    # signature format: "1:1000004:1" (gid:sid:rev)
    if signature and ":" in signature:
        parts = signature.split(":")
        if len(parts) >= 2:
            return parts[1]
    return None

def process_line(line, cursor):
    line = line.strip()
    if not line:
        return False
    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        return False
    rule = alert.get("rule", {})
    if rule.get("id") != "100002":
        return False
    data = alert.get("data", {})
    timestamp = data.get("timestamp")
    src_ip, src_port = split_ap(data.get("src_ap"))
    dst_ip, dst_port = split_ap(data.get("dst_ap"))
    protocol = data.get("proto")
    signature = data.get("rule")
    severity = rule.get("level")

    sid = extract_sid(signature)
    if src_ip in EXCLUDED_IPS:
        return False  # Skip - not attacker or baseline traffic, just management/dashboard access
    label = "normal" if src_ip == NORMAL_SOURCE_IP else "attack"

    cursor.execute("""
        INSERT INTO alerts
        (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature, severity, abuse_score, action_taken, label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
    """, (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature, severity, label))
    return True

def watch():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    offset = get_last_offset()
    print(f"Starting watch on {LOG_PATH} from byte offset {offset}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            with open(LOG_PATH, "r") as f:
                f.seek(offset)
                new_lines = f.readlines()
                offset = f.tell()
            inserted = 0
            for line in new_lines:
                if process_line(line, cursor):
                    inserted += 1
            if inserted > 0:
                conn.commit()
                save_offset(offset)
                print(f"[{time.strftime('%H:%M:%S')}] Inserted {inserted} new alert(s).")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped watching. Progress saved.")
        conn.close()

if __name__ == "__main__":
    watch()
