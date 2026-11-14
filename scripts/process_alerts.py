import json
import sqlite3

DB_PATH = "/home/wejdan/idrs/db/idrs.db"
LOG_PATH = "/var/ossec/logs/alerts/alerts.json"

def split_ap(ap_string):
    if ap_string and ":" in ap_string:
        ip, port = ap_string.rsplit(":", 1)
        return ip, int(port)
    return ap_string, None

def parse_and_insert():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    inserted = 0
    skipped = 0

    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            rule = alert.get("rule", {})
            if rule.get("id") != "100002":
                skipped += 1
                continue

            data = alert.get("data", {})
            timestamp = data.get("timestamp")
            src_ip, src_port = split_ap(data.get("src_ap"))
            dst_ip, dst_port = split_ap(data.get("dst_ap"))
            protocol = data.get("proto")
            signature = data.get("rule")
            severity = rule.get("level")
            action_taken = None

            cursor.execute("""
                INSERT INTO alerts
                (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature, severity, abuse_score, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """, (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature, severity, action_taken))
            inserted += 1

    conn.commit()
    conn.close()
    print(f"Inserted {inserted} alerts. Skipped {skipped} non-Snort alerts.")

if __name__ == "__main__":
    parse_and_insert()
