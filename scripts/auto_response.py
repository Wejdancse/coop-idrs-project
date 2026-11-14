import sqlite3
import subprocess
import threading
import time
from datetime import datetime

DB_PATH = "/home/wejdan/idrs/db/idrs.db"
LOG_PATH = "/home/wejdan/idrs/logs/incidents.log"
SAFE_IPS = {"192.168.56.1", "192.168.56.10", "192.168.56.105"}
BLOCK_DURATION_SECONDS = 20

SID_SEVERITY = {
    "1000001": ("ICMP ping - reconnaissance", False),
    "1000002": ("SSH brute-force - active credential attack", True),
    "1000003": ("Port scan - reconnaissance", False),
    "1000005": ("SQL injection UNION SELECT - active exploitation", True),
    "1000006": ("SQL injection OR 1=1 - active exploitation", True),
    "1000007": ("SQL injection DROP TABLE - active exploitation", True),
    "1000008": ("Cross-site scripting script tag - active exploitation", True),
    "1000009": ("Cross-site scripting onerror - active exploitation", True),
    "1000010": ("Directory traversal - active exploitation", True),
    "1000011": ("Directory traversal encoded - active exploitation", True),
    "1000012": ("OS command injection semicolon - active exploitation", True),
    "1000013": ("OS command injection pipe - active exploitation", True),
    "1000014": ("WordPress wp-login probe - reconnaissance", False),
    "1000015": ("WordPress xmlrpc probe - reconnaissance", False),
    "1000016": ("Admin panel probe - reconnaissance", False),
    "1000017": ("phpMyAdmin probe - reconnaissance", False),
    "1000018": ("Bash Shellshock injection - active exploitation", True),
    "1000019": ("OpenSSL Heartbleed probe - active exploitation", True),
    "1000020": ("Web shell connection attempt - active exploitation", True),
    "1000021": ("Log4Shell JNDI lookup - active exploitation", True),
    "1000022": ("sqlmap scanner detected - reconnaissance", False),
    "1000023": ("Nikto scanner detected - reconnaissance", False),
    "1000024": ("Nmap NSE scripting detected - reconnaissance", False),
    "1000025": ("curl automated tool detected - reconnaissance", False),
    "1000026": ("python-requests automated tool detected - reconnaissance", False),
    "1000027": ("SSH version scan probe - reconnaissance", False),
    "1000028": ("Anonymous FTP login attempt - active exploitation", True),
    "1000029": ("SMB NULL session attempt - active exploitation", True),
}

def extract_sid(signature):
    if signature and ":" in signature:
        parts = signature.split(":")
        if len(parts) >= 2:
            return parts[1]
    return None

def log_incident(src_ip, signature, sid_label, response):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] src={src_ip} signature={signature} type={sid_label} response={response}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)
    print(f"LOGGED: {line.strip()}")

def unblock_after_delay(ip, delay):
    time.sleep(delay)
    subprocess.run(["sudo", "ufw", "delete", "deny", "from", ip], capture_output=True, text=True)
    print(f"Auto-unblocked {ip} after {delay}s")

def block_ip(ip):
    result = subprocess.run(
        ["sudo", "ufw", "insert", "1", "deny", "from", ip],
        capture_output=True, text=True
    )
    print(f"Blocked {ip} for {BLOCK_DURATION_SECONDS}s: {result.stdout.strip()}")
    timer = threading.Thread(target=unblock_after_delay, args=(ip, BLOCK_DURATION_SECONDS))
    timer.daemon = True
    timer.start()

def check_and_respond():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, src_ip, signature FROM alerts
        WHERE label = 'attack' AND (action_taken IS NULL OR action_taken = '')
    """)
    rows = cursor.fetchall()

    blocked_ips = set()
    for row_id, src_ip, signature in rows:
        if src_ip in SAFE_IPS:
            cursor.execute("UPDATE alerts SET action_taken = 'skipped_safe_ip' WHERE id = ?", (row_id,))
            continue

        sid = extract_sid(signature)
        sid_label, should_block = SID_SEVERITY.get(sid, ("Unknown attack type", True))

        if should_block:
            if src_ip not in blocked_ips:
                block_ip(src_ip)
                blocked_ips.add(src_ip)
            log_incident(src_ip, signature, sid_label, "blocked_temp")
            cursor.execute("UPDATE alerts SET action_taken = 'blocked_temp' WHERE id = ?", (row_id,))
        else:
            log_incident(src_ip, signature, sid_label, "logged_only")
            cursor.execute("UPDATE alerts SET action_taken = 'logged_only' WHERE id = ?", (row_id,))

    conn.commit()
    conn.close()
    print(f"\nProcessed {len(rows)} unactioned attack rows. Blocked IPs: {blocked_ips}")

    if blocked_ips:
        print(f"Waiting {BLOCK_DURATION_SECONDS + 2}s for auto-unblock timer to complete...")
        time.sleep(BLOCK_DURATION_SECONDS + 2)

if __name__ == "__main__":
    check_and_respond()
