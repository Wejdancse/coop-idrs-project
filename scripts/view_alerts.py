import sqlite3

DB_PATH = "/home/wejdan/idrs/db/idrs.db"

def view_alerts(limit=10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]
    print(f"Total alerts in database: {total}\n")

    cursor.execute(f"""
        SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature
        FROM alerts
        ORDER BY id DESC
        LIMIT {limit}
    """)
    rows = cursor.fetchall()

    print(f"Showing last {limit} alerts:\n")
    for row in rows:
        print(row)

    conn.close()

if __name__ == "__main__":
    view_alerts()
