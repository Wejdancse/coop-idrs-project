
import sqlite3
import os
DB_PATH = os.path.expanduser("~/idrs/db/idrs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            signature TEXT,
            severity INTEGER,
            abuse_score INTEGER,
            action_taken TEXT
        )
    """)

    conn.commit()
    conn.close()
    print(f"database initialized at {DB_PATH}")

if __name__ == "__main__":
    init_db()
