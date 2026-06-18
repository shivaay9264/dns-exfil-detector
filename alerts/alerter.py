import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "../database/dns_logs.db")

def init_alerts_table():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            domain    TEXT NOT NULL,
            score     INTEGER NOT NULL,
            severity  TEXT NOT NULL,
            reasons   TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_alert(domain, score, severity, reasons):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (timestamp, domain, score, severity, reasons) VALUES (?, ?, ?, ?, ?)",
        (timestamp, domain, score, severity, ', '.join(reasons))
    )
    conn.commit()
    conn.close()
    return timestamp

def process_alert(result):
    score    = result['score']
    severity = result['severity']
    domain   = result['domain']
    reasons  = result['reasons']

    # Only alert if score is 40+
    if score < 40:
        return

    timestamp = save_alert(domain, score, severity, reasons)

    # CRITICAL — print to console immediately
    if severity == "CRITICAL":
        print(f"\n{'='*50}")
        print(f"[CRITICAL ALERT] {timestamp}")
        print(f"Domain  : {domain}")
        print(f"Score   : {score}/100")
        print(f"Reasons : {', '.join(reasons)}")
        print(f"{'='*50}\n")

    elif severity == "MEDIUM":
        print(f"[MEDIUM ALERT] {timestamp} | {domain} | Score: {score}")

def get_all_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return rows
