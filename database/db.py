import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "dns_logs.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip    TEXT NOT NULL,
            domain    TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_query(timestamp, src_ip, domain):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO dns_queries (timestamp, src_ip, domain) VALUES (?, ?, ?)",
        (timestamp, src_ip, domain)
    )
    conn.commit()
    conn.close()
