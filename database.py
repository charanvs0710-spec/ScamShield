import sqlite3

DATABASE = "scamshield.db"


def init_db():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            risk TEXT,
            score INTEGER,
            category TEXT,
            confidence INTEGER,
            intent TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(message, risk, score, category, confidence, intent):
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        INSERT INTO scans
        (message, risk, score, category, confidence, intent)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (message, risk, score, category, confidence, intent))

    conn.commit()
    conn.close()