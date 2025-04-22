import sqlite3
import os

DB_PATH = "database.db"

def init_db():
    """Initialize the database and create the scans table if not exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            module TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(target,module,result):
    """Save a scan result to the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (target,module,result) VALUES (?, ?,?)", (target, module, result))
    conn.commit()
    conn.close()

def get_previous_scans():
    """Retrieve all previous scans."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, target,module, result, timestamp FROM scans ORDER BY timestamp DESC")
    scans = cursor.fetchall()
    conn.close()
    return scans

# Initialize database on first run
if not os.path.exists(DB_PATH):
    init_db()
