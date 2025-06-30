import sqlite3

conn = sqlite3.connect('sessions.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS scan_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        scan_time TEXT,
        status TEXT
    )
''')
conn.commit()
conn.close()
print("scan_logs table created.")