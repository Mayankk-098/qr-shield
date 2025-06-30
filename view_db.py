import sqlite3

conn = sqlite3.connect('sessions.db')
c = conn.cursor()
for row in c.execute('SELECT * FROM sessions'):
    print(row)
conn.close()
