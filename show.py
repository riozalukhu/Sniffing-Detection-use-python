import sqlite3

# Connect to database
conn = sqlite3.connect('log.db')
c = conn.cursor()

# Fetch all logs from the database
c.execute("SELECT * FROM log")
logs = c.fetchall()

# Print all logs
for log in logs:
    print(log)
