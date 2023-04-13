from flask import Flask, render_template
import sqlite3

app = Flask(__name__)


@app.route('/')
def index():
    def index():
    # Create a new connection and cursor in the Flask application thread
    conn = sqlite3.connect('log.db')
    c = conn.cursor()

    # Execute the SQL query and fetch all rows
    c.execute("SELECT * FROM log")
    rows = c.fetchall()

    # Close the connection
    conn.close()

    return render_template('index.html', rows=rows)

@app.route('/alerts')
def alerts():
    # Get data from database
    c.execute("SELECT * FROM log WHERE protocol='Ping' AND timestamp > datetime('now', '-10 seconds')")
    pings = c.fetchall()

    c.execute("SELECT * FROM log WHERE protocol='DNS Query' AND timestamp > datetime('now', '-10 seconds')")
    dns_queries = c.fetchall()

    c.execute("SELECT * FROM log WHERE protocol='ARP Request' AND timestamp > datetime('now', '-10 seconds')")
    arp_requests = c.fetchall()

    return render_template('alerts.html', pings=pings, dns_queries=dns_queries, arp_requests=arp_requests)

if __name__ == '__main__':
    app.run(debug=True)
