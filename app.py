from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    # Connect to database
    conn = sqlite3.connect('log.db')
    c = conn.cursor()

    # Get all logs from the database
    c.execute("SELECT * FROM log")
    logs = c.fetchall()

    # Close the database connection
    conn.close()

    return render_template('index.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
