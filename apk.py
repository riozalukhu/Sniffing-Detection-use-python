import sqlite3
import tkinter as tk
from tkinter import ttk

# Create a window
window = tk.Tk()
window.title("Log Viewer")
window.geometry("600x400")

# Create a treeview to display the logs
tree = ttk.Treeview(window)
tree["columns"] = ("timestamp", "source_mac", "source_ip", "protocol", "payload")
tree.column("#0", width=0, stretch=tk.NO)
tree.column("timestamp", anchor=tk.CENTER, width=120)
tree.column("source_mac", anchor=tk.CENTER, width=120)
tree.column("source_ip", anchor=tk.CENTER, width=120)
tree.column("protocol", anchor=tk.CENTER, width=120)
tree.column("payload", anchor=tk.CENTER, width=120)
tree.heading("timestamp", text="Timestamp")
tree.heading("source_mac", text="Source MAC")
tree.heading("source_ip", text="Source IP")
tree.heading("protocol", text="Protocol")
tree.heading("payload", text="Payload")
tree.pack(fill=tk.BOTH, expand=1)

# Connect to database
conn = sqlite3.connect('log.db')
c = conn.cursor()

# Fetch all logs from the database
c.execute("SELECT * FROM log")
logs = c.fetchall()

# Insert the logs into the treeview
for log in logs:
    tree.insert("", tk.END, text=log[0], values=log[1:])

# Close the database connection
conn.close()

# Start the window
window.mainloop()

