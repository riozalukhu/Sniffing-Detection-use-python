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

# Get total number of logs
c.execute("SELECT COUNT(*) FROM log")
total_logs = c.fetchone()[0]

# Set page size to 50
page_size = 50
total_pages = (total_logs + page_size - 1) // page_size

# Set initial page to 1
current_page = 1

# Function to display logs based on the current page
def display_logs():
    # Clear the treeview
    tree.delete(*tree.get_children())

    # Calculate the offset and limit for the current page
    offset = (current_page - 1) * page_size
    limit = page_size

    # Fetch logs from the database based on the offset and limit
    c.execute("SELECT * FROM log LIMIT ? OFFSET ?", (limit, offset))
    logs = c.fetchall()

    # Insert the logs into the treeview
    for log in logs:
        tree.insert("", tk.END, text=log[0], values=log[1:])

    # Update the page label
    page_label.config(text="Page {} of {}".format(current_page, total_pages))

# Function to go to the next page
def next_page():
    global current_page
    if current_page < total_pages:
        current_page += 1
        display_logs()

# Function to go to the previous page
def prev_page():
    global current_page
    if current_page > 1:
        current_page -= 1
        display_logs()

# Create buttons for pagination
prev_button = ttk.Button(window, text="Previous", command=prev_page)
prev_button.pack(side=tk.LEFT, padx=5, pady=5)

page_label = ttk.Label(window, text="")
page_label.pack(side=tk.LEFT, padx=5, pady=5)

next_button = ttk.Button(window, text="Next", command=next_page)
next_button.pack(side=tk.LEFT, padx=5, pady=5)

# Create a search frame
search_frame = ttk.Frame(window)
search_frame.pack(side=tk.TOP, fill=tk.X)

# Create a label and a combobox for the search field
search_label = ttk.Label(search_frame, text="Search Field:")
search_label.pack(side=tk.LEFT, padx=5, pady=5)

search_field_combobox = ttk.Combobox(search_frame, values=["timestamp", "source_mac", "source_ip", "protocol", "payload"])
search_field_combobox.pack(side=tk.LEFT, padx=5, pady=5)

#Create a label and an entry for the search query
query_label = ttk.Label(search_frame, text="Search Query:")
query_label.pack(side=tk.LEFT, padx=5, pady=5)

query_entry = ttk.Entry(search_frame)
query_entry.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5)

#Function to perform the search
# Function to perform the search
def search_logs():
    # Get the search field and query

 search_field = search_field_combobox.get()
    query = query_entry.get()

    # Clear the treeview
    tree.delete(*tree.get_children())

    # Perform the search query
    if search_field == "timestamp":
        c.execute("SELECT * FROM log WHERE timestamp LIKE ?", ('%'+query+'%',))
    elif search_field == "source_mac":
        c.execute("SELECT * FROM log WHERE source_mac LIKE ?", ('%'+query+'%',))
    elif search_field == "source_ip":
        c.execute("SELECT * FROM log WHERE source_ip LIKE ?", ('%'+query+'%',))
    elif search_field == "protocol":
        c.execute("SELECT * FROM log WHERE protocol LIKE ?", ('%'+query+'%',))
    elif search_field == "payload":
        c.execute("SELECT * FROM log WHERE payload LIKE ?", ('%'+query+'%',))

    # Get the search results and insert them into the treeview
    search_results = c.fetchall()
    for result in search_results:
        tree.insert("", tk.END, text=result[0], values=result[1:])

# Create a search button
search_button = ttk.Button(search_frame, text="Search", command=search_logs)
search_button.pack(side=tk.LEFT, padx=5, pady=5)

# Display the initial page of logs
display_logs()

# Close the database connection
conn.close()

# Start the window
window.mainloop()
