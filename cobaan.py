import datetime
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import *

# Global variables
window = tk.Tk()
window.title("Sniffing Detection")
window.geometry('800x600')

tree = ttk.Treeview(window)
tree["columns"] = ("timestamp", "source_mac", "source_ip", "protocol", "payload")
tree.column("#0", width=0, stretch=tk.NO)
tree.column("timestamp", anchor=tk.CENTER, width=150)
tree.column("source_mac", anchor=tk.CENTER, width=150)
tree.column("source_ip", anchor=tk.CENTER, width=150)
tree.column("protocol", anchor=tk.CENTER, width=150)
tree.column("payload", anchor=tk.CENTER, width=300)
tree.heading("timestamp", text="Timestamp")
tree.heading("source_mac", text="Source MAC")
tree.heading("source_ip", text="Source IP")
tree.heading("protocol", text="Protocol")
tree.heading("payload", text="Payload")
tree.pack(fill=tk.BOTH, expand=1)

conn = sqlite3.connect('log.db')
c = conn.cursor()

def create_table():
    c.execute('''CREATE TABLE IF NOT EXISTS log
                 (timestamp text, source_mac text, source_ip text, protocol text, payload text)''')

create_table()

def fetch_logs():
    c.execute("SELECT * FROM log")
    logs = c.fetchall()
    for log in logs:
        tree.insert("", tk.END, text=log[0], values=log[1:])

fetch_logs()

def close_connection():
    conn.close()

window.protocol("WM_DELETE_WINDOW", close_connection)

def sniff_packets():
    sniff(filter="icmp or dns or arp", prn=process_packet, store=0)

def process_packet(pkt):
    try:
        if pkt.haslayer(ICMP):
            print("ICMP Packet Detected")
            messagebox.showwarning("Sniffing Alert", "ICMP Packet Detected!")
            
        elif pkt.haslayer(DNS):
            print("DNS Packet Detected")
            messagebox.showwarning("Sniffing Alert", "DNS Packet Detected!")

        elif pkt.haslayer(ARP):
            print("ARP Packet Detected")
            messagebox.showwarning("Sniffing Alert", "ARP Packet Detected!")

        timestamp = datetime.datetime.now()
        source_mac = pkt.src
        source_ip = pkt[IP].src
        protocol = pkt.summary()
        payload = str(pkt.payload)

        tree.insert("", tk.END, text=timestamp, values=(timestamp, source_mac, source_ip, protocol, payload))

    except Exception as e:
        print(e)

t = threading.Thread(target=sniff_packets)
t.start()

window.mainloop()
