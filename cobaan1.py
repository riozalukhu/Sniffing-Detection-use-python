import datetime
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.layers.inet import ICMP, DNS, IP
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff, srp, Ether, ARP as ARPpkt

#Global variables
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

def ping_detection(ip):
# Ping with incorrect MAC address to detect promiscuous mode
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(dst=ip)/ICMP(), timeout=2, verbose=0)
for snd, rcv in ans:
if rcv.haslayer(ICMP) and rcv.getlayer(ICMP).type == 0:
print(f"[+] {rcv.src} is in promiscuous mode")

def dns_detection():
# Reverse DNS lookup monitoring
# Monitor incoming reverse DNS lookups on DNS server
pass

def arp_detection():
# ARP monitoring
# Send non-broadcast ARP to all nodes in network
# Node in promiscuous mode will cache local ARP address and respond to broadcast ping with correct MAC
# Only that node will respond, other nodes will send ARP probe
# Detect node with sniffer based on ARP probe response
pass

def sniff_packets():
sniff(filter="icmp or dns or arp", prn=process_packet, store=0)

def process_packet(pkt):
try:
if pkt.haslayer(ICMP):
print("ICMP Packet Detected")
messagebox.showwarning("Sniffing Alert", "ICMP Packet Detected!")
ping_detection(pkt[IP].src)

scss
Copy code
    elif pkt.haslayer(DNS):
        print("DNS Packet Detected")
        messagebox.showwarning("Sniffing Alert", "DNS Packet Detected!")
        dns_detection()
        
    elif pkt.haslayer(ARP):
        print("ARP Packet Detected")
        messagebox.showwarning("Sniffing Alert", "ARP Packet Detected!")
        arp_detection()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
