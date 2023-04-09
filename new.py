import logging
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from scapy.all import *

# Set up logging configuration
logging.basicConfig(filename='logs.log', level=logging.DEBUG)

# Connect to database
conn = sqlite3.connect('log.db')
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_mac TEXT,
    source_ip TEXT,
    protocol TEXT,
    payload TEXT
)''')
conn.commit()

# Create a window
window = tk.Tk()
window.title("Sniffing Detection")
window.geometry('800x600')

# Create a treeview to display the logs
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

# Define a function to insert log into database
def insert_log(pkt):
    protocol = 'Unknown'
    payload = ''
    if IP not in pkt:
        return

    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        protocol = 'Ping'
        payload = f"Source: {pkt[Ether].src} ({pkt[IP].src})"
    elif pkt.haslayer(DNSQR):
        protocol = 'DNS Query'
        payload = f"Source: {pkt[Ether].src} ({pkt[IP].src}) for: {pkt[DNSQR].qname.decode()}"
    elif pkt.haslayer(ARP):
        protocol = 'ARP Request'
        payload = f"Source: {pkt[Ether].src} ({pkt[ARP].psrc}) for: {pkt[ARP].pdst}"
    else:
        return
    timestamp = str(datetime.now())
    source_mac = pkt[Ether].src
    source_ip = pkt[IP].src

    # Insert log into database
    c.execute("INSERT INTO log (timestamp, source_mac, source_ip, protocol, payload) VALUES (?, ?, ?, ?, ?)",
              (timestamp, source_mac, source_ip, protocol, payload))
    conn.commit()

    # Insert log into treeview
    tree.insert("", tk.END, text='', values=(timestamp, source_mac, source_ip, protocol, payload))

# Check for sniffing using ICMP Ping, DNS, and ARP methods
# Check for sniffing using ICMP Ping method
    if protocol == 'Ping':
    	suspected_ip = source_ip
    	incorrect_mac = "00:11:22:33:44:55"  # Incorrect MAC address to send the ping request with
    	ping_request = IP(dst=suspected_ip) / ICMP() / Raw(load="This is a ping request to detect sniffing activity.")
    	ping_request[Ether].src = incorrect_mac
    	ping_response = sr1(ping_request, timeout=1, verbose=0)

    if ping_response is None:
        messagebox.showwarning("Sniffing Detected!", f"ICMP Ping request from {source_ip} ({source_mac}) has not received any response. A potential sniffing activity may be happening.")

# Check for sniffing using DNS method
    elif protocol == 'DNS Query':
    	suspected_domain = pkt[DNSQR].qname.decode()
    	incorrect_ip = "1.2.3.4"  # Incorrect IP address to send the DNS response with

    # Send a DNS response with incorrect IP address
    	dns_response = IP(dst=source_ip) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / DNS(
        id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
        an=DNSRR(rrname=pkt[DNSQR].qname, rdata=incorrect_ip))
    	send(dns_response, verbose=0)

    # Wait for the DNS query response and check if the incorrect IP address is returned
    dns_query_response = sniff(filter=f"src {suspected_ip} and dst port {pkt[UDP].sport} and udp and host {source_ip}",
                      stop_filter=lambda x: x.haslayer(DNS) and x[DNS].id == pkt[DNS].id and x[DNS].qr == 1,
                      timeout=5)
    if dns_query_response:
        for resp_pkt in dns_query_response:
            if DNSRR in resp_pkt and resp_pkt[DNSRR].rrname.decode() == suspected_domain:
                if resp_pkt[DNSRR].rdata == incorrect_ip:
                    messagebox.showwarning("Sniffing Detected!", f"DNS response for {suspected_domain} from {suspected_ip} has returned an incorrect IP address. A potential sniffing activity may be happening.")

# Check for sniffing using ARP method
    elif protocol == 'ARP Request':
    	suspected_ip = pkt[ARP].pdst
    	incorrect_mac = "00:11:22:33:44:55" # Incorrect MAC address to send the ARP reply with

    # Define a function to send an ARP reply
    def send_arp_reply():
        # Construct ARP reply packet with incorrect MAC address
        arp_reply = ARP(op=2, hwsrc=incorrect_mac, psrc=suspected_ip, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)

        # Send ARP reply
        send(arp_reply, verbose=0)

        # Wait for response
        arp_response = sniff(filter=f"src {pkt[ARP].psrc} and dst {suspected_ip} and arp", timeout=5)

        # Check if response is received
        if not arp_response:
            messagebox.showwarning("Sniffing Detected!", f"ARP request for {suspected_ip} from {pkt[Ether].src} has not received any response. A potential sniffing activity may be happening.")

    # Create a thread to send the ARP reply
    t = threading.Thread(target=send_arp_reply)
    t.start()

#Define a function to start packet sniffing
def start_sniffing():
    # Create a thread for packet sniffing
    t = threading.Thread(target=lambda: sniff(filter="icmp or udp port 53 or arp", prn=insert_log))
    t.start()

#Create a button to start packet sniffing
btn_start_sniffing = tk.Button(window, text="Start Sniffing", command=start_sniffing)
btn_start_sniffing.pack()

#Run the GUI
window.mainloop()

#Close the database connection
conn.close()

#Clear the log file
open('logs.log', 'w').close()
