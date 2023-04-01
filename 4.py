import logging
import mysql.connector
from scapy.all import *

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG)

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        logging.info("Ping detected from source: %s", pkt[IP].src)

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        logging.info("DNS query detected for: %s", pkt[DNSQR].qname.decode())

# Define a function to analyze ARP packets
def arp_monitor(pkt):
    if pkt.haslayer(ARP):
        logging.info("ARP request detected from source: %s", pkt[ARP].psrc)

        # Connect to the MySQL database
        mydb = mysql.connector.connect(
            host="localhost",
            user="rioz",
            password="zalukhu2020",
            database="log"
        )

        # Insert the logging information into the database
        mycursor = mydb.cursor()
        sql = "INSERT INTO logss (source, type) VALUES (%s, %s)"
        val = (pkt[ARP].psrc, "ARP request")
        mycursor.execute(sql, val)
        mydb.commit()

# Start capturing packets and analyzing them
sniff(filter="icmp or udp port 53 or arp", prn=lambda x: ping_monitor(x) or dns_monitor(x) or arp_monitor(x))
