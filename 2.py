import logging
import mysql.connector
from scapy.all import *

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG)

# Connect to the MySQL database
cnx = mysql.connector.connect(user='rioz', password='zalukhu2020', host='localhost', database='log')
cursor = cnx.cursor()

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        logging.info("Ping detected from source: %s", pkt[IP].src)
        # Insert log record into the database
        add_log_record("Ping", pkt[IP].src)

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        logging.info("DNS query detected for: %s", pkt[DNSQR].qname.decode())
        # Insert log record into the database
        add_log_record("DNS", pkt[DNSQR].qname.decode())

# Define a function to analyze HTTP packets
def http_monitor(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if b"GET" in pkt[Raw].load:
            logging.info("HTTP GET request detected from source: %s", pkt[IP].src)
            # Insert log record into the database
            add_log_record("HTTP", pkt[IP].src)

# Define a function to insert a log record into the database
def add_log_record(log_type, source):
    add_log_record_query = ("INSERT INTO logs (type, source) VALUES (%s, %s)")
    add_log_record_data = (log_type, source)
    cursor.execute(add_log_record_query, add_log_record_data)
    cnx.commit()

# Start capturing packets and analyzing them
sniff(filter="icmp or udp port 53 or tcp port 80", prn=lambda x: ping_monitor(x) or dns_monitor(x) or http_monitor(x))

# Close the database connection
cursor.close()
cnx.close()
