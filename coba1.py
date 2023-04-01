from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Create the database
engine = create_engine('sqlite:///sniffing.db')

# Create the session
Session = sessionmaker(bind=engine)
session = Session()

# Define the table
Base = declarative_base()
class SniffingData(Base):
    __tablename__ = 'sniffing_data'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    source_mac = Column(String)
    source_ip = Column(String)
    protocol = Column(String)
    query = Column(String)

    def __repr__(self):
        return f"<SniffingData(timestamp='{self.timestamp}', source_mac='{self.source_mac}', source_ip='{self.source_ip}', protocol='{self.protocol}', query='{self.query}')>"

# Create the table
Base.metadata.create_all(engine)

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        data = SniffingData(timestamp=datetime.now(), source_mac=pkt[Ether].src, source_ip=pkt[IP].src, protocol='ICMP', query='')
        session.add(data)
        session.commit()
        logging.info("%s Ping detected from source: %s (%s)", datetime.now(), pkt[Ether].src, pkt[IP].src)

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        data = SniffingData(timestamp=datetime.now(), source_mac=pkt[Ether].src, source_ip=pkt[IP].src, protocol='DNS', query=pkt[DNSQR].qname.decode())
        session.add(data)
        session.commit()
        logging.info("%s DNS query detected from source: %s (%s) for: %s", datetime.now(), pkt[Ether].src, pkt[IP].src, pkt[DNSQR].qname.decode())

# Define a function to analyze ARP packets
def arp_monitor(pkt):
    if pkt.haslayer(ARP):
        data = SniffingData(timestamp=datetime.now(), source_mac=pkt[Ether].src, source_ip=pkt[ARP].psrc, protocol='ARP', query=pkt[ARP].pdst)
        session.add(data)
        session.commit()
        logging.info("%s ARP request detected from source: %s (%s) for: %s", datetime.now(), pkt[Ether].src, pkt[ARP].psrc, pkt[ARP].pdst)


def show_data(page=1, per_page=50, search=None):
query = session.query(SniffingData)

if search:
    query = query.filter(
        (SniffingData.source_mac.like(f'%{search}%')) |
        (SniffingData.source_ip.like(f'%{search}%')) |
        (SniffingData.packet_type.like(f'%{search}%')) |
        (SniffingData.timestamp.like(f'%{search}%'))
    )

data = query.order_by(SniffingData.timestamp.desc()).paginate(page=page, per_page=per_page)

# Check for sniffing
prev_mac = None
prev_ip = None
for row in data.items:
    if prev_mac and prev_mac != row.source_mac:
        print('\033[91mSniffing detected!\033[0m')
    if prev_ip and prev_ip != row.source_ip:
        print('\033[91mSniffing detected!\033[0m')
    prev_mac = row.source_mac
    prev_ip = row.source_ip

# Print table header
print('{:<20} {:<20} {:<20} {:<40}'.format('Timestamp', 'Packet Type', 'Source MAC', 'Source IP'))
print('-' * 100)

# Print table data
for row in data.items:
    print('{:<20} {:<20} {:<20} {:<40}'.format(row.timestamp, row.packet_type, row.source_mac, row.source_ip))

# Print pagination info
print('-' * 100)
print('Page {} of {}, showing {} results per page'.format(data.page, data.pages, per_page))
