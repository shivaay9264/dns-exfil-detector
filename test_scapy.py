from scapy.all import sniff, DNS, DNSQR, IP
from datetime import datetime
import sys
sys.path.append("/root/Desktop/project/dns-exfil-detector")
from database.db import init_db, save_query

# DNS query type mapping
QTYPE_MAP = {
    1:  'A',
    16: 'TXT',
    10: 'NULL',
    28: 'AAAA',
    5:  'CNAME'
}

# Suspicious record types
SUSPICIOUS_QTYPES = [16, 10]  # TXT and NULL

init_db()

def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain    = packet[DNSQR].qname.decode()
        src_ip    = packet[IP].src
        qtype_id  = packet[DNSQR].qtype
        qtype     = QTYPE_MAP.get(qtype_id, f'UNKNOWN({qtype_id})')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Flag suspicious record types
        type_flag = '🚨' if qtype_id in SUSPICIOUS_QTYPES else '✅'

        print(f"[{timestamp}] {src_ip} → {domain} [{qtype}] {type_flag}")
        save_query(timestamp, src_ip, domain)

print("DNS traffic sun raha hoon... (Ctrl+C se band karo)")
sniff(filter="udp port 53", prn=process_packet, store=0)
