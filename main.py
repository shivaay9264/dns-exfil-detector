from scapy.all import sniff, DNS, DNSQR, IP
from datetime import datetime
from database.db import init_db, save_query
from analyzer.scorer import calculate_risk_score
from alerts.alerter import init_alerts_table, process_alert

QTYPE_MAP = {
    1:  'A',
    16: 'TXT',
    10: 'NULL',
    28: 'AAAA',
    5:  'CNAME',
    65: 'HTTPS'
}

MY_IP = '192.168.1.44'

def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode()
        src_ip = packet[IP].src

        # Skip router queries — sirf apni machine process karo
        if src_ip != MY_IP:
            return

        # Skip local router suffix queries
        if '.hgu_lan' in domain or domain.endswith('.local.'):
            return

        qtype     = packet[DNSQR].qtype
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        save_query(timestamp, src_ip, domain)
        result = calculate_risk_score(domain, qtype=qtype)

        qtype_name = QTYPE_MAP.get(qtype, f'UNKNOWN({qtype})')
        print(f"[{timestamp}] {src_ip} → {domain} [{qtype_name}] Score:{result['score']} {result['severity']}")
        process_alert(result)

if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    init_alerts_table()
    print(f"Monitoring IP: {MY_IP}")
    print("DNS Exfiltration Detector started... (Ctrl+C to stop)\n")
    sniff(filter="udp port 53", prn=process_packet, store=0)
