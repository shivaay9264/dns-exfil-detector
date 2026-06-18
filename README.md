# 🔍 DNS Exfiltration Detection System

> Real-time DNS traffic monitoring and covert data exfiltration detection tool built for SOC environments.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-red)
![Tool](https://img.shields.io/badge/Tool-Scapy-orange)

---

## 🚨 Problem Statement

91% of malware uses DNS for C2 communication. Traditional firewalls rarely block DNS traffic — making it a **blind spot** for most organizations.

Attackers encode sensitive data inside DNS subdomains and send them out silently:

```
# Normal DNS query — firewall ignores
google.com → 142.250.80.46

# Attacker exfiltrating credentials over DNS
c2VjcmV0cGFzc3dvcmQ=.evil-c2.com   →  base64("secretpassword")
b3JkPVN1cGVyU2VjcmV0.evil-c2.com   →  base64("ord=SuperSecret")
cmVkaXRjYXJkPTQxMTE=.evil-c2.com   →  base64("creditcard=4111")
```

**Firewall sees normal DNS. Data is already gone.**

This tool detects it in real-time using a 7-layer analysis engine.

---

## 🏗️ Architecture

```
Network Interface (UDP Port 53)
          ↓
    Scapy DNS Sniffer
    (Passive — no traffic impact)
          ↓
   ┌─────────────────────────┐
   │   7-Layer Analysis      │
   │   Engine                │
   │  ├── Shannon Entropy    │
   │  ├── Base64/Hex Pattern │
   │  ├── Subdomain Length   │
   │  ├── Query Frequency    │
   │  ├── Unique Subdomains  │
   │  ├── Data Volume        │
   │  └── DNS Record Type    │
   └─────────────────────────┘
          ↓
    Risk Scorer (0-100)
          ↓
    ┌─────┴──────┐
  Alert DB    Dashboard
 (SQLite)   (Streamlit)
```

---

## 🔍 Detection Layers — How Each Attack Is Caught

### Layer 1 — Shannon Entropy Analysis
Encoded data has high randomness. Normal words have low entropy.
```
"google"           → entropy 1.92  ✅ NORMAL
"c2VjcmV0ZGF0YQ==" → entropy 3.50  🚨 SUSPICIOUS
```

### Layer 2 — Base64 / Hex Pattern Detection
Checks if subdomain contains valid Base64 or Hex encoded strings combined with suspicious length (>15 chars).
```
mail.google.com              → NORMAL  (short, no encoding)
c2VjcmV0cGFzc3dvcmQ.evil.com → SUSPICIOUS (base64 + long)
```

### Layer 3 — Query Frequency Monitoring
Attacker sends data in chunks — same base domain gets flooded with queries.
```
google.com  → 3 queries/min  → NORMAL
evil-c2.com → 50 queries/min → SUSPICIOUS
```

### Layer 4 — Unique Subdomain Tracking
dnscat2 and similar tools use different subdomains per chunk.
```
chunk1.evil.com, chunk2.evil.com ... chunk20.evil.com
→ 20 unique subdomains in 1 minute → SUSPICIOUS
```

### Layer 5 — Data Volume Analysis
Tracks total bytes transferred via DNS subdomains to a single domain.
```
normal CDN  → ~50 bytes   → NORMAL
exfiltration → 400+ bytes → SUSPICIOUS
```

### Layer 6 — DNS Record Type Analysis
Attackers use TXT and NULL record types to carry more data per query (iodine-style attacks).
```
A record    → normal IP lookup  ✅
TXT record  → data carrier      🚨
NULL record → almost never legitimate 🚨
```

### Layer 7 — New Domain Detection
Newly seen domains that immediately show suspicious patterns get a score bonus.
```
Known domain + suspicious  → score as-is
New domain + suspicious    → +5 bonus points
```

---

## 📊 Risk Scoring System

| Detection Check | Points |
|----------------|--------|
| High entropy (>3.4) | +25 |
| Encoding detected | +30 |
| High frequency (>10/min) | +20 |
| Unique subdomains >5 | +10 |
| Data volume >400 bytes | +5 |
| Suspicious record type (TXT/NULL) | +10 |
| New domain bonus | +5 |
| **Maximum Score** | **100** |

| Score | Severity | Action |
|-------|----------|--------|
| 0 | CLEAN | No action |
| 1–39 | LOW | Log only |
| 40–69 | MEDIUM | Analyst review required |
| 70–100 | CRITICAL | Immediate alert fired |

---

## 📁 Project Structure

```
dns-exfil-detector/
├── main.py                  # Entry point — DNS capture + alert pipeline
├── analyzer/
│   ├── entropy.py           # Shannon entropy calculation
│   ├── patterns.py          # Base64/Hex pattern + length detection
│   ├── frequency.py         # Per-domain query frequency tracker
│   ├── tracker.py           # Unique subdomain + volume + baseline
│   └── scorer.py            # 7-layer risk score engine + whitelist
├── alerts/
│   └── alerter.py           # Alert generation + SQLite storage
├── simulator/
│   └── simulate.py          # Realistic DNS exfiltration attack simulator
├── dashboard/
│   └── app.py               # Streamlit real-time monitoring dashboard
├── database/
│   └── db.py                # SQLite schema + query handler
└── test_scapy.py            # DNS sniffer test script
```

---

## ⚙️ Installation

**Requirements:**
- Linux (Kali recommended)
- Python 3.10+
- Root access (for packet capture)

```bash
# Clone the repository
git clone https://github.com/shivaay9264/dns-exfil-detector.git
cd dns-exfil-detector

# Install dependencies
pip3 install scapy streamlit --break-system-packages
```

---

## 🚀 Usage

### Step 1 — Start the Detector
```bash
sudo python3 main.py
```
Output:
```
Initializing database...
Monitoring IP: 192.168.1.44
DNS Exfiltration Detector started... (Ctrl+C to stop)

[2026-06-18 17:44:15] 192.168.1.44 → google.com. [A] Score:0 CLEAN
[2026-06-18 17:44:16] 192.168.1.44 → c2stcHJvZC1h.evil-c2.com. [A] Score:70 CRITICAL
```

### Step 2 — Simulate an Attack (optional)
```bash
python3 simulator/simulate.py
```
Output:
```
[ATTACKER] Starting DNS exfiltration to evil-c2.com
[ATTACKER] Data: username=admin&password=SuperSecret123&creditcard=4111...
[ATTACKER] Chunk 1/13 sent: dXNlcm5hbWU9YWRtaW4mcGFzc3c.evil-c2.com
...
[ATTACKER] Exfiltration complete — 13 chunks sent
```

### Step 3 — Launch Dashboard
```bash
streamlit run dashboard/app.py
```
Open browser: `http://localhost:8501`

---

## 🖥️ Dashboard

Real-time Streamlit dashboard showing:
- Total DNS queries monitored
- Total alerts generated
- Critical alert count
- Color-coded alert feed (RED=Critical, YELLOW=Medium)
- Risk score distribution graph (auto-refreshes every 5 seconds)

---

## 🛡️ False Positive Handling

Two-layer approach to minimize false positives:

**Layer 1 — Static Whitelist**

Known legitimate domains are immediately marked CLEAN without analysis:
```python
STATIC_WHITELIST = [
    'google.com', 'googleapis.com', 'cloudflare.com',
    'amazonaws.com', 'microsoft.com', 'youtube.com',
    'intercom.io', 'mozilla.org', 'anthropic.com' ...
]
```

**Layer 2 — Auto Behavioral Baseline**

Domains seen consistently for **24+ hours** with **10+ queries** are automatically trusted — no manual configuration needed.
```
New domain  + suspicious pattern → ALERT  🚨
Known domain (24hr baseline)     → CLEAN  ✅
```

---

## ⚠️ Known Limitations

| Limitation | Reason |
|-----------|--------|
| DoH/DoT not covered | Encrypted DNS requires different interception approach |
| Slow attacks may evade | Very low frequency exfiltration below threshold |
| Baseline resets on restart | In-memory storage — not persisted to disk |
| Static whitelist manual | New legitimate services need manual addition |

---

## 🔮 Future Improvements

- [ ] VirusTotal / AbuseIPDB API integration for real-time threat intelligence
- [ ] ML-based anomaly detection (Isolation Forest / Autoencoder)
- [ ] DoH/DoT traffic interception and analysis
- [ ] SIEM integration (Splunk / ELK Stack)
- [ ] Persistent baseline storage across restarts
- [ ] Automated IP blocking via iptables on CRITICAL alerts

---

## 💡 Real-World Context

Concepts implemented in this project are used in enterprise security products:

| Concept Used | Enterprise Equivalent |
|-------------|----------------------|
| DNS Exfiltration Detection | Palo Alto DNS Security |
| Behavioral Baselining | CrowdStrike Falcon |
| Multi-layer Risk Scoring | Darktrace |
| SIEM Alerting | Splunk SIEM |
| Threat Detection Engine | IBM QRadar |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Packet Capture | Scapy 2.7 |
| Analysis Engine | Python 3.13 |
| Data Storage | SQLite |
| Dashboard | Streamlit 1.58 |
| Detection Logic | Shannon Entropy + Statistical Analysis |
| OS | Kali Linux |

---

## 👤 Author

**Shiva Kumar**
MCA | Cybersecurity Enthusiast
GitHub: [@shivaay9264](https://github.com/shivaay9264)

---

## 📄 License

MIT License — Free to use for educational and research purposes.
