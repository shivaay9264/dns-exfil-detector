from analyzer.entropy import is_high_entropy
from analyzer.patterns import check_patterns
from analyzer.frequency import record_query, is_high_frequency
from analyzer.tracker import record_domain, check_unique_subdomains, check_data_volume, check_new_domain, is_baseline_trusted

SUSPICIOUS_QTYPES = [16, 10]

# Static whitelist — guaranteed safe domains
STATIC_WHITELIST = [
    'google.com', 'googleapis.com', 'gstatic.com',
    'cloudflare.com', 'amazonaws.com', 'microsoft.com',
    'akamai.com', 'intercom.io', 'fivetran.com',
    'mozilla.com', 'mozilla.org', 'adblockplus.org',
    'anthropic.com', 'streamlit.io', 'youtube.com',
    'apple.com', 'icloud.com', 'fastly.net',
    'thmcell.click',      # TryHackMe latency checker
    'googlevideo.com',    # YouTube video streaming
]

def is_whitelisted(domain):
    domain = domain.rstrip('.')
    parts = domain.split('.')
    base = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
    return base in STATIC_WHITELIST

def calculate_risk_score(domain, qtype=1):
    # Layer 1 — Static whitelist
    if is_whitelisted(domain):
        return {'domain': domain, 'score': 0, 'severity': 'CLEAN', 'reasons': ['static_whitelist']}

    subdomain = domain.rstrip('.')
    parts = subdomain.split('.')
    sub = parts[0] if len(parts) > 1 else subdomain
    base = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    # Record first — needed for baseline check
    record_domain(domain)

    # Layer 2 — Auto baseline
    if is_baseline_trusted(base):
        return {'domain': domain, 'score': 0, 'severity': 'CLEAN', 'reasons': ['baseline_trusted']}

    score = 0
    reasons = []

    # Check 1 — Entropy
    entropy_flag, entropy_val = is_high_entropy(sub)
    if entropy_flag:
        score += 25
        reasons.append(f"high_entropy({entropy_val})")

    # Check 2 — Pattern
    pattern_result = check_patterns(sub)
    if pattern_result['flagged']:
        score += 30
        reasons.append("encoding_detected")

    # Check 3 — Frequency
    record_query(domain)
    freq_flag, freq_val = is_high_frequency(domain)
    if freq_flag:
        score += 20
        reasons.append(f"high_frequency({freq_val}/min)")

    # Check 4 — Unique subdomains
    u_flag, u_count = check_unique_subdomains(base)
    if u_flag:
        score += 10
        reasons.append(f"unique_subdomains({u_count})")

    # Check 5 — Data volume
    v_flag, v_volume = check_data_volume(base)
    if v_flag:
        score += 5
        reasons.append(f"high_volume({v_volume}bytes)")

    # Check 6 — Suspicious record type
    if qtype in SUSPICIOUS_QTYPES:
        score += 10
        reasons.append(f"suspicious_qtype({qtype})")

    # Check 7 — New domain + suspicious
    if check_new_domain(base) and score > 0:
        score = min(score + 5, 100)
        reasons.append("new_domain")

    if score >= 70:
        severity = "CRITICAL"
    elif score >= 40:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "CLEAN"

    return {
        'domain': domain,
        'score': min(score, 100),
        'severity': severity,
        'reasons': reasons
    }
