from collections import defaultdict
from datetime import datetime, timedelta

# Gap 1 — Unique subdomains per base domain
unique_subdomains = defaultdict(set)

# Gap 3 — Data volume per domain (bytes)
data_volume = defaultdict(int)

# Gap 4 — First seen timestamp per domain
first_seen = {}

# Baseline — domains seen consistently
domain_query_count = defaultdict(int)

# Thresholds
UNIQUE_SUB_THRESHOLD = 5
VOLUME_THRESHOLD = 400
NEW_DOMAIN_WINDOW = 60

# Baseline — domain trusted after seen 10+ times over 24hrs
BASELINE_MIN_QUERIES = 10
BASELINE_MIN_HOURS = 24

def record_domain(domain):
    parts = domain.rstrip('.').split('.')
    if len(parts) >= 2:
        base_domain = '.'.join(parts[-2:])
        subdomain = parts[0] if len(parts) > 2 else ''
    else:
        base_domain = domain
        subdomain = ''

    now = datetime.now()

    # Gap 1 — Track unique subdomains
    if subdomain:
        unique_subdomains[base_domain].add(subdomain)

    # Gap 3 — Track data volume
    data_volume[base_domain] += len(subdomain)

    # Gap 4 — Track first seen
    if base_domain not in first_seen:
        first_seen[base_domain] = now

    # Baseline — count total queries
    domain_query_count[base_domain] += 1

    return base_domain, subdomain

def is_baseline_trusted(base_domain):
    # Domain must be seen for 24+ hours AND 10+ queries
    if base_domain not in first_seen:
        return False
    hours_known = (datetime.now() - first_seen[base_domain]).total_seconds() / 3600
    query_count = domain_query_count[base_domain]
    return hours_known >= BASELINE_MIN_HOURS and query_count >= BASELINE_MIN_QUERIES

def check_unique_subdomains(base_domain):
    count = len(unique_subdomains[base_domain])
    return count > UNIQUE_SUB_THRESHOLD, count

def check_data_volume(base_domain):
    volume = data_volume[base_domain]
    return volume > VOLUME_THRESHOLD, volume

def check_new_domain(base_domain):
    if base_domain not in first_seen:
        return False
    seconds_since_first = (datetime.now() - first_seen[base_domain]).seconds
    return seconds_since_first <= NEW_DOMAIN_WINDOW
