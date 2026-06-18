from collections import defaultdict
from datetime import datetime

# In-memory store: domain -> list of timestamps
query_log = defaultdict(list)

WINDOW_SECONDS = 60
HIGH_FREQ_THRESHOLD = 10

def record_query(domain):
    now = datetime.now()
    query_log[domain].append(now)

    # Remove entries outside the time window
    query_log[domain] = [
        t for t in query_log[domain]
        if (now - t).seconds <= WINDOW_SECONDS
    ]

def get_frequency(domain):
    return len(query_log[domain])

def is_high_frequency(domain):
    freq = get_frequency(domain)
    return freq > HIGH_FREQ_THRESHOLD, freq
