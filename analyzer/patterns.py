import re
import base64

def is_base64(text):
    # Remove padding first
    base = text.rstrip('=')
    pattern = r'^[A-Za-z0-9+/\-_]{10,}$'
    if not re.match(pattern, base):
        return False
    try:
        padded = base + '=' * (4 - len(base) % 4)
        base64.b64decode(padded)
        return True
    except Exception:
        return False

def is_hex(text):
    # Only 0-9 and a-f, even length, min 16 chars
    pattern = r'^[0-9a-fA-F]{16,}$'
    if not re.match(pattern, text):
        return False
    return len(text) % 2 == 0

def is_suspicious_length(subdomain):
    part = subdomain.split('.')[0]
    return len(part) >= 15, len(part)

def check_patterns(subdomain):
    part = subdomain.split('.')[0]
    length_flag, length = is_suspicious_length(subdomain)

    results = {
        'is_base64': is_base64(part),
        'is_hex': is_hex(part),
        'long_subdomain': length_flag,
        'subdomain_length': length,
        'flagged': False
    }

    # Suspicious if encoded AND long
    if (results['is_base64'] or results['is_hex']) and length_flag:
        results['flagged'] = True

    # Extremely long subdomain — suspicious regardless
    if length > 40:
        results['flagged'] = True

    return results
