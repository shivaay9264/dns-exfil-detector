import math
from collections import Counter

def calculate_entropy(text):
    if not text:
        return 0.0
    
    # Har character kitni baar aaya
    counts = Counter(text)
    
    # Total characters
    total = len(text)
    
    # Entropy formula
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    
    return round(entropy, 2)

def is_high_entropy(text, threshold=3.4):
    score = calculate_entropy(text)
    return score > threshold, score
