import math
from collections import Counter
from pathlib import Path

def calculate_bytes_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data (range 0.0 to 8.0).
    Values > 7.2 typically indicate encrypted, compressed, or packed payloads.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)

def calculate_file_entropy(file_path: str | Path, sample_size: int = 1024 * 1024) -> dict:
    """Read initial sample of file and compute Shannon entropy."""
    path = Path(file_path)
    with open(path, "rb") as f:
        sample_data = f.read(sample_size)

    entropy_score = calculate_bytes_entropy(sample_data)
    is_high_entropy = entropy_score >= 7.2

    classification = "Normal / Plaintext / Structured Code"
    if entropy_score > 7.5:
        classification = "High Entropy: Likely Strongly Encrypted, Compressed, or Packed Malware"
    elif entropy_score >= 7.0:
        classification = "Elevated Entropy: Potential Obfuscation or Compression"

    return {
        "entropy": entropy_score,
        "is_packed_or_encrypted": is_high_entropy,
        "classification": classification,
        "sample_bytes_analyzed": len(sample_data)
    }

