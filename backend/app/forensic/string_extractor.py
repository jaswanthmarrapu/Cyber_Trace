import re
from pathlib import Path
from typing import List, Dict

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_REGEX = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.~:?#[\]@!$&\'()*+,;=]*')
BASE64_REGEX = re.compile(r'\b[A-Za-z0-9+/]{24,}={0,2}\b')
COMMAND_REGEX = re.compile(r'\b(powershell|cmd\.exe|wget|curl|whoami|netsh|certutil|sudo|bash|chmod|shadow)\b', re.IGNORECASE)

def extract_printable_strings(file_path: str | Path, min_len: int = 4, max_strings: int = 200) -> Dict[str, any]:
    """Extract printable ASCII and Unicode strings from binary files and flag potential IOCs."""
    path = Path(file_path)
    with open(path, "rb") as f:
        data = f.read(2 * 1024 * 1024)  # Read up to 2MB for string analysis

    # Printable ASCII range
    pattern = re.compile(rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}')
    matches = [m.group().decode('latin1', errors='ignore') for m in pattern.finditer(data)]

    text_blob = "\n".join(matches)
    extracted_ips = list(set(IP_REGEX.findall(text_blob)))
    extracted_urls = list(set(URL_REGEX.findall(text_blob)))
    extracted_commands = list(set(COMMAND_REGEX.findall(text_blob)))

    return {
        "total_strings_found": len(matches),
        "sample_strings": matches[:max_strings],
        "iocs": {
            "ips": extracted_ips[:20],
            "urls": extracted_urls[:20],
            "commands": extracted_commands[:20],
        }
    }

