from pathlib import Path
from typing import Dict
from app.utils.constants import MAGIC_SIGNATURES

def detect_magic_bytes(file_path: str | Path) -> Dict[str, str]:
    """Read file header bytes to determine actual file type independently of extension."""
    path = Path(file_path)
    with open(path, "rb") as f:
        header = f.read(32)

    magic_hex = header[:8].hex(" ").upper()
    detected_mime = "application/octet-stream (Raw Binary / Unknown)"

    for sig, description in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            detected_mime = description
            break

    # Text detection fallback
    if detected_mime.startswith("application/octet-stream"):
        try:
            header.decode("utf-8")
            detected_mime = "text/plain (UTF-8 / ASCII text)"
        except UnicodeDecodeError:
            pass

    return {
        "magic_hex": magic_hex,
        "detected_type": detected_mime,
    }

