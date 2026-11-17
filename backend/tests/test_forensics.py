import sys
import unittest
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.forensic.entropy import calculate_bytes_entropy

class TestForensics(unittest.TestCase):
    def test_entropy_calculation(self):
        # Low entropy: repetitive bytes
        low_data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        low_entropy = calculate_bytes_entropy(low_data)
        self.assertEqual(low_entropy, 0.0)

        # High entropy: diverse pseudo-random bytes
        high_data = bytes(range(256))
        high_entropy = calculate_bytes_entropy(high_data)
        self.assertGreaterEqual(high_entropy, 7.9)

