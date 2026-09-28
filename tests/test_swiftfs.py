"""
Integration tests for SwiftFS Python interface.
"""

import os
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from python.formatter import format_bytes, format_duration


class TestFormatter(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 * 1024 * 5), "5.00 MB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB")

    def test_format_duration(self):
        self.assertTrue("ms" in format_duration(0.05) or "µs" in format_duration(0.05))
        self.assertTrue("s" in format_duration(2.5))
        self.assertTrue("m" in format_duration(125.0))


if __name__ == "__main__":
    unittest.main()
