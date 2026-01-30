"""
rules.py

This file contains detection rules used by the scanner.
Each rule is defined as a dictionary.
"""

import re


RULES = [
    {
        "id": "HARDCODED_PASSWORD",
        "category": "SECRET",
        "priority": "P0",
        "description": "Hardcoded credentials may allow direct authentication.",
        "pattern": re.compile(
            r'(password|passwd|pwd|db_pass|db_password)\s*=\s*["\'][^"\']+["\']',
            re.IGNORECASE
        )
    }
]
