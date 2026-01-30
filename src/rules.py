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
    },
    {
        "id": "ABSOLUTE_PATH",
        "category": "PATH",
        "priority": "P1",
        "description": "Hardcoded absolute paths may reveal sensitive directories or enable path traversal attacks.",
        "pattern": re.compile(
            r'["\']/(var|home|opt|etc|usr)/[^"\']+["\']'
        )
    },
    {
    "id": "WEB_ENDPOINT",
    "category": "ENDPOINT",
    "priority": "P1",
    "description": "Exposed web route detected. May reveal attack surface or hidden functionality.",
    "pattern": re.compile(
        r'(app\.get|app\.post|router\.get|router\.post)\s*\(\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    ),
    "extract": True
    },
    {
    "id": "DANGEROUS_EXECUTION_SINK",
    "category": "SINK",
    "priority": "P0",
    "description": "Potential command execution sink detected. If user-controlled input reaches this, it may lead to RCE.",
    "pattern": re.compile(
        r'(os\.system|subprocess\.call|subprocess\.run|eval|exec|child_process\.exec)\s*\(',
        re.IGNORECASE
    )
    },
    {
    "id": "POTENTIAL_PATH_TRAVERSAL",
    "category": "FILE_SINK",
    "priority": "P1",
    "description": "File operation detected. If user input reaches this without validation, it may allow path traversal.",
    "pattern": re.compile(
        r'(open|send_file|fs\.readFile|res\.sendFile)\s*\(',
        re.IGNORECASE
    )
    },
    {
    "id": "USER_INPUT_SOURCE",
    "category": "SOURCE",
    "priority": "P2",
    "description": "User-controlled input detected. If this flows into a sink, it may lead to exploitation.",
    "pattern": re.compile(
        r'(request\.args|request\.form|request\.get_json|req\.query|req\.body|req\.params|input\s*\()',
        re.IGNORECASE
    )
    }
]
