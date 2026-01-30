"""
scanner.py

MVP source code scanner.
Step 4: Add first detection rule (hardcoded secret).
"""

import os
import re


# Supported file extensions
SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".php",
    ".env",
    ".txt",
    ".conf"
}


# === FIRST DETECTION RULE ===
HARDCODED_PASSWORD_REGEX = re.compile(
    r'(password|passwd|pwd|db_pass|db_password)\s*=\s*["\'][^"\']+["\']',
    re.IGNORECASE
)


def is_supported_file(file_name):
    _, ext = os.path.splitext(file_name)
    return ext.lower() in SUPPORTED_EXTENSIONS


def scan_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):

                # Apply hardcoded password rule
                if HARDCODED_PASSWORD_REGEX.search(line):
                    print("\n[!!! P0 SECRET DETECTED !!!]")
                    print(f"File: {file_path}")
                    print(f"Line: {line_number}")
                    print(f"Code: {line.strip()}")
                    print("Why this matters: Hardcoded credentials may allow direct authentication.\n")

    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")


def traverse_directory(root_path):
    for root, dirs, files in os.walk(root_path):
        for file_name in files:
            if is_supported_file(file_name):
                full_path = os.path.join(root, file_name)
                scan_file(full_path)


def main():
    target_directory = "./test_repo"

    if not os.path.isdir(target_directory):
        print(f"[!] Directory not found: {target_directory}")
        return

    print(f"[*] Scanning directory: {target_directory}")
    traverse_directory(target_directory)


if __name__ == "__main__":
    main()
