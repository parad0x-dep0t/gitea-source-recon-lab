"""
scanner.py

MVP source code scanner.
Step 3: Directory traversal + extension filtering + line-by-line reading.
"""

import os


# Supported file extensions (initial scope)
SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".php",
    ".env",
    ".txt",
    ".conf"
}


def is_supported_file(file_name):
    """
    Check if file has a supported extension.
    """
    _, ext = os.path.splitext(file_name)
    return ext.lower() in SUPPORTED_EXTENSIONS


def scan_file(file_path):
    """
    Read file line-by-line.
    (No detection logic yet.)
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                # For now, just print line numbers for proof of reading
                print(f"[READ] {file_path}:{line_number}")
    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")


def traverse_directory(root_path):
    """
    Recursively walk through a directory and scan supported files.
    """
    for root, dirs, files in os.walk(root_path):
        for file_name in files:
            if is_supported_file(file_name):
                full_path = os.path.join(root, file_name)
                scan_file(full_path)


def main():
    # Temporary hardcoded path for testing
    target_directory = "./test_repo"

    if not os.path.isdir(target_directory):
        print(f"[!] Directory not found: {target_directory}")
        return

    print(f"[*] Scanning directory: {target_directory}")
    traverse_directory(target_directory)


if __name__ == "__main__":
    main()
