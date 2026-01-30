"""
scanner.py

MVP source code scanner.
Step 2: Directory traversal + file extension filtering.
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


def traverse_directory(root_path):
    """
    Recursively walk through a directory and print supported files.
    """
    for root, dirs, files in os.walk(root_path):
        for file_name in files:
            if is_supported_file(file_name):
                full_path = os.path.join(root, file_name)
                print(f"[SUPPORTED] {full_path}")
            else:
                # Uncomment below if you want to see skipped files
                # print(f"[SKIPPED] {file_name}")
                pass


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
