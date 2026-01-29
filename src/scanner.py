"""
scanner.py

MVP source code scanner.
Step 1: Directory traversal only.
"""

import os


def traverse_directory(root_path):
    """
    Recursively walk through a directory and print file paths.
    """
    for root, dirs, files in os.walk(root_path):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            print(f"[FILE] {full_path}")


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
