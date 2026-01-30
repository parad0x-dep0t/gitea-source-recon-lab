"""
scanner.py

MVP source code scanner.
Step 6: Finding storage and priority sorting.
"""

import os
from rules import RULES


# Supported file extensions
SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".php",
    ".env",
    ".txt",
    ".conf"
}

# Global findings list
FINDINGS = []


def is_supported_file(file_name):
    _, ext = os.path.splitext(file_name)
    return ext.lower() in SUPPORTED_EXTENSIONS


def apply_rules(file_path, line, line_number):
    """
    Apply all detection rules to a single line.
    Store findings instead of printing immediately.
    """
    for rule in RULES:
        match = rule["pattern"].search(line)

        if match:
            finding = {
                "priority": rule["priority"],
                "category": rule["category"],
                "rule_id": rule["id"],
                "file": file_path,
                "line": line_number,
                "description": rule["description"]
            }

            # Special extraction for endpoint rule
            if rule.get("extract"):
                method_raw = match.group(1)
                route = match.group(2)

                method = method_raw.split(".")[-1].upper()

                finding["route"] = route
                finding["method"] = method
            else:
                finding["code"] = line.strip()

            FINDINGS.append(finding)

def scan_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                apply_rules(file_path, line, line_number)
    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")


def traverse_directory(root_path):
    for root, dirs, files in os.walk(root_path):
        for file_name in files:
            if is_supported_file(file_name):
                full_path = os.path.join(root, file_name)
                scan_file(full_path)


def priority_sort_key(finding):
    """
    Convert priority label into sortable value.
    Lower number = higher priority.
    """
    priority_map = {
        "P0": 0,
        "P1": 1,
        "P2": 2,
        "P3": 3
    }
    return priority_map.get(finding["priority"], 99)


def detect_basic_correlations():
    """
    Detect simple SOURCE → SINK correlation within same file.
    """
    file_map = {}

    # Group findings by file
    for finding in FINDINGS:
        file_name = finding["file"]
        category = finding["category"]

        if file_name not in file_map:
            file_map[file_name] = set()

        file_map[file_name].add(category)

    # Check for SOURCE + SINK in same file
    print("\n=== CORRELATION WARNINGS ===\n")

    correlation_found = False

    for file_name, categories in file_map.items():
        if "SOURCE" in categories and "SINK" in categories:
            correlation_found = True
            print(f"  Potential RCE Chain Detected in: {file_name}")
            print("    SOURCE and SINK found in same file.\n")

        if "SOURCE" in categories and "FILE_SINK" in categories:
            correlation_found = True
            print(f"  Potential Path Traversal Chain in: {file_name}")
            print("    SOURCE and FILE_SINK found in same file.\n")

    if not correlation_found:
        print("No obvious SOURCE → SINK correlations detected.\n")


def print_findings():
    if not FINDINGS:
        print("\n[+] No findings detected.")
        return

    print("\n=== SCAN RESULTS ===\n")

    # Sort findings by priority
    sorted_findings = sorted(FINDINGS, key=priority_sort_key)
    
    for finding in sorted_findings:
        print(f"[{finding['priority']}][{finding['category']}] {finding['file']}:{finding['line']}")
        if finding["category"] == "ENDPOINT":
            print(f"  Route:  {finding.get('route')}")
            print(f"  Method: {finding.get('method')}")
        else:
            print(f"  Code: {finding.get('code')}")
        print(f"  Why:  {finding['description']}\n")

def main():
    target_directory = "./test_repo"

    if not os.path.isdir(target_directory):
        print(f"[!] Directory not found: {target_directory}")
        return

    print(f"[*] Scanning directory: {target_directory}")
    traverse_directory(target_directory)
    print_findings()


if __name__ == "__main__":
    main()
