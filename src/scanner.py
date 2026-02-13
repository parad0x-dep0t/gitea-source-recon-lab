"""
scanner.py

MVP source code scanner.
Step 6: Finding storage and priority sorting.
"""

import os
import argparse
import json
from rules import RULES
from gitea_client import GiteaClient


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
CURRENT_SCAN_MODE = "all"


def is_supported_file(file_name):
    _, ext = os.path.splitext(file_name)
    return ext.lower() in SUPPORTED_EXTENSIONS



def apply_rules(file_path, line, line_number, scan_mode):
    """
    Apply all detection rules to a single line.
    Store findings instead of printing immediately.
    """

    for rule in RULES:

        # ---- Scan Mode Filtering ----
        if scan_mode != "all":
            if scan_mode == "secrets" and rule["category"] != "SECRET":
                continue
            if scan_mode == "endpoints" and rule["category"] != "ENDPOINT":
                continue
            if scan_mode == "sinks" and rule["category"] != "SINK":
                continue
            if scan_mode == "sources" and rule["category"] != "SOURCE":
                continue
            if scan_mode == "paths" and rule["category"] not in ["PATH", "FILE_SINK"]:
                continue

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


def scan_file(file_path, scan_mode):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                apply_rules(file_path, line, line_number, scan_mode)
    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")


def traverse_directory(root_path, scan_mode):
    for root, dirs, files in os.walk(root_path):
        for file_name in files:
            if is_supported_file(file_name):
                full_path = os.path.join(root, file_name)
                scan_file(full_path, scan_mode)


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
    Detect simple SOURCE → SINK correlations and print matched lines.
    """
    file_map = {}

    # Group findings by file
    for finding in FINDINGS:
        file_name = finding["file"]

        if file_name not in file_map:
            file_map[file_name] = []

        file_map[file_name].append(finding)

    print("\n=== CORRELATION WARNINGS ===\n")

    correlation_found = False

    for file_name, findings in file_map.items():

        sources = [f for f in findings if f["category"] == "SOURCE"]
        sinks = [f for f in findings if f["category"] == "SINK"]
        file_sinks = [f for f in findings if f["category"] == "FILE_SINK"]

        # SOURCE + SINK → Potential RCE
        if sources and sinks:
            correlation_found = True
            print(f"!!!  Potential RCE Chain Detected in: {file_name}\n")

            print("    SOURCE:")
            for s in sources:
                print(f"        Line {s['line']} → {s.get('code')}")

            print("\n    SINK:")
            for s in sinks:
                print(f"        Line {s['line']} → {s.get('code')}")

            print("\n")

        # SOURCE + FILE_SINK → Potential Path Traversal
        if sources and file_sinks:
            correlation_found = True
            print(f"!!!  Potential Path Traversal Chain in: {file_name}\n")

            print("    SOURCE:")
            for s in sources:
                print(f"        Line {s['line']} → {s.get('code')}")

            print("\n    FILE_SINK:")
            for s in file_sinks:
                print(f"        Line {s['line']} → {s.get('code')}")

            print("\n")

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


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="gitea-recon",
        description="Gitea Source Code Recon Scanner (CTF-focused)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "directory",
        help="Path to the source code directory to scan"
    )

    parser.add_argument(
        "--scan",
        choices=["all", "secrets", "endpoints", "sinks", "sources", "paths"],
        default="all",
        help="Specify category to scan"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Export findings in JSON format"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress banner and non-essential output"
    )

    parser.add_argument(
        "--gitea",
        help="Base URL of Gitea instance (e.g., http://gitea.htb)"
    )

    parser.add_argument(
        "--token",
        help="Gitea API token for authentication"
    )


    return parser.parse_args()


def main():
    args = parse_arguments()

    target_directory = args.directory
    scan_mode = args.scan
    quiet_mode = args.quiet
    json_output = args.json

    if not os.path.isdir(target_directory):
        print(f"[!] Directory not found: {target_directory}")
        return

    if not quiet_mode:
        print("========================================")
        print("   Gitea Source Recon Scanner")
        print("   CTF-Focused Static Analysis Tool")
        print("========================================")
        print(f"[*] Directory: {target_directory}")
        print(f"[*] Scan mode: {scan_mode}\n")

    traverse_directory(target_directory, scan_mode)

    if json_output:
        export_json()
    else:
        print_findings()
        detect_basic_correlations()
        print_summary()


def print_summary():
    print("=== SUMMARY ===\n")
    summary = {}
    for finding in FINDINGS:
        category = finding["category"]
        summary[category] = summary.get(category, 0) + 1
    for category, count in summary.items():
        print(f"{category}: {count}")
    print(f"\nTotal Findings: {len(FINDINGS)}\n")

def export_json():
    print(json.dumps(FINDINGS, indent=4))

if __name__ == "__main__":
    main()
