"""
scanner.py

Gitea Source Code Reconnaissance Scanner (CTF-focused static analysis).
Extracts secrets, endpoints, dangerous sinks, and correlates attack chains.
"""

import os
import sys
import argparse
import json
import re
import yaml

# Ensure robust stdout encoding across platforms
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure local imports work regardless of execution working directory
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from gitea_client import GiteaClient
except ImportError:
    GiteaClient = None

# Default rules file location
DEFAULT_RULES_PATH = os.path.join(CURRENT_DIR, "rules.yaml")

# Supported file extensions for static analysis
SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".php",
    ".env",
    ".txt",
    ".conf",
    ".config",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".sh",
    ".bash"
}

# Global state
FINDINGS = []


def load_rules(rules_path=DEFAULT_RULES_PATH):
    """
    Load and compile detection rules from YAML.
    """
    if not os.path.isfile(rules_path):
        raise FileNotFoundError(f"Rules file not found at: {rules_path}")

    with open(rules_path, "r", encoding="utf-8") as f:
        raw_rules = yaml.safe_load(f)

    if not isinstance(raw_rules, list):
        raise ValueError(f"Invalid rule format in {rules_path}. Expected a list of rule definitions.")

    compiled_rules = []
    for rule in raw_rules:
        compiled_rule = rule.copy()
        try:
            compiled_rule["pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
            compiled_rules.append(compiled_rule)
        except re.error as e:
            print(f"[!] Warning: Failed to compile regex for rule '{rule.get('id')}': {e}", file=sys.stderr)

    return compiled_rules


def is_supported_file(file_name):
    _, ext = os.path.splitext(file_name)
    return ext.lower() in SUPPORTED_EXTENSIONS


def apply_rules(rules, file_path, line, line_number, scan_mode):
    """
    Apply detection rules to a line of source code.
    """
    for rule in rules:
        category = rule.get("category", "").upper()

        # ---- Scan Mode Filtering ----
        if scan_mode != "all":
            if scan_mode == "secrets" and category != "SECRET":
                continue
            if scan_mode == "endpoints" and category != "ENDPOINT":
                continue
            if scan_mode == "sinks" and category not in ["SINK", "FILE_SINK"]:
                continue
            if scan_mode == "sources" and category != "SOURCE":
                continue
            if scan_mode == "paths" and category != "PATH":
                continue

        match = rule["pattern"].search(line)
        if match:
            finding = {
                "priority": rule.get("priority", "P3"),
                "category": category,
                "rule_id": rule.get("id"),
                "file": file_path.replace("\\", "/"),
                "line": line_number,
                "description": rule.get("description", "")
            }

            # Special endpoint route extraction if regex has capture groups
            if rule.get("extract") and match.groups():
                groups = match.groups()
                if len(groups) >= 2:
                    raw_method = groups[0]
                    finding["route"] = groups[1]
                    finding["method"] = raw_method.split(".")[-1].replace("@", "").upper()
                else:
                    finding["route"] = groups[0]
                    finding["method"] = "HTTP"
            else:
                finding["code"] = line.strip()

            FINDINGS.append(finding)


def scan_file(rules, file_path, scan_mode):
    """
    Read and scan a single file line-by-line.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                apply_rules(rules, file_path, line, line_number, scan_mode)
    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}", file=sys.stderr)


def traverse_directory(rules, root_path, scan_mode):
    """
    Recursively scan all supported files in directory.
    """
    for root, _, files in os.walk(root_path):
        for file_name in files:
            if is_supported_file(file_name):
                full_path = os.path.join(root, file_name)
                scan_file(rules, full_path, scan_mode)


def priority_sort_key(finding):
    priority_map = {
        "P0": 0,
        "P1": 1,
        "P2": 2,
        "P3": 3
    }
    return priority_map.get(finding["priority"], 99)


def detect_correlations():
    """
    Detect source-to-sink correlations in the same file (potential attack chains).
    """
    file_map = {}
    for finding in FINDINGS:
        file_name = finding["file"]
        if file_name not in file_map:
            file_map[file_name] = []
        file_map[file_name].append(finding)

    print("\n=== CORRELATION & ATTACK CHAIN WARNINGS ===")
    correlation_found = False

    for file_name, findings in file_map.items():
        sources = [f for f in findings if f["category"] == "SOURCE"]
        sinks = [f for f in findings if f["category"] == "SINK"]
        file_sinks = [f for f in findings if f["category"] == "FILE_SINK"]

        # SOURCE + SINK -> Potential RCE
        if sources and sinks:
            correlation_found = True
            print(f"\n[!] POTENTIAL RCE CHAIN DETECTED: {file_name}")
            print("    [+] User Input Sources:")
            for s in sources:
                print(f"        Line {s['line']}: {s.get('code')}")
            print("    [-] Dangerous Execution Sinks:")
            for s in sinks:
                print(f"        Line {s['line']}: {s.get('code')}")

        # SOURCE + FILE_SINK -> Potential Path Traversal / LFI
        if sources and file_sinks:
            correlation_found = True
            print(f"\n[!] POTENTIAL PATH TRAVERSAL / LFI CHAIN DETECTED: {file_name}")
            print("    [+] User Input Sources:")
            for s in sources:
                print(f"        Line {s['line']}: {s.get('code')}")
            print("    [-] File Sinks:")
            for s in file_sinks:
                print(f"        Line {s['line']}: {s.get('code')}")

    if not correlation_found:
        print("No immediate single-file SOURCE -> SINK correlations detected.\n")
    else:
        print("")


def print_findings():
    if not FINDINGS:
        print("\n[+] No findings detected.")
        return

    print("\n=== SCAN FINDINGS ===")
    sorted_findings = sorted(FINDINGS, key=priority_sort_key)

    for finding in sorted_findings:
        print(f"\n[{finding['priority']}][{finding['category']}] {finding['file']}:{finding['line']}")
        if finding["category"] == "ENDPOINT":
            print(f"  Route:  {finding.get('route')}")
            if finding.get('method'):
                print(f"  Method: {finding.get('method')}")
        else:
            print(f"  Code:   {finding.get('code')}")
        print(f"  Why:    {finding['description']}")


def print_summary():
    print("=== SUMMARY ===")
    summary = {}
    for finding in FINDINGS:
        category = finding["category"]
        summary[category] = summary.get(category, 0) + 1

    for category, count in sorted(summary.items()):
        print(f"  {category:<12}: {count}")
    print(f"\nTotal Findings: {len(FINDINGS)}\n")


def export_json():
    print(json.dumps(FINDINGS, indent=2))


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="gitea-recon",
        description="Gitea Source Code Reconnaissance Scanner (CTF-focused)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "directory",
        nargs="?",
        help="Path to the source code directory to scan"
    )

    parser.add_argument(
        "--rules",
        default=DEFAULT_RULES_PATH,
        help="Custom YAML rules file path"
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
        help="Base URL of Gitea instance (e.g., http://gitea.htb:3000)"
    )

    parser.add_argument(
        "--token",
        help="Gitea API token (for authenticated scan)"
    )

    parser.add_argument(
        "--repo",
        help="Scan only a specific repository name"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    target_directory = args.directory
    scan_mode = args.scan
    quiet_mode = args.quiet
    json_output = args.json
    gitea_url = args.gitea
    token = args.token
    rules_file = args.rules

    if not gitea_url and not target_directory:
        print("[!] Error: You must provide either a target directory or a --gitea URL.", file=sys.stderr)
        parser = parse_arguments()
        return

    try:
        rules = load_rules(rules_file)
    except Exception as e:
        print(f"[!] Failed to load rules: {e}", file=sys.stderr)
        sys.exit(1)

    FINDINGS.clear()

    if not quiet_mode and not json_output:
        print("========================================")
        print("   Gitea Source Recon Scanner")
        print("   CTF-Focused Static Analysis Tool")
        print("========================================")
        print(f"[*] Rules loaded: {len(rules)} from {os.path.basename(rules_file)}")
        print(f"[*] Scan mode   : {scan_mode}\n")

    # GITEA REMOTE SCAN MODE
    if gitea_url:
        if GiteaClient is None:
            print("[!] Error: GiteaClient module is missing.", file=sys.stderr)
            sys.exit(1)

        if not quiet_mode and not json_output:
            print(f"[*] Connecting to Gitea instance: {gitea_url}")

        client = GiteaClient(gitea_url, token)
        try:
            repos = client.list_repositories()
            if args.repo:
                repos = [r for r in repos if r.get("name") == args.repo]
                if not repos:
                    print(f"[!] Repository '{args.repo}' not found on target Gitea.", file=sys.stderr)
                    return
        except Exception as e:
            print(f"[!] Failed to query Gitea: {e}", file=sys.stderr)
            return

        if not repos:
            if not quiet_mode and not json_output:
                print("[!] No repositories found.")
            return

        if not quiet_mode and not json_output:
            print(f"[*] Found {len(repos)} accessible repositories.\n")

        for repo in repos:
            owner = repo.get("owner", {}).get("login", "unknown")
            repo_name = repo.get("name", "unknown")

            if not quiet_mode and not json_output:
                print(f"[+] Downloading & extracting {owner}/{repo_name}...")

            try:
                repo_path = client.download_repo(owner, repo_name)
                traverse_directory(rules, repo_path, scan_mode)
            except Exception as e:
                print(f"[!] Failed to download/scan {owner}/{repo_name}: {e}", file=sys.stderr)

    # LOCAL DIRECTORY SCAN MODE
    else:
        if not os.path.isdir(target_directory):
            print(f"[!] Error: Target directory '{target_directory}' does not exist.", file=sys.stderr)
            sys.exit(1)

        if not quiet_mode and not json_output:
            print(f"[*] Scanning local path: {target_directory}\n")

        traverse_directory(rules, target_directory, scan_mode)

    # OUTPUT PRESENTATION
    if json_output:
        export_json()
    else:
        print_findings()
        detect_correlations()
        print_summary()


if __name__ == "__main__":
    main()
