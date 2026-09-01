# Gitea Source Recon Scanner

A focused, high-signal static analysis and reconnaissance scanner designed for analyzing source code from Gitea repositories and local directories. 

Built specifically for CTF challenges, security research, and code review workflows, this tool emphasizes **actionable security primitives** (hardcoded credentials, dangerous execution sinks, exposed API endpoints, and source-to-sink attack chain correlations) with minimal false positives.

---

## Key Features

* **Target Modes**:
  * **Local Codebase**: Recursively scans directories supporting `.py`, `.js`, `.ts`, `.php`, `.env`, `.conf`, `.json`, `.yaml`, `.ini`, and shell scripts.
  * **Remote Gitea Instance**: Enumerates accessible repositories via the Gitea REST API (`/api/v1`) and downloads/extracts them automatically.
* **Attacker-Focused Prioritization**:
  * **P0 (Critical / Immediate)**: Hardcoded secrets, passwords, API tokens, JWT keys, command execution sinks (`os.system`, `subprocess`, `exec`), and unsafe deserialization.
  * **P1 (High / Strong Candidates)**: Web endpoints (`@app.route`, `router.get/post`), sensitive system paths (`/var`, `/etc`, `/opt`), and file sinks (`send_file`, `fs.readFile`).
  * **P2 (Medium / Supporting Sources)**: User-controlled input sources (`request.args`, `req.query`, `req.body`, `$_GET`, `$_POST`).
* **Attack Chain Correlation**:
  * Automatically flags potential single-file chains (e.g., **User Input Source $\to$ Execution Sink** for RCE, or **User Input Source $\to$ File Sink** for Path Traversal / LFI).
* **Flexible Output**:
  * Prioritized terminal output with color-ready formatting.
  * Category filtering (`--scan secrets`, `--scan endpoints`, `--scan sinks`, etc.).
  * Structured JSON export (`--json`) for pipeline integration.

---

## Installation

### Prerequisites
* Python 3.8 or higher

### Setup
Clone the repository and install the required dependencies:

```bash
git clone https://github.com/your-username/gitea-source-recon-lab.git
cd gitea-source-recon-lab
pip install -r requirements.txt
```

---

## Usage

### 1. Scan a Local Directory
```bash
python src/scanner.py /path/to/project
```

### 2. Category-Specific Scan
Filter findings by category (`secrets`, `endpoints`, `sinks`, `sources`, `paths`):
```bash
# Scan only for secrets and credentials
python src/scanner.py test_repo --scan secrets

# Scan only for exposed API endpoints
python src/scanner.py test_repo --scan endpoints

# Scan only for dangerous execution & file sinks
python src/scanner.py test_repo --scan sinks
```

### 3. Scan a Remote Gitea Instance
```bash
# Unauthenticated scan of public repositories
python src/scanner.py --gitea http://gitea.local:3000

# Authenticated scan (including private repos accessible to token)
python src/scanner.py --gitea http://gitea.local:3000 --token YOUR_GITEA_API_TOKEN

# Scan a single repository from Gitea
python src/scanner.py --gitea http://gitea.local:3000 --repo target-repo
```

### 4. Export Findings to JSON
```bash
python src/scanner.py test_repo --json > findings.json
```

---

## CLI Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `directory` | Target local directory to scan | None |
| `--gitea <URL>` | Base URL of the target Gitea instance | None |
| `--token <TOKEN>` | Gitea personal access token for authentication | None |
| `--repo <NAME>` | Target a specific repository on Gitea | None |
| `--scan <CATEGORY>` | Filter by `all`, `secrets`, `endpoints`, `sinks`, `sources`, `paths` | `all` |
| `--rules <PATH>` | Path to custom YAML rules file | `src/rules.yaml` |
| `--json` | Output results in JSON format | `false` |
| `--quiet` | Suppress banner and non-essential status messages | `false` |

---

## Rule Engine & Custom Rules

Rules are defined in declarative YAML format within [`src/rules.yaml`](src/rules.yaml):

```yaml
- id: HARDCODED_PASSWORD
  category: SECRET
  priority: P0
  description: Hardcoded credentials or password detected.
  pattern: '(?i)(password|passwd|pwd|db_pass|db_password)\s*=\s*["''][^"'']+["'']'

- id: DANGEROUS_EXECUTION_SINK
  category: SINK
  priority: P0
  description: Potential command execution or eval sink detected (RCE risk).
  pattern: '(os\.system|subprocess\.call|subprocess\.run|eval|exec|child_process\.exec|shell_exec)\s*\('
```

You can supply your own rule set via the `--rules` flag:
```bash
python src/scanner.py ./codebase --rules custom_rules.yaml
```

---

## Project Structure

```
gitea-source-recon-lab/
├── src/
│   ├── scanner.py        # Core scanner engine and CLI entry point
│   ├── gitea_client.py   # Gitea REST API interaction client
│   └── rules.yaml        # YAML detection rules definition
├── design/               # Architecture and rule design documents
├── docs/                 # Methodology and workflow documentation
├── test_repo/            # Multi-language test fixtures (Flask, Express)
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

---

## Disclaimer

This tool is designed for authorized security assessments, educational CTF environments, and defensive source code audits. Always obtain explicit authorization before testing systems or repositories you do not own.
