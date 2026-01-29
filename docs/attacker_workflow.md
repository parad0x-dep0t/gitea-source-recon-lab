# Attacker Workflow: Exploiting Gitea Source Code

This document defines an attacker-centric workflow for analyzing source
code obtained from a Gitea repository during CTF-style engagements.

The goal is to move from **source code access → exploitable attack paths**
as efficiently as possible.

---

## 1. Entry Conditions

An attacker may gain access to Gitea source code via:
- Publicly accessible repositories
- Authenticated access using leaked or reused credentials
- Low-privileged user access with read permissions

Once source code is accessible, it becomes a high-value recon asset.

---

## 2. Attacker Priorities (In Order)

Attackers do not review code randomly. They prioritize based on
**exploit value and time efficiency**.

### Priority Order
1. Hardcoded secrets and credentials
2. Configuration files and environment variables
3. Network-facing endpoints
4. File system interactions
5. Dangerous code patterns
6. Dependency and technology weaknesses

---

## 3. Phase 1: High-Impact Recon (Fast Wins)

### 3.1 Search for Secrets

Attackers first look for anything that grants **direct access**.

Examples:
- Database credentials
- API tokens
- JWT secrets
- SMTP credentials
- Admin passwords

Typical locations:
- `.env`
- `config.*`
- `settings.*`
- Source files with inline credentials

Outcome:
- Direct login
- Token reuse
- Privilege escalation
- Lateral movement

---

### 3.2 Identify Absolute Paths & Sensitive Files

Hardcoded paths often reveal:
- Deployment layout
- Writable directories
- User home directories
- Backup locations

Examples:
- `/var/www/html`
- `/home/dev/`
- `/opt/app/`
- `.bak`, `.old`, `.zip` files

Outcome:
- Path traversal exploitation
- File overwrite attacks
- Information disclosure

---

## 4. Phase 2: Attack Surface Mapping

### 4.1 Endpoint Enumeration

Attackers extract routes to understand the application's exposed
functionality.

Examples:
- `/admin`
- `/upload`
- `/debug`
- `/api/internal`
- `/download?file=`

Key questions:
- Is authentication enforced?
- Is user input used directly?
- Are there file operations?

Outcome:
- IDOR
- File upload abuse
- Unauthenticated access
- Logic flaws

---

### 4.2 Authentication & Authorization Logic Review

Attackers analyze:
- Login flow
- Role checks
- Token validation
- Session handling

Red flags:
- Hardcoded admin roles
- Client-side authorization
- Missing access checks

Outcome:
- Auth bypass
- Privilege escalation

---

## 5. Phase 3: Vulnerable Code Pattern Analysis

### 5.1 Command Execution

Examples:
- `os.system()`
- `exec()`
- `Runtime.getRuntime().exec()`

Attackers check:
- Is input user-controlled?
- Is sanitization missing?

Outcome:
- Remote Command Execution (RCE)

---

### 5.2 File Handling & Path Traversal

Examples:
- `open("/uploads/" + filename)`
- `send_file(userInput)`
- `readFile(req.query.file)`

Outcome:
- Arbitrary file read/write
- Config leakage
- Credential exposure

---

### 5.3 Injection Flaws

Patterns:
- SQL string concatenation
- `eval()` usage
- Unsafe deserialization

Outcome:
- SQL injection
- Code execution
- Auth bypass

---

## 6. Phase 4: Dependency & Technology Weaknesses

Attackers inspect:
- `package.json`
- `requirements.txt`
- `go.mod`
- Framework versions

They look for:
- Outdated frameworks
- Known vulnerable libraries
- Deprecated security controls

Outcome:
- Known CVE exploitation
- Auth bypass via framework flaws

---

## 7. Phase 5: Attack Chain Construction

The real power of source code access is **chaining findings**.

Example chains:
- Hardcoded DB creds → Admin login → File upload → RCE
- Debug endpoint → Path traversal → Config leak → JWT forgery
- Weak auth check → IDOR → Privilege escalation

Attackers prioritize chains with:
- Fewest steps
- Highest impact
- Remote exploitability

---

## 8. Implications for Tool Design

A CTF-focused tool should:
- Prioritize findings by attacker value
- Correlate findings across files
- Highlight possible attack chains
- Reduce noise and false positives

The tool should behave like an attacker assistant,
not a compliance scanner.

---

## 9. Key Design Principle

> Source code is not the goal.
> Exploitation paths are the goal.

Every feature in the tool should support this mindset.
