# Detection Categories & Priorities

This document defines the detection categories used by the Gitea source
recon tool, along with attacker-focused priorities.

The purpose is to ensure that findings are ranked by **exploitation value**,
not generic severity ratings.

---

## 1. Detection Philosophy

Unlike traditional SAST tools, this project prioritizes findings based on:
- Exploitability
- Attacker usefulness
- Chain potential
- Time-to-impact in CTF scenarios

Each finding belongs to **one primary category** and is assigned a
priority level.

---

## 2. Priority Levels

### 🔴 P0 – Immediate Exploitation
Findings that can directly lead to compromise with minimal effort.

- Often usable without additional vulnerabilities
- High confidence
- Low false-positive rate

---

### 🟠 P1 – Strong Exploitation Candidate
Findings that enable exploitation when combined with one more step.

- Requires chaining
- High attacker value
- Common in CTFs

---

### 🟡 P2 – Supporting Weakness
Findings that assist in exploitation but are not sufficient alone.

- Recon-enabling
- Context-providing
- Environment mapping

---

### 🔵 P3 – Informational
Low-risk findings useful mainly for context.

- Tech stack identification
- Minor misconfigurations

---

## 3. Detection Categories

---

### 🔑 Category 1: Secrets & Credentials (P0)

**Description**  
Hardcoded secrets that may grant direct access to systems or services.

**Examples**
- Passwords
- API keys
- Tokens
- JWT secrets
- Database credentials
- SSH keys

**Typical Files**
- `.env`
- `config.*`
- `settings.*`
- Source code files

**Attacker Outcome**
- Direct login
- Privilege escalation
- Lateral movement

---

### 📁 Category 2: Sensitive Paths & Files (P1)

**Description**  
Hardcoded filesystem paths or references to sensitive files.

**Examples**
- Absolute paths (`/var/www/`)
- User home directories
- Backup files (`.bak`, `.old`)
- Private keys

**Attacker Outcome**
- Path traversal
- File overwrite
- Information disclosure

---

### 🌐 Category 3: Network Endpoints (P1)

**Description**  
Exposed or hidden endpoints that define the application's attack surface.

**Examples**
- Admin panels
- Upload endpoints
- Debug routes
- Internal APIs

**Attacker Outcome**
- IDOR
- Auth bypass
- File upload abuse

---

### 🧨 Category 4: Dangerous Code Patterns (P0 / P1)

**Description**  
Code constructs that frequently lead to exploitation when combined with
user input.

**Examples**
- Command execution (`os.system`, `exec`)
- Unsafe deserialization
- Path traversal patterns
- `eval()` usage

**Attacker Outcome**
- RCE
- File read/write
- Auth bypass

---

### 🔐 Category 5: Authentication & Authorization Logic (P0 / P1)

**Description**  
Weak or flawed access control logic.

**Examples**
- Hardcoded admin roles
- Missing auth checks
- Client-side role enforcement

**Attacker Outcome**
- Privilege escalation
- Account takeover

---

### 📦 Category 6: Dependency & Technology Weaknesses (P2)

**Description**  
Outdated or vulnerable dependencies and frameworks.

**Examples**
- Old framework versions
- Known vulnerable libraries
- Deprecated crypto

**Attacker Outcome**
- CVE-based exploitation
- Known bypass techniques

---

### 🧩 Category 7: Configuration Weaknesses (P1 / P2)

**Description**  
Insecure configuration patterns.

**Examples**
- Debug mode enabled
- Hardcoded environment modes
- Insecure default settings

**Attacker Outcome**
- Information disclosure
- Debug abuse

---

### 🧠 Category 8: Recon & Context Indicators (P3)

**Description**  
Information that helps attackers understand the environment.

**Examples**
- Internal hostnames
- Comments revealing architecture
- Dev notes

**Attacker Outcome**
- Better attack planning

---

## 4. Category-to-Tool Mapping

Each category will map to:
- One or more detection rules
- A default priority
- Suggested attack chains

Example:
- Secrets → Immediate exploitation → Auth pivot
- Endpoints → Input analysis → RCE chain
- Paths → Traversal → Config leak → Secret reuse

---

## 5. Design Rule

> If a finding does not help an attacker move forward,
> it should not be prioritized.

This ensures the tool remains **CTF-focused and signal-rich**.
