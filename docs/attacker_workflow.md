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
- `
