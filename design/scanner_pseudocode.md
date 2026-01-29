# Scanner Pseudocode (MVP)

This document describes the high-level logic of the first MVP scanner.
It is intentionally language-agnostic and avoids implementation details.

---

## 1. Input

- Path to local source code directory (downloaded Gitea repo)

Example:
scan("/home/user/ctf/repo")


---

## 2. Initialization

- Load detection rules
  - Secrets regex rules
  - Path regex rules
  - Endpoint regex rules

- Initialize empty findings list

---

## 3. Directory Traversal

FOR each file in the target directory (recursive):
    IF file extension is supported:
        Read file line-by-line
        Send file content to scanner

Supported extensions (initial):
- .py
- .js
- .php
- .env
- .txt
- .conf

---

## 4. File Scanning Logic

FOR each line in the file:
    FOR each detection rule:
        IF rule matches the line:
            Create a finding with:
                - Rule ID
                - Category
                - Priority
                - File name
                - Line number
                - Matched content
                - Attacker value description
            Add finding to findings list

---

## 5. Post-Processing

- Sort findings by priority (P0 → P3)
- Remove exact duplicate findings (optional)

---

## 6. Output

FOR each finding in sorted findings:
    Print:
        [PRIORITY][CATEGORY] file:line
        matched content
        attacker value explanation

---

## 7. Termination

- Exit after all files are scanned
- Return exit code 0

---

## 8. Design Notes

- Scanner is read-only
- Scanner does not modify files
- Scanner does not execute code
- Scanner favors clarity over completeness
- False negatives are acceptable
