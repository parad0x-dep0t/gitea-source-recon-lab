# Rule Engine Design

This document defines how detection rules are structured, executed,
and prioritized in the Gitea source reconnaissance tool.

The rule engine is intentionally simple, transparent, and attacker-focused.

---

## 1. Rule Engine Philosophy

The rule engine is designed to:
- Be easy to extend
- Prefer false negatives over false positives
- Surface attacker-useful findings only
- Support attack-chain reasoning later

This is **not** a full SAST engine.
It is a targeted exploitation assistant.

---

## 2. Core Rule Engine Flow

The rule engine operates in the following stages:

1. File ingestion
2. Rule matching
3. Finding creation
4. Prioritization
5. Correlation (future phase)

High-level flow:
Source File
↓
Applicable Rules
↓
Rule Match?
↓
Finding Object
↓
Prioritized Output


---

## 3. Rule Granularity

Each rule:
- Targets **one specific weakness**
- Produces **one type of finding**
- Belongs to **one detection category**

Rules should be:
- Small
- Focused
- Easy to reason about

---

## 4. Rule Types

The engine supports multiple rule types.

### 4.1 Regex Rules (Phase 1)

Used for:
- Secrets
- Paths
- Endpoints
- Simple dangerous patterns

Pros:
- Fast
- Language-agnostic
- Easy to maintain

Cons:
- Limited context

---

### 4.2 AST Rules (Phase 2+)

Used for:
- Python
- JavaScript
- PHP

Pros:
- Better accuracy
- Context awareness

Cons:
- Language-specific
- Higher complexity

---

### 4.3 Metadata Rules

Used for:
- File names
- File extensions
- Dependency files

Examples:
- `.env`
- `package.json`
- `requirements.txt`

---

## 5. Rule Format (Canonical)

All rules should follow a **single consistent structure**.

### Canonical Rule Schema

```yaml
id: SECRET_HARDCODED_PASSWORD
name: Hardcoded Password
category: secrets
priority: P0
confidence: high

applies_to:
  - python
  - javascript
  - php
  - text

match:
  type: regex
  pattern: '(password|passwd|pwd)\s*=\s*["''][^"'']+["'']'

context:
  description: Hardcoded password found in source code
  attacker_value: Direct authentication or privilege escalation

output:
  message: Hardcoded password detected
  recommendation: Attempt credential reuse across services
```
---
> Note: This document defines the planned rule engine design.
> No detection rules are implemented at this stage.

