# mock-vuln-app

> **FOR SECURITY TESTING AND DEMONSTRATION PURPOSES ONLY.**
> This repository contains intentionally vulnerable code. Do not deploy to production.

A mock multi-language application used to demonstrate automated security scanning
and AI-driven remediation using **Semgrep** + **Claude Code**.

---

## Repository Structure

```
mock-vuln-app/
├── CLAUDE.md                          # Claude Code remediation instructions
├── semgrep.yml                        # Custom Semgrep rules (OWASP Top 10)
├── .semgrep/.semgrepignore
├── .github/workflows/
│   ├── semgrep-scan.yml               # Automated Semgrep scanning
│   └── claude-remediate.yml           # Claude Code auto-remediation
├── python-app/
│   ├── app.py                         # Vulnerable Flask app (~10 findings)
│   ├── db.py                          # Vulnerable DB utilities (~6 findings)
│   └── requirements.txt
└── node-app/
    ├── app.js                         # Vulnerable Express app (~11 findings)
    ├── auth.js                        # Vulnerable auth module (~7 findings)
    └── package.json
```

---

## Vulnerability Coverage

| ID | Vulnerability | Severity | File(s) |
|----|--------------|----------|---------|
| VULN-001 | Hardcoded Flask secret key | ERROR | python-app/app.py |
| VULN-002 | Hardcoded AWS/DB credentials | ERROR | python-app/app.py |
| VULN-003 | SQL Injection (login) | ERROR | python-app/app.py |
| VULN-004 | Cross-Site Scripting (XSS) | ERROR | python-app/app.py |
| VULN-005 | Command Injection (shell=True) | ERROR | python-app/app.py |
| VULN-006 | Path Traversal | ERROR | python-app/app.py |
| VULN-007 | Insecure Deserialization (pickle) | ERROR | python-app/app.py |
| VULN-008 | Weak Cryptography (MD5 passwords) | WARNING | python-app/app.py |
| VULN-009 | SQL Injection (user endpoint) | ERROR | python-app/app.py |
| VULN-010 | Flask Debug Mode in production | WARNING | python-app/app.py |
| VULN-011 | Hardcoded DB connection strings | ERROR | python-app/db.py |
| VULN-012–016 | Multiple SQL Injections | ERROR | python-app/db.py |
| VULN-014 | Unsafe yaml.load() | ERROR | python-app/db.py |
| VULN-101 | Hardcoded JWT/API/Stripe secrets | ERROR | node-app/app.js |
| VULN-102 | SQL Injection (login) | ERROR | node-app/app.js |
| VULN-103 | XSS via template literal | ERROR | node-app/app.js |
| VULN-104 | Command Injection (exec) | ERROR | node-app/app.js |
| VULN-105 | Code Injection (eval) | ERROR | node-app/app.js |
| VULN-106 | Path Traversal | ERROR | node-app/app.js |
| VULN-107 | Insecure Direct Object Reference | WARNING | node-app/app.js |
| VULN-108 | JWT Algorithm Confusion (none) | ERROR | node-app/app.js |
| VULN-110 | Prototype Pollution | WARNING | node-app/app.js |
| VULN-111 | SQL Injection (product search) | ERROR | node-app/app.js |
| VULN-112 | Hardcoded credentials | ERROR | node-app/auth.js |
| VULN-113 | Weak password hashing (MD5) | WARNING | node-app/auth.js |
| VULN-114 | Predictable reset token | WARNING | node-app/auth.js |
| VULN-116 | JWT no expiry + weak key | ERROR | node-app/auth.js |
| VULN-117 | Timing attack (string comparison) | WARNING | node-app/auth.js |
| VULN-118 | Password logged in plaintext | ERROR | node-app/auth.js |

---

## Automated Workflows

### 1. Semgrep Scan (`semgrep-scan.yml`)

Triggers on: push to `main`/`develop`, pull requests, daily at 08:00 UTC, or manually.

- Runs custom rules (`semgrep.yml`) + OWASP Top 10 ruleset + secrets detection
- Uploads findings as GitHub Actions artifacts
- Automatically triggers the remediation workflow on push to `main`

### 2. Claude Code Remediation (`claude-remediate.yml`)

Triggers on: automatic trigger from scan workflow, or manual dispatch.

Inputs:
- `severity_filter`: Minimum severity to fix (`ERROR` / `WARNING` / `INFO`)
- `trigger_source`: Label for audit trail

Steps:
1. Runs a fresh Semgrep scan
2. Generates a remediation prompt from findings
3. Calls Claude Code CLI with allowed tools (`Read`, `Edit`, `Write`, `Bash`)
4. Verifies fixes with a post-fix re-scan
5. Commits changes to a `fix/claude-security-remediation-*` branch
6. Opens a pull request with a summary of fixes

---

## Setup Guide

### Prerequisites

- GitHub account with Actions enabled
- `ANTHROPIC_API_KEY` added as a repository secret

### Step 1: Create the repository

```bash
gh repo create mock-vuln-app --public --clone
cd mock-vuln-app
# Copy all files from this package into the directory
git add .
git commit -m "chore: initial commit — mock vulnerable app"
git push origin main
```

### Step 2: Add the Anthropic API key secret

```
GitHub repo → Settings → Secrets and variables → Actions → New repository secret
Name:  ANTHROPIC_API_KEY
Value: sk-ant-...
```

### Step 3: Run the scan manually

```
GitHub repo → Actions → Semgrep Security Scan → Run workflow
```

### Step 4: Run remediation manually

```
GitHub repo → Actions → Claude Code Security Remediation → Run workflow
```

### Step 5: Run locally with Claude Code CLI

```bash
# Install Claude Code
npm install -g @anthropic-ai/claude-code

# Run Semgrep locally
pip install semgrep
semgrep --config semgrep.yml --config "p/owasp-top-ten" --json --output findings.json .

# Run Claude Code interactively
claude

# Or non-interactively (pipe a prompt)
claude --print --allowedTools "Read,Edit,Write" \
  "Read findings.json and fix all SQL injection findings in python-app/app.py"
```

---

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key for Claude Code |

---

## License

MIT — for educational and security research purposes only.
