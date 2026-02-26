# Claude Code — Security Remediation Instructions

This file configures Claude Code's behavior when performing automated security
remediation in this repository. Claude Code reads this file at the start of
every session.

---

## Project Overview

This repository contains two intentionally vulnerable demo applications:

- **`python-app/`** — Flask application (`app.py`, `db.py`) with OWASP Top 10 vulnerabilities
- **`node-app/`** — Express.js application (`app.js`, `auth.js`) with common Node.js security issues

Semgrep is used to scan for vulnerabilities and Claude Code is responsible for
applying fixes and opening pull requests.

---

## Remediation Rules

When fixing security findings, always follow these rules strictly.

### SQL Injection (CWE-89)

**Python:** Replace all string interpolation/concatenation in SQL queries with
parameterized queries using `?` placeholders.

```python
# BEFORE (vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# AFTER (fixed)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Node.js (sqlite3):** Use `?` placeholders with the callback-style API.

```javascript
// BEFORE (vulnerable)
db.get(`SELECT * FROM users WHERE id = ${req.params.id}`, callback);

// AFTER (fixed)
db.get("SELECT * FROM users WHERE id = ?", [req.params.id], callback);
```

---

### Hardcoded Secrets (CWE-798)

Replace all hardcoded credentials with environment variable lookups. Add a
comment documenting the required environment variable name.

```python
# BEFORE (vulnerable)
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# AFTER (fixed)
# Required env var: AWS_SECRET_KEY
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")
```

```javascript
// BEFORE (vulnerable)
const JWT_SECRET = "hardcoded_jwt_secret_do_not_use";

// AFTER (fixed)
// Required env var: JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET;
```

Also create or update a `.env.example` file listing all required variables
(with placeholder values, never real secrets).

---

### Command Injection (CWE-78)

**Python:** Replace `shell=True` with `shell=False` and a list of arguments.
Validate and allowlist the input before use.

```python
# BEFORE (vulnerable)
result = subprocess.check_output(f"ping -c 1 {host}", shell=True)

# AFTER (fixed)
import re
if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
    raise ValueError("Invalid host")
result = subprocess.check_output(["ping", "-c", "1", host], shell=False)
```

**Node.js:** Replace `exec()` with `execFile()` using a hardcoded command path.

```javascript
// BEFORE (vulnerable)
exec(cmd, (error, stdout) => { ... });

// AFTER (fixed)
const { execFile } = require("child_process");
// Only allow specific whitelisted commands
const ALLOWED_COMMANDS = { ping: "/bin/ping" };
if (!ALLOWED_COMMANDS[commandName]) throw new Error("Command not allowed");
execFile(ALLOWED_COMMANDS[commandName], ["-c", "1", sanitizedHost], callback);
```

---

### Insecure Deserialization (CWE-502)

Replace `pickle.loads()` with JSON deserialization.

```python
# BEFORE (vulnerable)
obj = pickle.loads(data)

# AFTER (fixed)
import json
obj = json.loads(data)
```

---

### Weak Password Hashing (CWE-916)

Replace `md5` / `sha1` with `bcrypt` (Node.js) or `hashlib.scrypt` (Python).

```python
# BEFORE (vulnerable)
hashed = hashlib.md5(password.encode()).hexdigest()

# AFTER (fixed)
import hashlib, os
salt = os.urandom(16)
hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()
# Store salt alongside hash: f"{salt.hex()}:{hashed}"
```

```javascript
// BEFORE (vulnerable)
const hashed = crypto.createHash("md5").update(password).digest("hex");

// AFTER (fixed)
const bcrypt = require("bcrypt");
const hashed = await bcrypt.hash(password, 12);
```

---

### Unsafe YAML Loading (CWE-502)

```python
# BEFORE (vulnerable)
return yaml.load(f.read())

# AFTER (fixed)
return yaml.safe_load(f.read())
```

---

### eval() Usage (CWE-94)

Remove `eval()` entirely. Implement the required logic explicitly.

```javascript
// BEFORE (vulnerable)
const result = eval(expression);

// AFTER (fixed)
// Use a safe math expression parser instead of eval
const { create, all } = require("mathjs");
const math = create(all);
const result = math.evaluate(expression);
// Or for simple arithmetic, implement a parser manually
```

---

### JWT Algorithm Confusion (CWE-347)

```javascript
// BEFORE (vulnerable)
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });

// AFTER (fixed)
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
```

---

### Prototype Pollution (CWE-1321)

```javascript
// BEFORE (vulnerable)
for (let key in source) {
    target[key] = source[key];
}

// AFTER (fixed)
for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    if (Object.hasOwn(source, key)) {
        target[key] = source[key];
    }
}
```

---

### Flask Debug Mode (CWE-489)

```python
# BEFORE (vulnerable)
app.run(debug=True, host="0.0.0.0")

# AFTER (fixed)
debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.run(debug=debug_mode, host="0.0.0.0")
```

---

### XSS — Template Injection (CWE-79)

**Python/Flask:** Use `escape()` from `markupsafe` before rendering user input.

```python
# BEFORE (vulnerable)
template = f"<h1>Search results for: {query}</h1>"
return render_template_string(template)

# AFTER (fixed)
from markupsafe import escape
return f"<h1>Search results for: {escape(query)}</h1>"
```

**Node.js:** Use a templating engine with auto-escaping or sanitize manually.

```javascript
// BEFORE (vulnerable)
const html = `<h1>Results for: ${query}</h1>`;
res.send(html);

// AFTER (fixed)
const escapeHtml = (str) => str
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&#039;");
const html = `<h1>Results for: ${escapeHtml(query)}</h1>`;
res.send(html);
```

---

## Workflow

When remediating findings from Semgrep output:

1. Read each affected file completely before making any changes
2. Apply all fixes for a file in a single edit pass
3. Preserve all existing functionality — do not refactor unrelated code
4. Add a one-line comment above each fix: `# Security fix: <brief description>`
5. After fixing all files, run a quick syntax check if possible
6. Output a concise summary: number of files changed, findings fixed, findings remaining

---

## Out of Scope

Do NOT make the following changes without explicit instruction:

- Refactoring or restructuring existing code beyond what is needed for the fix
- Adding new features or business logic
- Changing test files
- Modifying `.github/workflows/` files
- Deleting files
