/**
 * VulnExpress - Intentionally Vulnerable Node.js Application
 * FOR SECURITY TESTING AND DEMONSTRATION PURPOSES ONLY
 */

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { exec } = require("child_process");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULN-101: Hardcoded secrets
const JWT_SECRET = "hardcoded_jwt_secret_do_not_use";
const API_KEY = "sk-prod-1234567890abcdef";
const DB_PASSWORD = "admin123";
const STRIPE_KEY = "sk_live_FAKEKEYFORDEMOPURPOSES";

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, email TEXT, role TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com', 'admin')");
  db.run("INSERT INTO users VALUES (2, 'alice', 'password', 'alice@example.com', 'user')");
  db.run("CREATE TABLE products (id INT, name TEXT, price REAL, description TEXT)");
  db.run("INSERT INTO products VALUES (1, 'Widget', 9.99, 'A nice widget')");
  db.run("INSERT INTO products VALUES (2, 'Gadget', 29.99, 'An expensive gadget')");
});

// VULN-102: SQL Injection via string concatenation
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(query, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (user) {
      const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "24h" });
      return res.json({ token });
    }
    res.status(401).json({ error: "Invalid credentials" });
  });
});

// VULN-103: Cross-Site Scripting (XSS) via direct HTML injection
app.get("/search", (req, res) => {
  const query = req.query.q || "";
  // Vulnerable: user input embedded directly into HTML without sanitization
  const html = `
    <html><body>
      <h1>Search results for: ${query}</h1>
      <p>You searched for <b>${query}</b></p>
    </body></html>
  `;
  res.send(html);
});

// VULN-104: Command Injection
app.get("/exec", (req, res) => {
  const cmd = req.query.cmd;
  // Vulnerable: unsanitized input passed to exec()
  exec(cmd, (error, stdout, stderr) => {
    res.json({ output: stdout, error: stderr });
  });
});

// VULN-105: eval() with user input
app.post("/calculate", (req, res) => {
  const { expression } = req.body;
  try {
    // Vulnerable: eval allows arbitrary code execution
    const result = eval(expression);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// VULN-106: Path Traversal
app.get("/download", (req, res) => {
  const filename = req.query.file;
  // Vulnerable: no path normalization or boundary check
  const filePath = `/var/app/uploads/${filename}`;
  res.sendFile(filePath);
});

// VULN-107: Insecure Direct Object Reference (IDOR)
app.get("/user/:id", (req, res) => {
  // Vulnerable: no authorization check — any user can access any user's data
  db.get(`SELECT * FROM users WHERE id = ${req.params.id}`, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    // Also returns password field
    res.json(user);
  });
});

// VULN-108: Weak JWT verification (algorithm confusion)
app.get("/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    // Vulnerable: accepts 'none' algorithm — allows signature bypass
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });
    db.get(`SELECT * FROM users WHERE id = ${decoded.id}`, (err, user) => {
      res.json(user);
    });
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// VULN-109: XML External Entity (XXE) via unsafe XML parsing
app.post("/import", (req, res) => {
  const xmlData = req.body.xml;
  // Vulnerable: using xml2js or similar without disabling entity expansion
  const { parseString } = require("xml2js");
  parseString(xmlData, { explicitArray: false }, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(result);
  });
});

// VULN-110: Prototype pollution
app.post("/merge", (req, res) => {
  const target = {};
  const source = req.body;
  // Vulnerable: deep merge without prototype chain checks
  function merge(target, source) {
    for (let key in source) {
      if (typeof source[key] === "object") {
        target[key] = merge(target[key] || {}, source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  const result = merge(target, source);
  res.json(result);
});

// VULN-111: SQL Injection in product search
app.get("/products", (req, res) => {
  const search = req.query.search || "";
  const sortBy = req.query.sort || "name";
  // Vulnerable: both search and sortBy are injectable
  const query = `SELECT * FROM products WHERE name LIKE '%${search}%' ORDER BY ${sortBy}`;
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`VulnExpress running on port ${PORT}`);
});

module.exports = app;
