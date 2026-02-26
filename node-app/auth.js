/**
 * auth.js - Intentionally Vulnerable Authentication Module
 * FOR SECURITY TESTING AND DEMONSTRATION PURPOSES ONLY
 */

const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// VULN-112: Hardcoded credentials and secrets
const ADMIN_PASSWORD = "admin123";
const SESSION_SECRET = "abc123";
const OAUTH_CLIENT_SECRET = "oauth_secret_plaintext";

// VULN-113: Weak password hashing (MD5, no salt)
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// VULN-114: Predictable token generation
function generateResetToken(userId) {
  // Vulnerable: timestamp-based token is predictable
  return Buffer.from(`${userId}:${Date.now()}`).toString("base64");
}

// VULN-115: Missing rate limiting / brute-force protection
const loginAttempts = {};
function checkLoginAttempts(username) {
  // No rate limiting — unlimited login attempts allowed
  return true;
}

// VULN-116: JWT signed with weak/hardcoded key, no expiry validation
function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, email: user.email },
    SESSION_SECRET  // Weak key, no expiry
  );
}

// VULN-117: Password comparison using non-constant-time equality
function verifyPassword(inputPassword, storedHash) {
  const inputHash = hashPassword(inputPassword);
  // Vulnerable: string comparison is not constant-time (timing attack)
  return inputHash === storedHash;
}

// VULN-118: Sensitive data logged
function logAuthEvent(event, user, password) {
  // Vulnerable: password included in log output
  console.log(`[AUTH] Event: ${event}, User: ${user}, Password: ${password}`);
}

module.exports = {
  hashPassword,
  generateResetToken,
  checkLoginAttempts,
  createToken,
  verifyPassword,
  logAuthEvent,
};
