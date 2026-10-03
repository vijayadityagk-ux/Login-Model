# Security Audit & Threat Modeling Report: VaultKey

**Application:** VaultKey Secure Authentication & 2FA Engine  
**Version:** 1.0.0  
**Audit Standard:** OWASP Top 10 (2021) & NIST Special Publication 800-63B  
**Target Environment:** Python 3.14 / FastAPI / SQLite (Parameterized)

---

## 1. Executive Summary

VaultKey was designed and implemented from the ground up according to strict **defense-in-depth** and **zero-trust** software security principles. All critical attack vectors identified in the project requirements—including password cracking, SQL injection, session hijacking, credential stuffing, and unauthorized access—have dedicated cryptographic and architectural safeguards.

---

## 2. OWASP Top 10 Security Controls & Implementations

| OWASP Risk Category | Vulnerability Mitigated | VaultKey Technical Implementation | Status |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | Session fixation, vertical privilege bypass, unauthorized endpoint access | Server-side session verification via `sessions` table in SQLite; `get_current_session` dependency validates token freshness on every protected route. | **MITIGATED** |
| **A02: Cryptographic Failures** | Weak password hashing, predictable tokens, timing attacks | `bcrypt` with adaptive salt (work factor: 12); OS-level CSPRNG (`secrets.token_urlsafe(32)`); constant-time byte comparisons (`bcrypt.checkpw`). | **MITIGATED** |
| **A03: Injection (SQLi)** | Tautology authentication bypass (`' OR '1'='1`), UNION data exfiltration | 100% Parameterized queries using SQLite `?` placeholders across all DB operations. Payload input is treated strictly as literal data, never executable syntax. | **MITIGATED** |
| **A05: Security Misconfiguration** | Cookie tampering, cross-site script access to tokens | HTTP-only, SameSite=Lax flags on session cookies (`vaultkey_session`); path restriction (`/`); token deletion on explicit logout. | **MITIGATED** |
| **A07: Identification & Auth Failures** | Credential stuffing, weak passwords, brute force | OWASP/NIST password complexity validation (min 8 chars, uppercase, lowercase, digit, special symbol); RFC 6238 TOTP Two-Factor Authentication with ±30s drift tolerance. | **MITIGATED** |
| **A09: Security Logging & Monitoring** | Undetected unauthorized access attempts | Centralized `audit_logs` table recording `REGISTER_SUCCESS`, `LOGIN_FAILED_BAD_PASSWORD`, `LOGIN_FAILED_BAD_TOTP`, `TOTP_ACTIVATED`, and IP address metadata. | **MITIGATED** |

---

## 3. Cryptographic Deep-Dive

### 3.1 Password Hashing (bcrypt)
- **Work Factor (Cost):** 12 rounds (\(2^{12} = 4,096\) iterations of the Eksblowfish key schedule).
- **Salt Generation:** Unique, cryptographically random 128-bit salt generated per password instance using `bcrypt.gensalt(12)`. Identical passwords produce distinct, non-correlatable hashes, preventing rainbow table attacks.
- **Timing Attack Resistance:** Constant-time hash verification via `bcrypt.checkpw()`, ensuring attackers cannot deduce partial matches by measuring response latency.

### 3.2 Session Management
- **Token Generation:** Generated via `secrets.token_urlsafe(32)` providing 256 bits of cryptographic entropy.
- **Storage:** Stored in the server-side SQLite `sessions` table with an explicit ISO-8601 `expires_at` timestamp.
- **Cookie Security Attributes:**
  - `HttpOnly = True`: Blocks JavaScript `document.cookie` reads, neutralizing token theft via Cross-Site Scripting (XSS).
  - `SameSite = "lax"`: Shields against Cross-Site Request Forgery (CSRF).
  - `Path = "/"`: Restricts cookie scope across the domain.
- **Logout Destruction:** Immediate row deletion in SQLite `sessions` table plus `response.delete_cookie()` browser-side invalidation.

### 3.3 Two-Factor Authentication (RFC 6238 TOTP)
- **Algorithm:** HMAC-based One-Time Password algorithm timed at 30-second steps using SHA-1 (RFC 6238).
- **Secret Key:** 160-bit Base32 secret generated via `pyotp.random_base32()`.
- **Clock Drift Tolerance:** Configured with `valid_window=1`, permitting a \(\pm 30\)-second window for client clock discrepancy while denying replay attempts.
- **Provisioning:** Compatible with all standard authenticator apps (Google Authenticator, Microsoft Authenticator, 1Password, Aegis).
- **Emergency Recovery:** Generates 5 high-entropy recovery backup codes in format `xxxx-xxxx`.

---

## 4. SQL Injection Neutralization Analysis

### Raw Concatenation (Vulnerable Anti-Pattern)
```python
# VULNERABLE: Direct string interpolation allows payload to break out of SQL syntax
cursor.execute(f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'")
```
If an attacker inputs `admin'--`, the query parses as:
```sql
SELECT * FROM users WHERE email = 'admin'--' AND password = '...'
```
The `--` truncates the query, bypassing the password check entirely.

### Parameterized Query (VaultKey Implementation)
```python
# SECURE: Database driver treats the parameter as a literal value
cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
```
When `admin'--` or `' OR '1'='1` is submitted:
- The database pre-compiles the SQL query structure first.
- The parameter is inserted strictly into the data slot.
- SQLite queries the table for a user whose literal email address is the string `' OR '1'='1`. Because no such literal email exists, 0 records are returned, completely neutralizing the attack.

---

## 5. Verification Test Suite Matrix

The automated test suite (`test_security.py`) validates every security boundary:

1. **`TestPasswordHashing`**:
   - Ensures hash starts with `$2b$12$` work factor.
   - Verifies identical passwords generate distinct salts.
   - Validates constant-time true/false resolution.
2. **`TestSQLInjectionDefense`**:
   - Tautology attack (`' OR '1'='1`): Verified 0 leaked records.
   - Comment termination attack (`admin'--`): Verified 0 leaked records.
   - UNION query extraction attack: Verified 0 leaked records.
3. **`TestInputValidation`**:
   - RFC 5322 email syntax validation.
   - NIST/OWASP password strength rules (length, uppercase, lowercase, number, special char).
   - Username character restrictions and XSS tag neutralization.
4. **`TestSessionLifecycle`**:
   - CSPRNG token generation and server-side retrieval.
   - Session termination upon logout.
5. **`TestTwoFactorAuthentication`**:
   - TOTP Base32 secret creation.
   - Active time-step verification and invalid code rejection.
6. **`TestFastAPIIntegration`**:
   - Full registration, login, 2FA challenge (202 Accepted), TOTP validation, protected route access (`/api/me`), and logout.
