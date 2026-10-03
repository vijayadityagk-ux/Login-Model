# VaultKey — Secure Login & Authentication System

VaultKey is a production-grade, hardened authentication and authorization system built with **FastAPI**, **SQLite**, **bcrypt**, and **RFC 6238 TOTP Two-Factor Authentication**. It was engineered to fulfill and exceed modern security standards (OWASP Top 10 & NIST SP 800-63B).

---

## 🔒 Key Security Features

1. **Password Hashing (bcrypt)**:
   - Uses adaptive work factor (cost = 12 rounds) with unique 128-bit cryptographic salts.
   - Constant-time password verification via `bcrypt.checkpw` immune to timing analysis.
2. **SQL Injection Defense (100% Parameterized Queries)**:
   - All database reads and writes use SQLite parameterized placeholders (`?`).
   - Inputs are treated strictly as literal data values; SQL grammar modification is impossible.
   - Includes an interactive **SQL Injection Defense Lab** demonstrating side-by-side comparison between raw concatenation and parameterized queries.
3. **Session Management (HTTP-only Cookies & Revocation)**:
   - 256-bit entropy CSPRNG session identifiers (`secrets.token_urlsafe(32)`).
   - Stored in server-side SQLite with timestamp expiration.
   - Transmitted via `HttpOnly`, `SameSite=Lax` cookies, preventing XSS token theft and CSRF.
   - Explicit logout endpoint terminates active session in database and invalidates the browser cookie.
4. **Two-Factor Authentication (2FA / TOTP)**:
   - RFC 6238 compliant Time-Based One-Time Password algorithm.
   - Compatible with Google Authenticator, Microsoft Authenticator, and 1Password.
   - Generates emergency single-use backup recovery codes.
5. **Input Validation & Sanitization**:
   - RFC 5322 regex email validation.
   - Strict password complexity policy (minimum 8 characters, uppercase, lowercase, digit, special character).
   - Real-time password strength meter on registration UI.
   - Username sanitization against Cross-Site Scripting (XSS).

---

## 📁 Project Architecture

```
New folder (3)/
├── app.py                 # FastAPI server & route handlers
├── auth.py                # Cryptographic core (bcrypt, secrets, pyotp)
├── database.py            # SQLite database schema & parameterized CRUD
├── validators.py          # Input validation (email, password strength, username)
├── test_security.py       # Automated unit & integration verification test suite
├── requirements.txt       # Dependencies
├── SECURITY_AUDIT.md      # Comprehensive OWASP & threat modeling report
├── README.md              # Project documentation & setup instructions
├── static/
│   └── index.html         # Glassmorphic SPA UI with Auth & SQLi Lab
└── secure_app.db          # SQLite database (auto-created on first launch)
```

---

## 🚀 Quickstart & Setup

### 1. Requirements
- Python 3.10+ (tested on Python 3.14 on Windows)
- Required packages:
  ```bash
  py -m pip install fastapi uvicorn bcrypt pyotp pydantic
  ```

### 2. Run Automated Verification Tests
Run the comprehensive 13-test security and integration test suite:
```bash
py test_security.py
```
Output:
```
Ran 13 tests in 6.200s
OK
[PASS] ALL SECURITY AND INTEGRATION TESTS PASSED (100%)
```

### 3. Launch the Web Application
Start the VaultKey server:
```bash
py app.py
```
Or with Uvicorn:
```bash
py -m uvicorn app:app --host 127.0.0.1 --port 8000
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 🧪 Interactive Walkthrough

### 1. Register a Secure Account
- Navigate to the **Sign Up** tab.
- Try entering a weak password (e.g. `123456` or `password`) to observe real-time feedback and server-side rejection.
- Enter a strong password (e.g. `VaultKey#2026!`).
- Click **Create Account**.

### 2. Sign In & Session Cookies
- Sign in with your registered credentials.
- Notice the secure `vaultkey_session` cookie set in the browser DevTools (`HttpOnly`, `SameSite=Lax`).
- The protected **Dashboard** displays your session telemetry, account ID, and 2FA status.

### 3. Enable Two-Factor Authentication (2FA)
- On the Dashboard, click **Enable 2FA**.
- A unique Base32 TOTP secret is displayed along with setup instructions.
- Add the secret key to your authenticator app (Google Authenticator, Microsoft Authenticator) or test using a Python one-liner:
  ```python
  import pyotp
  totp = pyotp.TOTP("<YOUR_SECRET>")
  print(totp.now())
  ```
- Enter the 6-digit code and click **Verify & Enable**.
- 2FA is now active, and emergency backup codes are generated.

### 4. Test 2FA Step-up Verification
- Click **Sign Out**. Your database session is instantly destroyed.
- Attempt to sign in again with your email and password.
- The system automatically challenges you with the **6-digit TOTP code** field.
- Incorrect codes are rejected (HTTP 401); entering the active code authenticates you successfully!

### 5. Interactive SQL Injection Defense Lab
- Switch to the **SQLi Defense Lab** tab in the navigation bar.
- Test standard injection payloads:
  - `' OR '1'='1`
  - `admin'--`
  - `' UNION SELECT null, username, password_hash FROM users--`
- Review the live comparison showing how vulnerable queries break vs. how VaultKey's parameterized query neutralizes the attack.

---

## 🛡️ API Endpoints Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/register` | Register new user account | No |
| `POST` | `/api/login` | Authenticate credentials & TOTP | No |
| `POST` | `/api/logout` | Revoke session & clear cookie | Yes (Cookie) |
| `GET` | `/api/me` | Fetch active user profile | Yes (Cookie) |
| `POST` | `/api/2fa/setup` | Generate TOTP secret & QR URI | Yes (Cookie) |
| `POST` | `/api/2fa/verify-enable`| Verify code & activate 2FA | Yes (Cookie) |
| `POST` | `/api/2fa/disable` | Disable 2FA on account | Yes (Cookie) |
| `POST` | `/api/sqli-test` | Test SQL injection defense | No |
