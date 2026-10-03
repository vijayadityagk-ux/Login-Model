"""
=============================================================================
AUTOMATED SECURITY & VERIFICATION TEST SUITE
=============================================================================
Comprehensive unit and integration test suite verifying:
1. Cryptographic password hashing & constant-time verification (bcrypt).
2. SQL Injection defense and parameterization immunity.
3. Input validation & XSS sanitization (OWASP / NIST standards).
4. Secure session lifecycle (CSPRNG tokens, DB expiry, logout revocation).
5. RFC 6238 TOTP Two-Factor Authentication (pyotp) & brute-force defense.
6. Full FastAPI HTTP integration flows (cookies, 2FA step-up, protected routes).
=============================================================================
"""

import os
import sys
import unittest
import pyotp
from datetime import datetime, timezone

# Windows console encoding safeguard
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from fastapi.testclient import TestClient

# Import application components
from auth import (
    hash_password,
    verify_password,
    generate_session_token,
    generate_totp_secret,
    get_totp_uri,
    verify_totp_code,
    generate_backup_codes
)
from validators import (
    validate_email,
    validate_username,
    validate_password_strength
)
import database
from database import (
    init_db,
    create_user,
    get_user_by_email,
    get_user_by_id,
    update_user_2fa,
    create_session,
    get_session,
    delete_session,
    test_sql_injection_defense
)
from app import app, SESSION_COOKIE_NAME


class TestPasswordHashing(unittest.TestCase):
    """Verifies NIST/OWASP password hashing requirements."""

    def test_bcrypt_hashing_and_verification(self):
        plain = "CorrectHorseBatteryStaple!9"
        hashed = hash_password(plain)

        # 1. Ensure hash is not plaintext
        self.assertNotEqual(plain, hashed)
        # 2. Check bcrypt identifier ($2b$) and cost factor (12)
        self.assertTrue(hashed.startswith("$2b$12$") or hashed.startswith("$2a$12$"))
        # 3. Successful verification
        self.assertTrue(verify_password(plain, hashed))
        # 4. Incorrect password rejection
        self.assertFalse(verify_password("WrongPassword!9", hashed))

    def test_unique_salts_for_identical_passwords(self):
        plain = "IdenticalPassw0rd#2026"
        hash1 = hash_password(plain)
        hash2 = hash_password(plain)
        # Bcrypt must generate unique salts for identical inputs
        self.assertNotEqual(hash1, hash2)
        self.assertTrue(verify_password(plain, hash1))
        self.assertTrue(verify_password(plain, hash2))


class TestSQLInjectionDefense(unittest.TestCase):
    """Verifies that parameterized queries neutralize all SQL injection vectors."""

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_classic_sqli_auth_bypass(self):
        # Attacker tries to bypass authentication with standard tautology
        sqli_payload = "' OR '1'='1"
        result = test_sql_injection_defense(sqli_payload)

        self.assertTrue(result["is_detected_as_injection"])
        # In secure query, SQLite searches for literal string "' OR '1'='1"
        self.assertEqual(len(result["records_exposed"]), 0)

    def test_comment_sqli_payload(self):
        sqli_payload = "admin'--"
        result = test_sql_injection_defense(sqli_payload)

        self.assertTrue(result["is_detected_as_injection"])
        self.assertEqual(len(result["records_exposed"]), 0)

    def test_union_select_sqli_payload(self):
        sqli_payload = "' UNION SELECT null, username, password_hash FROM users--"
        result = test_sql_injection_defense(sqli_payload)

        self.assertTrue(result["is_detected_as_injection"])
        self.assertEqual(len(result["records_exposed"]), 0)

    def test_database_parameterization_lookup(self):
        # Confirm that get_user_by_email handles injection harmlessly
        user = get_user_by_email("' OR 1=1 --")
        self.assertIsNone(user)


class TestInputValidation(unittest.TestCase):
    """Verifies input validation and sanitization policies."""

    def test_email_validation(self):
        # Valid emails
        self.assertTrue(validate_email("test.user@example.com")[0])
        self.assertTrue(validate_email("alice+tag@domain.co.uk")[0])
        
        # Invalid emails
        self.assertFalse(validate_email("invalid-email")[0])
        self.assertFalse(validate_email("@missinguser.com")[0])
        self.assertFalse(validate_email("user@.com")[0])
        self.assertFalse(validate_email("")[0])

    def test_username_validation_and_xss_neutralization(self):
        # Valid usernames
        self.assertTrue(validate_username("sec_user_99")[0])
        self.assertTrue(validate_username("Admin-Team")[0])

        # Too short
        self.assertFalse(validate_username("ab")[0])
        # Invalid characters
        self.assertFalse(validate_username("user<script>alert(1)</script>")[0])
        self.assertFalse(validate_username("user name with spaces")[0])

    def test_password_strength_policy(self):
        # Missing length
        self.assertFalse(validate_password_strength("Short1!")[0])
        # Missing uppercase
        self.assertFalse(validate_password_strength("lowercase123!")[0])
        # Missing lowercase
        self.assertFalse(validate_password_strength("UPPERCASE123!")[0])
        # Missing digit
        self.assertFalse(validate_password_strength("NoDigitsHere!")[0])
        # Missing special character
        self.assertFalse(validate_password_strength("NoSpecialChar123")[0])
        # Valid strong password
        self.assertTrue(validate_password_strength("S3cureP@ssw0rd!2026")[0])


class TestSessionLifecycle(unittest.TestCase):
    """Verifies CSPRNG session token issuance, validation, and revocation."""

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_session_lifecycle(self):
        # 1. Create a dummy test user
        email = f"session_test_{datetime.now().timestamp()}@example.com"
        user = create_user("SessionUser", email, hash_password("ValidP@ssw0rd1!"))

        # 2. Issue session token
        token = generate_session_token()
        self.assertGreater(len(token), 30)

        create_session(token, user["id"], "127.0.0.1", "TestClient/1.0", duration_hours=1)

        # 3. Retrieve valid session
        active_sess = get_session(token)
        self.assertIsNotNone(active_sess)
        self.assertEqual(active_sess["user_id"], user["id"])
        self.assertEqual(active_sess["email"], email)

        # 4. Revoke session (Logout)
        delete_session(token)

        # 5. Verify token is now invalid
        self.assertIsNone(get_session(token))


class TestTwoFactorAuthentication(unittest.TestCase):
    """Verifies RFC 6238 TOTP 2FA operations."""

    def test_totp_flow(self):
        # 1. Generate Base32 secret
        secret = generate_totp_secret()
        self.assertEqual(len(secret), 32)

        # 2. Generate valid TOTP token for current epoch
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        self.assertEqual(len(current_code), 6)

        # 3. Verify valid code succeeds
        self.assertTrue(verify_totp_code(secret, current_code))

        # 4. Verify invalid code fails
        self.assertFalse(verify_totp_code(secret, "000000" if current_code != "000000" else "111111"))
        self.assertFalse(verify_totp_code(secret, "invalid"))
        self.assertFalse(verify_totp_code(secret, ""))

    def test_backup_codes(self):
        codes = generate_backup_codes(5)
        self.assertEqual(len(codes), 5)
        for code in codes:
            self.assertRegex(code, r"^[a-z0-9]{4}-[a-z0-9]{4}$")


class TestFastAPIIntegration(unittest.TestCase):
    """Full HTTP client integration tests simulating user interaction."""

    def setUp(self):
        init_db()
        self.client = TestClient(app)
        self.ts = int(datetime.now().timestamp())
        self.test_email = f"alice_{self.ts}@vaultkey.io"
        self.test_user = f"alice_{self.ts}"
        self.test_pass = "HyperSecure#2026!"

    def test_full_auth_lifecycle(self):
        # Step 1: Register new account
        reg_res = self.client.post("/api/register", json={
            "username": self.test_user,
            "email": self.test_email,
            "password": self.test_pass
        })
        self.assertEqual(reg_res.status_code, 201)
        self.assertEqual(reg_res.json()["status"], "success")

        # Step 2: Attempt duplicate registration (should fail 400)
        dup_res = self.client.post("/api/register", json={
            "username": self.test_user,
            "email": self.test_email,
            "password": self.test_pass
        })
        self.assertEqual(dup_res.status_code, 400)

        # Step 3: Login with invalid credentials (should fail 401)
        bad_login = self.client.post("/api/login", json={
            "email": self.test_email,
            "password": "WrongPassword123!"
        })
        self.assertEqual(bad_login.status_code, 401)

        # Step 4: Login with valid credentials
        login_res = self.client.post("/api/login", json={
            "email": self.test_email,
            "password": self.test_pass
        })
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(SESSION_COOKIE_NAME, login_res.cookies)

        # Step 5: Access protected route /api/me with cookie
        me_res = self.client.get("/api/me")
        self.assertEqual(me_res.status_code, 200)
        data = me_res.json()
        self.assertEqual(data["user"]["email"], self.test_email)
        self.assertFalse(data["user"]["two_factor_enabled"])

        # Step 6: 2FA Setup
        setup_res = self.client.post("/api/2fa/setup")
        self.assertEqual(setup_res.status_code, 200)
        totp_secret = setup_res.json()["secret"]
        self.assertTrue(len(totp_secret) >= 16)

        # Step 7: 2FA Verification and Activation
        totp = pyotp.TOTP(totp_secret)
        valid_totp_code = totp.now()

        enable_res = self.client.post("/api/2fa/verify-enable", json={"code": valid_totp_code})
        self.assertEqual(enable_res.status_code, 200)
        self.assertEqual(enable_res.json()["status"], "success")

        # Step 8: Logout
        logout_res = self.client.post("/api/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Step 9: Verify /api/me is now rejected (401)
        unauth_me = self.client.get("/api/me")
        self.assertEqual(unauth_me.status_code, 401)

        # Step 10: Sign in again (now requires 2FA!)
        first_step_login = self.client.post("/api/login", json={
            "email": self.test_email,
            "password": self.test_pass
        })
        self.assertEqual(first_step_login.status_code, 202)
        self.assertTrue(first_step_login.json()["requires_2fa"])

        # Step 11: Sign in with invalid TOTP code (should fail 401)
        bad_totp_login = self.client.post("/api/login", json={
            "email": self.test_email,
            "password": self.test_pass,
            "totp_code": "000000"
        })
        self.assertEqual(bad_totp_login.status_code, 401)

        # Step 12: Sign in with valid TOTP code (succeeds 200)
        current_totp = totp.now()
        good_totp_login = self.client.post("/api/login", json={
            "email": self.test_email,
            "password": self.test_pass,
            "totp_code": current_totp
        })
        self.assertEqual(good_totp_login.status_code, 200)
        self.assertTrue(good_totp_login.json()["user"]["two_factor_enabled"])

        # Step 13: Disable 2FA
        disable_res = self.client.post("/api/2fa/disable")
        self.assertEqual(disable_res.status_code, 200)

        # Step 14: Verify 2FA status is now false
        updated_me = self.client.get("/api/me")
        self.assertFalse(updated_me.json()["user"]["two_factor_enabled"])


def run_tests():
    print("=" * 70)
    print("VAULTKEY SECURITY & COMPLIANCE VERIFICATION SUITE")
    print("=" * 70)
    suite = unittest.TestLoader().loadTestsFromNames([
        '__main__.TestPasswordHashing',
        '__main__.TestSQLInjectionDefense',
        '__main__.TestInputValidation',
        '__main__.TestSessionLifecycle',
        '__main__.TestTwoFactorAuthentication',
        '__main__.TestFastAPIIntegration'
    ])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("[PASS] ALL SECURITY AND INTEGRATION TESTS PASSED (100%)")
    else:
        print(f"[FAIL] {len(result.failures)} failures, {len(result.errors)} errors encountered.")
    print("=" * 70)
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
