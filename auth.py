"""
=============================================================================
CRYPTOGRAPHIC SECURITY & AUTHENTICATION ENGINE
=============================================================================
Provides:
1. Password hashing with bcrypt (12 rounds of salt).
2. Constant-time password verification against timing attacks.
3. Cryptographically strong random session token generation (secrets module).
4. RFC 6238 TOTP Two-Factor Authentication (2FA) via pyotp.
=============================================================================
"""

import bcrypt
import pyotp
import secrets
import string

def hash_password(plain_password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with an adaptive salt (12 work factor rounds).
    Returns a UTF-8 string containing the algorithm, cost factor, salt, and hash.
    """
    password_bytes = plain_password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored bcrypt hash in constant time.
    Resistant to timing attacks.
    """
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False

def generate_session_token() -> str:
    """
    Generates a cryptographically secure, high-entropy 256-bit random session identifier.
    Uses Python's OS-level CSPRNG (os.urandom under the hood).
    """
    return secrets.token_urlsafe(32)

def generate_totp_secret() -> str:
    """
    Generates a random 160-bit Base32 secret key for RFC 6238 TOTP 2FA.
    """
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str, issuer_name: str = "SecureLoginSystem") -> str:
    """
    Generates standard otpauth:// URI that can be rendered as a QR code or loaded in
    Google Authenticator, Microsoft Authenticator, or 1Password.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer_name)

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifies a 6-digit TOTP code with a valid_window of 1 (±30s clock drift tolerance).
    """
    if not secret or not code:
        return False
    clean_code = str(code).strip().replace(" ", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(clean_code, valid_window=1)

def generate_backup_codes(count: int = 5) -> list[str]:
    """
    Generates single-use emergency backup recovery codes (e.g. 'a89c-4f12').
    """
    chars = string.ascii_lowercase + string.digits
    codes = []
    for _ in range(count):
        part1 = ''.join(secrets.choice(chars) for _ in range(4))
        part2 = ''.join(secrets.choice(chars) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes
