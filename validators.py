"""
=============================================================================
INPUT VALIDATION & SANITIZATION ENGINE
=============================================================================
Provides rigorous validation for:
1. Email syntax and domain sanity (RFC 5322 regex).
2. Strong password policy enforcement (NIST & OWASP guidelines).
3. Username format and XSS tag neutralization.
=============================================================================
"""

import re
import html

# RFC 5322 compliant email regex
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

# Username regex: 3-30 characters, alphanumeric, underscores, hyphens
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")

def validate_email(email: str) -> tuple[bool, str]:
    if not email or not isinstance(email, str):
        return False, "Email address is required."
    clean_email = email.strip()
    if len(clean_email) > 254:
        return False, "Email address is too long (maximum 254 characters)."
    if not EMAIL_REGEX.match(clean_email):
        return False, "Invalid email address format."
    return True, clean_email.lower()

def validate_username(username: str) -> tuple[bool, str]:
    if not username or not isinstance(username, str):
        return False, "Username is required."
    clean_user = username.strip()
    if not USERNAME_REGEX.match(clean_user):
        return False, "Username must be 3-30 characters long and contain only letters, numbers, hyphens, or underscores."
    # Sanitize against any stray HTML characters
    sanitized = html.escape(clean_user)
    return True, sanitized

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforces OWASP recommended password policy:
    - Minimum 8 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one number (0-9)
    - At least one special symbol (!@#$%^&*...)
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one numeric digit (0-9)."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\/`~]', password):
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, "Password meets strength criteria."
