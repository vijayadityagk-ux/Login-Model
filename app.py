"""
=============================================================================
VAULTKEY - SECURE LOGIN & AUTHENTICATION SYSTEM
=============================================================================
FastAPI Application implementing:
1. Registration with NIST/OWASP password & email validation and bcrypt hashing.
2. Login with bcrypt verification, brute force defense, and TOTP 2FA step-up.
3. HTTP-only, SameSite session cookies with server-side validation.
4. Complete logout mechanism that terminates DB sessions and invalidates cookies.
5. RFC 6238 TOTP Two-Factor Authentication setup, activation, and deactivation.
6. SQL Injection defense test lab endpoint demonstrating parameterized queries.
=============================================================================
"""

import os
import sys
from contextlib import asynccontextmanager
from typing import Optional

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from auth import (
    hash_password,
    verify_password,
    generate_session_token,
    generate_totp_secret,
    get_totp_uri,
    verify_totp_code,
    generate_backup_codes
)
from database import (
    init_db,
    create_user,
    get_user_by_email,
    get_user_by_id,
    update_user_2fa,
    update_last_login,
    create_session,
    get_session,
    delete_session,
    log_audit_event,
    test_sql_injection_defense
)
from validators import (
    validate_email,
    validate_username,
    validate_password_strength
)

SESSION_COOKIE_NAME = "vaultkey_session"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database schema
    init_db()
    print("[INIT] SQLite database schema verified and initialized.")
    yield

app = FastAPI(
    title="VaultKey Secure Authentication System",
    description="Enterprise-grade authentication with bcrypt, TOTP 2FA, session cookies, and SQLi protection",
    version="1.0.0",
    lifespan=lifespan
)

# Serve static assets if any exist
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ==============================================================================
# REQUEST & RESPONSE SCHEMAS
# ==============================================================================

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: str
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: Optional[str] = None

class TotpVerifyRequest(BaseModel):
    code: str

class SqliTestRequest(BaseModel):
    payload: str

# ==============================================================================
# AUTH HELPER DEPENDENCY
# ==============================================================================

def get_current_session(request: Request) -> dict:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: No active session cookie found."
        )
    session = get_session(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please sign in again."
        )
    return session

# ==============================================================================
# WEB UI ROOT
# ==============================================================================

@app.get("/")
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "VaultKey API is running. static/index.html not found."}

# ==============================================================================
# AUTHENTICATION API ENDPOINTS
# ==============================================================================

@app.post("/api/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, request: Request):
    ip_addr = request.client.host if request.client else "127.0.0.1"

    # 1. Validate Username
    valid_u, u_result = validate_username(req.username)
    if not valid_u:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=u_result)

    # 2. Validate Email
    valid_e, e_result = validate_email(req.email)
    if not valid_e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_result)

    # 3. Validate Password Strength
    valid_p, p_result = validate_password_strength(req.password)
    if not valid_p:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=p_result)

    # 4. Check for duplicate account
    existing_user = get_user_by_email(e_result)
    if existing_user:
        log_audit_event("REGISTER_DUPLICATE_ATTEMPT", ip_address=ip_addr, details=f"Email: {e_result}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address is already registered."
        )

    # 5. Hash password with bcrypt (12 rounds)
    hashed_pw = hash_password(req.password)

    # 6. Store user via Parameterized Query
    try:
        user_record = create_user(u_result, e_result, hashed_pw)
        log_audit_event("REGISTER_SUCCESS", user_id=user_record["id"], ip_address=ip_addr, details=f"User: {u_result}")
        return {
            "status": "success",
            "message": "Account registered successfully!",
            "user": user_record
        }
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email is already taken.")


@app.post("/api/login")
async def login(req: LoginRequest, request: Request, response: Response):
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    # 1. Email format check
    valid_e, clean_email = validate_email(req.email)
    if not valid_e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format.")

    # 2. User lookup (Parameterized)
    user = get_user_by_email(clean_email)
    if not user:
        log_audit_event("LOGIN_FAILED_UNKNOWN_EMAIL", ip_address=ip_addr, details=f"Email: {clean_email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # 3. Constant-time password verification
    if not verify_password(req.password, user["password_hash"]):
        log_audit_event("LOGIN_FAILED_BAD_PASSWORD", user_id=user["id"], ip_address=ip_addr)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # 4. Check Two-Factor Authentication requirement
    if user["two_factor_enabled"]:
        # If code not supplied yet, challenge user with 202 Accepted
        if not req.totp_code:
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "status": "requires_2fa",
                    "requires_2fa": True,
                    "message": "Two-factor authentication is active. Please enter your 6-digit TOTP code."
                }
            )

        # Code supplied -> verify TOTP
        if not verify_totp_code(user["two_factor_secret"], req.totp_code):
            log_audit_event("LOGIN_FAILED_BAD_TOTP", user_id=user["id"], ip_address=ip_addr)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired two-factor authentication code."
            )

    # 5. Successful login: update DB metadata
    update_last_login(user["id"])

    # 6. Issue high-entropy CSPRNG session token
    session_token = generate_session_token()
    create_session(
        session_id=session_token,
        user_id=user["id"],
        ip_address=ip_addr,
        user_agent=user_agent,
        duration_hours=24
    )

    # 7. Set HTTP-only, secure, SameSite session cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in production HTTPS environments
        max_age=86400,
        path="/"
    )

    log_audit_event("LOGIN_SUCCESS", user_id=user["id"], ip_address=ip_addr)

    return {
        "status": "success",
        "message": "Authenticated successfully.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "two_factor_enabled": bool(user["two_factor_enabled"]),
            "created_at": user["created_at"]
        }
    }


@app.post("/api/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        delete_session(token)
    
    # Invalidate cookie in client browser
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "success", "message": "Session terminated and cookie cleared."}


@app.get("/api/me")
async def get_current_user(request: Request):
    session = get_current_session(request)
    return {
        "status": "success",
        "user": {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email"],
            "two_factor_enabled": bool(session["two_factor_enabled"]),
            "created_at": session.get("user_created_at") or session.get("created_at")
        }
    }

# ==============================================================================
# TWO-FACTOR AUTHENTICATION (TOTP) WORKFLOW
# ==============================================================================

@app.post("/api/2fa/setup")
async def setup_2fa(request: Request):
    session = get_current_session(request)
    user_id = session["user_id"]
    email = session["email"]

    # Generate new RFC 6238 Base32 Secret
    totp_secret = generate_totp_secret()
    provisioning_uri = get_totp_uri(totp_secret, email, issuer_name="VaultKey")

    # Temporarily store secret in user row (pending verification)
    update_user_2fa(user_id=user_id, enabled=False, secret=totp_secret)
    log_audit_event("TOTP_SETUP_INITIATED", user_id=user_id)

    return {
        "status": "success",
        "secret": totp_secret,
        "otpauth_url": provisioning_uri
    }


@app.post("/api/2fa/verify-enable")
async def verify_enable_2fa(req: TotpVerifyRequest, request: Request):
    session = get_current_session(request)
    user_id = session["user_id"]
    user = get_user_by_id(user_id)

    if not user or not user.get("two_factor_secret"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA setup found. Please initiate 2FA setup first."
        )

    # Verify the code against the secret key
    is_valid = verify_totp_code(user["two_factor_secret"], req.code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit code. Ensure your device time is synchronized and try again."
        )

    # Generate single-use recovery backup codes
    backup_codes = generate_backup_codes(5)

    # Persist enabled 2FA state
    update_user_2fa(user_id=user_id, enabled=True, secret=user["two_factor_secret"], backup_codes=backup_codes)
    log_audit_event("TOTP_ACTIVATED", user_id=user_id)

    return {
        "status": "success",
        "message": "Two-Factor Authentication has been successfully activated!",
        "backup_codes": backup_codes
    }


@app.post("/api/2fa/disable")
async def disable_2fa(request: Request):
    session = get_current_session(request)
    user_id = session["user_id"]

    # Clear 2FA credentials
    update_user_2fa(user_id=user_id, enabled=False, secret=None, backup_codes=None)
    log_audit_event("TOTP_DISABLED", user_id=user_id)

    return {
        "status": "success",
        "message": "Two-Factor Authentication has been disabled on your account."
    }

# ==============================================================================
# SQL INJECTION DEFENSE DEMONSTRATION LAB
# ==============================================================================

@app.post("/api/sqli-test")
async def test_sqli(req: SqliTestRequest):
    result = test_sql_injection_defense(req.payload)
    return result

# ==============================================================================
# RUN DIRECTLY VIA PYTHON
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    print("[SERVER] Starting VaultKey Secure Authentication Server on http://127.0.0.1:8000 ...")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
