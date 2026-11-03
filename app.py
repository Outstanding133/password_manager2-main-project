"""
Secure Password Manager — Flask Application
REST API for managing encrypted credentials.
"""

import os
import secrets
import hmac
import threading
import time
import math
from flask import Flask, request, jsonify, render_template, session
from cryptography.fernet import InvalidToken

import database as db
import encryption as enc
import password_utils as pwutil

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Encryption keys stay in server memory. The browser receives only a random,
# opaque session identifier in Flask's signed session cookie.
_ACTIVE_VAULT_KEYS = {}
_ACTIVE_VAULT_KEYS_LOCK = threading.Lock()

# Development-grade, per-client-IP login throttling.
# Five failed attempts within 15 minutes trigger a 15-minute cooldown.
_LOGIN_FAILURES = {}
_LOGIN_FAILURES_LOCK = threading.Lock()
_LOGIN_MAX_FAILURES = 5
_LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_LOCKOUT_SECONDS = 15 * 60


def _login_lockout_remaining(client_id: str) -> int:
    """Return remaining lockout seconds, or zero when login may proceed."""
    now = time.monotonic()
    with _LOGIN_FAILURES_LOCK:
        record = _LOGIN_FAILURES.get(client_id)
        if not record:
            return 0

        blocked_until = record.get("blocked_until", 0)
        if blocked_until > now:
            return math.ceil(blocked_until - now)

        # Expired cooldown: start with a clean attempt window.
        if blocked_until:
            _LOGIN_FAILURES.pop(client_id, None)
            return 0

        record["failures"] = [
            stamp for stamp in record.get("failures", [])
            if now - stamp < _LOGIN_WINDOW_SECONDS
        ]
        if not record["failures"]:
            _LOGIN_FAILURES.pop(client_id, None)
        return 0


def _record_failed_login(client_id: str) -> int:
    """Record a failed login and return cooldown seconds if threshold is reached."""
    now = time.monotonic()
    with _LOGIN_FAILURES_LOCK:
        record = _LOGIN_FAILURES.setdefault(
            client_id, {"failures": [], "blocked_until": 0}
        )
        record["failures"] = [
            stamp for stamp in record["failures"]
            if now - stamp < _LOGIN_WINDOW_SECONDS
        ]
        record["failures"].append(now)

        if len(record["failures"]) >= _LOGIN_MAX_FAILURES:
            record["blocked_until"] = now + _LOGIN_LOCKOUT_SECONDS
            return _LOGIN_LOCKOUT_SECONDS
        return 0


def _clear_login_failures(client_id: str) -> None:
    """Clear failed attempts after a successful authentication."""
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.pop(client_id, None)


# ---------------------------------------------------------------------------
# Initialise database on startup
# ---------------------------------------------------------------------------
db.init_db()


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

@app.before_request
def protect_state_changing_requests():
    """Require a session-bound CSRF token for every unsafe HTTP method."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected_token = session.get("csrf_token")
        supplied_token = request.headers.get("X-CSRF-Token", "")
        if (
            not expected_token
            or not supplied_token
            or not hmac.compare_digest(expected_token, supplied_token)
        ):
            return jsonify({"error": "CSRF validation failed. Refresh the page and try again."}), 403


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_key():
    """Retrieve the vault key from server memory using an opaque session ID."""
    session_id = session.get("vault_session_id")
    if not session_id:
        return None
    with _ACTIVE_VAULT_KEYS_LOCK:
        return _ACTIVE_VAULT_KEYS.get(session_id)


def _store_key(key: bytes):
    """Store a vault key server-side; put only a random ID in the client cookie."""
    _clear_key()
    session_id = secrets.token_urlsafe(32)
    with _ACTIVE_VAULT_KEYS_LOCK:
        _ACTIVE_VAULT_KEYS[session_id] = key
    session["vault_session_id"] = session_id


def _clear_key():
    """Invalidate the current server-side vault key and remove its cookie ID."""
    session_id = session.pop("vault_session_id", None)
    if session_id:
        with _ACTIVE_VAULT_KEYS_LOCK:
            _ACTIVE_VAULT_KEYS.pop(session_id, None)


def _require_unlocked(f):
    """Decorator that ensures the vault is unlocked before proceeding."""
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if _get_key() is None:
            return jsonify({"error": "Vault is locked"}), 403
        return f(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------

@app.route("/api/csrf", methods=["GET"])
def csrf_token():
    """Issue a session-bound token for same-origin state-changing API requests."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    response = jsonify({"csrf_token": token})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/status")
def vault_status():
    """Return whether master is set and whether vault is currently unlocked."""
    return jsonify({
        "master_set": db.is_master_set(),
        "unlocked": _get_key() is not None,
    })


@app.route("/api/setup", methods=["POST"])
def setup():
    """First-time setup: create master password."""
    if db.is_master_set():
        return jsonify({"error": "Master password already configured"}), 400

    data = request.get_json(force=True)
    master_pw = data.get("master_password", "").strip()

    if len(master_pw) < 8:
        return jsonify({"error": "Master password must be at least 8 characters"}), 400

    # Analyse strength
    analysis = pwutil.analyze_strength(master_pw)
    if analysis["score"] < 40:
        return jsonify({"error": "Master password is too weak. Please choose a stronger one.", "analysis": analysis}), 400

    salt = enc.generate_salt()
    key = enc.derive_key(master_pw, salt)
    key_hash = enc.hash_key(key)

    db.save_master(salt, key_hash)

    # Auto-unlock after setup
    _store_key(key)

    return jsonify({"message": "Master password created successfully", "analysis": analysis})


@app.route("/api/unlock", methods=["POST"])
def unlock():
    """Authenticate with master password, with failed-attempt throttling."""
    # Use the direct client address. Do not trust arbitrary X-Forwarded-For
    # headers; configure trusted proxy handling explicitly if deployed behind one.
    client_id = request.remote_addr or "unknown"
    retry_after = _login_lockout_remaining(client_id)
    if retry_after:
        response = jsonify({
            "error": "Too many failed master-password attempts. Try again later.",
            "retry_after_seconds": retry_after,
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    if not db.is_master_set():
        return jsonify({"error": "No master password configured"}), 400

    data = request.get_json(force=True)
    master_pw = data.get("master_password", "").strip()

    master = db.get_master()
    key = enc.derive_key(master_pw, master["salt"])
    key_hash = enc.hash_key(key)

    if key_hash != master["key_hash"]:
        retry_after = _record_failed_login(client_id)
        if retry_after:
            response = jsonify({
                "error": "Too many failed master-password attempts. Try again in 15 minutes.",
                "retry_after_seconds": retry_after,
            })
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response
        return jsonify({"error": "Incorrect master password"}), 401

    _clear_login_failures(client_id)

    # Vault authenticated! Automatically rotate master password.
    # Generate new 20-character secure password (~131 bits of entropy)
    new_master_password = pwutil.generate_password(
        length=20,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True
    )

    new_salt = enc.generate_salt()
    new_key = enc.derive_key(new_master_password, new_salt)
    new_key_hash = enc.hash_key(new_key)

    # Retrieve and decrypt all passwords with current key
    rows = db.get_all_passwords()
    reencrypted_list = []
    for r in rows:
        try:
            decrypted_pw = enc.decrypt_data(r["encrypted_password"], key)
            new_encrypted = enc.encrypt_data(decrypted_pw, new_key)
            reencrypted_list.append((r["id"], new_encrypted))
        except InvalidToken:
            return jsonify({"error": "Re-keying failed during automatic rotation"}), 500

    # Perform atomic re-keying in DB transaction
    success = db.update_master_and_reencrypt(new_salt, new_key_hash, reencrypted_list)
    if not success:
        return jsonify({"error": "Failed to rotate master password in database"}), 500

    # Save new key in session
    _store_key(new_key)

    return jsonify({
        "message": "Vault unlocked and master password rotated successfully!",
        "rotated_password": new_master_password
    })


@app.route("/api/lock", methods=["POST"])
def lock():
    """Lock the vault by clearing the session key."""
    _clear_key()
    return jsonify({"message": "Vault locked"})


@app.route("/api/change-master", methods=["POST"])
@_require_unlocked
def change_master():
    """Change the master password and re-encrypt all credentials."""
    data = request.get_json(force=True)
    current_pw = data.get("current_password", "").strip()
    new_pw = data.get("new_password", "").strip()

    if not current_pw or not new_pw:
        return jsonify({"error": "Current and new passwords are required"}), 400

    if len(new_pw) < 8:
        return jsonify({"error": "New master password must be at least 8 characters"}), 400

    # Verify current master password
    master = db.get_master()
    old_key = _get_key()  # Retrieve verified key from session
    old_key_hash = enc.hash_key(old_key)

    # Re-verify old password hash
    test_key = enc.derive_key(current_pw, master["salt"])
    test_key_hash = enc.hash_key(test_key)

    if test_key_hash != master["key_hash"]:
        return jsonify({"error": "Incorrect current master password"}), 401

    # Analyze new password strength
    analysis = pwutil.analyze_strength(new_pw)
    if analysis["score"] < 40:
        return jsonify({"error": "New master password is too weak. Please choose a stronger one.", "analysis": analysis}), 400

    # Retrieve all credentials to re-encrypt
    rows = db.get_all_passwords()
    reencrypted_list = []
    
    # Decrypt with old key, re-encrypt with new key
    new_salt = enc.generate_salt()
    new_key = enc.derive_key(new_pw, new_salt)
    new_key_hash = enc.hash_key(new_key)

    for r in rows:
        try:
            decrypted_pw = enc.decrypt_data(r["encrypted_password"], old_key)
            new_encrypted = enc.encrypt_data(decrypted_pw, new_key)
            reencrypted_list.append((r["id"], new_encrypted))
        except InvalidToken:
            return jsonify({"error": "Failed to decrypt existing passwords during re-keying"}), 500

    # Perform transaction to update master salt/hash and all passwords
    success = db.update_master_and_reencrypt(new_salt, new_key_hash, reencrypted_list)
    if not success:
        return jsonify({"error": "Failed to update vault database"}), 500

    # Update current session key
    _store_key(new_key)

    return jsonify({"message": "Master password changed successfully", "analysis": analysis})


# ---------------------------------------------------------------------------
# Passwords API
# ---------------------------------------------------------------------------

@app.route("/api/passwords", methods=["GET"])
@_require_unlocked
def list_passwords():
    """Return all credentials with passwords decrypted."""
    key = _get_key()
    rows = db.get_all_passwords()
    result = []
    for r in rows:
        try:
            decrypted_pw = enc.decrypt_data(r["encrypted_password"], key)
        except InvalidToken:
            decrypted_pw = "⚠️ Decryption failed"
        result.append({
            "id": r["id"],
            "site_name": r["site_name"],
            "site_url": r["site_url"],
            "username": r["username"],
            "password": decrypted_pw,
            "category": r["category"],
            "notes": r["notes"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    return jsonify(result)


@app.route("/api/passwords", methods=["POST"])
@_require_unlocked
def create_password():
    """Add a new credential."""
    key = _get_key()
    data = request.get_json(force=True)

    site_name = data.get("site_name", "").strip()
    site_url = data.get("site_url", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    category = data.get("category", "General").strip()
    notes = data.get("notes", "").strip()

    if not site_name or not username or not password:
        return jsonify({"error": "site_name, username, and password are required"}), 400

    encrypted = enc.encrypt_data(password, key)
    new_id = db.add_password(site_name, site_url, username, encrypted, category, notes)

    return jsonify({"message": "Credential saved", "id": new_id}), 201


@app.route("/api/passwords/<int:pw_id>", methods=["PUT"])
@_require_unlocked
def update_password_route(pw_id):
    """Update an existing credential."""
    key = _get_key()
    data = request.get_json(force=True)

    existing = db.get_password_by_id(pw_id)
    if not existing:
        return jsonify({"error": "Not found"}), 404

    site_name = data.get("site_name", existing["site_name"]).strip()
    site_url = data.get("site_url", existing["site_url"]).strip()
    username = data.get("username", existing["username"]).strip()
    password = data.get("password", "").strip()
    category = data.get("category", existing["category"]).strip()
    notes = data.get("notes", existing["notes"]).strip()

    if password:
        encrypted = enc.encrypt_data(password, key)
    else:
        encrypted = existing["encrypted_password"]

    db.update_password(pw_id, site_name, site_url, username, encrypted, category, notes)
    return jsonify({"message": "Credential updated"})


@app.route("/api/passwords/<int:pw_id>", methods=["DELETE"])
@_require_unlocked
def delete_password_route(pw_id):
    """Delete a credential."""
    if db.delete_password(pw_id):
        return jsonify({"message": "Credential deleted"})
    return jsonify({"error": "Not found"}), 404


# ---------------------------------------------------------------------------
# Utility API
# ---------------------------------------------------------------------------

@app.route("/api/generate", methods=["POST"])
def generate():
    """Generate a random password."""
    data = request.get_json(force=True) if request.is_json else {}
    password = pwutil.generate_password(
        length=data.get("length", 16),
        use_upper=data.get("use_upper", True),
        use_lower=data.get("use_lower", True),
        use_digits=data.get("use_digits", True),
        use_symbols=data.get("use_symbols", True),
        exclude_ambiguous=data.get("exclude_ambiguous", False),
    )
    analysis = pwutil.analyze_strength(password)
    return jsonify({"password": password, "analysis": analysis})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Analyze password strength."""
    data = request.get_json(force=True)
    password = data.get("password", "")
    analysis = pwutil.analyze_strength(password)
    return jsonify(analysis)


@app.route("/api/stats", methods=["GET"])
@_require_unlocked
def stats():
    """Return dashboard statistics including weak password count."""
    key = _get_key()
    raw_stats = db.get_stats()

    # Count weak passwords
    rows = db.get_all_passwords()
    weak_count = 0
    for r in rows:
        try:
            pw = enc.decrypt_data(r["encrypted_password"], key)
            analysis = pwutil.analyze_strength(pw)
            if analysis["score"] < 40:
                weak_count += 1
        except InvalidToken:
            weak_count += 1

    raw_stats["weak"] = weak_count
    return jsonify(raw_stats)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n  [*] Secure Password Manager")
    print("  ----------------------------")
    print("  Running at http://localhost:5000\n")
    app.run(debug=True, port=5000)
