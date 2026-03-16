import os
import hashlib
import sqlite3
import secrets
import time
from flask import Flask, request, jsonify, render_template, session

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Security configuration
# ---------------------------------------------------------------------------

# The secret key signs the session cookie. Generated fresh at every container
# startup, which invalidates all existing sessions on restart — intentional
# behavior for a CTF environment where the instructor controls the lifecycle.
secret_key = os.environ.get("SECRET_KEY", "")
if not secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Run prepare.sh before building the portal container."
    )
app.secret_key = secret_key

# Session cookie hardening. The cookie is HttpOnly and SameSite=Strict,
# preventing JavaScript access and cross-site request forgery respectively.
# Secure=False is intentional since the portal runs over plain HTTP in a
# lab environment without TLS termination.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_NAME="pm_session",
    PERMANENT_SESSION_LIFETIME=86400,
    SESSION_REFRESH_EACH_REQUEST=False,
)

# ---------------------------------------------------------------------------
# Flag configuration
# ---------------------------------------------------------------------------

# Flag hashes and the master flag arrive exclusively via environment variables.
# They are never written to disk, never stored in the session, and never
# included in any response payload until all three flags are correctly solved.

FLAG_HASHES = {
    1: os.environ.get("FLAG1_HASH", ""),
    2: os.environ.get("FLAG2_HASH", ""),
    3: os.environ.get("FLAG3_HASH", ""),
}

MASTER_FLAG = os.environ.get("MASTER_FLAG", "")

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

# In-process store keyed by IP address. Each entry is a list of UNIX timestamps
# representing submission attempts within the current window.
# This store is per-worker — with multiple Gunicorn workers each worker maintains
# its own store. The effective limit is RATE_LIMIT_MAX per worker per window,
# which is acceptable for a lab environment where true precision is not required.

_rate_store: dict[str, list[float]] = {}

RATE_LIMIT_MAX    = 5
RATE_LIMIT_WINDOW = 60


def _get_client_ip() -> str:
    """
    Resolves the real client IP, respecting X-Forwarded-For only if the request
    originates from localhost (i.e., a trusted reverse proxy). In direct
    deployments without a proxy, request.remote_addr is used as-is.
    """
    if request.remote_addr in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr


def is_rate_limited(ip: str) -> bool:
    """
    Returns True if the given IP has exceeded RATE_LIMIT_MAX submission attempts
    within the last RATE_LIMIT_WINDOW seconds. Expired entries are pruned on
    every call to prevent unbounded memory growth over long deployments.
    """
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW

    timestamps = _rate_store.get(ip, [])
    timestamps = [t for t in timestamps if t > window_start]
    _rate_store[ip] = timestamps

    if len(timestamps) >= RATE_LIMIT_MAX:
        return True

    _rate_store[ip].append(now)
    return False

# ---------------------------------------------------------------------------
# CSRF token utilities
# ---------------------------------------------------------------------------

# A per-session CSRF token is generated on first page load and embedded in the
# HTML as a meta tag. The JavaScript reads it and includes it as a custom header
# on every POST request. The server validates it on every /submit call.
# This prevents a student from calling /submit directly with curl or a script
# without first loading the page and extracting the token.

def get_csrf_token() -> str:
    """
    Returns the CSRF token for the current session, generating and persisting
    one if absent. The session is marked as modified in both cases to guarantee
    Flask flushes the cookie to the client on this response cycle.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    session.modified = True
    return session["csrf_token"]



def validate_csrf(token: str) -> bool:
    """
    Validates the submitted CSRF token against the session-bound token using
    a constant-time comparison to prevent timing-based token oracle attacks.
    """
    expected = session.get("csrf_token", "")
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)

# ---------------------------------------------------------------------------
# Session-scoped flag state
# ---------------------------------------------------------------------------

def get_flag_states() -> dict:
    """
    Returns the solved state for all three flags scoped to the current session.
    Each student's browser session is fully independent — one student completing
    the challenge does not affect the portal state visible to any other student.
    """
    return {
        1: session.get("flag1_solved", False),
        2: session.get("flag2_solved", False),
        3: session.get("flag3_solved", False),
    }


def mark_flag_solved(flag_id: int) -> None:
    """
    Marks the specified flag as solved within the current session.
    The session is explicitly marked as modified to ensure Flask persists
    the change even when only mutable nested structures are updated.
    """
    session[f"flag{flag_id}_solved"] = True
    session.modified = True


def all_flags_solved(states: dict) -> bool:
    """
    Returns True only when all three flags are marked as solved in the session.
    """
    return all(states.get(i, False) for i in (1, 2, 3))

# ---------------------------------------------------------------------------
# Hash validation
# ---------------------------------------------------------------------------

def hash_submission(value: str) -> str:
    """
    Computes the SHA256 hash of the submitted flag value after stripping
    surrounding whitespace. Stripping prevents trivial failures caused by
    terminal copy-paste artifacts such as trailing newlines.
    """
    return hashlib.sha256(value.strip().encode()).hexdigest()


def validate_flag(flag_id: int, submitted_value: str) -> bool:
    """
    Validates a submitted flag against the pre-computed hash for that flag ID.
    Uses a constant-time comparison to prevent hash oracle timing attacks.
    """
    expected = FLAG_HASHES.get(flag_id, "")
    if not expected:
        return False
    return secrets.compare_digest(
        hash_submission(submitted_value),
        expected
    )

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    # Force the session to be created and the cookie to be sent on the very
    # first visit by marking it as modified unconditionally. Without this,
    # Flask may defer writing a new empty session, causing the CSRF token
    # embedded in the page to be unvalidatable on the immediately following
    # POST request because the cookie has not been established yet.
    if "initialized" not in session:
        session["initialized"] = True
        session.modified = True

    csrf_token  = get_csrf_token()
    states      = get_flag_states()
    show_master = all_flags_solved(states)
    master_flag = MASTER_FLAG if show_master else None

    return render_template(
        "index.html",
        states=states,
        show_master=show_master,
        master_flag=None,
        csrf_token=csrf_token,
    )



@app.route("/submit", methods=["POST"])
def submit():
    """
    Validates a flag submission against the session CSRF token and the flag hash.

    Security checks applied in order:
      1. CSRF token validation — rejects requests without a valid session token,
         blocking direct curl/script calls that have not loaded the page first.
      2. Rate limiting — rejects IPs that exceed RATE_LIMIT_MAX attempts per window.
      3. Input validation — rejects malformed payloads.
      4. Flag hash validation — constant-time comparison against environment hash.

    Expected request body:
        { "flag_id": 1, "value": "CTF{...}" }

    Expected request header:
        X-CSRF-Token: <token from meta tag>
    """
    submitted_csrf = request.headers.get("X-CSRF-Token", "")
    if not validate_csrf(submitted_csrf):
        return jsonify({"error": "Invalid or missing CSRF token."}), 403

    client_ip = _get_client_ip()
    if is_rate_limited(client_ip):
        return jsonify({"error": "Too many attempts. Wait 60 seconds."}), 429

    data = request.get_json(silent=True)
    if not data or "flag_id" not in data or "value" not in data:
        return jsonify({"error": "Invalid request payload."}), 400

    flag_id = data.get("flag_id")
    submitted_value = data.get("value", "")

    if flag_id not in (1, 2, 3):
        return jsonify({"error": "Invalid flag_id."}), 400

    correct = validate_flag(flag_id, submitted_value)

    if correct:
        mark_flag_solved(flag_id)

    states      = get_flag_states()
    show_master = all_flags_solved(states)
    master_flag = MASTER_FLAG if show_master else None

    return jsonify({
        "correct":     correct,
        "flag_id":     flag_id,
        "states":      {str(k): v for k, v in states.items()},
        "show_master": show_master,
        "master_flag": master_flag,
    })


@app.route("/status", methods=["GET"])
def status():
    """
    Returns the current session-scoped flag solve state.
    Does not expose the master flag regardless of solve state —
    the master flag is only delivered via the /submit response or page render.
    """
    states = get_flag_states()
    return jsonify({
        "states":      {str(k): v for k, v in states.items()},
        "show_master": all_flags_solved(states),
    })
