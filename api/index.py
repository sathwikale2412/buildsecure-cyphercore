"""Cypher Core gateway.

Two jobs, both of them things a browser cannot be trusted to do:

1.  Validate and throttle sign-in before the credentials reach the identity provider.
2.  Fail closed. Without SUPABASE_URL / SUPABASE_ANON_KEY this service answers 503 and
    says so, rather than pretending a vault opened.

The vault itself is deliberately *not* proxied through here. Ciphertext travels straight
from the browser to Postgres under row-level security, so the server holds no plaintext,
no key and no password — and a compromise of this function yields nothing readable.
"""

import os
import re
import time
import uuid

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

GENERIC_FAILURE = "The vault service could not complete that request. Try again shortly."
BAD_CREDENTIALS = "Email or password is not correct."
DUPLICATE_SIGNUP = "An account for that address already exists."
MALFORMED = "Check the email address and password, then try again."
UNAVAILABLE = (
    "This deployment is not attached to an identity provider yet, so sign-in is refused."
)

MAX_EMAIL_CHARS = 254
MIN_PASSWORD_CHARS = 10
MAX_PASSWORD_CHARS = 72  # bcrypt discards bytes past 72; rejecting is kinder than truncating
MAX_BODY_BYTES = 8192

AUTH_WINDOW_SECONDS = 60
AUTH_MAX_PER_WINDOW = 8
OPEN_WINDOW_SECONDS = 60
OPEN_MAX_PER_WINDOW = 40

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

_hits: dict[str, list[float]] = {}

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "").strip()
CONFIGURED = SUPABASE_URL.startswith("https://") and bool(SUPABASE_ANON_KEY)


def _ref():
    """Correlator for the platform log. Nothing from the upstream response, an exception
    message or a stack ever reaches the caller — only this."""
    return uuid.uuid4().hex[:8]


def _caller_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() or request.remote_addr or "unknown"


def rate_limited(bucket, limit, window=AUTH_WINDOW_SECONDS):
    """Per warm instance only: a stateless function has no shared counter, so this is a
    brake on one visitor, not a guarantee across the fleet. The identity provider
    throttles independently on top of it."""
    key = f"{bucket}:{_caller_ip()}"
    now = time.time()
    seen = [stamp for stamp in _hits.get(key, []) if now - stamp < window]
    if len(seen) >= limit:
        _hits[key] = seen
        return True
    seen.append(now)
    _hits[key] = seen
    return False


def _credentials():
    """Return (email, password) or None. Anything odd about the request shape is a
    validation failure, never a 500."""
    if request.content_length and request.content_length > MAX_BODY_BYTES:
        return None
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None
    email = body.get("email")
    password = body.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return None
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_CHARS or not EMAIL_RE.match(email):
        return None
    if not password or len(password) > MAX_PASSWORD_CHARS:
        return None
    return email, password


def _gotrue(path, payload, ref):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    try:
        return requests.post(f"{SUPABASE_URL}{path}", json=payload, headers=headers, timeout=8)
    except requests.RequestException as exc:
        app.logger.error("Cypher Core upstream failure (ref %s): %s", ref, type(exc).__name__)
        return None


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def gateway(path):
    action = path.rstrip("/").split("/")[-1]
    ref = _ref()

    if action == "health":
        return jsonify({"status": "ok", "configured": CONFIGURED})

    if action not in ("login", "signup"):
        return jsonify({"status": "error", "message": "No such endpoint."}), 404

    if request.method != "POST":
        return jsonify({"status": "error", "message": "That request shape is not accepted."}), 405

    if not CONFIGURED:
        return jsonify({"status": "unavailable", "message": UNAVAILABLE, "ref": ref}), 503

    if rate_limited("auth", AUTH_MAX_PER_WINDOW):
        app.logger.warning("Cypher Core auth throttle tripped (ref %s)", ref)
        return jsonify({"status": "blocked", "message": "Too many attempts. Wait a minute."}), 429

    credentials = _credentials()
    if credentials is None:
        return jsonify({"status": "invalid", "message": MALFORMED, "ref": ref}), 400
    email, password = credentials

    if action == "signup":
        return _signup(email, password, ref)
    return _login(email, password, ref)


def _signup(email, password, ref):
    if len(password) < MIN_PASSWORD_CHARS:
        return jsonify({"status": "invalid", "message": MALFORMED, "ref": ref}), 400
    response = _gotrue("/auth/v1/signup", {"email": email, "password": password}, ref)
    if response is None:
        return jsonify({"status": "error", "message": GENERIC_FAILURE, "ref": ref}), 502
    if response.status_code == 200:
        payload = response.json()
        if not payload.get("access_token"):
            return jsonify({"status": "confirmation_required", "needs_confirmation": True})
        return jsonify(_session(payload))
    if response.status_code in (422, 409, 400) and "already registered" in response.text.lower():
        return jsonify({"status": "taken", "message": DUPLICATE_SIGNUP, "ref": ref}), 409
    app.logger.error("Cypher Core signup rejected upstream (ref %s, status %s)", ref, response.status_code)
    return jsonify({"status": "error", "message": GENERIC_FAILURE, "ref": ref}), 502


def _login(email, password, ref):
    response = _gotrue("/auth/v1/token?grant_type=password", {"email": email, "password": password}, ref)
    if response is None:
        return jsonify({"status": "error", "message": GENERIC_FAILURE, "ref": ref}), 502
    if response.status_code != 200:
        # GoTrue's own wording ("Invalid login credentials", rate-limit notices, email
        # confirmation prompts) varies by cause; one sentence here keeps a failed attempt
        # from telling a caller whether the address exists.
        app.logger.warning("Cypher Core login failed (ref %s, status %s)", ref, response.status_code)
        return jsonify({"status": "denied", "message": BAD_CREDENTIALS, "ref": ref}), 401
    return jsonify(_session(response.json()))


def _session(payload):
    """Hand back only what the browser needs to open an RLS-scoped session."""
    user = payload.get("user") or {}
    return {
        "status": "ok",
        "access_token": payload.get("access_token"),
        "refresh_token": payload.get("refresh_token"),
        "expires_in": payload.get("expires_in"),
        "token_type": payload.get("token_type", "bearer"),
        "user": {"id": user.get("id"), "email": user.get("email")},
    }


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"status": "error", "message": "No such endpoint."}), 404


@app.errorhandler(405)
def bad_method(_error):
    return jsonify({"status": "error", "message": "That request shape is not accepted."}), 405


@app.errorhandler(Exception)
def unhandled(error):
    ref = _ref()
    app.logger.exception("Cypher Core gateway failure (ref %s)", ref)
    return jsonify({"status": "error", "message": GENERIC_FAILURE, "ref": ref}), 500


if __name__ == "__main__":
    app.run(port=5001)
