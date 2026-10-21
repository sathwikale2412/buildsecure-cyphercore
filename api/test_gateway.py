"""Offline security tests for the Cypher Core gateway.

Run from anywhere:  python api/test_gateway.py

Nothing here touches the network or a database. The upstream call is replaced with a
stub, so every assertion is about what this service is willing to say back to a caller.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

os.environ.pop("SUPABASE_URL", None)
os.environ.pop("SUPABASE_ANON_KEY", None)

spec = importlib.util.spec_from_file_location("cypher_gateway", ROOT / "api" / "index.py")
index = importlib.util.module_from_spec(spec)
sys.modules["cypher_gateway"] = index
spec.loader.exec_module(index)

client = index.app.test_client()

FAKE_URL = "https://stub-project.supabase.co"
FAKE_KEY = "anon-key-that-must-never-appear-in-a-response"

passed = failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label} {detail}")


def post(path, payload, raw=None):
    headers = {"Content-Type": "application/json"}
    body = raw if raw is not None else json.dumps(payload)
    return client.post(path, data=body, headers=headers)


def body_of(response):
    try:
        return response.get_json()
    except Exception:  # noqa: BLE001
        return {"_raw": response.get_data(as_text=True)}


class StubResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


SESSION = {
    "access_token": "jwt-access-token",
    "refresh_token": "refresh-token",
    "expires_in": 3600,
    "token_type": "bearer",
    "user": {"id": "11111111-2222-3333-4444-555555555555", "email": "a@b.co", "encrypted_password": "hash"},
}

leaked = []

FORBIDDEN = (FAKE_KEY, "stub-project", "supabase.co", "Traceback", "ConnectionError", "hash", "long-enough-pw")


def install_stub(handler):
    index.requests.post = handler
    index._hits.clear()


def reset():
    """The throttle is per client address, so a long test run must clear it between
    sections or every later assertion argues with the limiter instead of the code."""
    index._hits.clear()


def no_upstream(*_args, **_kwargs):
    raise index.requests.exceptions.ConnectionError(" refused to reach " + FAKE_URL)


def upstream(status, wording):
    def handler(*_args, **_kwargs):
        return StubResponse(status, {"error": wording}, text=wording)

    return handler


def assert_clean(label, payload):
    text = json.dumps(payload)
    offenders = [needle for needle in FORBIDDEN if needle in text]
    if offenders:
        leaked.append((label, offenders))
    check(f"{label} leaks nothing", not offenders, offenders)


print("\n--- fail closed before any credentials exist ---")
r = post("/auth/login", {"email": "a@b.co", "password": "correct-horse"})
check("unconfigured gateway refuses login", r.status_code == 503, r.status_code)
check("the refusal is the generic one", body_of(r).get("message") == index.UNAVAILABLE, body_of(r))
r = client.get("/health")
check("health stays readable", r.status_code == 200 and body_of(r)["configured"] is False, body_of(r))

# Switch to a configured service for the rest of the run.
index.CONFIGURED = True
index.SUPABASE_URL = FAKE_URL
index.SUPABASE_ANON_KEY = FAKE_KEY

print("\n--- server-side validation, before anything is sent upstream ---")
called = {"n": 0}


def counting_stub(*_a, **_k):
    called["n"] += 1
    return StubResponse(200, SESSION)


install_stub(counting_stub)
for label, payload in [
    ("missing password", {"email": "a@b.co"}),
    ("missing email", {"password": "long-enough-pw"}),
    ("malformed email", {"email": "not-an-email", "password": "long-enough-pw"}),
    ("oversized email", {"email": "x" * 300 + "@b.co", "password": "long-enough-pw"}),
    ("empty password", {"email": "a@b.co", "password": ""}),
    ("json array body", ["a@b.co", "password"]),
]:
    reset()
    r = post("/auth/login", payload)
    check(f"{label} rejected with 400", r.status_code == 400, r.status_code)
    assert_clean(label, body_of(r))

reset()
r = post("/auth/signup", {"email": "a@b.co", "password": "123456789"})
check("signup enforces the minimum length", r.status_code == 400, r.status_code)
reset()
r = client.post("/auth/login", data="email=a@b.co&password=long-enough-pw", content_type="application/x-www-form-urlencoded")
check("non-JSON body rejected", r.status_code == 400, r.status_code)
check("validation ran without reaching upstream", called["n"] == 0, called["n"])

print("\n--- a good login returns a session and nothing else ---")
reset()
r = post("/auth/login", {"email": "A@B.co ", "password": "long-enough-pw"})
payload = body_of(r)
check("login succeeds", r.status_code == 200, r.status_code)
check("tokens are present", payload.get("access_token") == "jwt-access-token")
check("user id is present", payload.get("user", {}).get("id") == SESSION["user"]["id"])
check("the stored hash is not handed out", "encrypted_password" not in json.dumps(payload))
check("the password is not echoed", "long-enough-pw" not in json.dumps(payload))

print("\n--- a bad login says one sentence, whichever way it failed ---")
for status, wording in [(400, "Invalid login credentials"), (401, "invalid claim"), (403, "Email not confirmed"), (429, "rate limit exceeded")]:
    install_stub(upstream(status, wording))
    r = post("/auth/login", {"email": "a@b.co", "password": "wrong-password"})
    payload = body_of(r)
    check(f"upstream {status} becomes a 401", r.status_code == 401, r.status_code)
    check(f"upstream {status} leaks its wording", payload.get("message") == index.BAD_CREDENTIALS, payload)

print("\n--- signup outcomes a caller needs to know, and only those ---")
install_stub(lambda *a, **k: StubResponse(422, {"error_code": "user_already_exists"}, text="User already registered"))
r = post("/auth/signup", {"email": "a@b.co", "password": "long-enough-pw"})
check("duplicate address is named plainly", r.status_code == 409 and body_of(r).get("message") == index.DUPLICATE_SIGNUP, body_of(r))
install_stub(lambda *a, **k: StubResponse(200, {"id": "u", "email": "a@b.co"}))
r = post("/auth/signup", {"email": "a@b.co", "password": "long-enough-pw"})
check("confirmation-required is reported, not faked", body_of(r).get("needs_confirmation") is True, body_of(r))
install_stub(lambda *a, **k: StubResponse(500, {"msg": "internal GoTrue detail"}, text="internal GoTrue detail"))
r = post("/auth/signup", {"email": "a@b.co", "password": "long-enough-pw"})
check("upstream 500 becomes a generic failure", r.status_code == 502 and body_of(r).get("message") == index.GENERIC_FAILURE, body_of(r))
check("the upstream detail is not repeated", "GoTrue" not in json.dumps(body_of(r)))

print("\n--- upstream failure produces no internals ---")
install_stub(no_upstream)
for route in ("/auth/login", "/auth/signup"):
    r = post(route, {"email": "a@b.co", "password": "long-enough-pw"})
    payload = body_of(r)
    check(f"{route} fails generically", r.status_code == 502 and payload.get("message") == index.GENERIC_FAILURE, payload)
    assert_clean(route, payload)

print("\n--- the login throttle ---")
install_stub(no_upstream)
statuses = []
for _ in range(index.AUTH_MAX_PER_WINDOW + 3):
    r = post("/auth/login", {"email": "a@b.co", "password": "long-enough-pw"})
    statuses.append(r.status_code)
allowed = [s for s in statuses if s != 429]
check("attempts past the window are refused", 429 in statuses, statuses)
check("the window matches the documented limit", len(allowed) == index.AUTH_MAX_PER_WINDOW, len(allowed))
r = post("/auth/login", {"email": "a@b.co", "password": "long-enough-pw"})
check("refusal is one sentence", body_of(r).get("message") == "Too many attempts. Wait a minute.", body_of(r))

print("\n--- unknown paths, wrong methods ---")
install_stub(counting_stub)
r = client.get("/auth/login")
check("GET on the auth routes is refused", r.status_code in (404, 405), r.status_code)
r = post("/api/nonsense", {})
check("unknown endpoint says nothing about itself", r.status_code == 404, r.status_code)

print("\n--- leakage sweep ---")
check("no stub credential or host appeared anywhere", not leaked, leaked)

print(f"\n{passed} passed, {failed} failed\n")
sys.exit(1 if failed or leaked else 0)
