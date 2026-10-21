# Cypher Core

An encrypted secret vault. Sign in with an email and password, then store credentials that
the server never sees in the clear: entries are ciphered in your browser with AES-256-GCM
under a key derived from your password, and only ciphertext, a nonce and a salt are ever
written to Postgres.

Live: **https://buildsecure-cyphercore.vercel.app** — reachable from any device; sign-in
stays refused until the four environment variables below are set and `supabase/schema.sql`
is applied. Built for the Build Secure review as a worked example of the controls the
brief asks for; it is a standalone app, not a submission inside the (closed) hackathon
window.

---

## Why there is a backend at all

The vault does not need one: ciphertext goes straight from the browser to Postgres under
row-level security. The part that *does* need a server is the door. If the browser talked
to the identity provider on its own, then validation, throttling and the failure wording
would all be things an attacker can edit, and the checks would exist only on paper.

So `api/index.py` owns sign-in and sign-up, and nothing else. It never receives, stores or
handles a vault key.

```
browser                          gateway (Flask)                    Supabase
  │  POST /api/auth/login           │                                 │
  │  ──────────────────────────────>│  shape + length checks          │
  │                                 │  sliding-window throttle /min   │
  │                                 │  ───────── grant_type=password ─>│  bcrypt verify
  │  <── one sentence + ref ────────│<───────── token or denial ───────│
  │                                 │  (never the upstream wording)    │
  │                                                          (RLS-scoped, direct)
  ├─ AES-GCM encrypt here ─────────────────────────────────────────────┤
  └─ vault_items: ciphertext + nonce only ─────────────────────────────>│
```

## Environment

| Name | Read by | Type | Without it |
|---|---|---|---|
| `VITE_SUPABASE_URL` | browser | Config | App renders, sign-in refused |
| `VITE_SUPABASE_ANON_KEY` | browser | Config | App renders, sign-in refused |
| `SUPABASE_URL` | gateway | Secret | Gateway answers 503 |
| `SUPABASE_ANON_KEY` | gateway | Secret | Gateway answers 503 |

`VITE_` names are inlined into the public bundle at build time — they must be added as
type **Config**, and the site must be redeployed after changing them. The anon key is
public by design: it can read nothing without a signed-in session, and row-level security
pins every row to `auth.uid()`. The `service_role` key is absent from this repository; it
would bypass exactly the policies that keep one vault away from another.

## The controls, and where they actually live

1. **Server-side validation** — `api/index.py` rejects a malformed or oversized email, a
   password outside 10–72 characters, non-JSON bodies and bodies past 8 KB *before* any
   upstream call. The 72-character ceiling is deliberate: bcrypt silently discards bytes
   beyond it, so a longer password would appear to work and then fail on the next sign-in.
   Vault rows are validated at the data layer too — every ciphertext column carries a
   `char_length` check.
2. **Login rate limiting** — a sliding window per client address, 8 auth attempts a
   minute, returning `429`. It is per warm instance, so it is a brake on one visitor
   rather than a fleet-wide guarantee; GoTrue throttles independently on top of it. Both
   facts are stated here rather than glossed over.
3. **Password storage** — bcrypt, inside Supabase. There is no hashing code in this repo
   and no password column in the schema. Writing a home-grown hasher would be a
   downgrade.
4. **Generic errors** — every failure is one sentence plus a short `ref`. The traceback
   and the upstream body go to the platform log. That matters most for the upstream
   exception path: a `requests` error message repeats the URL and headers of the call that
   failed.
5. **Authorisation** — `supabase/schema.sql` enables and *forces* RLS on both tables with
   `using (auth.uid() = user_id) with check (auth.uid() = user_id)`, and grants nothing to
   `anon`.
6. **Transport** — CSP with `script-src 'self'` (no `unsafe-eval`), `nosniff`,
   `frame-ancestors 'none'`, `form-action 'self'`, `no-store` on API responses.
7. **Confidentiality** — PBKDF2-SHA256 with 210,000 iterations mints a **non-extractable**
   `CryptoKey`, so no script — including a compromised one on the page — can serialise the
   key out of the tab. A sealed sentinel proves the password produced the right key
   without storing either.

## Two consequences worth knowing before a demo

* **Changing the Supabase password orphans the vault.** The key is derived from the
  password that sealed it, so after a change the unlock screen needs the *old* password.
  There is no reset: lost password means lost ciphertext, which is the point of client-side
  encryption.
* **Sign-up may need email confirmation**, depending on the Supabase project's Auth →
  Providers → Email settings. The gateway reports `confirmation_required` honestly instead
  of pretending a session opened.

## Run it

```bash
npm install
npm run dev                                  # http://localhost:5173
flask --app api/index.py run --port 5001      # in another shell, reads .env if exported
```

Tests — both run offline, no network and no database:

```bash
npm run test:api       # 45 assertions: validation, throttle, fail-closed, leakage sweep
npm run test:crypto    #  9 assertions: round trip, wrong key, tampered ciphertext
```

`api/test_gateway.py` replaces the upstream call with a stub and asserts on every response
body that no key, host, traceback or upstream wording escaped.

## Deploy

Two Vercel services from one repository (`vercel.json`): `frontend` builds with Vite,
`backend` runs `api/index.py`, with `/api/*` rewritten to the backend.

```bash
npx vercel deploy --prod
npx vercel env add VITE_SUPABASE_URL        production --project buildsecure-cyphercore
npx vercel env add VITE_SUPABASE_ANON_KEY   production --project buildsecure-cyphercore
npx vercel env add SUPABASE_URL             production --secret --project buildsecure-cyphercore
npx vercel env add SUPABASE_ANON_KEY        production --secret --project buildsecure-cyphercore
```

Then apply `supabase/schema.sql` in the Supabase SQL editor and redeploy once so the
`VITE_` values are compiled in.

## Layout

```
api/index.py        gateway: validation, throttle, fail-closed auth
api/test_gateway.py offline security tests
src/crypto.js       PBKDF2 + AES-GCM, non-extractable key
src/vault.js        ciphertext CRUD against the two tables
src/App.jsx         sign in → unlock → vault, with idle auto-lock after 5 minutes
check-crypto.mjs    Node-side proof of the crypto layer
supabase/schema.sql tables, constraints, forced RLS
```
