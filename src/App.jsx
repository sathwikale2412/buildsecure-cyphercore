import { useCallback, useEffect, useRef, useState } from 'react'
import { health, login, signup } from './api'
import { isSupabaseConfigured, supabase } from './supabase'
import { addItem, listItems, openVault, readItem, removeItem } from './vault'

const IDLE_LOCK_MS = 5 * 60 * 1000
const LIMITS = { label: 120, value: 4096, note: 4096 }

export default function App() {
  const [phase, setPhase] = useState('boot')
  const [mode, setMode] = useState('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [status, setStatus] = useState({ tone: 'info', text: '' })
  const [gateway, setGateway] = useState({ checked: false, ready: false })
  const [items, setItems] = useState([])
  const [draft, setDraft] = useState({ label: '', value: '', note: '' })
  const [revealed, setRevealed] = useState({})
  const [busy, setBusy] = useState(false)

  const keyRef = useRef(null)
  const userRef = useRef(null)

  const say = (tone, text) => setStatus({ tone, text })

  const refreshItems = useCallback(async () => {
    if (!userRef.current || !keyRef.current) return
    try {
      setItems(await listItems(userRef.current.id))
    } catch {
      say('error', 'The stored records could not be read. The vault tables may not exist yet — run supabase/schema.sql in the database.')
    }
  }, [])

  useEffect(() => {
    let alive = true
    health().then((result) => alive && setGateway({ checked: true, ready: Boolean(result.ok && result.data?.configured) }))
    if (!isSupabaseConfigured) {
      setPhase('auth')
      return () => {
        alive = false
      }
    }
    supabase.auth.getSession().then(({ data }) => {
      if (!alive) return
      if (data.session) {
        userRef.current = data.session.user
        setEmail(data.session.user.email ?? '')
        setPhase('unlock')
      } else {
        setPhase('auth')
      }
    })
    return () => {
      alive = false
    }
  }, [])

  const lock = useCallback(() => {
    keyRef.current = null
    setItems([])
    setRevealed({})
    setPassword('')
    setPhase('unlock')
  }, [])

  useEffect(() => {
    if (phase !== 'vault') return undefined
    let timer
    const bump = () => {
      clearTimeout(timer)
      timer = setTimeout(lock, IDLE_LOCK_MS)
    }
    const events = ['click', 'keydown', 'pointermove', 'input']
    events.forEach((name) => window.addEventListener(name, bump, { passive: true }))
    bump()
    return () => {
      clearTimeout(timer)
      events.forEach((name) => window.removeEventListener(name, bump))
    }
  }, [phase, lock])

  async function submitCredentials(event) {
    event.preventDefault()
    setBusy(true)
    const run = mode === 'signup' ? signup : login
    const result = await run(email.trim(), password)
    if (!result.ok) {
      say('error', result.ref ? `${result.message} (ref ${result.ref})` : result.message)
      if (result.unavailable) setGateway({ checked: true, ready: false })
      setBusy(false)
      return
    }
    const { access_token: access, refresh_token: refresh, needs_confirmation: confirm } = result.data
    if (confirm) {
      say('info', 'Account created. Confirm the address from the email Supabase sends, then sign in.')
      setMode('login')
      setBusy(false)
      return
    }
    if (result.data.sandbox || !supabase) {
      const demoUser = result.data.user || {
        id: `usr-${email.trim().toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
        email: email.trim().toLowerCase(),
      }
      userRef.current = demoUser
      setEmail(demoUser.email)
      await unlockWith(password)
      setBusy(false)
      return
    }
    const { data, error } = await supabase.auth.setSession({ access_token: access, refresh_token: refresh })
    if (error || !data.session) {
      say('error', 'The session could not be opened. Try again.')
      setBusy(false)
      return
    }
    userRef.current = data.session.user
    setEmail(data.session.user.email ?? email.trim())
    await unlockWith(password)
    setBusy(false)
  }

  async function unlockWith(plain) {
    if (!userRef.current) {
      say('error', 'Sign in first before unlocking.')
      return false
    }
    try {
      const key = await openVault(userRef.current.id, plain)
      if (!key) {
        keyRef.current = null
        say('error', 'This vault was sealed with a different password. Ciphertext cannot be recovered without it.')
        setPassword('')
        return false
      }
      keyRef.current = key
      setPassword('')
      setRevealed({})
      setPhase('vault')
      say('info', 'Vault unlocked. Nothing here is deciphered on a server.')
      await refreshItems()
      return true
    } catch (e) {
      console.warn('Vault open warning:', e)
      say('error', 'The vault records could not be initialized.')
      return false
    }
  }

  async function submitUnlock(event) {
    event.preventDefault()
    setBusy(true)
    await unlockWith(password)
    setBusy(false)
  }

  async function saveItem(event) {
    event.preventDefault()
    const label = draft.label.trim()
    const value = draft.value.trim()
    if (!label || !value) {
      say('error', 'A name and a secret are both required.')
      return
    }
    if (label.length > LIMITS.label || value.length > LIMITS.value || draft.note.length > LIMITS.note) {
      say('error', 'That entry is too long for the vault.')
      return
    }
    setBusy(true)
    try {
      await addItem(userRef.current.id, keyRef.current, { label, value, note: draft.note.trim() })
      setDraft({ label: '', value: '', note: '' })
      say('info', `Encrypted and stored “${label}”.`)
      await refreshItems()
    } catch {
      say('error', 'The entry could not be stored. Check the vault tables exist.')
    }
    setBusy(false)
  }

  async function toggleReveal(row) {
    if (revealed[row.id]) {
      const next = { ...revealed }
      delete next[row.id]
      setRevealed(next)
      return
    }
    try {
      const plain = await readItem(keyRef.current, row)
      setRevealed((current) => ({ ...current, [row.id]: plain }))
    } catch {
      say('error', 'That record could not be decrypted with this vault key.')
    }
  }

  async function forget(row) {
    try {
      await removeItem(userRef.current.id, row.id)
      setItems((current) => current.filter((item) => item.id !== row.id))
      say('info', 'Record deleted.')
    } catch {
      say('error', 'The record is still stored.')
    }
  }

  async function copy(plain) {
    try {
      await navigator.clipboard.writeText(plain.value)
      say('info', 'Copied to the clipboard.')
    } catch {
      say('error', 'The browser blocked clipboard access.')
    }
  }

  async function signOut() {
    if (isSupabaseConfigured) await supabase.auth.signOut()
    keyRef.current = null
    userRef.current = null
    setItems([])
    setPassword('')
    setEmail('')
    setPhase('auth')
    say('info', 'Signed out. The key left memory with the session.')
  }

  return (
    <div className="shell">
      <header className="masthead">
        <div>
          <h1>Cypher Core</h1>
          <p className="tagline">Client-side encrypted secret vault · AES-256-GCM, PBKDF2-SHA256 210k</p>
        </div>
        <div className="chips">
          <span className={`chip ${gateway.checked ? (gateway.ready ? 'good' : 'warn') : ''}`}>
            gateway {gateway.checked ? (gateway.ready ? 'reachable' : 'not configured') : 'checking'}
          </span>
          {phase === 'vault' && <span className="chip good">{items.length} sealed</span>}
          {phase === 'vault' && (
            <button className="chip action" onClick={lock}>
              lock
            </button>
          )}
          {phase === 'vault' && (
            <button className="chip action" onClick={signOut}>
              sign out
            </button>
          )}
        </div>
      </header>

      {!isSupabaseConfigured && phase !== 'boot' && (
        <p className="banner" style={{ borderColor: 'rgba(0, 242, 254, 0.4)', background: 'rgba(0, 242, 254, 0.05)', color: '#00f2fe' }}>
          Zero-Knowledge Vault Sandbox Active — Encrypted with AES-GCM-256 via Web Crypto API in local browser memory.
        </p>
      )}

      {status.text && <p className={`status ${status.tone}`}>{status.text}</p>}

      {phase === 'boot' && <p className="quiet">Opening the vault service…</p>}

      {phase === 'auth' && (
        <form className="card" onSubmit={submitCredentials}>
          <div className="tabs">
            <button type="button" className={mode === 'login' ? 'on' : ''} onClick={() => setMode('login')}>
              Sign in
            </button>
            <button type="button" className={mode === 'signup' ? 'on' : ''} onClick={() => setMode('signup')}>
              Create vault
            </button>
          </div>
          <label>
            Email
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              maxLength={254}
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={mode === 'signup' ? 10 : undefined}
              maxLength={72}
              required
            />
            {mode === 'signup' && <small>Ten characters or more. This same password seals the vault.</small>}
          </label>
          <button className="primary" disabled={busy}>
            {busy ? 'Working…' : mode === 'signup' ? 'Create and seal' : 'Unlock vault'}
          </button>
          <p className="fine">
            Credentials are checked and throttled on the server before they reach the identity provider. The
            password is never stored — Supabase keeps a bcrypt hash, and the browser derives a separate key from
            it that is marked non-extractable.
          </p>
        </form>
      )}

      {phase === 'unlock' && (
        <form className="card" onSubmit={submitUnlock}>
          <h2>Sealed vault</h2>
          <p className="quiet">
            Signed in as {email}. The session proves who you are, but the key lives only in this tab; it was
            derived from your password and dropped when the vault locked.
          </p>
          <label>
            Password
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              maxLength={72}
              required
            />
          </label>
          <button className="primary" disabled={busy}>
            {busy ? 'Deriving key…' : 'Decrypt'}
          </button>
        </form>
      )}

      {phase === 'vault' && (
        <main className="grid">
          <form className="card" onSubmit={saveItem}>
            <h2>Seal a new secret</h2>
            <label>
              Name
              <input
                value={draft.label}
                onChange={(e) => setDraft({ ...draft, label: e.target.value })}
                maxLength={LIMITS.label}
                placeholder="AWS staging key"
                required
              />
            </label>
            <label>
              Secret
              <textarea
                value={draft.value}
                onChange={(e) => setDraft({ ...draft, value: e.target.value })}
                maxLength={LIMITS.value}
                rows={3}
                placeholder="AKIA…"
                required
              />
            </label>
            <label>
              Note (optional)
              <textarea
                value={draft.note}
                onChange={(e) => setDraft({ ...draft, note: e.target.value })}
                maxLength={LIMITS.note}
                rows={2}
              />
            </label>
            <button className="primary" disabled={busy}>
              Encrypt and store
            </button>
          </form>

          <section className="card">
            <h2>Contents</h2>
            {items.length === 0 && <p className="quiet">Nothing stored yet.</p>}
            <ul className="items">
              {items.map((row) => {
                const plain = revealed[row.id]
                return (
                  <li key={row.id}>
                    <div className="row-head">
                      <strong>{plain ? plain.label : '· · · · · · · ·'}</strong>
                      <span className="when">{new Date(row.created_at).toLocaleString()}</span>
                    </div>
                    {plain && (
                      <pre className="secret">{plain.value}</pre>
                    )}
                    {plain && plain.note && <p className="note">{plain.note}</p>}
                    <div className="row-actions">
                      <button onClick={() => toggleReveal(row)}>{plain ? 'Hide' : 'Reveal'}</button>
                      {plain && <button onClick={() => copy(plain)}>Copy</button>}
                      <button className="danger" onClick={() => forget(row)}>
                        Delete
                      </button>
                    </div>
                  </li>
                )
              })}
            </ul>
          </section>
        </main>
      )}

      <footer className="card controls">
        <h2>Controls in this build</h2>
        <ul>
          <li><b>Server-side validation</b> — email shape and length, 10–72 character passwords, JSON shape and size limits enforced in api/index.py before any upstream call.</li>
          <li><b>Login rate limiting</b> — sliding window per client address, 8 auth attempts a minute on the gateway, plus the identity provider's own throttle.</li>
          <li><b>Password storage</b> — bcrypt inside Supabase GoTrue; this repo holds no hashing code and no plaintext column.</li>
          <li><b>Generic errors</b> — failures return one sentence and a short <code>ref</code>; tracebacks and upstream bodies go to the platform log only.</li>
          <li><b>Authorisation</b> — every row is pinned to <code>auth.uid()</code> by row-level security, so one account can never read another's ciphertext.</li>
          <li><b>Transport hardening</b> — CSP with <code>script-src 'self'</code>, nosniff, frame denial, no-store on API responses.</li>
          <li><b>Confidentiality</b> — AES-256-GCM in the browser with a non-extractable PBKDF2 key; the server stores ciphertext, nonce and salt only.</li>
        </ul>
      </footer>
    </div>
  )
}
