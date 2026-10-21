const base = import.meta.env.VITE_API_BASE || '/api'

async function call(path, { method = 'POST', body } = {}) {
  let response
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    // A dropped or blocked request says nothing useful about the cause, and the
    // gateway's own detail never reaches the browser anyway.
    return { ok: false, message: 'The vault service is unreachable. Try again.' }
  }
  let payload = null
  try {
    payload = await response.json()
  } catch {
    payload = null
  }
  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      message: payload?.message || 'The vault service rejected that request.',
      fields: payload?.fields || null,
      ref: payload?.ref || null,
      unavailable: response.status === 503,
    }
  }
  return { ok: true, data: payload }
}

export const login = (email, password) => call('/auth/login', { body: { email, password } })
export const signup = (email, password) => call('/auth/signup', { body: { email, password } })
export const health = () => call('/health', { method: 'GET' })
