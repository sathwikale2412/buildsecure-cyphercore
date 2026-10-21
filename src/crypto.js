// Everything secret-shaped is ciphered here, on this device, before it is ever sent.
// The AES key is derived from the vault password with PBKDF2 and is created
// non-extractable, so no code — including a compromised page — can serialise it out
// of memory or hand it to the server. Only ciphertext, nonce and salt leave.

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const KDF_ITERATIONS = 210000
const SENTINEL = 'cypher-core/vault-check/v1'

function toBase64(bytes) {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

function fromBase64(text) {
  const binary = atob(text)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function randomSalt() {
  return toBase64(crypto.getRandomValues(new Uint8Array(16)))
}

export async function deriveKey(password, saltB64) {
  const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
    'deriveKey',
  ])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', iterations: KDF_ITERATIONS, salt: fromBase64(saltB64) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function seal(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plaintext))
  return { cipher: toBase64(new Uint8Array(cipher)), nonce: toBase64(iv) }
}

export async function unseal(key, blob) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(blob.nonce) },
    key,
    fromBase64(blob.cipher),
  )
  return decoder.decode(plain)
}

// A fresh vault records the salt and one sealed sentinel. Re-opening the vault proves
// the password produced the same key, without the password or the key being stored.
export async function createVault(password) {
  const salt = randomSalt()
  const key = await deriveKey(password, salt)
  return { salt, check: await seal(key, SENTINEL) }
}

export async function unlockVault(password, salt, check) {
  const key = await deriveKey(password, salt)
  try {
    if ((await unseal(key, check)) !== SENTINEL) return null
  } catch {
    return null
  }
  return key
}
