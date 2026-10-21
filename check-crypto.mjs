// Node-side check of the browser crypto layer. WebCrypto is global in Node 20+, so the
// same functions that run in the vault tab can be proven here: a round trip, a wrong
// password, and a tampered ciphertext all behave without a browser or a database.
//
//   npm run test:crypto

import { randomBytes } from 'node:crypto'
import { createVault, deriveKey, seal, unseal, unlockVault } from './src/crypto.js'

let passed = 0
let failed = 0
const check = (label, ok, detail = '') => {
  if (ok) {
    passed += 1
    console.log(`  PASS  ${label}`)
  } else {
    failed += 1
    console.log(`  FAIL  ${label} ${detail}`)
  }
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64')

console.log('\n--- the vault key survives a round trip and nothing else does ---')
const password = 'a-keeper-of-secrets-42'
const vault = await createVault(password)
check('a salt is minted per vault', typeof vault.salt === 'string' && vault.salt.length >= 16)
check('the sentinel is stored as ciphertext', vault.check.cipher !== 'cypher-core/vault-check/v1')

const key = await unlockVault(password, vault.salt, vault.check)
check('the right password opens the vault', key !== null)
check('the wrong password is refused', (await unlockVault('guessed-wrong-1', vault.salt, vault.check)) === null)
check('a different salt is a different key', (await unlockVault(password, b64(randomBytes(16)), vault.check)) === null)

const item = await seal(key, JSON.stringify({ label: 'staging', value: 'AKIAIOSFODNN7', note: '' }))
check('plaintext never appears in the sealed blob', !item.cipher.includes('AKIAIOSFODNN7'))
check('decryption returns the entry', (await unseal(key, item)) === JSON.stringify({ label: 'staging', value: 'AKIAIOSFODNN7', note: '' }))

const other = await deriveKey(password, b64(randomBytes(16)))
let tamperRejected = false
try {
  await unseal(other, item)
} catch {
  tamperRejected = true
}
check('another key cannot read it', tamperRejected)

const flipped = { ...item, cipher: item.cipher.slice(0, -4) + (item.cipher.endsWith('AAAA') ? 'BBBB' : 'AAAA') }
let gcmRejected = false
try {
  await unseal(key, flipped)
} catch {
  gcmRejected = true
}
check('a edited ciphertext fails the GCM tag', gcmRejected)

console.log(`\n${passed} passed, ${failed} failed\n`)
process.exit(failed ? 1 : 0)
