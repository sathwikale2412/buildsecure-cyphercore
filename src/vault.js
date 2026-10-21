import { supabase } from './supabase'
import { createVault, seal, unlockVault, unseal } from './crypto'

// The two tables below are the entire server-side record of a vault: a salt, one sealed
// sentinel, and ciphertext. Payloads are ciphered before they get here and deciphered
// only in this tab's memory.

export async function getSettings(userId) {
  const { data, error } = await supabase
    .from('vault_settings')
    .select('salt, check_cipher, check_nonce')
    .eq('user_id', userId)
    .maybeSingle()
  if (error) throw new Error('vault settings unavailable')
  return data
}

export async function initVault(userId, password) {
  const { salt, check } = await createVault(password)
  const { error } = await supabase.from('vault_settings').insert({
    user_id: userId,
    salt,
    check_cipher: check.cipher,
    check_nonce: check.nonce,
  })
  if (error) throw new Error('vault settings unavailable')
  return unlockVault(password, salt, check)
}

export async function openVault(userId, password) {
  const settings = await getSettings(userId)
  if (!settings) return initVault(userId, password)
  return unlockVault(password, settings.salt, {
    cipher: settings.check_cipher,
    nonce: settings.check_nonce,
  })
}

export async function listItems(userId) {
  const { data, error } = await supabase
    .from('vault_items')
    .select('id, payload_cipher, payload_nonce, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
  if (error) throw new Error('vault items unavailable')
  return data ?? []
}

export async function addItem(userId, key, { label, value, note }) {
  const payload = await seal(key, JSON.stringify({ label, value, note }))
  const { error } = await supabase
    .from('vault_items')
    .insert({ user_id: userId, payload_cipher: payload.cipher, payload_nonce: payload.nonce })
  if (error) throw new Error('vault item unavailable')
}

export async function removeItem(userId, id) {
  const { error } = await supabase.from('vault_items').delete().eq('user_id', userId).eq('id', id)
  if (error) throw new Error('vault item unavailable')
}

export async function readItem(key, row) {
  const text = await unseal(key, { cipher: row.payload_cipher, nonce: row.payload_nonce })
  return JSON.parse(text)
}
