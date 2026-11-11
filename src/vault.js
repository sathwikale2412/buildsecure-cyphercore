import { supabase } from './supabase'
import { createVault, seal, unlockVault, unseal } from './crypto'

function localSettingsKey(userId) {
  return `cyphercore_settings_${userId}`
}

function localItemsKey(userId) {
  return `cyphercore_items_${userId}`
}

function getLocalSettings(userId) {
  try {
    const raw = localStorage.getItem(localSettingsKey(userId))
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

function setLocalSettings(userId, settings) {
  try {
    localStorage.setItem(localSettingsKey(userId), JSON.stringify(settings))
  } catch {}
}

function getLocalItems(userId) {
  try {
    const raw = localStorage.getItem(localItemsKey(userId))
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

function setLocalItems(userId, items) {
  try {
    localStorage.setItem(localItemsKey(userId), JSON.stringify(items))
  } catch {}
}

export async function getSettings(userId) {
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('vault_settings')
        .select('salt, check_cipher, check_nonce')
        .eq('user_id', userId)
        .maybeSingle()
      if (!error && data) return data
    } catch {}
  }
  return getLocalSettings(userId)
}

export async function initVault(userId, password) {
  const { salt, check } = await createVault(password)
  const settingsObj = {
    salt,
    check_cipher: check.cipher,
    check_nonce: check.nonce,
  }
  if (supabase) {
    try {
      await supabase.from('vault_settings').insert({
        user_id: userId,
        ...settingsObj,
      })
    } catch {}
  }
  setLocalSettings(userId, settingsObj)
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
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('vault_items')
        .select('id, payload_cipher, payload_nonce, created_at')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
      if (!error && data && data.length > 0) return data
    } catch {}
  }
  return getLocalItems(userId)
}

export async function addItem(userId, key, { label, value, note }) {
  const payload = await seal(key, JSON.stringify({ label, value, note }))
  const itemObj = {
    id: `item-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    user_id: userId,
    payload_cipher: payload.cipher,
    payload_nonce: payload.nonce,
    created_at: new Date().toISOString()
  }
  if (supabase) {
    try {
      await supabase.from('vault_items').insert({
        user_id: userId,
        payload_cipher: payload.cipher,
        payload_nonce: payload.nonce
      })
    } catch {}
  }
  const items = getLocalItems(userId)
  items.unshift(itemObj)
  setLocalItems(userId, items)
}

export async function removeItem(userId, id) {
  if (supabase) {
    try {
      await supabase.from('vault_items').delete().eq('user_id', userId).eq('id', id)
    } catch {}
  }
  const items = getLocalItems(userId).filter((i) => i.id !== id)
  setLocalItems(userId, items)
}

export async function readItem(key, row) {
  const text = await unseal(key, { cipher: row.payload_cipher, nonce: row.payload_nonce })
  return JSON.parse(text)
}
