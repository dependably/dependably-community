// Client-side mirror of src/Dependably/Security/PasswordPolicy.cs.
// The SERVER is the authoritative gate; this module exists only to give the
// user immediate feedback in the password modal and to block obviously-weak
// submits before the round-trip. Any policy change must be made in BOTH
// places, with the server treated as source of truth.

import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core'
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common'
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en'

export const MIN_LENGTH = 12
export const MAX_BYTES_UTF8 = 72
export const MIN_ZXCVBN_SCORE = 3
export const ALWAYS_BLOCKED = ['dependably']

let configured = false
function ensureConfigured() {
  if (configured) return
  zxcvbnOptions.setOptions({
    translations: zxcvbnEnPackage.translations,
    graphs: zxcvbnCommonPackage.adjacencyGraphs,
    dictionary: { ...zxcvbnCommonPackage.dictionary, ...zxcvbnEnPackage.dictionary },
  })
  configured = true
}

function normalize(value) {
  return value
    .normalize('NFC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, '')
}

function emailLocalPart(email) {
  if (!email) return null
  const at = email.indexOf('@')
  return at > 0 ? email.slice(0, at) : null
}

function findContextMatch(password, context) {
  const { email, tenantSlug } = context ?? {}
  const normalized = normalize(password)
  for (const blocked of ALWAYS_BLOCKED) {
    if (normalized.includes(blocked)) return blocked
  }
  const local = emailLocalPart(email)
  if (local && local.length >= 3 && normalized.includes(normalize(local))) return local
  if (tenantSlug && tenantSlug.length >= 3 && normalized.includes(normalize(tenantSlug))) return tenantSlug
  return null
}

/**
 * Evaluate a candidate password against the same rules as the server.
 * Returns:
 *   { verdict, score?, byteLength?, matchedTerm?, warning?, suggestions? }
 *
 * verdict ∈ 'ok' | 'too_short' | 'too_long' | 'low_entropy' | 'contains_context'
 */
export function evaluatePassword(password, context = {}) {
  ensureConfigured()
  const pw = password ?? ''
  if (pw.length < MIN_LENGTH) {
    return { verdict: 'too_short', minLength: MIN_LENGTH, score: 0 }
  }
  const byteLength = new TextEncoder().encode(pw).length
  if (byteLength > MAX_BYTES_UTF8) {
    return { verdict: 'too_long', maxBytes: MAX_BYTES_UTF8, byteLength, score: 0 }
  }
  const matched = findContextMatch(pw, context)
  if (matched !== null) {
    return { verdict: 'contains_context', matchedTerm: matched, score: 0 }
  }
  const userInputs = [
    ...ALWAYS_BLOCKED,
    context.email,
    emailLocalPart(context.email),
    context.tenantSlug,
  ].filter(Boolean)
  const result = zxcvbn(pw, userInputs)
  if (result.score < MIN_ZXCVBN_SCORE) {
    return {
      verdict: 'low_entropy',
      score: result.score,
      warning: result.feedback?.warning || '',
      suggestions: result.feedback?.suggestions || [],
    }
  }
  return { verdict: 'ok', score: result.score }
}
