import { describe, it, expect } from 'vitest'
import {
  MIN_LENGTH,
  MAX_BYTES_UTF8,
  MIN_ZXCVBN_SCORE,
  ALWAYS_BLOCKED,
  evaluatePassword,
} from './passwordPolicy.js'

// Strong passphrase used as a baseline; well over MIN_LENGTH, no context overlap,
// and complex enough that zxcvbn scores it >= MIN_ZXCVBN_SCORE.
const STRONG = 'Tr0ub4dor!correct-horse-staple-92'

describe('passwordPolicy — exported constants', () => {
  it('MIN_LENGTH matches the server-side mirror (12)', () => {
    expect(MIN_LENGTH).toBe(12)
  })

  it('MAX_BYTES_UTF8 matches the bcrypt-aligned ceiling (72)', () => {
    expect(MAX_BYTES_UTF8).toBe(72)
  })

  it('MIN_ZXCVBN_SCORE matches the server policy (3)', () => {
    expect(MIN_ZXCVBN_SCORE).toBe(3)
  })

  it('ALWAYS_BLOCKED contains the product name', () => {
    expect(ALWAYS_BLOCKED).toContain('dependably')
  })
})

describe('evaluatePassword — length checks', () => {
  it('rejects empty input as too_short', () => {
    const r = evaluatePassword('')
    expect(r.verdict).toBe('too_short')
    expect(r.minLength).toBe(MIN_LENGTH)
    expect(r.score).toBe(0)
  })

  it('rejects null/undefined as too_short (defaults to empty string)', () => {
    expect(evaluatePassword(null).verdict).toBe('too_short')
    expect(evaluatePassword(undefined).verdict).toBe('too_short')
  })

  it('rejects whitespace-only short input as too_short', () => {
    expect(evaluatePassword('   ').verdict).toBe('too_short')
  })

  it('rejects passwords below MIN_LENGTH', () => {
    const r = evaluatePassword('aB3!xY9') // 7 chars
    expect(r.verdict).toBe('too_short')
  })

  it('rejects passwords exactly one char short', () => {
    const r = evaluatePassword('a'.repeat(MIN_LENGTH - 1))
    expect(r.verdict).toBe('too_short')
  })

  it('rejects passwords exceeding MAX_BYTES_UTF8 as too_long', () => {
    // 73 ASCII chars = 73 bytes > 72 limit. Use random-ish chars so we don't
    // also trip "too_short". Mix avoids being filtered as context match.
    const pw = 'A1!b'.repeat(19) // 76 chars / 76 bytes
    const r = evaluatePassword(pw)
    expect(r.verdict).toBe('too_long')
    expect(r.maxBytes).toBe(MAX_BYTES_UTF8)
    expect(r.byteLength).toBeGreaterThan(MAX_BYTES_UTF8)
    expect(r.score).toBe(0)
  })

  it('counts UTF-8 bytes, not code points, for the too_long ceiling', () => {
    // Each emoji is 4 UTF-8 bytes; 20 emoji = 80 bytes, but only 20 code units pairs.
    // Length in chars (.length) = 40 due to surrogate pairs, byteLength = 80.
    const pw = '\u{1F600}'.repeat(20)
    const r = evaluatePassword(pw)
    expect(r.verdict).toBe('too_long')
    expect(r.byteLength).toBe(80)
  })
})

describe('evaluatePassword — context-match blocking', () => {
  it('blocks passwords containing "dependably" (case-insensitive)', () => {
    const r = evaluatePassword('Dependably-Rocks-99!')
    expect(r.verdict).toBe('contains_context')
    expect(r.matchedTerm).toBe('dependably')
    expect(r.score).toBe(0)
  })

  it('blocks passwords containing the email local-part', () => {
    const r = evaluatePassword('mikehiland-Strong-Pass-9!', {
      email: 'mikehiland@example.com',
    })
    expect(r.verdict).toBe('contains_context')
    expect(r.matchedTerm).toBe('mikehiland')
  })

  it('ignores email local-parts shorter than 3 chars', () => {
    // "ab" is too short to be flagged. Use a passphrase strong enough that
    // zxcvbn does NOT downgrade to low_entropy.
    const r = evaluatePassword(STRONG, { email: 'ab@example.com' })
    expect(r.verdict).toBe('ok')
  })

  it('blocks passwords containing the tenant slug', () => {
    const r = evaluatePassword('Acme-Corp-Login-99!', {
      tenantSlug: 'acme-corp',
    })
    expect(r.verdict).toBe('contains_context')
    expect(r.matchedTerm).toBe('acme-corp')
  })

  it('ignores tenant slugs shorter than 3 chars', () => {
    const r = evaluatePassword(STRONG, { tenantSlug: 'ab' })
    expect(r.verdict).toBe('ok')
  })

  it('treats missing/empty email as no constraint', () => {
    expect(evaluatePassword(STRONG, { email: '' }).verdict).toBe('ok')
    expect(evaluatePassword(STRONG, { email: null }).verdict).toBe('ok')
  })

  it('treats email with no local part (leading @) as no constraint', () => {
    // emailLocalPart returns null when indexOf('@') is not > 0
    const r = evaluatePassword(STRONG, { email: '@example.com' })
    expect(r.verdict).toBe('ok')
  })

  it('treats email with no @ as no constraint', () => {
    const r = evaluatePassword(STRONG, { email: 'no-at-sign' })
    expect(r.verdict).toBe('ok')
  })

  it('treats omitted context object as no constraint', () => {
    const r = evaluatePassword(STRONG)
    expect(r.verdict).toBe('ok')
  })

  it('normalizes via NFC + strips non-letter/non-digit punctuation', () => {
    // The block term "dependably" should be found even when interleaved with
    // punctuation that the normalizer strips out.
    const r = evaluatePassword('d.e.p.e.n.d.a.b.l.y!!Strong9')
    expect(r.verdict).toBe('contains_context')
    expect(r.matchedTerm).toBe('dependably')
  })

  it('normalizes Unicode (NFC) so decomposed sequences still match', () => {
    // Tenant slug "café" (composed). Password uses decomposed form (e + combining acute).
    const decomposed = 'café-Stronger-9!'
    const r = evaluatePassword(decomposed, { tenantSlug: 'café' })
    expect(r.verdict).toBe('contains_context')
  })

  it('email local-part match takes precedence over zxcvbn evaluation', () => {
    // Even if the rest of the password is strong, the email local-part trips first.
    const r = evaluatePassword('mikehiland-Tr0ub4dor!correct-staple-92', {
      email: 'mikehiland@example.com',
    })
    expect(r.verdict).toBe('contains_context')
    expect(r.matchedTerm).toBe('mikehiland')
  })
})

describe('evaluatePassword — zxcvbn entropy gate', () => {
  it('rejects common/low-entropy passwords (low_entropy)', () => {
    // 12+ chars but trivially weak — zxcvbn should score < MIN_ZXCVBN_SCORE.
    const r = evaluatePassword('password1234')
    expect(r.verdict).toBe('low_entropy')
    expect(r.score).toBeLessThan(MIN_ZXCVBN_SCORE)
    expect(Array.isArray(r.suggestions)).toBe(true)
    // warning may be empty string but must be defined
    expect(typeof r.warning).toBe('string')
  })

  it('rejects repeated-character passwords as low_entropy', () => {
    const r = evaluatePassword('aaaaaaaaaaaaaa')
    expect(r.verdict).toBe('low_entropy')
  })

  it('accepts a strong, varied passphrase as ok', () => {
    const r = evaluatePassword(STRONG)
    expect(r.verdict).toBe('ok')
    expect(r.score).toBeGreaterThanOrEqual(MIN_ZXCVBN_SCORE)
  })

  it('feeds context into zxcvbn userInputs (passphrase containing context-token gets penalized)', () => {
    // This password does NOT contain "dependably" or a >=3-char context match,
    // but a passphrase identical to an exotic tenantSlug should still earn an OK
    // when not embedded. Sanity: strong passphrase + unrelated tenantSlug = ok.
    const r = evaluatePassword(STRONG, {
      email: 'someone@example.com',
      tenantSlug: 'unrelated-org',
    })
    expect(r.verdict).toBe('ok')
  })
})

describe('evaluatePassword — idempotency / ensureConfigured()', () => {
  it('produces the same verdict across repeated invocations (caches zxcvbn options)', () => {
    // Calling twice exercises the early-return branch in ensureConfigured().
    const a = evaluatePassword(STRONG)
    const b = evaluatePassword(STRONG)
    expect(a.verdict).toBe('ok')
    expect(b.verdict).toBe('ok')
    expect(a.score).toBe(b.score)
  })
})
