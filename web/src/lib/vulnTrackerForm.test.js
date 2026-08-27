import { describe, it, expect } from 'vitest'
import {
  BATCH_MAX,
  BATCH_MIN,
  DEFAULT_BATCH_SIZE,
  DEFAULT_STALENESS_HOURS,
  STALENESS_MAX,
  STALENESS_MIN,
  buildPayload,
  clearsStoredConnection,
  connectionState,
  discardsStoredToken,
  formFromConfig,
  isValidBaseUrl,
  validateForm,
} from './vulnTrackerForm.js'

/** A GET /vuln-tracker-config response with a live, credentialed connection. */
function storedConfig(overrides = {}) {
  return {
    enabled: true,
    baseUrl: 'https://tracker.example.com',
    hasToken: true,
    maxStalenessHours: 72,
    batchSize: 250,
    configured: true,
    active: true,
    secretsAvailable: true,
    ...overrides,
  }
}

describe('formFromConfig', () => {
  it('seeds every editable field from the response', () => {
    expect(formFromConfig(storedConfig())).toEqual({
      enabled: true,
      baseUrl: 'https://tracker.example.com',
      maxStalenessHours: '72',
      batchSize: '250',
    })
  })

  it('never seeds a token field — the token is write-only and never echoed', () => {
    const form = formFromConfig(storedConfig())
    expect(form).not.toHaveProperty('token')
    expect(JSON.stringify(form)).not.toContain('Token')
  })

  it('falls back to the server defaults when nothing is stored yet', () => {
    expect(formFromConfig(null)).toEqual({
      enabled: false,
      baseUrl: '',
      maxStalenessHours: String(DEFAULT_STALENESS_HOURS),
      batchSize: String(DEFAULT_BATCH_SIZE),
    })
  })

  it('keeps an explicit zero-ish stored value rather than substituting the default', () => {
    const form = formFromConfig(storedConfig({ maxStalenessHours: 1, batchSize: 1 }))
    expect(form.maxStalenessHours).toBe('1')
    expect(form.batchSize).toBe('1')
  })
})

describe('buildPayload', () => {
  const form = { enabled: true, baseUrl: '  https://tracker.example.com  ', maxStalenessHours: '72', batchSize: '250' }

  it('sends null for an untouched token so the stored one is preserved', () => {
    expect(buildPayload(form, '').token).toBeNull()
  })

  it('sends the typed token so a non-empty value rotates the stored one', () => {
    expect(buildPayload(form, 'new-secret').token).toBe('new-secret')
  })

  it('trims the base URL and coerces the numeric fields', () => {
    expect(buildPayload(form, '')).toEqual({
      enabled: true,
      baseUrl: 'https://tracker.example.com',
      token: null,
      maxStalenessHours: 72,
      batchSize: 250,
    })
  })

  it('sends an empty base URL verbatim — that is how the connection is torn down', () => {
    expect(buildPayload({ ...form, baseUrl: '   ' }, '').baseUrl).toBe('')
  })

  it('carries enabled=false with the URL intact — pausing does not discard the connection', () => {
    const paused = buildPayload({ ...form, enabled: false }, '')
    expect(paused.enabled).toBe(false)
    expect(paused.baseUrl).toBe('https://tracker.example.com')
  })
})

describe('isValidBaseUrl', () => {
  it.each([
    'https://tracker.example.com',
    'http://tracker.internal:8080/api',
    'https://tracker.example.com/base/path',
  ])('accepts the absolute http(s) URL %s', (url) => {
    expect(isValidBaseUrl(url)).toBe(true)
  })

  it.each([
    ['a relative path', '/api/tracker'],
    ['a bare host', 'tracker.example.com'],
    ['a file scheme', 'file:///etc/passwd'],
    ['an ftp scheme', 'ftp://tracker.example.com'],
    ['garbage', 'http://'],
    ['an empty string', ''],
    ['whitespace only', '   '],
  ])('rejects %s', (_label, url) => {
    expect(isValidBaseUrl(url)).toBe(false)
  })
})

describe('validateForm', () => {
  const valid = { enabled: true, baseUrl: 'https://tracker.example.com', maxStalenessHours: '72', batchSize: '250' }

  it('passes a well-formed connection', () => {
    expect(validateForm(valid)).toBeNull()
  })

  it('passes an empty base URL — that is the off switch, not an error', () => {
    expect(validateForm({ ...valid, baseUrl: '' })).toBeNull()
  })

  it('rejects a non-http scheme before the request is sent', () => {
    expect(validateForm({ ...valid, baseUrl: 'ftp://tracker.example.com' }))
      .toBe('settings.vulnTracker.errors.baseUrl')
  })

  it.each([
    ['below the floor', String(STALENESS_MIN - 1)],
    ['above the ceiling', String(STALENESS_MAX + 1)],
    ['empty', ''],
    ['non-numeric', 'soon'],
    ['fractional', '1.5'],
  ])('rejects a staleness horizon that is %s', (_label, hours) => {
    expect(validateForm({ ...valid, maxStalenessHours: hours }))
      .toBe('settings.vulnTracker.errors.staleness')
  })

  it.each([String(STALENESS_MIN), String(STALENESS_MAX)])(
    'accepts the staleness bound %s', (hours) => {
      expect(validateForm({ ...valid, maxStalenessHours: hours })).toBeNull()
    })

  it.each([
    ['below the floor', String(BATCH_MIN - 1)],
    ['above the producer cap', String(BATCH_MAX + 1)],
    ['empty', ''],
    ['non-numeric', 'lots'],
  ])('rejects a batch size that is %s', (_label, size) => {
    expect(validateForm({ ...valid, batchSize: size }))
      .toBe('settings.vulnTracker.errors.batchSize')
  })

  it.each([String(BATCH_MIN), String(BATCH_MAX)])('accepts the batch bound %s', (size) => {
    expect(validateForm({ ...valid, batchSize: size })).toBeNull()
  })

  it('reports the base URL first when several fields are wrong at once', () => {
    expect(validateForm({ baseUrl: 'nope', maxStalenessHours: '0', batchSize: '0' }))
      .toBe('settings.vulnTracker.errors.baseUrl')
  })
})

describe('clearsStoredConnection / discardsStoredToken', () => {
  it('flags emptying a stored base URL', () => {
    expect(clearsStoredConnection(storedConfig(), '')).toBe(true)
    expect(clearsStoredConnection(storedConfig(), '   ')).toBe(true)
  })

  it('does not flag editing a stored base URL to another value', () => {
    expect(clearsStoredConnection(storedConfig(), 'https://other.example.com')).toBe(false)
  })

  it('does not flag an empty field when nothing was stored', () => {
    expect(clearsStoredConnection(storedConfig({ baseUrl: '' }), '')).toBe(false)
    expect(clearsStoredConnection(null, '')).toBe(false)
  })

  it('escalates to the credential warning only when a token is actually stored', () => {
    expect(discardsStoredToken(storedConfig(), '')).toBe(true)
    expect(discardsStoredToken(storedConfig({ hasToken: false }), '')).toBe(false)
  })

  it('does not warn about the credential when the URL is merely being changed', () => {
    expect(discardsStoredToken(storedConfig(), 'https://other.example.com')).toBe(false)
  })
})

describe('connectionState', () => {
  it('is active when a URL is stored and enrichment is enabled', () => {
    expect(connectionState(storedConfig())).toBe('active')
  })

  it('is paused — not unconfigured — when a stored connection is disabled', () => {
    expect(connectionState(storedConfig({ enabled: false, active: false }))).toBe('paused')
  })

  it('is notConfigured when no usable base URL is stored, enabled or not', () => {
    expect(connectionState(storedConfig({ configured: false, active: false }))).toBe('notConfigured')
    expect(connectionState(storedConfig({ enabled: false, configured: false, active: false })))
      .toBe('notConfigured')
  })

  it('treats a missing config as notConfigured', () => {
    expect(connectionState(null)).toBe('notConfigured')
  })
})
