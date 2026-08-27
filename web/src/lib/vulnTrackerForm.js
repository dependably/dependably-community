// Pure form logic for the instance vulnerability-tracker connection editor
// (settings/SettingsVulnTracker.svelte).
//
// The connection is instance-level state: one per deployment, owned by the operator, serving
// every tenant. There is no per-org override, so nothing here is tenant-aware.
//
// Kept out of the .svelte file because the interesting parts are decisions, not markup: which
// payload a given form state produces, whether a save is about to discard a stored credential,
// and whether a value will clear the server's bounds check before the request is sent. Svelte
// components have no test harness in this repo; a module does.

/** Lower bound the server enforces on maxStalenessHours (VulnTrackerSettings.Validate). */
export const STALENESS_MIN = 1
/** Upper bound the server enforces on maxStalenessHours (one year, in hours). */
export const STALENESS_MAX = 8760
/** Lower bound the server enforces on batchSize. */
export const BATCH_MIN = 1
/** Upper bound the server enforces on batchSize — the producer's published per-request cap. */
export const BATCH_MAX = 1000

/** Server-side default staleness horizon (VulnTrackerSettings.DefaultMaxStalenessHours). */
export const DEFAULT_STALENESS_HOURS = 168
/** Server-side default batch size (VulnTrackerSettings.DefaultBatchSize). */
export const DEFAULT_BATCH_SIZE = 100

/**
 * Seed the editable form fields from a GET response. The token is deliberately absent: it is
 * write-only and never echoed, so the input always starts empty and submitting it empty
 * preserves whatever is stored.
 *
 * @param {{enabled?: boolean, baseUrl?: string|null, maxStalenessHours?: number|null, batchSize?: number|null}|null} config
 */
export function formFromConfig(config) {
  return {
    enabled: !!config?.enabled,
    baseUrl: config?.baseUrl || '',
    maxStalenessHours: String(config?.maxStalenessHours ?? DEFAULT_STALENESS_HOURS),
    batchSize: String(config?.batchSize ?? DEFAULT_BATCH_SIZE),
  }
}

/**
 * Build the PUT body. `token` is sent as null when the operator typed nothing, which the server
 * reads as "leave the stored token unchanged" — the same write-only-secret contract the SMTP
 * password uses. The base URL is trimmed and may be the empty string: that is how the connection
 * is torn down.
 *
 * @param {{enabled: boolean, baseUrl: string, maxStalenessHours: string|number, batchSize: string|number}} form
 * @param {string} token
 */
export function buildPayload(form, token) {
  return {
    enabled: !!form.enabled,
    baseUrl: (form.baseUrl || '').trim(),
    token: token ? token : null,
    maxStalenessHours: Number(form.maxStalenessHours),
    batchSize: Number(form.batchSize),
  }
}

/**
 * True when the supplied value is an absolute http(s) URL — the same scheme allowlist
 * VulnTrackerSettings.TryParseBaseUrl applies, so an unsupported scheme is refused here rather
 * than round-tripping to a 422.
 */
export function isValidBaseUrl(value) {
  const raw = (value || '').trim()
  if (!raw) return false
  let parsed
  try {
    parsed = new URL(raw)
  } catch {
    return false
  }
  return parsed.protocol === 'http:' || parsed.protocol === 'https:'
}

/**
 * Client-side mirror of the server's bounds check. Returns the i18n key of the first failing
 * field, or null when the form will pass. An empty base URL is valid — it is the off switch.
 *
 * @returns {string|null}
 */
export function validateForm(form) {
  const baseUrl = (form.baseUrl || '').trim()
  if (baseUrl && !isValidBaseUrl(baseUrl)) return 'settings.vulnTracker.errors.baseUrl'

  const hours = Number(form.maxStalenessHours)
  if (!Number.isInteger(hours) || hours < STALENESS_MIN || hours > STALENESS_MAX) {
    return 'settings.vulnTracker.errors.staleness'
  }

  const size = Number(form.batchSize)
  if (!Number.isInteger(size) || size < BATCH_MIN || size > BATCH_MAX) {
    return 'settings.vulnTracker.errors.batchSize'
  }

  return null
}

/**
 * True when saving the form as it stands would tear down a stored connection — a base URL is
 * stored and the field has been emptied. The server clears the token alongside the URL, so this
 * is the trigger for the credential-loss warning rather than a generic "you changed something".
 */
export function clearsStoredConnection(config, baseUrl) {
  return !!config?.baseUrl && (baseUrl || '').trim() === ''
}

/**
 * True when that teardown would additionally discard a stored bearer token. Separated from
 * clearsStoredConnection because only this case is unrecoverable without re-entering a secret.
 */
export function discardsStoredToken(config, baseUrl) {
  return clearsStoredConnection(config, baseUrl) && !!config?.hasToken
}

/**
 * Collapse the server's three separate facts into the one word the status tag renders.
 * `configured` means a usable base URL is stored; `enabled` is operator intent; `active` is
 * both. They stay distinct on the wire precisely so pausing never means discarding, and this
 * function is the only place the UI flattens them.
 *
 * @returns {'active'|'paused'|'notConfigured'}
 */
export function connectionState(config) {
  if (!config?.configured) return 'notConfigured'
  return config?.enabled ? 'active' : 'paused'
}
