// Table state ↔ URL query string sync.
//
// List pages keep their search/filter/pagination/sort state in the query string so the
// state survives navigating into a detail page and back (pages are destroyed/recreated
// on every route change), as well as hard reloads and copied links. Fresh navigations
// via `navigate()` produce a clean URL, which reads back as the page's defaults — so a
// nav-link click intentionally resets the table.

/**
 * Reads the current location.search into a state object shaped by `defaults`.
 * Only keys present in `defaults` are read; unknown params are ignored. A default
 * whose value is a number coerces the param with parseInt, falling back to the
 * default when the param is missing, non-numeric, or < 1.
 *
 * @template {Record<string, string | number>} T
 * @param {T} defaults
 * @returns {T}
 */
export function readQuery(defaults) {
  if (typeof window === 'undefined') return /** @type {T} */ ({ ...defaults })
  /** @type {Record<string, string | number>} */
  const out = { ...defaults }
  const params = new URLSearchParams(window.location.search)
  for (const [key, fallback] of Object.entries(defaults)) {
    const raw = params.get(key)
    if (raw === null) continue
    if (typeof fallback === 'number') {
      const n = parseInt(raw, 10)
      out[key] = Number.isFinite(n) && n >= 1 ? n : fallback
    } else {
      out[key] = raw
    }
  }
  return /** @type {T} */ (out)
}

/**
 * Serializes `state` into the CURRENT history entry's query string via replaceState.
 * Only keys whose value differs from `defaults` are written, so default state yields
 * a clean URL (/packages, not /packages?page=1&limit=50).
 *
 * The existing history state object is passed through untouched — the router's
 * `{ page, params, idx }` entry state drives the popstate restore in App.svelte and
 * the in-app Back check on detail pages, and must never be replaced here.
 *
 * @param {Record<string, string | number>} state
 * @param {Record<string, string | number>} defaults
 */
export function writeQuery(state, defaults) {
  if (typeof window === 'undefined' || !window.history) return
  const params = new URLSearchParams()
  for (const [key, fallback] of Object.entries(defaults)) {
    const value = state[key]
    if (value === undefined || value === fallback) continue
    params.set(key, String(value))
  }
  const qs = params.toString()
  const url = window.location.pathname + (qs ? `?${qs}` : '')
  window.history.replaceState(window.history.state, '', url)
}
