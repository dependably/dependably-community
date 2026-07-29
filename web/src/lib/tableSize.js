/**
 * Remembers how many rows a table actually held, so its loading placeholder reserves the height
 * the loaded table will occupy rather than the page size it asked for.
 *
 * Reserving the page size is a guess that is wrong for every table with fewer rows than its
 * limit: fifty placeholder rows collapsing to four moves everything below the table further than
 * having reserved nothing. The last real count is the best available estimate, and on every
 * visit after the first it is exact.
 *
 * Session-scoped: the counts describe this tenant's data as the user is currently filtering it,
 * which is not worth carrying across browser sessions, and sessionStorage is per-tab so two tabs
 * on different orgs cannot seed each other.
 */

const KEY = 'tableRowCounts'

/** Beyond a viewport's worth of rows the reservation stops buying anything (see DataTable). */
const MAX_REMEMBERED = 30

function read() {
  if (typeof sessionStorage === 'undefined') return {}
  try {
    const raw = sessionStorage.getItem(KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    // Unparseable or unavailable storage is not worth failing a page render over — the table
    // falls back to its caller-supplied estimate.
    return {}
  }
}

/**
 * The remembered row count for a table, or null when it has not been seen this session.
 * @param {string} key stable identifier for the table, e.g. 'packages'
 * @returns {number | null}
 */
export function rememberedRowCount(key) {
  if (!key) return null
  const count = read()[key]
  return typeof count === 'number' && count > 0 ? Math.min(count, MAX_REMEMBERED) : null
}

/**
 * Records the row count a table just rendered. Zero is recorded as absent rather than as zero: a
 * table that legitimately has no rows renders its empty-state text, which is a fixed height the
 * placeholder should not try to match.
 * @param {string} key
 * @param {number} count
 */
export function rememberRowCount(key, count) {
  if (!key || typeof sessionStorage === 'undefined') return
  if (typeof count !== 'number' || count <= 0) return
  try {
    const all = read()
    const next = Math.min(count, MAX_REMEMBERED)
    if (all[key] === next) return
    all[key] = next
    sessionStorage.setItem(KEY, JSON.stringify(all))
  } catch {
    // Storage full or blocked — the memory is an optimization, never a correctness requirement.
  }
}
