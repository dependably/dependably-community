// Whole days elapsed since an ISO 8601 timestamp. Used for presentational "open N days" /
// "approved N days ago" copy on the vuln, quarantine, and dashboard surfaces — nothing branches
// on the value (it is display-only), so reading the browser clock needs no injected TimeProvider
// the way a src/** gate decision would.
export function daysSince(iso, nowMs = Date.now()) {
  if (!iso) return null
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return null
  return Math.max(0, Math.floor((nowMs - then) / 86_400_000))
}
