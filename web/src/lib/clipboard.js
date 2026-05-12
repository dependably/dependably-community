// `navigator.clipboard` is only defined in secure contexts (HTTPS or localhost).
// Self-hosted dependably is commonly accessed over plain HTTP on a LAN, where
// the API is undefined and silently no-ops. Fall back to a hidden textarea +
// document.execCommand('copy') so Copy buttons keep working everywhere.
export async function copyToClipboard(text) {
  if (text === null || text === undefined) return false
  const value = String(text)

  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch {
      // fall through to legacy path
    }
  }

  if (typeof document === 'undefined') return false
  const ta = document.createElement('textarea')
  ta.value = value
  ta.setAttribute('readonly', '')
  ta.style.position = 'fixed'
  ta.style.top = '0'
  ta.style.left = '0'
  ta.style.opacity = '0'
  ta.style.pointerEvents = 'none'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  let ok
  try { ok = document.execCommand('copy') } catch { ok = false } // NOSONAR: javascript:S1874 — deliberate fallback (see file header)
  document.body.removeChild(ta)
  return ok === true
}
