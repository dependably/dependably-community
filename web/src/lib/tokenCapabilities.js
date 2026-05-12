/**
 * Token-issuance UI helpers.
 *
 * The server's token-creation API takes a capabilities array (e.g. ["read:metadata",
 * "publish:*"]) and rejects the retired `scope` shorthand. The token modal still offers
 * two presets ("pull" / "push") because exposing the raw capability vocabulary in a
 * dropdown would be a UX downgrade. These helpers translate in both directions:
 *
 *   preset → capabilities  on submit
 *   capabilities → preset  for the row badge after a token lands
 */

const PULL_CAPS = ['read:metadata', 'read:artifact']
const PUSH_CAPS = ['read:metadata', 'read:artifact', 'publish:*']

export function presetToCapabilities(preset) {
  if (preset === 'push') return PUSH_CAPS
  return PULL_CAPS
}

/**
 * Best-effort label from a TokenRecord's capabilities JSON string. Returns 'pull',
 * 'push', 'custom' (anything that has caps but doesn't match a known preset), or
 * '—' when the value is missing/unparseable. Used for the row badge — display only.
 */
export function capabilitiesToLabel(capabilitiesJson) {
  if (!capabilitiesJson) return '—'
  let caps
  try { caps = JSON.parse(capabilitiesJson) } catch { return '—' }
  if (!Array.isArray(caps) || caps.length === 0) return '—'
  const hasPublish = caps.some((c) => typeof c === 'string' && c.startsWith('publish:'))
  const hasRead = caps.some((c) => typeof c === 'string' && c.startsWith('read:'))
  if (hasPublish && hasRead) return 'push'
  if (hasRead && !hasPublish) return 'pull'
  return 'custom'
}
