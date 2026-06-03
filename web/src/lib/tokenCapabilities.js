/**
 * Token-issuance UI helpers.
 *
 * The server's token-creation API takes a capabilities array (e.g. ["read:metadata",
 * "publish:*"]) and rejects the retired `scope` shorthand. The token modal offers a small
 * set of presets because exposing the raw capability vocabulary in a dropdown would be a
 * UX downgrade. These helpers translate in both directions:
 *
 *   preset → capabilities  on submit
 *   capabilities → preset  for the row badge after a token lands
 *
 * Preset semantics:
 *   pull   — read-only            (read:metadata + read:artifact)
 *   push   — publish-only         (publish:*)
 *   both   — read + publish       (read:metadata + read:artifact + publish:*)
 *   admin  — org configuration    (tenant:configure + read:tenant)
 *   audit  — audit-log reads      (read:audit) — for SIEM / logging integrations
 *
 * The package presets (pull/push/both) are always offered. The privileged presets
 * (admin/audit) are gated to admin/owner callers in the UI and to the admin-only
 * service-token screen; the server enforces the same ceiling regardless.
 */

const PRESET_CAPS = {
  pull:  ['read:metadata', 'read:artifact'],
  push:  ['publish:*'],
  both:  ['read:metadata', 'read:artifact', 'publish:*'],
  admin: ['tenant:configure', 'read:tenant'],
  audit: ['read:audit'],
}

export const PACKAGE_PRESETS = ['pull', 'push', 'both']
export const PRIVILEGED_PRESETS = ['admin', 'audit']

export function presetToCapabilities(preset) {
  return PRESET_CAPS[preset] ?? PRESET_CAPS.pull
}

/**
 * Best-effort preset key from a TokenRecord's capabilities JSON string. Returns one of
 * 'pull' | 'push' | 'both' | 'admin' | 'audit' | 'custom' (caps that don't match a known
 * preset), or '—' when the value is missing/unparseable. The key is CSS-class-safe (no
 * spaces) — display text is resolved from i18n (`tokenScopes.<key>`). Used for the row
 * badge class, sort comparator, and display label.
 */
export function capabilitiesToLabel(capabilitiesJson) {
  if (!capabilitiesJson) return '—'
  let caps
  try { caps = JSON.parse(capabilitiesJson) } catch { return '—' }
  if (!Array.isArray(caps) || caps.length === 0) return '—'
  const has = (c) => caps.includes(c)
  const hasPublish = caps.some((c) => typeof c === 'string' && c.startsWith('publish:'))
  const hasPkgRead = has('read:metadata') || has('read:artifact')
  const hasConfig = has('tenant:configure')
  const hasAudit = has('read:audit')
  if (hasConfig) return 'admin'
  if (hasAudit && !hasPublish && !hasPkgRead) return 'audit'
  if (hasPublish && hasPkgRead) return 'both'
  if (hasPkgRead && !hasPublish) return 'pull'
  if (hasPublish && !hasPkgRead) return 'push'
  return 'custom'
}
