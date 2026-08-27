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
 *   pull   — read-only            (read:metadata + read:artifact + read:packages)
 *   push   — publish-only         (publish:*)
 *   both   — read + publish       (read:metadata + read:artifact + read:packages + publish:*)
 *   admin  — org configuration    (tenant:configure + read:tenant)
 *   audit  — audit-log reads      (read:audit) — for SIEM / logging integrations
 *   sbom   — SBOM upload only     (sbom:upload) — CI uploading SBOM/VEX/SARIF, nothing else.
 *            Privileged, not package: sbom:upload is in AdminCaps, so only an admin/owner
 *            token may carry it — offering it to a member would render a control the server
 *            refuses as privilege escalation. It is also deliberately its own preset rather
 *            than folded into `push`: publish:* already covers uploading a package, and
 *            widening it to also cover SBOM upload would silently broaden what every existing
 *            `push`/`both` token can already do.
 *
 * The capabilities → preset direction is only ever a convenience label, and it matches a
 * preset's exact capability set and nothing else. A token minted through the API can hold any
 * subset of the vocabulary, and an approximate label on a credential is worse than no label:
 * inferring "push" from the presence of any `publish:` entry makes a `publish:nuget` token
 * indistinguishable from a `publish:*` one, and only the second can push an OCI image.
 * Anything that is not exactly a preset is `custom`, and every caller renders
 * `capabilitiesToText` alongside the badge only in that case — a preset match already names
 * the grant, so the raw list would be noise on every ordinary row; it earns its place once the
 * badge can no longer speak for the token.
 *
 * The package presets (pull/push/both) are always offered. The privileged presets
 * (admin/audit/sbom) are gated to admin/owner callers in the UI and to the admin-only
 * service-token screen; the server enforces the same ceiling regardless.
 */

const PRESET_CAPS = {
  pull:  ['read:metadata', 'read:artifact', 'read:packages'],
  push:  ['publish:*'],
  both:  ['read:metadata', 'read:artifact', 'read:packages', 'publish:*'],
  sbom:  ['sbom:upload'],
  admin: ['tenant:configure', 'read:tenant'],
  audit: ['read:audit'],
}

// `sbom` sits with the privileged presets because `sbom:upload` is in AdminCaps: only an
// admin or owner carries it, so offering it to a member would render a control whose mint
// the server refuses as privilege escalation.
export const PACKAGE_PRESETS = ['pull', 'push', 'both']
export const PRIVILEGED_PRESETS = ['admin', 'audit', 'sbom']

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
  const caps = parseCapabilities(capabilitiesJson)
  if (caps === null) return '—'
  if (caps.length === 0) return '—'
  const sorted = [...caps].sort()
  for (const [preset, presetCaps] of Object.entries(PRESET_CAPS)) {
    const target = [...presetCaps].sort()
    if (sorted.length === target.length && sorted.every((c, i) => c === target[i])) {
      return preset
    }
  }
  return 'custom'
}

/**
 * The capability array exactly as stored, sorted, for display next to the badge. Returns
 * '—' for a missing, unparseable, or empty value — the same shapes the server treats as
 * deny-all. This is the authoritative answer to "what can this credential do"; the badge
 * beside it is shorthand.
 */
export function capabilitiesToText(capabilitiesJson) {
  const caps = parseCapabilities(capabilitiesJson)
  if (caps === null || caps.length === 0) return '—'
  return [...caps].sort().join(', ')
}

/**
 * Mirrors how the server reads the same column, which is all-or-nothing: `CapabilitySet`
 * deserializes to `string[]`, so a single non-string element throws and the whole token is
 * left granting nothing. Filtering the bad entries and keeping the rest would render a grant
 * the credential does not hold — the precise failure this display exists to remove — so any
 * malformed element voids the array here too. Blank entries are the one exception: the server
 * drops those individually and keeps the rest, so this does the same.
 */
function parseCapabilities(capabilitiesJson) {
  if (!capabilitiesJson) return null
  let caps
  try { caps = JSON.parse(capabilitiesJson) } catch { return null }
  if (!Array.isArray(caps)) return null
  if (caps.some((c) => typeof c !== 'string')) return null
  return caps.filter((c) => c.trim().length > 0)
}
