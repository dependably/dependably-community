// Byte<->MB conversion + ceiling validation for the org-level upload-limits editor
// (SettingsUpload.svelte). Storage stays in bytes end to end (org_settings.max_upload_bytes*);
// this module is the single place that converts for display/edit and checks the instance
// ceiling in a unit-consistent way.

export const BYTES_PER_MB = 1024 * 1024

// Stored byte value (string/number, or '' / null / undefined for "unset") -> the MB string
// shown in the editable field. Division by a power of two keeps sub-MB values exact doubles,
// so mbToBytes(bytesToMb(x)) round-trips losslessly for realistic upload sizes.
export function bytesToMb(bytes) {
  if (bytes === undefined || bytes === null || bytes === '') return ''
  const n = Number(bytes)
  if (!Number.isFinite(n)) return ''
  return String(n / BYTES_PER_MB)
}

// Editable MB string -> the byte string persisted to settings[key]. Rounds to the nearest
// byte so floating-point noise from the MB conversion never drifts the stored value.
export function mbToBytes(mbValue) {
  if (mbValue === undefined || mbValue === null || mbValue === '') return ''
  const n = Number(mbValue)
  if (!Number.isFinite(n)) return ''
  return String(Math.round(n * BYTES_PER_MB))
}

// Unit-consistent over-ceiling check: compares MB * BYTES_PER_MB against the instance ceiling
// in bytes, so fractional MB values (e.g. "0.5") are compared correctly instead of being
// floored to 0 by a naive parseInt.
export function exceedsInstanceCeiling(mbValue, instanceMaxBytes) {
  if (!instanceMaxBytes || mbValue === undefined || mbValue === null || mbValue === '') return false
  const n = Number(mbValue)
  if (!Number.isFinite(n)) return false
  return n * BYTES_PER_MB > instanceMaxBytes
}

// Display-only MB label (placeholders, hints) — rounded to 2 decimals so an odd instance
// ceiling still reads cleanly. Not used for the editable field value, where full precision
// matters for round-tripping.
export function formatMbLabel(bytes) {
  if (bytes === undefined || bytes === null || bytes === '') return ''
  const n = Number(bytes)
  if (!Number.isFinite(n)) return ''
  return String(Math.round((n / BYTES_PER_MB) * 100) / 100)
}
