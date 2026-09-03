/**
 * Pure per-file batch/outcome logic for SbomUploadModal — kept out of the .svelte component so
 * batch ordering and outcome mapping are unit-testable without a Svelte component-render harness
 * (none exists in this repo).
 */

// Upload order within one batch: the SBOM PUT must land before a VEX/SARIF PUT that references
// the same project version, because those two 404 on a version the server doesn't know about
// yet. Ties keep their original staged order; Array#sort is stable in every JS engine this app
// ships to.
const KIND_PRIORITY = { sbom: 0, vex: 1, sarif: 1 }

/**
 * Returns a new array of staged files ordered sbom-first for sequential upload. Generic over
 * the staged-item shape (the modal's items carry `id`/`file`/`text`/`status` alongside `kind`)
 * so callers keep their full item type instead of widening to `{ kind }`.
 * @template {{ kind: string }} T
 * @param {T[]} staged
 * @returns {T[]}
 */
export function orderStagedFiles(staged) {
  return [...staged]
    .map((item, index) => ({ item, index }))
    .sort((a, b) => {
      const pa = KIND_PRIORITY[a.item.kind] ?? 1
      const pb = KIND_PRIORITY[b.item.kind] ?? 1
      return pa - pb || a.index - b.index
    })
    .map(({ item }) => item)
}

/**
 * The two document kinds that attach to an existing project version rather than creating one.
 * A VEX or SARIF PUT against a version the server does not know about is a 404 by design.
 */
const SBOM_DEPENDENT_KINDS = new Set(['vex', 'sarif'])

/**
 * Whether a staged VEX/SARIF must not be sent at all, because the SBOM that would have created
 * its target version was rejected earlier in the same batch.
 *
 * Sending it anyway is what produces the misleading outcome this guards against: the server
 * answers a truthful "No such project version", which lands on the VEX/SARIF row and reads as if
 * that document were at fault, while the actual cause — the SBOM's own rejection — sits in a
 * different row the operator has to connect for themselves.
 *
 * `versionExisted` is what keeps this from suppressing legitimate work: a VEX or SARIF for a
 * version that already exists is unaffected by a co-submitted SBOM being rejected, so only a
 * version this batch was going to create is treated as unreachable.
 *
 * @param {string} kind  the endpoint the file is submitted against ('sbom' | 'vex' | 'sarif'),
 *                        not the sniffed kind — an unrecognised document goes to the SBOM
 *                        endpoint and is a prerequisite like any other SBOM.
 * @param {{ sbomRejected: boolean, versionExisted: boolean }} batch
 * @returns {boolean}
 */
export function isBlockedBySbomFailure(kind, { sbomRejected, versionExisted }) {
  if (!sbomRejected || versionExisted) return false
  return SBOM_DEPENDENT_KINDS.has(kind)
}

/**
 * Describe a successful (HTTP 200) upload response as an i18n descriptor
 * `{ key, values }` for `$t(key, { values })`. Branches on `kind`, not on response shape,
 * because the three endpoints echo distinct count shapes (components / statements / results).
 *
 * The `components.added === 0 && components.removed === 0` case is the documented idempotent
 * re-upload no-op and gets its own copy rather than reading as "0 added" — the operator needs
 * to know nothing changed, not that nothing changed because it failed.
 *
 * @param {string} kind  'sbom' | 'vex' | 'sarif' in normal operation; any other value (an
 *                        unrecognised sniff result the caller submitted against the SBOM
 *                        endpoint's default) falls through to the generic descriptor below.
 * @param {any} response
 * @returns {{ key: string, values: Record<string, number> }}
 */
/** An inventory diff: the no-op case names only the total, because nothing moved. */
function describeSbomUpload(response) {
  const c = response?.components ?? {}
  const added = c.added ?? 0
  const removed = c.removed ?? 0
  const total = c.total ?? 0
  if (added === 0 && removed === 0) {
    return { key: 'sbomUpload.outcome.detail.sbomNoop', values: { total } }
  }
  return {
    key: 'sbomUpload.outcome.detail.sbom',
    values: { added, removed, unchanged: c.unchanged ?? 0, total },
  }
}

/** VEX and SARIF report the same applied/total/unmatched triple over different count objects. */
function describeApplied(kind, counts) {
  const c = counts ?? {}
  return {
    key: `sbomUpload.outcome.detail.${kind}`,
    values: { applied: c.applied ?? 0, total: c.total ?? 0, unmatched: c.unmatched ?? 0 },
  }
}

// A Map rather than an object literal: `kind` reaches here straight from the caller, and an
// object lookup would resolve inherited names like 'constructor' to a callable.
const SUCCESS_DESCRIBERS = new Map([
  ['sbom', describeSbomUpload],
  ['vex', (response) => describeApplied('vex', response?.statements)],
  ['sarif', (response) => describeApplied('sarif', response?.results)],
])

export function describeSuccess(kind, response) {
  const describe = SUCCESS_DESCRIBERS.get(kind)
  return describe
    ? describe(response)
    : { key: 'sbomUpload.outcome.detail.generic', values: {} }
}

/**
 * Describe a failed upload. Prefers the server's own localized problem-detail text (already
 * rendered in the operator's language server-side) so a 422 kind-mismatch, a 409
 * collection-target, or a 413 too-large all read exactly as the server explains them; only a
 * transport failure with no server body at all falls back to a generic i18n key.
 *
 * @param {any} error  an ApiError (web/src/lib/api.js — `.status`/`.body`), a raw transport
 *                      Error, or any other thrown value; deliberately untyped since callers pass
 *                      whatever a `catch` clause hands them.
 * @returns {{ text: string | null, key: string | null, values: Record<string, unknown> }}
 */
export function describeFailure(error) {
  // ApiError (web/src/lib/api.js) always carries `.status`; only it has a server-rendered body.
  const isApiError = typeof error?.status === 'number'
  const detail = isApiError ? (error?.body?.detail || error?.message) : null
  if (detail) return { text: detail, key: null, values: {} }
  return { text: null, key: 'sbomUpload.outcome.detail.error', values: { message: error?.message ?? String(error) } }
}
