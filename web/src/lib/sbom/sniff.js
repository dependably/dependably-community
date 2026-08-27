/**
 * Client-side document-kind sniff for SbomUploadModal.
 *
 * This is a PREVIEW only — it picks which of the three PUT endpoints
 * (`/api/v1/sbom`, `/api/v1/vex`, `/api/v1/sarif`) a staged file is sent to, and drives the
 * detected-type badge in the staged-file list, but the server verdict is always authoritative:
 * a mismatch renders as the 422 the server returns, not as a client-side block. Pure and
 * synchronous so it is unit-testable without a Svelte render harness (none exists in this repo).
 */

/** @typedef {'sbom' | 'vex' | 'sarif' | 'unknown'} DocumentKind */

/**
 * Parse `text` as JSON and classify it. Returns `{ kind, parsed, parseError }` — `parsed` is
 * `null` and `parseError` carries the exception message when `text` is not valid JSON (the
 * upload still proceeds with `kind: 'unknown'`; the server's own parse error is what the
 * operator actually needs to see).
 *
 * @param {string} text
 * @returns {{ kind: DocumentKind, parsed: any, parseError: string | null }}
 */
export function sniffDocumentText(text) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch (e) {
    return { kind: 'unknown', parsed: null, parseError: e?.message ?? String(e) }
  }
  return { kind: detectDocumentKind(parsed), parsed, parseError: null }
}

/**
 * Classify an already-parsed JSON document. Detection order mirrors the epic's documented
 * contract: SARIF's `runs[]` is checked first because a SARIF log has no
 * `bomFormat`/`@context` to collide with; OpenVEX's `@context` next; CycloneDX (SBOM or VEX)
 * last, since both wire formats share `bomFormat: 'CycloneDX'` and are told apart only by
 * whether the document carries components or is vulnerabilities-only.
 *
 * @param {any} doc
 * @returns {DocumentKind}
 */
export function detectDocumentKind(doc) {
  if (!doc || typeof doc !== 'object') return 'unknown'

  if (Array.isArray(doc.runs)) return 'sarif'

  const context = doc['@context']
  const contextText = Array.isArray(context) ? context.join(' ') : String(context ?? '')
  if (contextText.toLowerCase().includes('openvex')) return 'vex'

  if (doc.bomFormat === 'CycloneDX') {
    const hasComponents = Array.isArray(doc.components) && doc.components.length > 0
    const hasVulnerabilities = Array.isArray(doc.vulnerabilities) && doc.vulnerabilities.length > 0
    // A CycloneDX VEX document is vulnerabilities-only (no components); a CycloneDX SBOM
    // (including a VDR, which carries both) always has components — the /sbom vs /vex endpoint
    // choice below only matters for the vulnerabilities-only case.
    if (hasVulnerabilities && !hasComponents) return 'vex'
    return 'sbom'
  }

  return 'unknown'
}

/** Maps a detected kind to its upload endpoint path segment (without the leading `/api/v1`). */
export const DOCUMENT_KIND_ENDPOINT = Object.freeze({
  sbom: 'sbom',
  vex: 'vex',
  sarif: 'sarif',
  // An unrecognised file still has to go somewhere for the server's own error to surface;
  // SBOM is the most common first upload in a batch and gives the clearest 422 either way.
  unknown: 'sbom',
})
