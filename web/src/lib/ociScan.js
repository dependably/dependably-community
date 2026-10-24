// How an OCI image's security state reads on the version page.
//
// An image's findings live in the org's own scan result, not in the advisory links the other
// ecosystems use, so the page cannot tell a clean image from an unscanned one by looking for
// linked advisories. The server projects the org's scan state onto each row (`ociScan`); this
// module turns it into the one state the page renders. It never reads the display status,
// which blocked, allowed and deprecated mask.

/**
 * @typedef {{ state: string, gapCount?: number, findingCount?: number, maxScore?: number | null }} OciScan
 * @typedef {'vulnerable' | 'partial' | 'unscanned' | 'no_feed' | 'clean'} OciScanKind
 * @typedef {{ kind: OciScanKind, severity: string | null, count: number, gapCount: number }} OciSecurity
 */

// Worst first. Anything that is not 'clean' must never render in the clean tone.
const KIND_RANK = { vulnerable: 0, partial: 1, unscanned: 2, no_feed: 3, clean: 4 }

/**
 * CVSS base score to the severity bands the advisory chips use. A finding with no score is
 * UNKNOWN, not a severity nobody assigned.
 * @param {number | null | undefined} score
 */
export function severityForScore(score) {
  if (typeof score !== 'number' || Number.isNaN(score) || score <= 0) return 'UNKNOWN'
  if (score >= 9) return 'CRITICAL'
  if (score >= 7) return 'HIGH'
  if (score >= 4) return 'MEDIUM'
  return 'LOW'
}

/**
 * The security state of one OCI row, or null for any other ecosystem, in which case the caller
 * keeps its linked-advisory logic. An OCI row with no scan projection (a server that does not send
 * one) reads as unscanned, never as clean: its linked advisories say nothing about its scan.
 * @param {{ ociScan?: OciScan | null, purl?: string, [key: string]: any } | null | undefined} row
 * @returns {OciSecurity | null}
 */
export function ociSecurityFor(row) {
  const scan = row?.ociScan
  if (!scan) {
    return typeof row?.purl === 'string' && row.purl.startsWith('pkg:oci/')
      ? { kind: 'unscanned', severity: null, count: 0, gapCount: 0 }
      : null
  }
  const gapCount = scan.gapCount ?? 0
  if (scan.state === 'unscanned' || scan.state === 'no_feed') {
    return { kind: scan.state, severity: null, count: 0, gapCount: 0 }
  }
  if (scan.state !== 'scanned') {
    // An unrecognised state is not evidence of a clean image.
    return { kind: 'unscanned', severity: null, count: 0, gapCount: 0 }
  }
  const count = scan.findingCount ?? 0
  if (count > 0) {
    return { kind: 'vulnerable', severity: severityForScore(scan.maxScore), count, gapCount }
  }
  return { kind: gapCount > 0 ? 'partial' : 'clean', severity: null, count: 0, gapCount }
}

/**
 * The worst OCI security state across a version's rows, or null when none is an OCI row.
 * @param {Array<{ ociScan?: OciScan | null, [key: string]: any }>} rows
 * @returns {OciSecurity | null}
 */
export function worstOciSecurity(rows) {
  /** @type {OciSecurity | null} */
  let worst = null
  for (const row of rows ?? []) {
    const s = ociSecurityFor(row)
    if (s && (worst === null || KIND_RANK[s.kind] < KIND_RANK[worst.kind])) worst = s
  }
  return worst
}

/**
 * Whether an OCI row's linked advisories must be shown next to its scan state. A linked advisory
 * is a known finding, so a partial, unscanned or no-scanner state never hides it; a vulnerable
 * state already shows its findings.
 * @param {OciSecurity | null} oci
 * @param {number} linkedCount
 */
export function showsLinkedFindings(oci, linkedCount) {
  return !!oci && oci.kind !== 'clean' && oci.kind !== 'vulnerable' && linkedCount > 0
}

// ── The expanded row's scan detail ──────────────────────────────────────────────────────────
//
// The detail comes from GET /packages/oci/{name}/{digest}/scan. These helpers decide what the
// panel says; the component only renders their answer.

const DIGEST = /^sha256:[0-9a-f]{64}$/

/** Whether a version string is a manifest digest the scan-detail read accepts. @param {unknown} v */
export function isOciDigest(v) {
  return typeof v === 'string' && DIGEST.test(v)
}

/**
 * The reachability verdict to display. Only the two verdicts that say something are passed
 * through; anything else (`unknown`, null, or a value a newer scanner posts ahead of this UI)
 * reads as unknown, never as not reachable.
 * @param {unknown} value
 * @returns {'reachable' | 'not_observed' | 'unknown'}
 */
export function reachabilityKind(value) {
  return value === 'reachable' || value === 'not_observed' ? value : 'unknown'
}

/**
 * Whether a component sits in the entrypoint's link closure. Null means the scanner did not
 * determine it, which is never "outside".
 * @param {unknown} value
 * @returns {'inside' | 'outside' | 'undetermined'}
 */
export function closureKind(value) {
  if (value === true) return 'inside'
  if (value === false) return 'outside'
  return 'undetermined'
}

const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

/**
 * The severity chip for an advisory: its recorded severity, else the band of its CVSS score, else
 * UNKNOWN, which renders as the unscored chip rather than a severity nobody assigned.
 * @param {{ severity?: string | null, cvssScore?: number | null } | null | undefined} advisory
 */
export function advisorySeverity(advisory) {
  const s = typeof advisory?.severity === 'string' ? advisory.severity.toUpperCase() : null
  if (s && SEVERITIES.has(s)) return s
  return severityForScore(advisory?.cvssScore)
}

/**
 * How many of a component's findings the capped list leaves out.
 * @param {{ findingCount?: number, findings?: any[] } | null | undefined} c
 */
export function moreFindings(c) {
  return Math.max(0, (c?.findingCount ?? 0) - (c?.findings?.length ?? 0))
}

/**
 * What the expanded panel says for one scan-detail response. Without a stored result it is one
 * message and never a table; with one it names the platforms scanned, lists every platform's gaps
 * first, and is clean only when nothing on any platform is affected and nothing has a gap.
 * @param {any} detail
 */
export function ociScanPanel(detail) {
  if (detail?.state !== 'scanned') {
    return { kind: 'noResult', messageKey: noResultMessage(detail), attempts: detail?.job?.attempts ?? 0 }
  }
  const platforms = Array.isArray(detail.platforms) ? detail.platforms : []
  const gapPlatforms = platforms
    .filter(p => Array.isArray(p.gaps) && p.gaps.length > 0)
    .map(p => ({ platform: p.platform, gaps: p.gaps }))
  const affected = platforms.reduce((n, p) => n + (p.affectedComponentCount ?? 0), 0)
  // A clean verdict is only as current as the stalest platform's last match.
  const matchedAt = platforms.map(p => p.matchedAt ?? p.scannedAt).filter(Boolean).sort()[0] ?? null
  return {
    kind: 'scanned',
    platformNames: platforms.map(p => p.platform),
    gapPlatforms,
    clean: gapPlatforms.length === 0 && affected === 0,
    matchedAt,
  }
}

/**
 * The time line for one platform: when it was scanned, and when its findings were last matched
 * against OSV when that is a different time (a re-match), so re-matched findings never sit
 * beside only a stale scan time.
 * @param {{ scannedAt?: string | null, matchedAt?: string | null } | null | undefined} platform
 * @returns {{ scannedAt: string | null, matchedAt: string | null }}
 */
export function scanTimes(platform) {
  const scannedAt = platform?.scannedAt ?? null
  const matchedAt = platform?.matchedAt ?? null
  return { scannedAt, matchedAt: matchedAt && matchedAt !== scannedAt ? matchedAt : null }
}

function noResultMessage(detail) {
  if (detail?.state === 'no_feed') return 'noFeed'
  const job = detail?.job
  if (job?.state === 'failed') return 'unscannedFailed'
  if (job?.state === 'pending') return (job.attempts ?? 0) > 0 ? 'unscannedPendingAttempts' : 'unscannedPending'
  // An unrecognised state or job is not evidence of anything: it reads as not yet queued.
  return 'unscannedNone'
}

/**
 * What the components area shows for the selected platform: the "0 findings among N components"
 * line when the findings view is empty (never an empty table), else the page's rows and range.
 * @param {any} detail
 * @param {boolean} affectedOnly
 */
export function componentsView(detail, affectedOnly) {
  const page = detail?.components
  if (!page) return { kind: 'none' }
  const platform = (detail.platforms ?? []).find(p => p.platform === page.platform)
  const items = Array.isArray(page.items) ? page.items : []
  // An empty page in either view is the zero-findings line; in the inventory view it can only
  // mean the platform holds no components at all.
  if ((page.total ?? 0) === 0) {
    return { kind: 'zeroFindings', componentCount: affectedOnly ? (platform?.componentCount ?? 0) : 0 }
  }
  const offset = page.offset ?? 0
  const limit = page.limit ?? items.length
  return {
    kind: 'rows',
    items,
    from: offset + 1,
    to: offset + items.length,
    total: page.total,
    prevOffset: offset > 0 ? Math.max(0, offset - limit) : null,
    nextOffset: offset + items.length < page.total ? offset + limit : null,
  }
}

/**
 * The security state of one package-list row. The server rolls the org's scan results up across
 * the images the org holds into the row's `ociScan` (the same shape a version row carries), so
 * the list decides exactly as the version page does. Null for any other ecosystem. An OCI package
 * with no rollup reads as unscanned, never clean.
 * @param {{ ecosystem?: string, ociScan?: OciScan | null } | null | undefined} pkg
 * @returns {OciSecurity | null}
 */
export function ociSecurityForPackage(pkg) {
  if (pkg?.ecosystem !== 'oci') return null
  return ociSecurityFor({ ociScan: pkg.ociScan ?? null, purl: 'pkg:oci/' })
}

/**
 * What the list's vulnerability cell renders for a package: the OCI state (null outside OCI),
 * whether the linked-advisory severity counts show, and whether the cell may read "no known
 * vulnerabilities". Outside OCI the counts alone decide. For OCI only a package whose
 * every held image is scanned clean may read clean, and a linked advisory is never hidden by a
 * non-clean state.
 * @param {{ ecosystem?: string, ociScan?: OciScan | null, criticalCount?: number, highCount?: number, mediumCount?: number, lowCount?: number } | null | undefined} pkg
 * @returns {{ oci: OciSecurity | null, showLinked: boolean, showNone: boolean }}
 */
export function packageVulnCell(pkg) {
  const linked = (pkg?.criticalCount ?? 0) + (pkg?.highCount ?? 0) + (pkg?.mediumCount ?? 0) + (pkg?.lowCount ?? 0)
  const oci = ociSecurityForPackage(pkg)
  if (!oci) return { oci: null, showLinked: linked > 0, showNone: linked === 0 }
  if (oci.kind === 'clean') {
    // A clean scan beside linked advisories is contradictory; the advisories are known findings
    // and win, so the cell shows them rather than reading clean.
    return { oci, showLinked: linked > 0, showNone: linked === 0 }
  }
  return { oci, showLinked: showsLinkedFindings(oci, linked), showNone: false }
}
