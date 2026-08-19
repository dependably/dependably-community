// The package-level risk pillars on the package detail page.
//
// A package is a release history, and the question the pillars answer is "what
// is the state of this package" — which is the state of the version you would
// install today, not the worst thing that ever appeared in its history. Reading
// them worst-across-all-versions makes them describe a version nobody installs:
// a package whose current release is clean shows MEDIUM because a release from
// two years ago carries an advisory, and the operational pillar reports "38
// behind" directly above a banner saying the latest version is cached.
//
// Per-version risk is not lost by narrowing the pillars — every row of the table
// below carries its own status, advisory list, license and versions-behind
// count. The pillars are the headline; the table is the history.

import { compareVersions, isPreReleaseVersion } from './versionOrder.js'

// Worst-first. UNKNOWN is a recorded advisory whose severity never resolved, so
// it ranks last among real severities but still outranks "no advisory at all".
const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 }

/**
 * The version whose state the pillars report, as a version string.
 *
 * Resolution order:
 *   1. The upstream latest, when it is cached here — the authoritative answer,
 *      and the same version the currency banner and the table's Latest column
 *      already mark.
 *   2. Otherwise the newest cached version, which is what "current" means for a
 *      hosted-only package, an air-gapped instance, or a package that has gone
 *      stale against upstream. Stable releases win over pre-releases outright:
 *      a cached 2.0.0-rc.1 does not make 1.9.0 the old version.
 *
 * OCI takes the pushed-time branch throughout: a hosted OCI version IS the
 * manifest digest, and a digest has no magnitude to order by, so comparing them
 * would pick an arbitrary row and present it as the current one.
 *
 * @param {{ ecosystem?: string, upstreamLatestVersion?: string | null } | null} pkg
 * @param {Array<{ version: string, createdAt?: string | null, updatedAt?: string | null }> | null | undefined} versions
 *   The flat per-file version list, several rows of which may share one version.
 * @returns {string | null} null only when there are no versions at all.
 */
export function resolveStateVersion(pkg, versions) {
  const distinct = [...new Set((versions ?? []).map(v => v.version).filter(Boolean))]
  if (distinct.length === 0) return null

  const upstreamLatest = pkg?.upstreamLatestVersion
  if (upstreamLatest && distinct.includes(upstreamLatest)) return upstreamLatest

  if (pkg?.ecosystem === 'oci') return newestByPushedTime(versions, distinct)

  const stable = distinct.filter(v => !isPreReleaseVersion(v))
  const candidates = stable.length > 0 ? stable : distinct
  return candidates.reduce((newest, v) => (compareVersions(v, newest) > 0 ? v : newest))
}

// Most recently pushed version. A same-version re-push stamps updatedAt without
// disturbing createdAt, so the effective pushed time falls back to createdAt —
// the same rule the table's "pushed" sort uses.
function newestByPushedTime(versions, distinct) {
  const pushedAt = new Map()
  for (const v of versions) {
    const at = v.updatedAt ?? v.createdAt
    if (!at) continue
    const seen = pushedAt.get(v.version)
    if (!seen || new Date(at) > new Date(seen)) pushedAt.set(v.version, at)
  }
  return distinct.reduce((newest, v) => {
    const a = pushedAt.get(v)
    const b = pushedAt.get(newest)
    if (!a) return newest
    if (!b) return v
    return new Date(a) > new Date(b) ? v : newest
  })
}

/**
 * The rows belonging to one version. A multi-file version (Maven jar + pom,
 * PyPI wheel + sdist, NuGet nupkg + snupkg) contributes several.
 */
export function rowsForVersion(versions, version) {
  return version === null ? [] : (versions ?? []).filter(v => v.version === version)
}

/**
 * Worst severity across the advisories linked to these rows, or null when they
 * carry none. Multi-file versions share one purl per file, so the lookup is
 * deduplicated by advisory id before ranking.
 *
 * @param {Array<{ purl?: string }>} rows
 * @param {Map<string, Array<{ osvId: string, severity?: string }>>} vulnsByPurl
 */
export function worstSeverityFor(rows, vulnsByPurl) {
  const purls = new Set()
  for (const r of rows) {
    if (r.purl) purls.add(r.purl)
  }
  const seen = new Set()
  let worst = null
  for (const purl of purls) {
    for (const v of vulnsByPurl?.get(purl) ?? []) {
      if (seen.has(v.osvId)) continue
      seen.add(v.osvId)
      const sev = v.severity || 'UNKNOWN'
      if (worst === null || (SEVERITY_RANK[sev] ?? 5) < (SEVERITY_RANK[worst] ?? 5)) worst = sev
    }
  }
  return worst
}

/**
 * License posture of one version, as four states rather than two. A version with
 * no extracted SPDX entry is not a clean version — it is one nothing is known
 * about, and the license gate treats those differently per ecosystem, so
 * flattening it into "no risk" would claim a check that never ran. A version on
 * a conditional licence is not clean either: it serves, but the org recorded a
 * condition on it, and showing it as clean would hide the org's own note.
 *
 * Ranked most-severe first, so a version carrying both a blocked and a
 * conditional licence reports the blocked one.
 *
 * @param {Array<{ licenses?: string[] }>} rows
 * @param {Set<string>} blocklist Uppercased blocklisted SPDX identifiers.
 * @param {Set<string>} [conditional] Uppercased conditional SPDX identifiers.
 * @returns {'blocked' | 'undeclared' | 'review' | 'clean'}
 */
export function licenseStateFor(rows, blocklist, conditional) {
  const licenses = [...new Set(rows.flatMap(r => r.licenses ?? []))]
  if (licenses.some(l => blocklist?.has((l ?? '').toUpperCase()))) return 'blocked'
  if (licenses.length === 0) return 'undeclared'
  if (licenses.some(l => conditional?.has((l ?? '').toUpperCase()))) return 'review'
  return 'clean'
}

/**
 * Upstream-currency count for one version. Every file of a version resolves to
 * the same count, so the first known value answers for the version; null
 * (unknown — hosted-only, air-gapped, or not yet refreshed) is preserved rather
 * than coerced to 0.
 *
 * @param {Array<{ versionsBehind?: number | null }>} rows
 * @returns {number | null}
 */
export function versionsBehindFor(rows) {
  const known = rows.find(r => r.versionsBehind !== null && r.versionsBehind !== undefined)
  return known?.versionsBehind ?? null
}
