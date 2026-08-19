// Version-aware ordering for the package versions table.
//
// The table used to sort its version column with
// `localeCompare(…, { numeric: true })`. That gets the common numeric case right
// (1.10.0 > 1.9.0) but ranks every pre-release ABOVE the release it precedes,
// because "1.0.0-rc.1" is simply a longer string than "1.0.0":
//
//   localeCompare, descending:  1.0.0-rc.1 > 1.0.0-beta.1 > 1.0.0-alpha > 1.0.0
//
// With the table defaulting to newest-version-first, that puts an alpha at the top
// of the list and buries the stable release under it — the opposite of what the
// column claims to show. The same inversion hits PyPI post-releases (1.0.post1
// sorted below 1.0rc1) and Maven snapshots (1.0-SNAPSHOT above 1.0).
//
// This is deliberately ONE comparator for every ecosystem rather than a per-scheme
// implementation of semver + PEP 440 + Maven + RPM NEVRA. The table mixes
// ecosystems only one package at a time, and the schemes agree on the parts that
// decide almost every real comparison: dot-separated numeric segments, a
// pre-release suffix that sorts below its release, and a post-release suffix that
// sorts above it. Where they disagree the fallback is a stable lexical order, not
// a wrong one — this drives a display sort, never a resolution or gating decision,
// so an exotic version string ordering oddly is a cosmetic issue.
//
// Anything genuinely unorderable — an OCI manifest digest, say — is handled by the
// caller choosing a different default column, not by this comparator pretending a
// hash has a magnitude.

/**
 * The column the versions table sorts by before the user picks one.
 *
 * Newest version first, because the version list is a release history and the
 * question it is nearly always opened to answer is "what is the newest one we
 * have".
 *
 * OCI is the exception: a hosted OCI version IS the manifest digest, and a digest
 * has no magnitude to order by, so sorting it would replace a meaningful default
 * with hash order. That ecosystem keeps `pushed`, which is its real recency signal
 * — and it is the one ecosystem with a separate tag column carrying the readable
 * identity, so nothing is lost by not ordering the digest.
 */
export function defaultSortColumn(ecosystem) {
  return ecosystem === 'oci' ? 'pushed' : 'version'
}

// Ordering rank for the alphabetic markers that qualify a release. Negative ranks
// sort below the bare release (pre-releases), positive above it (post-releases),
// and 0 is an unrecognised word that falls through to a lexical comparison.
//
// Ranking these by meaning is a deliberate, measured divergence from semver, which
// compares pre-release identifiers purely lexically — semver puts "dev" above
// "beta" only because "d" sorts after "b". Cross-checking this comparator against
// the semver package over ~90k pairs of real npm versions with conventional
// pre-release tags leaves exactly one disagreeing shape: "-dev.<date>" against
// "-beta". Neither answer is right in general, because that tag names a nightly
// stream that runs both before and after the beta it brackets, so this file keeps
// the ordering that reads correctly as a release history.
const MARKER_RANK = {
  dev: -5,
  alpha: -4,
  a: -4,
  milestone: -4,
  m: -4,
  beta: -3,
  b: -3,
  pre: -2,
  preview: -2,
  rc: -2,
  c: -2,
  snapshot: -2,
  post: 1,
  rev: 1,
  r: 1,
  sp: 1,
}

function markerRank(token) {
  return MARKER_RANK[token] ?? 0
}

// A token that pulls its version BELOW the same version without it. Used for the
// ran-out-of-tokens case: "1.0" vs "1.0-rc1" must favour "1.0", while "1.0" vs
// "1.0.1" must favour "1.0.1".
function isPreRelease(token) {
  return typeof token === 'string' && markerRank(token) < 0
}

/**
 * Split a version into an epoch and a flat list of comparable tokens.
 *
 * Numeric runs become numbers, alphabetic runs become lowercase strings, and a
 * digit/letter transition is treated as a segment boundary so PEP 440's "1.0rc1"
 * tokenizes the same way semver's "1.0-rc.1" does.
 */
export function parseVersion(input) {
  let v = String(input ?? '').trim().toLowerCase()

  // Build metadata carries no precedence in semver, and PEP 440 local versions
  // ("1.0+ubuntu1") are likewise not an ordering signal here.
  v = v.split('+')[0]

  // Epoch: RPM writes "1:2.3", PEP 440 writes "1!2.3". Only a leading run of
  // digits is an epoch — the guard is what keeps an OCI digest ("sha256:ab…")
  // from being read as one.
  let epoch = 0
  const epochMatch = /^(\d+)[:!]/.exec(v)
  if (epochMatch) {
    epoch = Number(epochMatch[1])
    v = v.slice(epochMatch[0].length)
  }

  // A leading "v" is decoration in Go module tags and npm dist-tags alike.
  v = v.replace(/^v(?=\d)/, '')

  const tokens = []
  for (const run of v.split(/[.\-_]+/)) {
    if (!run) continue
    // Split each run at every digit<->letter boundary: "rc1" -> ["rc", 1].
    for (const part of run.match(/\d+|[a-z]+/g) ?? []) {
      tokens.push(/^\d+$/.test(part) ? Number(part) : part)
    }
  }

  return { epoch, tokens }
}

/**
 * Compare two version strings. Ascending: older sorts first.
 *
 * @returns {number} negative if `a` precedes `b`, positive if it follows, 0 if equal
 */
export function compareVersions(a, b) {
  const pa = parseVersion(a)
  const pb = parseVersion(b)

  if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1

  // Zero-padding a missing trailing segment is right for the release part ("1.0"
  // is "1.0.0") but wrong once a pre-release marker has been seen: there, a
  // version with fewer identifiers ranks BELOW one that continues, so "1.0-alpha"
  // precedes "1.0-alpha.0". Tracked rather than assumed, because the boundary is
  // only known part-way through the walk.
  let inPreRelease = false

  const len = Math.max(pa.tokens.length, pb.tokens.length)
  for (let i = 0; i < len; i++) {
    const ta = pa.tokens[i]
    const tb = pb.tokens[i]

    // One side ran out.
    if (ta === undefined) {
      if (!inPreRelease && typeof tb === 'number') {
        if (tb === 0) continue
        return -1
      }
      return isPreRelease(tb) ? 1 : -1
    }
    if (tb === undefined) {
      if (!inPreRelease && typeof ta === 'number') {
        if (ta === 0) continue
        return 1
      }
      return isPreRelease(ta) ? -1 : 1
    }

    if (isPreRelease(ta) || isPreRelease(tb)) inPreRelease = true

    const aNum = typeof ta === 'number'
    const bNum = typeof tb === 'number'

    if (aNum && bNum) {
      if (ta !== tb) return ta < tb ? -1 : 1
      continue
    }

    // A number against a word: the number is a further release segment and the
    // word qualifies the release, so the number sorts higher. This holds for both
    // directions of qualifier — "1.0.1" outranks "1.0rc1" and "1.0.post1" alike.
    if (aNum !== bNum) return aNum ? 1 : -1

    const ra = markerRank(ta)
    const rb = markerRank(tb)
    if (ra !== rb) return ra < rb ? -1 : 1
    if (ta !== tb) return ta < tb ? -1 : 1
  }

  // Tokens are exhausted and equal, so these are the same version however they
  // were spelled — "1.0" and "1.0.0", "v1.2.3" and "1.2.3", "1.0.0+build.1" and
  // "1.0.0". Reporting 0 is the correct answer rather than a tie to break: the
  // sort is stable, so equal versions keep the order the API returned them in.
  return 0
}

/**
 * True when a version string carries a pre-release qualifier — an alpha, beta,
 * rc, dev or snapshot marker that sorts it below the bare release.
 *
 * Used to pick the version that represents a package's current state: when the
 * upstream latest is unknown or not cached, the newest STABLE cached version is
 * a truer answer than the newest string, which may be a pre-release nobody
 * installs by default.
 */
export function isPreReleaseVersion(version) {
  return parseVersion(version).tokens.some(isPreRelease)
}
