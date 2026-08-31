// Pure helpers for the project-version analysis surface (component table, advisory panel,
// VEX triage editor, export menu).
//
// Everything here maps the analysis payload to something renderable. Nothing in this module
// decides security semantics: effective priority, policy verdicts, the prod/dev predicate and
// the sort order are all computed server-side and shipped in the payload, and these helpers
// only choose which badge class and which locale key render the value that arrived. The one
// exception is the per-row rollup (`rowPriority`, `rowReach`, `severityChips`), which picks
// the strongest of the values the server already assigned to that row's own advisories so the
// collapsed row can summarize itself.

/** Table state defaults. `scope: ''` reads as "all" — the API's `scope=all` is the same thing. */
export const DEFAULT_TABLE_STATE = {
  q: '',
  scope: '',
  sev: '',
  reach: '',
  registry: '',
  violations: '',
  suppressed: '',
  page: 1,
  limit: 50,
  sort: 'priority',
  dir: 'desc',
}

/** Scope chips, left to right. '' is the "all" chip — it sends no `scope` param. */
export const SCOPE_CHIPS = ['', 'prod', 'dev']

/** Severity chips share the vulnerability-report vocabulary ("medium", not "moderate"). */
export const SEVERITIES = ['critical', 'high', 'medium', 'low']

/** Reachability values the payload is known to carry; anything else renders as its raw label. */
export const REACHABILITIES = ['reachable', 'imported-not-called', 'not-observed', 'unknown']

/** CycloneDX `analysis.state` — the vocabulary the editor always writes. */
export const VEX_STATES = [
  'in_triage',
  'exploitable',
  'resolved',
  'resolved_with_pedigree',
  'false_positive',
  'not_affected',
]

/** CycloneDX `analysis.justification` — meaningful only alongside `not_affected`. */
export const VEX_JUSTIFICATIONS = [
  'code_not_present',
  'code_not_reachable',
  'requires_configuration',
  'requires_dependency',
  'requires_environment',
  'protected_by_compiler',
  'protected_at_runtime',
  'protected_at_perimeter',
  'protected_by_mitigating_control',
]

/** CycloneDX `analysis.response`. */
export const VEX_RESPONSES = ['can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available']

/**
 * CycloneDX only attaches a justification to `not_affected`; every other state leaves the
 * select disabled so the editor cannot write a combination the spec does not define.
 * @param {string|null|undefined} state
 */
export function justificationEnabled(state) {
  return state === 'not_affected'
}

/**
 * Build the query params for GET …/analysis from the URL-persisted table state. Keys whose
 * value is the default are omitted so the request mirrors the clean URL, and the two boolean
 * filters are sent as `true` only when switched on — their absence is the server's default.
 * @param {Record<string, string|number>} state
 */
export function analysisQuery(state) {
  const params = {
    page: state.page ?? 1,
    limit: state.limit ?? DEFAULT_TABLE_STATE.limit,
    sort: state.sort || DEFAULT_TABLE_STATE.sort,
    dir: state.dir || DEFAULT_TABLE_STATE.dir,
  }
  if (state.q) params.q = state.q
  if (state.scope) params.scope = state.scope
  if (state.sev) params.sev = state.sev
  if (state.reach) params.reach = state.reach
  if (state.registry) params.registry = state.registry
  if (state.violations) params.violations = 'true'
  if (state.suppressed) params.suppressed = 'true'
  return params
}

/**
 * The dev/prod signal for one component row — `dependencyScope`, owned by the reachability
 * scanner. Always returns a badge, defaulting to `unknown`: a component nobody classified is
 * not the same as a production one, and a blank cell would read as the latter.
 * @param {{ dependencyScope?: string|null }} item
 * @returns {{ key: string, cls: string, labelKey: string, titleKey: string }}
 */
export function dependencyScopeBadge(item) {
  const dep = item?.dependencyScope || 'unknown'
  return {
    key: `dep-${dep}`,
    cls: `scope-${dep}`,
    labelKey: `sbomAnalysis.scope.${dep}`,
    titleKey: `sbomAnalysis.scope.${dep}Help`,
  }
}

/**
 * The raw CycloneDX component scope for one component row — `sbomScope`, display only. Null
 * when the SBOM declared none, unlike `dependencyScopeBadge` which always has an `unknown` state.
 * @param {{ sbomScope?: string|null }} item
 * @returns {{ key: string, cls: string, labelKey: string, titleKey: string }|null}
 */
export function sbomScopeBadge(item) {
  const sbom = item?.sbomScope
  if (!sbom) return null
  return {
    key: `sbom-${sbom}`,
    cls: `scope-${sbom}`,
    labelKey: `sbomAnalysis.scope.${sbom}`,
    titleKey: `sbomAnalysis.scope.${sbom}Help`,
  }
}

const PRIORITY_RANK = { act: 4, attend: 3, track: 2, suppressed: 1 }

/** True when the server put this advisory in the suppressed bucket. */
export function isSuppressed(advisory) {
  return advisory?.effectivePriority === 'suppressed'
}

/**
 * The advisories a row shows. Suppressed ones are hidden unless "Show suppressed" is on — the
 * server applies the same rule to its own counts, so the two agree.
 */
export function visibleAdvisories(item, showSuppressed) {
  const all = item?.advisories ?? []
  return showSuppressed ? all : all.filter(a => !isSuppressed(a))
}

/** How many of a row's advisories the server put in the suppressed bucket. */
export function suppressedCount(item) {
  return (item?.advisories ?? []).filter(isSuppressed).length
}

/**
 * The row's headline priority: the strongest bucket the server assigned to any advisory it
 * carries. Null when the row has no advisory to summarize.
 * @returns {string|null}
 */
export function rowPriority(item, showSuppressed = false) {
  let best = null
  for (const a of visibleAdvisories(item, showSuppressed)) {
    const rank = PRIORITY_RANK[a?.effectivePriority] ?? 0
    if (rank === 0) continue
    if (best === null || rank > PRIORITY_RANK[best]) best = a.effectivePriority
  }
  return best
}

const REACH_RANK = { reachable: 4, 'imported-not-called': 3, 'not-observed': 2, unknown: 1 }

/** Normalize a reachability value to the badge spelling (`not_observed` → `not-observed`). */
export function normalizeReach(value) {
  if (!value) return null
  return String(value).trim().toLowerCase().replace(/[\s_]+/g, '-')
}

/**
 * The row's reachability: the strongest value any of its advisories carries. Null when no
 * advisory has one — no SARIF was uploaded, which the table renders as an em dash rather than
 * as "unknown", because "nobody told us" and "the analyzer said unknown" are different
 * statements.
 * @returns {string|null}
 */
export function rowReach(item, showSuppressed = false) {
  let best = null
  for (const a of visibleAdvisories(item, showSuppressed)) {
    const value = normalizeReach(a?.reachability)
    if (!value) continue
    if (best === null || (REACH_RANK[value] ?? 0) > (REACH_RANK[best] ?? 0)) best = value
  }
  return best
}

/** Badge class + locale key for a reachability value, or null when there is nothing to show. */
export function reachBadge(value) {
  const norm = normalizeReach(value)
  if (!norm) return null
  const known = REACHABILITIES.includes(norm)
  return {
    value: norm,
    cls: known ? `reach-${norm}` : 'reach-unknown',
    labelKey: known ? `sbomAnalysis.reach.${norm}` : null,
    raw: norm,
  }
}

/**
 * Optional decision-support chips an advisory may carry: an SSVC decision, the NVD/GHSA
 * severity bands, and the cvelistV5 CVSS/SSVC overlay. Nothing emits these yet, so an advisory
 * without them renders no chips at all rather than an empty or "unknown" one — an overlay that
 * is not configured has said nothing, and the panel must not put words in its mouth. Keeping the
 * field names in one place is what makes wiring the overlay a one-function change.
 *
 * The cvelistV5 chips are DELIBERATELY separate from the NVD/GHSA ones above, never merged: the
 * tracker's own design doc measured 34%+ disagreement between the NVD-mirror and cvelistV5
 * readings of the same CVE, so folding them into one chip would hide that disagreement.
 * @returns {Array<{ key: string, kind: string, value: string, title: string|null }>}
 */
export function overlayChips(advisory) {
  const chips = []
  const ssvc = advisory?.ssvcDecision
  if (ssvc) {
    chips.push({ key: 'ssvc', kind: 'ssvc', value: String(ssvc), title: advisory.ssvcVector ?? null })
  }
  const nvd = advisory?.nvdSeverityBand
  if (nvd) chips.push({ key: 'nvd', kind: 'band', value: `NVD ${nvd}`, title: null })
  const ghsa = advisory?.ghsaSeverityBand
  if (ghsa) chips.push({ key: 'ghsa', kind: 'band', value: `GHSA ${ghsa}`, title: null })
  const cvelistBand = advisory?.cvelistCvssSeverityBand
  if (cvelistBand) chips.push({ key: 'cvelist-cvss', kind: 'band', value: `cvelistV5 ${cvelistBand}`, title: null })
  const cvelistSsvc = advisory?.cvelistSsvcDecision
  if (cvelistSsvc) {
    chips.push({
      key: 'cvelist-ssvc', kind: 'ssvc',
      value: `cvelistV5 ${cvelistSsvc}`, title: advisory.cvelistSsvcVector ?? null,
    })
  }
  return chips
}

/**
 * Exploit-code observation chip — informational, alongside the EPSS/CVSS/KEV badges rather than
 * at a different visual tier. `exploitCodeExists` is never null at the source (the producer
 * defaults it false), so this renders only when true: a package nothing has observed exploit
 * code for says nothing, the same "no chip" convention every other optional signal here uses.
 * @returns {{ key: string, kind: string, value: string, title: string|null }|null}
 */
export function exploitCodeChip(advisory) {
  if (!advisory?.exploitCodeExists) return null
  const sources = Array.isArray(advisory.exploitCodeSources) ? advisory.exploitCodeSources : []
  const title = sources.length ? sources.join(', ') : null
  const weight = advisory.exploitCodeMaxWeight
  return {
    key: 'exploit-code',
    kind: 'exploit-code',
    value: weight === null || weight === undefined ? 'Exploit code' : `Exploit code (${weight})`,
    title,
  }
}

/**
 * The still-live-malicious badge — the version-precise signal wired into the live block gate
 * (BlockGateService's MaliciousLive arm), so it is rendered as the MOST alarming tier, matching
 * how the KEV-ransomware badge above is styled as this panel's current top tier. Distinct from
 * the raw `malStillLive`/`malLiveVersions` pass-through (whole-package, not version-scoped) —
 * this reads only the derived, already-version-precise flag.
 * @returns {{ checkedAt: string|null }|null}
 */
export function stillLiveMaliciousBadge(advisory) {
  if (!advisory?.malStillLive) return null
  return { checkedAt: advisory.malLiveCheckedAt ?? null }
}

/**
 * Compromised-versions chip — informational display of the OpenSSF malicious-packages raw
 * pass-through. Null when the producer named no compromised versions.
 * @returns {{ versions: string[] }|null}
 */
export function compromisedVersionsChip(advisory) {
  const versions = advisory?.malCompromisedVersions
  if (!Array.isArray(versions) || versions.length === 0) return null
  return { versions }
}

/**
 * Severity chip counts for a row, over the advisories it is currently showing. `unscored` is
 * its own bucket rather than being folded into "low" or dropped — an advisory nobody scored is
 * an open question, and the chip says so.
 */
export function severityChips(item, showSuppressed = false) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unscored: 0 }
  for (const a of visibleAdvisories(item, showSuppressed)) {
    if (a?.unscored) { counts.unscored++; continue }
    const sev = String(a?.severity ?? '').toLowerCase()
    if (SEVERITIES.includes(sev)) counts[sev]++
    else counts.unscored++
  }
  return counts
}

/** True when a row carries at least one policy violation on a visible advisory. */
export function hasViolation(item, showSuppressed = false) {
  return visibleAdvisories(item, showSuppressed).some(a => (a?.policyViolations ?? []).length > 0)
}

/** SPDX compound-expression operators, which are separators rather than licence identifiers. */
const SPDX_OPERATORS = new Set(['AND', 'OR', 'WITH'])

/**
 * SPDX identifiers for a component. The payload field is a single `licenseSpdx`, but a
 * component may legitimately declare several, so an array is accepted, and a compound
 * expression is split on its operators for per-identifier blocklist matching.
 * @returns {string[]}
 */
export function licenseList(item) {
  const raw = item?.licenseSpdx
  if (!raw) return []
  const values = Array.isArray(raw) ? raw : [raw]
  // Split on whitespace and drop the operator tokens rather than matching the operators
  // themselves: `\s+(?:AND|OR|WITH)\s+` backtracks quadratically over a long run of spaces,
  // where a bare `\s+` split cannot.
  return values
    .flatMap(v => String(v).split(/\s+/))
    .map(v => v.replace(/[()]/g, '').trim())
    .filter(v => v && !SPDX_OPERATORS.has(v.toUpperCase()))
}

/**
 * Whether an SPDX id sits on the org's license blocklist. The blocklist is the org's own
 * license policy, fetched alongside the analysis — the analysis payload carries the policy
 * verdict per advisory, not per license string.
 * @param {string} spdx
 * @param {Set<string>|null|undefined} blocklist uppercased identifiers
 */
export function isBlocklisted(spdx, blocklist) {
  if (!spdx || !blocklist) return false
  return blocklist.has(spdx.toUpperCase())
}

/**
 * Dependency-path breadcrumb labels. The path arrives as JSON from the SBOM's dependency
 * graph; entries may be plain strings or objects carrying a name/purl/ref, so all are accepted.
 * @returns {string[]}
 */
export function dependencyPathLabels(path) {
  if (!Array.isArray(path)) return []
  return path
    .map(node => {
      if (node === null || node === undefined) return ''
      if (typeof node === 'string') return node
      return String(node.name ?? node.purl ?? node.ref ?? '')
    })
    .map(s => s.trim())
    .filter(Boolean)
}

/**
 * Fallback download name for an export. `downloadBlob` prefers the server's
 * Content-Disposition and sanitizes whatever it ends up with to `[\w.-]`, so this is only the
 * name used when the server sends none.
 * @param {string} project
 * @param {string} version
 * @param {'inventory'|'vdr'|'vex'} variant
 */
export function exportFilename(project, version, variant) {
  // Rebuilt from its surviving segments rather than trimmed with `/^-+|-+$/`: that alternation
  // anchors each branch separately, and `-+$` backtracks quadratically over a run of dashes.
  const slug = (s) =>
    String(s ?? '')
      .split(/[^\w.-]+/)
      .flatMap(part => part.split('-'))
      .filter(Boolean)
      .join('-')
  const parts = [slug(project), slug(version), variant].filter(Boolean)
  return `${parts.join('-') || 'export'}.cdx.json`
}

/** Short display form of a sha256 — enough to eyeball against a CI log line. */
export function shortSha(sha) {
  if (!sha) return ''
  return String(sha).slice(0, 12)
}

/**
 * The body for PUT …/analysis. Only fields the operator actually changed travel, because the
 * endpoint carries its partial-update fields as Optional<T> — an absent field means "leave
 * unchanged", which is not the same as an explicit null. Extra keys are never added: the
 * management binder rejects an unmapped member with a 400.
 *
 * A state that carries no justification in CycloneDX clears any stale one, so the cleared
 * value travels explicitly rather than being left behind on the row.
 *
 * @param {{purlKey: string, vulnKey: string}} keys
 * @param {Record<string, any>} original the advisory as it arrived
 * @param {Record<string, any>} draft the edited values
 * @returns {Record<string, any>} the request body
 */
export function triagePatch(keys, original, draft) {
  const body = { purlKey: keys.purlKey, vulnKey: keys.vulnKey }
  const norm = (v) => (v === '' || v === undefined ? null : v)
  const state = norm(draft.vexState)
  if (state !== norm(original.vexState)) body.vexState = state

  const justification = justificationEnabled(state) ? norm(draft.vexJustification) : null
  if (justification !== norm(original.vexJustification)) body.vexJustification = justification

  const response = norm(draft.vexResponse)
  if (response !== norm(original.vexResponse)) body.vexResponse = response

  const detail = norm(draft.vexDetail)
  if (detail !== norm(original.vexDetail)) body.vexDetail = detail

  return body
}

/** True when a triage patch would change nothing — the Save button stays disabled. */
export function triagePatchIsEmpty(body) {
  return Object.keys(body).filter(k => k !== 'purlKey' && k !== 'vulnKey').length === 0
}

/**
 * Overlay the refreshed analysis row returned by the triage PUT onto the advisory already on
 * screen, so the row updates without a table reload. Only keys the response actually carries
 * are copied — a response that omits a field leaves the rendered value alone rather than
 * blanking it.
 */
export function mergeAnalysisRow(advisory, refreshed) {
  if (!refreshed) return advisory
  const merged = { ...advisory }
  const fields = [
    'vexState', 'vexJustification', 'vexResponse', 'vexDetail', 'vexSource',
    'vexUpdatedBy', 'vexUpdatedAt', 'effectivePriority', 'reachability', 'confidence',
    'sarifSuppressed', 'policyViolations',
  ]
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(refreshed, f)) merged[f] = refreshed[f]
  }
  // The write just stamped `updated_at = now`, so the row it produced can never predate the
  // version it was written against — an operator who just triaged this release did so *for*
  // this release, whatever the badge said a moment ago.
  merged.inherited = false
  return merged
}

/**
 * Worst non-suppressed severity across the version, for the Security pillar. Read off the
 * rollup's severity counts, which the server computes over the whole version rather than over
 * the page on screen. Returns 'unscored' when the only advisories are unscored ones, and null
 * when there are none at all.
 * @returns {string|null}
 */
export function worstSeverity(rollup) {
  const counts = rollup?.severityCounts ?? {}
  for (const sev of SEVERITIES) {
    if ((counts[sev] ?? 0) > 0) return sev
  }
  return (counts.unscored ?? 0) > 0 ? 'unscored' : null
}

/**
 * Policy pillar signal. `policyStatus` is null until the version has been evaluated once —
 * rendered as "not evaluated", never as a pass.
 * @returns {{ tone: string, status: string, count: number }}
 */
export function policySignal(rollup) {
  const count = rollup?.violationCount ?? 0
  const status = rollup?.policyStatus ?? null
  if (status === 'violation' || count > 0) return { tone: 'warn', status: 'violation', count }
  if (status === 'warn') return { tone: 'review', status: 'warn', count }
  if (status === 'pass') return { tone: 'clean', status: 'pass', count: 0 }
  return { tone: 'muted', status: 'unevaluated', count: 0 }
}

/**
 * Registry cross-link chips for one component row, in the order they read: blocked first (a
 * decision this registry has already taken), then deprecated, then the version gap.
 *
 * The server decides every one of these — the row only picks a class and a locale key. Two
 * distinctions are carried through deliberately:
 *
 * - `blocked`/`deprecated` are `'version'` (the exact version this application ships) or
 *   `'package'` (some other version of the same package). A package-level hit is rendered as its
 *   own weaker chip rather than dropped, because dropping it would read as a clean row on a
 *   package the operator has already quarantined.
 * - `outdated` is tri-state. `null` means the ecosystem has no native version ordering, so the
 *   chip states the version the registry knows and makes no claim about the one shipped —
 *   never a silent "up to date".
 *
 * @param {{ registry?: Record<string, any>|null, version?: string|null }} item
 * @returns {Array<{ key: string, cls: string, labelKey: string, titleKey: string, values?: Record<string, any> }>}
 */
/**
 * The blocked and deprecated chips share one shape: a `'version'` scope names the exact version
 * shipped, anything else is the weaker package-level hit, and both spellings key off the same
 * `Other` suffix.
 */
function scopedRegistryChip(kind, scope, cls) {
  const suffix = scope === 'version' ? '' : 'Other'
  return {
    key: kind,
    cls,
    labelKey: `sbomAnalysis.registry.${kind}${suffix}`,
    titleKey: `sbomAnalysis.registry.${kind}${suffix}Help`,
  }
}

/**
 * The version-gap chip, or null. `outdated === null` is the third state: the ecosystem has no
 * native ordering, so the chip states what the registry knows and claims nothing about the gap.
 */
function latestVersionChip(registry, shipped) {
  if (!registry.latestVersion) return null
  if (registry.outdated === true) {
    return {
      key: 'outdated',
      cls: 'registry-outdated',
      labelKey: 'sbomAnalysis.registry.outdated',
      titleKey: 'sbomAnalysis.registry.outdatedHelp',
      values: { latest: registry.latestVersion, shipped: shipped ?? '' },
    }
  }
  if (registry.outdated === null) {
    return {
      key: 'latest-unknown',
      cls: 'registry-unknown',
      labelKey: 'sbomAnalysis.registry.latestKnown',
      titleKey: 'sbomAnalysis.registry.latestKnownHelp',
      values: { latest: registry.latestVersion },
    }
  }
  return null
}

export function registryChips(item) {
  const registry = item?.registry
  if (!registry || registry.presence !== 'present') return []

  const out = []
  if (registry.blocked) {
    out.push(scopedRegistryChip(
      'blocked',
      registry.blocked,
      registry.blocked === 'version' ? 'registry-blocked' : 'registry-blocked-other'))
  }
  if (registry.deprecated) {
    out.push(scopedRegistryChip('deprecated', registry.deprecated, 'registry-deprecated'))
  }

  const latest = latestVersionChip(registry, item.version)
  if (latest) out.push(latest)

  return out
}

/**
 * Rollup note for the components this registry has never served — the blind spot. Null at zero,
 * for the same reason `unscannableNote` is: nothing unvetted is a non-event, and a zero badge
 * would be a reassurance nobody asked for.
 *
 * `unknown` is reported alongside rather than folded in. A component with no purl is a question
 * the registry cannot be asked; counting it as never-vetted would inflate the number the operator
 * is meant to act on, and hiding it would drop it entirely.
 * @returns {{ count: number, unknown: number, labelKey: string, titleKey: string }|null}
 */
export function blindSpotNote(rollup) {
  const counts = rollup?.registryCounts
  const count = counts?.notInRegistry ?? 0
  if (count <= 0) return null
  return {
    count,
    unknown: counts?.unknown ?? 0,
    labelKey: 'sbomAnalysis.rollup.notInRegistry',
    titleKey: 'sbomAnalysis.rollup.notInRegistryHelp',
  }
}

/**
 * Rollup note for components carrying no coordinate at all. Separate from `blindSpotNote` because
 * it is a different statement: not "the registry never served this" but "the registry cannot be
 * asked". Null at zero.
 * @returns {{ count: number, labelKey: string, titleKey: string }|null}
 */
export function uncoordinatedNote(rollup) {
  const count = rollup?.registryCounts?.unknown ?? 0
  if (count <= 0) return null
  return {
    count,
    labelKey: 'sbomAnalysis.rollup.registryUnknown',
    titleKey: 'sbomAnalysis.rollup.registryUnknownHelp',
  }
}

/**
 * Rollup note for components no advisory feed can ever answer for — no parseable
 * purl/ecosystem, or an ecosystem with no feed. Distinct from a deferred scan: a deferred scan
 * holds the version at warn and resolves once the advisory source is reachable again, while an
 * unscannable component does neither, so on a warn version the note carries the warn-specific
 * help so the operator knows waiting fixes the deferral, never these components. Null when the
 * count is zero — nothing unscannable is a non-event, and the page renders no affordance at
 * all rather than a reassuring zero.
 * @returns {{ count: number, labelKey: string, titleKey: string }|null}
 */
export function unscannableNote(rollup) {
  const count = rollup?.unscannableCount ?? 0
  if (count <= 0) return null
  const atWarn = policySignal(rollup).status === 'warn'
  return {
    count,
    labelKey: 'sbomAnalysis.rollup.unscannable',
    titleKey: atWarn
      ? 'sbomAnalysis.rollup.unscannableWarnHelp'
      : 'sbomAnalysis.rollup.unscannableHelp',
  }
}

/**
 * Rollup note for components the SBOM's own producer marked out of scope (`scope='excluded'`),
 * which the policy evaluator exempts from the four vulnerability arms — an exemption that is
 * otherwise invisible, the same blind spot `unscannableNote` closes for components no advisory
 * feed can answer for. Null at zero: nothing excluded is a non-event.
 *
 * Labelled "excluded", never "suppressed": the priority ribbon already owns "Suppressed" for the
 * VEX-suppression bucket (a VEX statement said the finding does not apply to this product) — a
 * different fact from a producer's own scope declaration. Two same-named numbers in one ribbon
 * are worse than one missing one, so this reads "excluded from build", the vocabulary CycloneDX's
 * own `scope` value already uses (see `sbomAnalysis.scope.excluded`).
 * @returns {{ count: number, labelKey: string, titleKey: string }|null}
 */
export function excludedByScopeNote(rollup) {
  const count = rollup?.scopeSuppressedCount ?? 0
  if (count <= 0) return null
  return {
    count,
    labelKey: 'sbomAnalysis.rollup.excludedByScope',
    titleKey: 'sbomAnalysis.rollup.excludedByScopeHelp',
  }
}

/** Priority buckets, strongest first — the order the ribbon renders them in. */
export const PRIORITY_BUCKETS = ['act', 'attend', 'track', 'suppressed']

/**
 * The version-wide priority tally for the header ribbon. Always four entries, zero-filled, so
 * the ribbon renders a stable set of splits rather than reflowing as buckets empty out. There is
 * no server-side priority filter, so these are deliberately read-only counts, never a control —
 * offering one would silently only ever narrow the page already on screen.
 * @returns {Array<{ key: string, count: number, labelKey: string }>}
 */
export function priorityBreakdown(rollup) {
  const counts = rollup?.priorityCounts ?? {}
  return PRIORITY_BUCKETS.map(key => ({
    key,
    count: counts[key] ?? 0,
    labelKey: `sbomAnalysis.priority.${key}`,
  }))
}

/**
 * Version-wide licence signal for the License pillar, read off the rollup rather than measured
 * over the page currently on screen. `blockedCount` sums the rollup's per-identifier tally for
 * every SPDX id on the org's blocklist — the rollup does not report a blocked count directly, but
 * `byIdentifier` carries enough to derive one without a second per-component pass.
 * @param {Record<string, any>|null} rollup
 * @param {Set<string>|null|undefined} blocklist uppercased identifiers
 * @returns {{ flagged: number, undeclared: number, blockedCount: number }}
 */
export function licenseRollupSignal(rollup, blocklist) {
  const counts = rollup?.licenseCounts
  const undeclared = counts?.undeclared ?? 0
  let blockedCount = 0
  if (blocklist && blocklist.size > 0) {
    for (const [identifier, count] of Object.entries(counts?.byIdentifier ?? {})) {
      if (isBlocklisted(identifier, blocklist)) blockedCount += count
    }
  }
  return { flagged: undeclared + blockedCount, undeclared, blockedCount }
}

/**
 * The strongest licence identifiers by component count, for a compact breakdown under the
 * License pillar. `byIdentifier` already arrives sorted desc from the server.
 * @param {Record<string, any>|null} rollup
 * @param {number} limit
 * @returns {Array<{ identifier: string, count: number }>}
 */
export function licenseBreakdown(rollup, limit = 5) {
  const byIdentifier = rollup?.licenseCounts?.byIdentifier ?? {}
  return Object.entries(byIdentifier)
    .slice(0, limit)
    .map(([identifier, count]) => ({ identifier, count }))
}
