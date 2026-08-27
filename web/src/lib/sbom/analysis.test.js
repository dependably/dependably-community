import { describe, it, expect } from 'vitest'
import {
  DEFAULT_TABLE_STATE,
  analysisQuery,
  blindSpotNote,
  dependencyPathLabels,
  dependencyScopeBadge,
  excludedByScopeNote,
  exportFilename,
  hasViolation,
  isBlocklisted,
  justificationEnabled,
  licenseBreakdown,
  licenseList,
  licenseRollupSignal,
  mergeAnalysisRow,
  normalizeReach,
  overlayChips,
  policySignal,
  priorityBreakdown,
  reachBadge,
  registryChips,
  rowPriority,
  rowReach,
  sbomScopeBadge,
  severityChips,
  shortSha,
  suppressedCount,
  triagePatch,
  triagePatchIsEmpty,
  uncoordinatedNote,
  unscannableNote,
  visibleAdvisories,
  worstSeverity,
} from './analysis.js'

describe('analysisQuery', () => {
  it('always sends page/limit/sort/dir so the server owns paging and ordering', () => {
    expect(analysisQuery(DEFAULT_TABLE_STATE)).toEqual({
      page: 1, limit: 50, sort: 'priority', dir: 'desc',
    })
  })

  it('omits every empty filter rather than sending blanks', () => {
    const q = analysisQuery({ ...DEFAULT_TABLE_STATE, q: '', scope: '', sev: '', reach: '' })
    expect(Object.keys(q).sort()).toEqual(['dir', 'limit', 'page', 'sort'])
  })

  it('passes the search, scope, severity and reachability filters straight through', () => {
    const q = analysisQuery({
      ...DEFAULT_TABLE_STATE, q: 'express', scope: 'prod', sev: 'high', reach: 'reachable', page: 3,
    })
    expect(q).toMatchObject({ q: 'express', scope: 'prod', sev: 'high', reach: 'reachable', page: 3 })
  })

  it('sends the two toggles as true only when switched on', () => {
    expect(analysisQuery({ ...DEFAULT_TABLE_STATE, violations: '1', suppressed: '1' }))
      .toMatchObject({ violations: 'true', suppressed: 'true' })
    const off = analysisQuery(DEFAULT_TABLE_STATE)
    expect(off.violations).toBeUndefined()
    expect(off.suppressed).toBeUndefined()
  })

  it('falls back to the default sort when the URL carried an empty one', () => {
    expect(analysisQuery({ ...DEFAULT_TABLE_STATE, sort: '', dir: '' }))
      .toMatchObject({ sort: 'priority', dir: 'desc' })
  })
})

describe('dependencyScopeBadge', () => {
  it('renders the dev/prod signal for the Dependency column', () => {
    expect(dependencyScopeBadge({ dependencyScope: 'runtime' }).cls).toBe('scope-runtime')
    expect(dependencyScopeBadge({ dependencyScope: 'dev' }).cls).toBe('scope-dev')
  })

  it('labels an unclassified component "unknown" instead of leaving it blank', () => {
    const badge = dependencyScopeBadge({ dependencyScope: null })
    expect(badge.cls).toBe('scope-unknown')
    expect(badge.labelKey).toBe('sbomAnalysis.scope.unknown')
  })
})

describe('sbomScopeBadge', () => {
  it('renders the raw CycloneDX scope for the Scope column', () => {
    expect(sbomScopeBadge({ sbomScope: 'required' })?.cls).toBe('scope-required')
    expect(sbomScopeBadge({ sbomScope: 'excluded' })?.cls).toBe('scope-excluded')
  })

  it('returns null rather than an "unknown" badge when the SBOM declared no scope', () => {
    expect(sbomScopeBadge({ sbomScope: null })).toBeNull()
    expect(sbomScopeBadge({})).toBeNull()
  })
})

describe('visibleAdvisories / suppressedCount', () => {
  const item = {
    advisories: [
      { vulnKey: 'a', effectivePriority: 'act' },
      { vulnKey: 'b', effectivePriority: 'suppressed' },
      { vulnKey: 'c', effectivePriority: 'track' },
    ],
  }

  it('hides suppressed advisories by default', () => {
    expect(visibleAdvisories(item, false).map(a => a.vulnKey)).toEqual(['a', 'c'])
  })

  it('shows them under the toggle', () => {
    expect(visibleAdvisories(item, true)).toHaveLength(3)
  })

  it('counts suppressed advisories regardless of the toggle', () => {
    expect(suppressedCount(item)).toBe(1)
    expect(suppressedCount({})).toBe(0)
  })
})

describe('rowPriority', () => {
  it('summarizes the row with the strongest bucket the server assigned', () => {
    const item = {
      advisories: [
        { effectivePriority: 'track' },
        { effectivePriority: 'act' },
        { effectivePriority: 'attend' },
      ],
    }
    expect(rowPriority(item)).toBe('act')
  })

  it('is null when every advisory is suppressed and the toggle is off', () => {
    expect(rowPriority({ advisories: [{ effectivePriority: 'suppressed' }] })).toBeNull()
  })

  it('reports the suppressed bucket when the toggle is on', () => {
    expect(rowPriority({ advisories: [{ effectivePriority: 'suppressed' }] }, true)).toBe('suppressed')
  })

  it('ignores a bucket name it does not recognise rather than ranking it', () => {
    expect(rowPriority({ advisories: [{ effectivePriority: 'whatever' }] })).toBeNull()
  })
})

describe('reachability', () => {
  it('normalizes the snake_case spelling the payload may use', () => {
    expect(normalizeReach('NOT_OBSERVED')).toBe('not-observed')
    expect(normalizeReach('imported not called')).toBe('imported-not-called')
    expect(normalizeReach(null)).toBeNull()
  })

  it('renders no badge at all when SARIF never supplied a value', () => {
    expect(reachBadge(null)).toBeNull()
    expect(rowReach({ advisories: [{ effectivePriority: 'act' }] })).toBeNull()
  })

  it('distinguishes an analyzer-declared unknown from an absent value', () => {
    const badge = reachBadge('unknown')
    expect(badge?.cls).toBe('reach-unknown')
    expect(badge?.labelKey).toBe('sbomAnalysis.reach.unknown')
  })

  it('falls back to the raw value for a reachability vocabulary it does not know', () => {
    const badge = reachBadge('partially-reachable')
    expect(badge?.cls).toBe('reach-unknown')
    expect(badge?.labelKey).toBeNull()
    expect(badge?.raw).toBe('partially-reachable')
  })

  it('summarizes a row with the strongest reachability among its advisories', () => {
    const item = {
      advisories: [
        { effectivePriority: 'track', reachability: 'not_observed' },
        { effectivePriority: 'act', reachability: 'reachable' },
      ],
    }
    expect(rowReach(item)).toBe('reachable')
  })
})

describe('severityChips', () => {
  it('buckets an unscored advisory on its own instead of dropping or downgrading it', () => {
    const item = {
      advisories: [
        { effectivePriority: 'act', severity: 'critical' },
        { effectivePriority: 'track', severity: null, unscored: true },
        { effectivePriority: 'track', severity: 'LOW' },
      ],
    }
    expect(severityChips(item)).toEqual({ critical: 1, high: 0, medium: 0, low: 1, unscored: 1 })
  })

  it('treats a severity string it does not recognise as unscored, never as silently absent', () => {
    const item = { advisories: [{ effectivePriority: 'track', severity: 'moderate' }] }
    expect(severityChips(item).unscored).toBe(1)
  })

  it('excludes suppressed advisories from the counts by default', () => {
    const item = {
      advisories: [
        { effectivePriority: 'suppressed', severity: 'critical' },
        { effectivePriority: 'act', severity: 'high' },
      ],
    }
    expect(severityChips(item)).toMatchObject({ critical: 0, high: 1 })
    expect(severityChips(item, true)).toMatchObject({ critical: 1, high: 1 })
  })
})

describe('overlayChips', () => {
  it('renders nothing when the decision-support overlay is not configured', () => {
    expect(overlayChips({ vulnKey: 'CVE-1', severity: 'high' })).toEqual([])
    expect(overlayChips({})).toEqual([])
  })

  it('renders the SSVC decision with its vector as the hover title', () => {
    const chips = overlayChips({ ssvcDecision: 'act', ssvcVector: 'SSVCv2/E:A/A:Y/' })
    expect(chips).toEqual([{ key: 'ssvc', kind: 'ssvc', value: 'act', title: 'SSVCv2/E:A/A:Y/' }])
  })

  it('renders each severity band that is present, independently', () => {
    expect(overlayChips({ nvdSeverityBand: 'HIGH' }).map(c => c.value)).toEqual(['NVD HIGH'])
    expect(overlayChips({ ghsaSeverityBand: 'MODERATE' }).map(c => c.value)).toEqual(['GHSA MODERATE'])
  })
})

describe('hasViolation', () => {
  it('is true only when a visible advisory carries a policy violation', () => {
    const suppressedOnly = {
      advisories: [{ effectivePriority: 'suppressed', policyViolations: [{ arm: 'KEV' }] }],
    }
    expect(hasViolation(suppressedOnly)).toBe(false)
    expect(hasViolation(suppressedOnly, true)).toBe(true)
    expect(hasViolation({ advisories: [{ effectivePriority: 'act', policyViolations: [] }] })).toBe(false)
  })
})

describe('licenseList / isBlocklisted', () => {
  it('splits a compound SPDX expression so each identifier can be matched', () => {
    expect(licenseList({ licenseSpdx: '(MIT OR Apache-2.0)' })).toEqual(['MIT', 'Apache-2.0'])
    expect(licenseList({ licenseSpdx: 'GPL-2.0-only WITH Classpath-exception-2.0' }))
      .toEqual(['GPL-2.0-only', 'Classpath-exception-2.0'])
  })

  it('accepts an array as well as a single value, and an absent licence as empty', () => {
    expect(licenseList({ licenseSpdx: ['MIT', 'ISC'] })).toEqual(['MIT', 'ISC'])
    expect(licenseList({})).toEqual([])
  })

  it('drops a bare operator token left by a malformed expression', () => {
    // The split is on whitespace, not on `\s+OPERATOR\s+`, so an operator with nothing after it
    // is dropped rather than carried into an identifier.
    expect(licenseList({ licenseSpdx: 'MIT OR' })).toEqual(['MIT'])
    expect(licenseList({ licenseSpdx: 'AND' })).toEqual([])
    expect(licenseList({ licenseSpdx: 'MIT   or   ISC' })).toEqual(['MIT', 'ISC'])
  })

  it('matches the blocklist case-insensitively', () => {
    const blocklist = new Set(['AGPL-3.0-ONLY'])
    expect(isBlocklisted('agpl-3.0-only', blocklist)).toBe(true)
    expect(isBlocklisted('MIT', blocklist)).toBe(false)
    expect(isBlocklisted('MIT', null)).toBe(false)
  })
})

describe('dependencyPathLabels', () => {
  it('reads plain string nodes', () => {
    expect(dependencyPathLabels(['webapp', 'express', 'qs'])).toEqual(['webapp', 'express', 'qs'])
  })

  it('reads object nodes by name, purl, then ref', () => {
    expect(dependencyPathLabels([{ name: 'webapp' }, { purl: 'pkg:npm/express@4' }, { ref: 'qs' }]))
      .toEqual(['webapp', 'pkg:npm/express@4', 'qs'])
  })

  it('drops empty nodes and a non-array path', () => {
    expect(dependencyPathLabels(['webapp', '', null])).toEqual(['webapp'])
    expect(dependencyPathLabels(null)).toEqual([])
  })
})

describe('exportFilename', () => {
  it('names the three exports after the project and version', () => {
    expect(exportFilename('checkout-api', '1.4.0', 'inventory')).toBe('checkout-api-1.4.0-inventory.cdx.json')
    expect(exportFilename('checkout-api', '1.4.0', 'vdr')).toBe('checkout-api-1.4.0-vdr.cdx.json')
    expect(exportFilename('checkout-api', '1.4.0', 'vex')).toBe('checkout-api-1.4.0-vex.cdx.json')
  })

  it('survives labels the download sanitizer would otherwise strip to nothing', () => {
    expect(exportFilename('my org/app', 'v1 (rc)', 'vdr')).toBe('my-org-app-v1-rc-vdr.cdx.json')
    expect(exportFilename('', '', 'vex')).toBe('vex.cdx.json')
  })

  it('leaves no leading, trailing, or repeated dash in a slug', () => {
    expect(exportFilename('--checkout--api--', '__1.4.0__', 'vdr'))
      .toBe('checkout-api-__1.4.0__-vdr.cdx.json')
    expect(exportFilename('///', '- -', 'vex')).toBe('vex.cdx.json')
  })
})

describe('shortSha', () => {
  it('truncates to twelve characters and tolerates an absent digest', () => {
    expect(shortSha('a'.repeat(64))).toBe('aaaaaaaaaaaa')
    expect(shortSha(null)).toBe('')
  })
})

describe('triagePatch', () => {
  const keys = { purlKey: 'pkg:npm/qs', vulnKey: 'CVE-2022-24999' }
  const original = {
    vexState: 'in_triage', vexJustification: null, vexResponse: null, vexDetail: null,
  }

  it('sends only the fields the operator changed', () => {
    const body = triagePatch(keys, original, { ...original, vexState: 'exploitable' })
    expect(body).toEqual({ ...keys, vexState: 'exploitable' })
  })

  it('never adds a key the endpoint does not declare', () => {
    const body = triagePatch(keys, original, { ...original, vexDetail: 'reviewed', extra: 'nope' })
    expect(Object.keys(body).sort()).toEqual(['purlKey', 'vexDetail', 'vulnKey'])
  })

  it('clears a stale justification when the state no longer permits one', () => {
    const withJustification = { ...original, vexState: 'not_affected', vexJustification: 'code_not_present' }
    const body = triagePatch(keys, withJustification, { ...withJustification, vexState: 'exploitable' })
    expect(body.vexJustification).toBeNull()
    expect(body.vexState).toBe('exploitable')
  })

  it('keeps the justification when the state still permits one', () => {
    const draft = { ...original, vexState: 'not_affected', vexJustification: 'code_not_reachable' }
    const body = triagePatch(keys, original, draft)
    expect(body.vexJustification).toBe('code_not_reachable')
  })

  it('treats an emptied field as an explicit clear, not as unchanged', () => {
    const withDetail = { ...original, vexDetail: 'old note' }
    const body = triagePatch(keys, withDetail, { ...withDetail, vexDetail: '' })
    expect(body.vexDetail).toBeNull()
  })

  it('reports an untouched form as an empty patch so Save stays disabled', () => {
    expect(triagePatchIsEmpty(triagePatch(keys, original, { ...original }))).toBe(true)
    expect(triagePatchIsEmpty(triagePatch(keys, original, { ...original, vexResponse: 'update' }))).toBe(false)
  })
})

describe('justificationEnabled', () => {
  it('is on for not_affected only', () => {
    expect(justificationEnabled('not_affected')).toBe(true)
    for (const state of ['in_triage', 'exploitable', 'resolved', 'resolved_with_pedigree', 'false_positive']) {
      expect(justificationEnabled(state)).toBe(false)
    }
  })
})

describe('mergeAnalysisRow', () => {
  const advisory = {
    vulnKey: 'CVE-1', severity: 'high', effectivePriority: 'act',
    vexState: 'in_triage', vexSource: null, reachability: 'reachable',
  }

  it('overlays the refreshed fields the response carried', () => {
    const merged = mergeAnalysisRow(advisory, {
      vexState: 'not_affected', vexSource: 'manual', effectivePriority: 'suppressed',
    })
    expect(merged).toMatchObject({
      vexState: 'not_affected', vexSource: 'manual', effectivePriority: 'suppressed',
    })
  })

  it('leaves fields the response omitted alone rather than blanking them', () => {
    const merged = mergeAnalysisRow(advisory, { vexState: 'resolved' })
    expect(merged.severity).toBe('high')
    expect(merged.reachability).toBe('reachable')
  })

  it('honours an explicit null in the response as a clear', () => {
    const merged = mergeAnalysisRow({ ...advisory, vexDetail: 'note' }, { vexDetail: null })
    expect(merged.vexDetail).toBeNull()
  })

  it('returns the advisory untouched when the response was empty', () => {
    expect(mergeAnalysisRow(advisory, null)).toBe(advisory)
  })
})

describe('worstSeverity', () => {
  it('reads the worst bucket off the server rollup', () => {
    expect(worstSeverity({ severityCounts: { critical: 0, high: 2, medium: 5 } })).toBe('high')
  })

  it('reports unscored rather than clean when the only advisories are unscored', () => {
    expect(worstSeverity({ severityCounts: { critical: 0, high: 0, medium: 0, low: 0, unscored: 3 } }))
      .toBe('unscored')
  })

  it('is null when there is nothing at all', () => {
    expect(worstSeverity({ severityCounts: {} })).toBeNull()
    expect(worstSeverity(null)).toBeNull()
  })
})

describe('policySignal', () => {
  it('reports a never-evaluated version as unevaluated, not as a pass', () => {
    expect(policySignal({ policyStatus: null, violationCount: 0 }))
      .toEqual({ tone: 'muted', status: 'unevaluated', count: 0 })
  })

  it('reports violations with their count', () => {
    expect(policySignal({ policyStatus: 'violation', violationCount: 4 }))
      .toEqual({ tone: 'warn', status: 'violation', count: 4 })
  })

  it('treats a nonzero violation count as a violation even if the status lags behind', () => {
    expect(policySignal({ policyStatus: 'pass', violationCount: 2 }).status).toBe('violation')
  })

  it('passes a clean evaluated version', () => {
    expect(policySignal({ policyStatus: 'pass', violationCount: 0 }))
      .toEqual({ tone: 'clean', status: 'pass', count: 0 })
    expect(policySignal({ policyStatus: 'warn', violationCount: 0 }).status).toBe('warn')
  })
})

describe('unscannableNote', () => {
  it('is null at zero so the page renders no affordance — not a reassuring zero', () => {
    expect(unscannableNote({ unscannableCount: 0, policyStatus: 'pass' })).toBeNull()
    expect(unscannableNote({ policyStatus: 'warn' })).toBeNull()
    expect(unscannableNote(null)).toBeNull()
  })

  it('reports the count with the plain no-feed help outside warn', () => {
    expect(unscannableNote({ unscannableCount: 3, policyStatus: 'pass', violationCount: 0 })).toEqual({
      count: 3,
      labelKey: 'sbomAnalysis.rollup.unscannable',
      titleKey: 'sbomAnalysis.rollup.unscannableHelp',
    })
  })

  it('carries the warn-specific help on a warn version, so the operator knows waiting resolves the deferral and never these components', () => {
    expect(unscannableNote({ unscannableCount: 2, policyStatus: 'warn', violationCount: 0 })).toEqual({
      count: 2,
      labelKey: 'sbomAnalysis.rollup.unscannable',
      titleKey: 'sbomAnalysis.rollup.unscannableWarnHelp',
    })
  })

  it('a version with violations is not merely warn — it keeps the plain help', () => {
    expect(unscannableNote({ unscannableCount: 1, policyStatus: 'warn', violationCount: 4 })?.titleKey)
      .toBe('sbomAnalysis.rollup.unscannableHelp')
  })

  it('still surfaces the count on an unevaluated version', () => {
    expect(unscannableNote({ unscannableCount: 5, policyStatus: null })?.count).toBe(5)
  })
})


describe('registryChips', () => {
  const present = (registry, version = '1.2.5') => ({ version, registry: { presence: 'present', ...registry } })

  it('renders nothing for a component the registry has never served', () => {
    expect(registryChips({ registry: { presence: 'absent' } })).toEqual([])
    expect(registryChips({ registry: { presence: 'unknown' } })).toEqual([])
    expect(registryChips({})).toEqual([])
  })

  it('reports a block on the shipped version at version granularity', () => {
    const [chip] = registryChips(present({ blocked: 'version' }))
    expect(chip.labelKey).toBe('sbomAnalysis.registry.blocked')
  })

  it('still reports a block that lands on another version, as its own weaker chip', () => {
    // Adversarial twin: dropping the package-level hit would render a clean row for a package the
    // operator has already quarantined — the one reading a chip must never produce.
    const [chip] = registryChips(present({ blocked: 'package' }))
    expect(chip.labelKey).toBe('sbomAnalysis.registry.blockedOther')
    expect(chip.cls).not.toBe('registry-blocked')
  })

  it('renders the version gap only when the server decided the row is behind', () => {
    const chips = registryChips(present({ latestVersion: '1.2.8', outdated: true }))
    expect(chips.map(c => c.key)).toEqual(['outdated'])
    expect(chips[0].values).toEqual({ latest: '1.2.8', shipped: '1.2.5' })
  })

  it('renders no version chip at all when the server decided the row is current', () => {
    expect(registryChips(present({ latestVersion: '1.2.5', outdated: false }))).toEqual([])
  })

  it('states the known upstream version without a verdict when the comparison is unavailable', () => {
    // Adversarial twin of the case above. `outdated: null` is "unknown", and rendering nothing
    // for it would be indistinguishable from "up to date" — a reassurance the server never gave.
    const chips = registryChips(present({ latestVersion: 'v1.4.0', outdated: null }))
    expect(chips.map(c => c.key)).toEqual(['latest-unknown'])
    expect(chips[0].cls).toBe('registry-unknown')
  })

  it('orders the chips block, deprecation, version gap', () => {
    const chips = registryChips(present({ blocked: 'version', deprecated: 'package', latestVersion: '2.0.0', outdated: true }))
    expect(chips.map(c => c.key)).toEqual(['blocked', 'deprecated', 'outdated'])
  })
})

describe('blindSpotNote / uncoordinatedNote', () => {
  it('reports the components the registry has never served', () => {
    expect(blindSpotNote({ registryCounts: { inRegistry: 4, notInRegistry: 7, unknown: 2 } })).toEqual({
      count: 7,
      unknown: 2,
      labelKey: 'sbomAnalysis.rollup.notInRegistry',
      titleKey: 'sbomAnalysis.rollup.notInRegistryHelp',
    })
  })

  it('renders no affordance at zero rather than a reassuring zero badge', () => {
    expect(blindSpotNote({ registryCounts: { inRegistry: 4, notInRegistry: 0, unknown: 0 } })).toBeNull()
    expect(blindSpotNote({})).toBeNull()
  })

  it('keeps the unanswerable components out of the blind-spot count and reports them on their own', () => {
    // Adversarial twin: folding `unknown` into `notInRegistry` inflates the number an operator is
    // meant to act on, and dropping it hides a component nobody can classify.
    const rollup = { registryCounts: { inRegistry: 1, notInRegistry: 2, unknown: 5 } }
    expect(blindSpotNote(rollup)?.count).toBe(2)
    expect(uncoordinatedNote(rollup)).toEqual({
      count: 5,
      labelKey: 'sbomAnalysis.rollup.registryUnknown',
      titleKey: 'sbomAnalysis.rollup.registryUnknownHelp',
    })
  })

  it('reports no uncoordinated note when every component carries a coordinate', () => {
    expect(uncoordinatedNote({ registryCounts: { inRegistry: 3, notInRegistry: 1, unknown: 0 } })).toBeNull()
  })
})

describe('analysisQuery registry filter', () => {
  it('sends the registry filter when one is set', () => {
    expect(analysisQuery({ ...DEFAULT_TABLE_STATE, registry: 'absent' }).registry).toBe('absent')
  })

  it('omits it entirely when unset, so the server applies no narrowing', () => {
    expect('registry' in analysisQuery({ ...DEFAULT_TABLE_STATE })).toBe(false)
  })
})

describe('excludedByScopeNote', () => {
  it('is null at zero — nothing excluded is a non-event', () => {
    expect(excludedByScopeNote({ scopeSuppressedCount: 0 })).toBeNull()
    expect(excludedByScopeNote(null)).toBeNull()
  })

  it('reports the count and its help key, under the "excluded" vocabulary', () => {
    // Adversarial twin: a label reading "suppressed" would collide with the priority ribbon's
    // own Suppressed bucket, which is a different fact (a VEX statement, not a scope
    // declaration). The rollup.excludedByScope* keys must never resurrect that collision.
    const note = excludedByScopeNote({ scopeSuppressedCount: 3 })
    expect(note).toEqual({
      count: 3,
      labelKey: 'sbomAnalysis.rollup.excludedByScope',
      titleKey: 'sbomAnalysis.rollup.excludedByScopeHelp',
    })
    expect(note?.labelKey.toLowerCase()).not.toContain('suppressed')
  })
})

describe('priorityBreakdown', () => {
  it('always returns all four buckets, strongest first, zero-filled', () => {
    expect(priorityBreakdown({ priorityCounts: { act: 2, attend: 0, track: 5, suppressed: 1 } }))
      .toEqual([
        { key: 'act', count: 2, labelKey: 'sbomAnalysis.priority.act' },
        { key: 'attend', count: 0, labelKey: 'sbomAnalysis.priority.attend' },
        { key: 'track', count: 5, labelKey: 'sbomAnalysis.priority.track' },
        { key: 'suppressed', count: 1, labelKey: 'sbomAnalysis.priority.suppressed' },
      ])
  })

  it('zero-fills every bucket when the rollup carries none', () => {
    expect(priorityBreakdown(null).every(b => b.count === 0)).toBe(true)
  })
})

describe('licenseRollupSignal', () => {
  const rollup = {
    licenseCounts: {
      total: 10, declared: 8, undeclared: 2,
      byIdentifier: { 'GPL-3.0-only': 3, MIT: 5 },
    },
  }

  it('flags undeclared licences even with an empty blocklist', () => {
    expect(licenseRollupSignal(rollup, new Set())).toEqual({ flagged: 2, undeclared: 2, blockedCount: 0 })
  })

  it('adds the blocklisted identifiers by their whole-version count, not the page count', () => {
    // This is the case the stale hover text used to lie about: the number comes from the
    // rollup's byIdentifier tally, not from counting items on the currently loaded page.
    const signal = licenseRollupSignal(rollup, new Set(['GPL-3.0-ONLY']))
    expect(signal.blockedCount).toBe(3)
    expect(signal.flagged).toBe(5) // 2 undeclared + 3 blocklisted
  })

  it('matches blocklist identifiers case-insensitively, mirroring isBlocklisted', () => {
    // isBlocklisted's own contract is an uppercased blocklist Set — same as isBlocklisted's
    // other callers pass — matched against a lowercased-in-source identifier.
    expect(licenseRollupSignal(rollup, new Set(['MIT'])).blockedCount).toBe(5)
  })

  it('reads zero from a rollup carrying no licence counts at all', () => {
    expect(licenseRollupSignal(null, new Set())).toEqual({ flagged: 0, undeclared: 0, blockedCount: 0 })
  })
})

describe('licenseBreakdown', () => {
  it('maps byIdentifier to an ordered list, already sorted by the server', () => {
    const rollup = { licenseCounts: { byIdentifier: { MIT: 5, 'Apache-2.0': 3 } } }
    expect(licenseBreakdown(rollup)).toEqual([
      { identifier: 'MIT', count: 5 },
      { identifier: 'Apache-2.0', count: 3 },
    ])
  })

  it('caps at the given limit', () => {
    const rollup = { licenseCounts: { byIdentifier: { A: 3, B: 2, C: 1 } } }
    expect(licenseBreakdown(rollup, 2)).toEqual([{ identifier: 'A', count: 3 }, { identifier: 'B', count: 2 }])
  })

  it('is empty for a rollup with no licence counts', () => {
    expect(licenseBreakdown(null)).toEqual([])
  })
})

describe('mergeAnalysisRow — inherited reset', () => {
  it('clears a stale inherited flag: a fresh save is decided for this release', () => {
    // Adversarial twin: a merge that left `inherited` untouched would keep showing "inherited,
    // decided <old date>" on a row an operator just triaged for this release.
    const advisory = { vulnKey: 'CVE-1', inherited: true, vexState: 'in_triage' }
    const merged = mergeAnalysisRow(advisory, { vexState: 'not_affected', vexUpdatedAt: '2026-01-01T00:00:00Z' })
    expect(merged.inherited).toBe(false)
  })
})
