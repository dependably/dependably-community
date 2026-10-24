import { describe, it, expect } from 'vitest'
import {
  advisorySeverity, closureKind, componentsView, isOciDigest, moreFindings, ociScanPanel, ociSecurityFor,
  ociSecurityForPackage, packageVulnCell, reachabilityKind, scanTimes, severityForScore, showsLinkedFindings, worstOciSecurity,
} from './ociScan.js'

const row = (ociScan, extra = {}) => ({ purl: 'pkg:oci/x@sha256:1', ociScan, ...extra })

describe('ociSecurityFor', () => {
  it('is null for a row with no scan projection (other ecosystems keep their logic)', () => {
    expect(ociSecurityFor({ purl: 'pkg:npm/x@1' })).toBeNull()
    expect(ociSecurityFor(null)).toBeNull()
  })

  it('reads an OCI row with no scan projection as unscanned, never clean', () => {
    expect(ociSecurityFor({ purl: 'pkg:oci/x@sha256:1' })).toEqual({ kind: 'unscanned', severity: null, count: 0, gapCount: 0 })
    expect(ociSecurityFor({ purl: 'pkg:oci/x@sha256:1', ociScan: null })?.kind).toBe('unscanned')
  })

  it('reads a scanned vulnerable image as vulnerable with its severity, with no linked advisories', () => {
    const s = ociSecurityFor(row({ state: 'scanned', findingCount: 3, gapCount: 0, maxScore: 7.5 }))
    expect(s).toEqual({ kind: 'vulnerable', severity: 'HIGH', count: 3, gapCount: 0 })
  })

  it('keeps the gaps of a vulnerable image that also has gaps', () => {
    const s = ociSecurityFor(row({ state: 'scanned', findingCount: 1, gapCount: 2, maxScore: null }))
    expect(s).toEqual({ kind: 'vulnerable', severity: 'UNKNOWN', count: 1, gapCount: 2 })
  })

  it('reads scanned with gaps and no findings as partial', () => {
    expect(ociSecurityFor(row({ state: 'scanned', findingCount: 0, gapCount: 1 }))?.kind).toBe('partial')
  })

  it('reads unscanned and no_feed as their own states', () => {
    expect(ociSecurityFor(row({ state: 'unscanned' }))?.kind).toBe('unscanned')
    expect(ociSecurityFor(row({ state: 'no_feed' }))?.kind).toBe('no_feed')
  })

  it('twin: scanned, no findings and no gaps is the only clean state', () => {
    expect(ociSecurityFor(row({ state: 'scanned', findingCount: 0, gapCount: 0 }))?.kind).toBe('clean')
  })

  it('never reads an unrecognised state as clean', () => {
    expect(ociSecurityFor(row({ state: 'mystery' }))?.kind).toBe('unscanned')
  })

  it('is not masked by the display status', () => {
    for (const status of ['blocked', 'allowed', 'deprecated']) {
      expect(ociSecurityFor(row({ state: 'unscanned' }, { status }))?.kind).toBe('unscanned')
      expect(ociSecurityFor(row({ state: 'scanned', findingCount: 0, gapCount: 1 }, { status }))?.kind).toBe('partial')
    }
  })
})

describe('worstOciSecurity', () => {
  it('is null when no row is an OCI row', () => {
    expect(worstOciSecurity([{ purl: 'a' }])).toBeNull()
  })

  it('ranks vulnerable above partial above unscanned above clean', () => {
    const rows = [
      row({ state: 'scanned', findingCount: 0, gapCount: 0 }),
      row({ state: 'unscanned' }),
      row({ state: 'scanned', findingCount: 0, gapCount: 2 }),
    ]
    expect(worstOciSecurity(rows)?.kind).toBe('partial')
    expect(worstOciSecurity([...rows, row({ state: 'scanned', findingCount: 1, maxScore: 9.8 })])?.kind).toBe('vulnerable')
  })
})

describe('severityForScore', () => {
  it('bands CVSS scores and leaves a missing score UNKNOWN', () => {
    expect(severityForScore(9.8)).toBe('CRITICAL')
    expect(severityForScore(7)).toBe('HIGH')
    expect(severityForScore(4.3)).toBe('MEDIUM')
    expect(severityForScore(2)).toBe('LOW')
    expect(severityForScore(null)).toBe('UNKNOWN')
    expect(severityForScore(0)).toBe('UNKNOWN')
  })
})

describe('ociSecurityForPackage', () => {
  const pkg = (ociScan, extra = {}) => ({ ecosystem: 'oci', ociScan, ...extra })

  it('is null outside OCI', () => {
    expect(ociSecurityForPackage({ ecosystem: 'npm', ociScan: { state: 'scanned' } })).toBeNull()
    expect(ociSecurityForPackage(null)).toBeNull()
  })

  it('reads an OCI package with no rollup as unscanned, never clean', () => {
    expect(ociSecurityForPackage({ ecosystem: 'oci' })?.kind).toBe('unscanned')
    expect(ociSecurityForPackage(pkg(null))?.kind).toBe('unscanned')
  })

  it('decides exactly as the version page does for the same scan shape', () => {
    for (const scan of [
      { state: 'scanned', findingCount: 2, gapCount: 0, maxScore: 9.1 },
      { state: 'scanned', findingCount: 0, gapCount: 3 },
      { state: 'scanned', findingCount: 0, gapCount: 0 },
      { state: 'unscanned' },
      { state: 'no_feed' },
    ]) {
      expect(ociSecurityForPackage(pkg(scan))).toEqual(ociSecurityFor(row(scan)))
    }
  })
})

describe('packageVulnCell', () => {
  const pkg = (ociScan, extra = {}) => ({ ecosystem: 'oci', ociScan, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, ...extra })

  it('shows a vulnerable package by its scan count and severity, not the clean line', () => {
    const cell = packageVulnCell(pkg({ state: 'scanned', findingCount: 4, gapCount: 0, maxScore: 9.8 }))
    expect(cell.oci).toMatchObject({ kind: 'vulnerable', severity: 'CRITICAL', count: 4 })
    expect(cell.showNone).toBe(false)
  })

  it('never reads unscanned, no_feed or partial as clean', () => {
    for (const scan of [{ state: 'unscanned' }, { state: 'no_feed' }, { state: 'scanned', findingCount: 0, gapCount: 1 }]) {
      expect(packageVulnCell(pkg(scan)).showNone).toBe(false)
    }
  })

  it('twin: only a package scanned clean reads clean', () => {
    expect(packageVulnCell(pkg({ state: 'scanned', findingCount: 0, gapCount: 0 })).showNone).toBe(true)
  })

  it('keeps linked advisories visible under a non-clean state, and over a clean scan', () => {
    expect(packageVulnCell(pkg({ state: 'unscanned' }, { highCount: 2 })).showLinked).toBe(true)
    const clean = packageVulnCell(pkg({ state: 'scanned', findingCount: 0, gapCount: 0 }, { highCount: 2 }))
    expect(clean.showLinked).toBe(true)
    expect(clean.showNone).toBe(false)
  })

  it('leaves other ecosystems to their counts alone', () => {
    expect(packageVulnCell({ ecosystem: 'npm', criticalCount: 0 })).toEqual({ oci: null, showLinked: false, showNone: true })
    expect(packageVulnCell({ ecosystem: 'npm', lowCount: 1 })).toEqual({ oci: null, showLinked: true, showNone: false })
  })
})

describe('showsLinkedFindings', () => {
  it('shows linked advisories under a partial, unscanned or no-scanner state', () => {
    for (const kind of /** @type {const} */ (['partial', 'unscanned', 'no_feed'])) {
      expect(showsLinkedFindings({ kind, severity: null, count: 0, gapCount: 0 }, 1)).toBe(true)
    }
  })

  it('adds nothing when there are no linked advisories, the image is vulnerable or clean, or the row is not OCI', () => {
    expect(showsLinkedFindings({ kind: 'no_feed', severity: null, count: 0, gapCount: 0 }, 0)).toBe(false)
    expect(showsLinkedFindings({ kind: 'vulnerable', severity: 'HIGH', count: 1, gapCount: 0 }, 1)).toBe(false)
    expect(showsLinkedFindings({ kind: 'clean', severity: null, count: 0, gapCount: 0 }, 1)).toBe(false)
    expect(showsLinkedFindings(null, 1)).toBe(false)
  })
})

describe('reachabilityKind', () => {
  it('passes through the two verdicts that say something', () => {
    expect(reachabilityKind('reachable')).toBe('reachable')
    expect(reachabilityKind('not_observed')).toBe('not_observed')
  })

  it('reads unknown, null and any unrecognised verdict as unknown, never as not reachable', () => {
    for (const v of ['unknown', null, undefined, '', 'unreachable', 'not_reachable', 'REACHABLE', 42]) {
      expect(reachabilityKind(v)).toBe('unknown')
    }
  })
})

describe('closureKind', () => {
  it('reads null as not determined, never as outside the closure', () => {
    expect(closureKind(null)).toBe('undetermined')
    expect(closureKind(undefined)).toBe('undetermined')
    expect(closureKind(true)).toBe('inside')
    expect(closureKind(false)).toBe('outside')
  })
})

describe('advisorySeverity', () => {
  it('uses the recorded severity, else the score band, else the unscored chip', () => {
    expect(advisorySeverity({ severity: 'HIGH', cvssScore: 9.9 })).toBe('HIGH')
    expect(advisorySeverity({ severity: null, cvssScore: 9.1 })).toBe('CRITICAL')
    expect(advisorySeverity({ severity: null, cvssScore: null })).toBe('UNKNOWN')
    expect(advisorySeverity(undefined)).toBe('UNKNOWN')
  })
})

describe('isOciDigest', () => {
  it('accepts only a lowercase sha256 manifest digest', () => {
    expect(isOciDigest('sha256:' + 'a'.repeat(64))).toBe(true)
    expect(isOciDigest('sha256:' + 'A'.repeat(64))).toBe(false)
    expect(isOciDigest('sha256:' + 'a'.repeat(64) + '\n')).toBe(false)
    expect(isOciDigest('latest')).toBe(false)
  })
})

describe('moreFindings', () => {
  it('counts what the per-component cap left out', () => {
    expect(moreFindings({ findingCount: 60, findings: new Array(50) })).toBe(10)
    expect(moreFindings({ findingCount: 2, findings: [1, 2] })).toBe(0)
  })
})

const platform = (over = {}) => ({
  platform: 'linux/amd64', scannedAt: '2026-06-15T12:00:00.000Z', gaps: [], componentCount: 12, affectedComponentCount: 0, ...over,
})

describe('ociScanPanel', () => {
  it('without a result is one message, never a table, chosen from state and job', () => {
    expect(ociScanPanel({ state: 'no_feed', job: null, platforms: [] })).toEqual({ kind: 'noResult', messageKey: 'noFeed', attempts: 0 })
    expect(ociScanPanel({ state: 'unscanned', job: { state: 'none' } }).messageKey).toBe('unscannedNone')
    expect(ociScanPanel({ state: 'unscanned', job: { state: 'pending', attempts: 0 } }).messageKey).toBe('unscannedPending')
    expect(ociScanPanel({ state: 'unscanned', job: { state: 'pending', attempts: 2 } })).toEqual({ kind: 'noResult', messageKey: 'unscannedPendingAttempts', attempts: 2 })
    expect(ociScanPanel({ state: 'unscanned', job: { state: 'failed', attempts: 5 } })).toEqual({ kind: 'noResult', messageKey: 'unscannedFailed', attempts: 5 })
    // An unrecognised state is not a scanned one.
    expect(ociScanPanel({ state: 'mystery' }).kind).toBe('noResult')
    expect(ociScanPanel(null).kind).toBe('noResult')
  })

  it('lists every platform with gaps first, and a partial image is never clean', () => {
    const p = ociScanPanel({
      state: 'scanned',
      platforms: [platform({ gaps: ['rpm: no feed'] }), platform({ platform: 'linux/arm64', gaps: [] })],
    })
    expect(p.kind).toBe('scanned')
    expect(p.platformNames).toEqual(['linux/amd64', 'linux/arm64'])
    expect(p.gapPlatforms).toEqual([{ platform: 'linux/amd64', gaps: ['rpm: no feed'] }])
    expect(p.clean).toBe(false)
  })

  it('is clean only with nothing affected and no gaps on any platform', () => {
    expect(ociScanPanel({ state: 'scanned', platforms: [platform()] }).clean).toBe(true)
    expect(ociScanPanel({ state: 'scanned', platforms: [platform(), platform({ platform: 'linux/arm64', affectedComponentCount: 1 })] }).clean).toBe(false)
  })

  it('dates a clean verdict by the stalest platform match, falling back to the scan time', () => {
    const p = ociScanPanel({
      state: 'scanned',
      platforms: [
        platform({ matchedAt: '2026-06-20T00:00:00.000Z' }),
        platform({ platform: 'linux/arm64', scannedAt: '2026-06-16T00:00:00.000Z', matchedAt: null }),
      ],
    })
    expect(p.matchedAt).toBe('2026-06-16T00:00:00.000Z')
  })
})

describe('scanTimes', () => {
  it('names the match time only when a re-match moved it past the scan', () => {
    expect(scanTimes({ scannedAt: 'S', matchedAt: 'S' })).toEqual({ scannedAt: 'S', matchedAt: null })
    expect(scanTimes({ scannedAt: 'S', matchedAt: null })).toEqual({ scannedAt: 'S', matchedAt: null })
    expect(scanTimes({ scannedAt: 'S', matchedAt: 'M' })).toEqual({ scannedAt: 'S', matchedAt: 'M' })
    expect(scanTimes(null)).toEqual({ scannedAt: null, matchedAt: null })
  })
})

describe('componentsView', () => {
  const detail = (components, platforms = [platform()]) => ({ state: 'scanned', platforms, components })

  it('renders an empty findings view as "0 findings among N components", never an empty table', () => {
    expect(componentsView(detail({ platform: 'linux/amd64', total: 0, offset: 0, limit: 100, items: [] }), true))
      .toEqual({ kind: 'zeroFindings', componentCount: 12 })
  })

  it('pages the rows with a range and the neighbouring offsets', () => {
    const items = new Array(100).fill({})
    const v = componentsView(detail({ platform: 'linux/amd64', total: 250, offset: 100, limit: 100, items }), false)
    expect(v).toMatchObject({ kind: 'rows', from: 101, to: 200, total: 250, prevOffset: 0, nextOffset: 200 })
    const last = componentsView(detail({ platform: 'linux/amd64', total: 250, offset: 200, limit: 100, items: new Array(50).fill({}) }), false)
    expect(last).toMatchObject({ from: 201, to: 250, prevOffset: 100, nextOffset: null })
  })

  it('has nothing to show without a stored result', () => {
    expect(componentsView({ state: 'unscanned', components: null }, true)).toEqual({ kind: 'none' })
  })
})
