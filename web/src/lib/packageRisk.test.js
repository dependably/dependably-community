import { describe, it, expect } from 'vitest'
import {
  licenseStateFor,
  resolveStateVersion,
  rowsForVersion,
  versionsBehindFor,
  worstSeverityFor
} from './packageRisk.js'

/** One version row as the package endpoint projects it, with only the fields the pillars read. */
const row = (version, extra = {}) => ({
  version,
  purl: `pkg:npm/nanoid@${version}`,
  licenses: ['MIT'],
  versionsBehind: null,
  ...extra
})

describe('resolveStateVersion', () => {
  it('picks the upstream latest when it is cached here', () => {
    const versions = [row('3.3.12'), row('6.0.1'), row('3.3.18')]
    expect(resolveStateVersion({ ecosystem: 'npm', upstreamLatestVersion: '6.0.1' }, versions))
      .toBe('6.0.1')
  })

  it('falls back to the newest cached version when the upstream latest is not cached', () => {
    // Stale package: upstream has moved to 7.0.0 but nothing has fetched it, so the newest
    // thing actually servable here is what the pillars must describe.
    const versions = [row('3.3.12'), row('6.0.1')]
    expect(resolveStateVersion({ ecosystem: 'npm', upstreamLatestVersion: '7.0.0' }, versions))
      .toBe('6.0.1')
  })

  it('falls back to the newest cached version when there is no upstream baseline at all', () => {
    // Hosted-only or air-gapped: upstream_latest_version was never resolved.
    const versions = [row('1.9.0'), row('1.10.0'), row('1.2.0')]
    expect(resolveStateVersion({ ecosystem: 'npm', upstreamLatestVersion: null }, versions))
      .toBe('1.10.0')
    expect(resolveStateVersion(null, versions)).toBe('1.10.0')
  })

  it('prefers the newest stable over a newer pre-release', () => {
    const versions = [row('1.9.0'), row('2.0.0-rc.1'), row('2.0.0-beta.3')]
    expect(resolveStateVersion({ ecosystem: 'npm' }, versions)).toBe('1.9.0')
  })

  it('uses a pre-release only when nothing stable is cached', () => {
    const versions = [row('2.0.0-beta.3'), row('2.0.0-rc.1')]
    expect(resolveStateVersion({ ecosystem: 'npm' }, versions)).toBe('2.0.0-rc.1')
  })

  it('orders OCI by pushed time, because its version is a manifest digest', () => {
    // Digests have no magnitude; comparing them would pick an arbitrary row and
    // present it as the current one.
    const versions = [
      row('sha256:ffff', { createdAt: '2026-01-01T00:00:00Z' }),
      row('sha256:0001', { createdAt: '2026-06-01T00:00:00Z' })
    ]
    expect(resolveStateVersion({ ecosystem: 'oci' }, versions)).toBe('sha256:0001')
  })

  it('treats a re-push as the version becoming current again', () => {
    const versions = [
      row('sha256:aaaa', { createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-07-01T00:00:00Z' }),
      row('sha256:bbbb', { createdAt: '2026-06-01T00:00:00Z' })
    ]
    expect(resolveStateVersion({ ecosystem: 'oci' }, versions)).toBe('sha256:aaaa')
  })

  it('returns null only when the package has no versions', () => {
    expect(resolveStateVersion({ ecosystem: 'npm' }, [])).toBeNull()
    expect(resolveStateVersion({ ecosystem: 'npm' }, undefined)).toBeNull()
  })
})

describe('worstSeverityFor', () => {
  const versions = [row('3.3.12'), row('6.0.1')]
  const vulns = new Map([
    ['pkg:npm/nanoid@3.3.12', [{ osvId: 'GHSA-old', severity: 'MEDIUM' }]]
  ])

  it('reports nothing for a clean current version even when an old one is vulnerable', () => {
    // The regression this whole change exists for: nanoid 6.0.1 has no advisories, but
    // 3.3.12 does, and the package headline read MEDIUM.
    const state = resolveStateVersion({ ecosystem: 'npm', upstreamLatestVersion: '6.0.1' }, versions)
    expect(worstSeverityFor(rowsForVersion(versions, state), vulns)).toBeNull()
  })

  it('reports the advisory when the current version is the affected one', () => {
    expect(worstSeverityFor(rowsForVersion(versions, '3.3.12'), vulns)).toBe('MEDIUM')
  })

  it('takes the worst severity across the version, not the first', () => {
    const v = [row('1.0.0')]
    const many = new Map([['pkg:npm/nanoid@1.0.0', [
      { osvId: 'A', severity: 'LOW' },
      { osvId: 'B', severity: 'CRITICAL' },
      { osvId: 'C', severity: 'HIGH' }
    ]]])
    expect(worstSeverityFor(v, many)).toBe('CRITICAL')
  })

  it('ranks a severity-less advisory as UNKNOWN rather than dropping it', () => {
    const v = [row('1.0.0')]
    const unscored = new Map([['pkg:npm/nanoid@1.0.0', [{ osvId: 'A' }]]])
    expect(worstSeverityFor(v, unscored)).toBe('UNKNOWN')
  })

  it('counts a multi-file version once per advisory', () => {
    // Maven jar + pom map to one purl, so the vuln report returns the advisory twice.
    const rows = [
      { version: '1.0.0', purl: 'pkg:maven/g/a@1.0.0' },
      { version: '1.0.0', purl: 'pkg:maven/g/a@1.0.0' }
    ]
    const dup = new Map([['pkg:maven/g/a@1.0.0', [
      { osvId: 'A', severity: 'HIGH' },
      { osvId: 'A', severity: 'HIGH' }
    ]]])
    expect(worstSeverityFor(rows, dup)).toBe('HIGH')
  })

  it('survives a package with no advisory data at all', () => {
    expect(worstSeverityFor([row('1.0.0')], new Map())).toBeNull()
  })
})

describe('licenseStateFor', () => {
  const blocklist = new Set(['GPL-3.0'])

  it('reports clean for an allowed license', () => {
    expect(licenseStateFor([row('1.0.0')], blocklist)).toBe('clean')
  })

  it('reports blocked for a blocklisted license, case-insensitively', () => {
    expect(licenseStateFor([row('1.0.0', { licenses: ['gpl-3.0'] })], blocklist)).toBe('blocked')
  })

  it('separates an undeclared license from a clean one', () => {
    // A version nothing is known about must not claim a check that never ran.
    expect(licenseStateFor([row('1.0.0', { licenses: [] })], blocklist)).toBe('undeclared')
    expect(licenseStateFor([row('1.0.0', { licenses: undefined })], blocklist)).toBe('undeclared')
  })

  it('lets one blocklisted file decide a multi-file version', () => {
    const rows = [row('1.0.0', { licenses: ['MIT'] }), row('1.0.0', { licenses: ['GPL-3.0'] })]
    expect(licenseStateFor(rows, blocklist)).toBe('blocked')
  })

  const conditional = new Set(['LGPL-3.0-ONLY'])

  it('reports review for a conditional license, case-insensitively', () => {
    // The version serves — the org marked the licence acceptable in some contexts — but showing
    // it as clean would hide the condition the org wrote down.
    expect(licenseStateFor([row('1.0.0', { licenses: ['lgpl-3.0-only'] })], blocklist, conditional))
      .toBe('review')
  })

  it('keeps a plainly-allowed license clean when a conditional set exists', () => {
    expect(licenseStateFor([row('1.0.0', { licenses: ['MIT'] })], blocklist, conditional)).toBe('clean')
  })

  it('ranks blocked above review', () => {
    const rows = [row('1.0.0', { licenses: ['LGPL-3.0-only'] }), row('1.0.0', { licenses: ['GPL-3.0'] })]
    expect(licenseStateFor(rows, blocklist, conditional)).toBe('blocked')
  })

  it('ranks undeclared above review — nothing known is not a condition', () => {
    expect(licenseStateFor([row('1.0.0', { licenses: [] })], blocklist, conditional)).toBe('undeclared')
  })

  it('behaves exactly as before when no conditional set is supplied', () => {
    expect(licenseStateFor([row('1.0.0', { licenses: ['lgpl-3.0-only'] })], blocklist)).toBe('clean')
  })
})

describe('versionsBehindFor', () => {
  it('reports the current version as up to date while older ones are far behind', () => {
    // The second half of the regression: the pillar read 38 behind directly above a
    // banner saying the latest version was cached.
    const versions = [
      row('3.3.12', { versionsBehind: 38 }),
      row('6.0.1', { versionsBehind: 0 })
    ]
    const state = resolveStateVersion({ ecosystem: 'npm', upstreamLatestVersion: '6.0.1' }, versions)
    expect(versionsBehindFor(rowsForVersion(versions, state))).toBe(0)
  })

  it('reports the real count when the current version is behind', () => {
    const versions = [row('6.0.1', { versionsBehind: 4 })]
    expect(versionsBehindFor(versions)).toBe(4)
  })

  it('preserves unknown rather than coercing it to zero', () => {
    expect(versionsBehindFor([row('1.0.0', { versionsBehind: null })])).toBeNull()
    expect(versionsBehindFor([])).toBeNull()
  })

  it('takes the first known count across a multi-file version', () => {
    const rows = [row('1.0.0', { versionsBehind: null }), row('1.0.0', { versionsBehind: 2 })]
    expect(versionsBehindFor(rows)).toBe(2)
  })
})

describe('rowsForVersion', () => {
  it('returns every file of the version and nothing else', () => {
    const versions = [row('1.0.0'), row('1.0.0'), row('2.0.0')]
    expect(rowsForVersion(versions, '1.0.0')).toHaveLength(2)
  })

  it('returns nothing when no version could be resolved', () => {
    expect(rowsForVersion([row('1.0.0')], null)).toEqual([])
  })
})
