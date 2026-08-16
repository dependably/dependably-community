import { describe, it, expect } from 'vitest'
import { compareVersions, defaultSortColumn, parseVersion } from './versionOrder.js'

/** Sort newest-first, the direction the versions table uses by default. */
const newestFirst = list => [...list].sort((a, b) => -compareVersions(a, b))

describe('defaultSortColumn', () => {
  it('defaults to the version column so the newest release is on top', () => {
    for (const eco of ['npm', 'pypi', 'nuget', 'maven', 'go', 'cargo', 'rpm']) {
      expect(defaultSortColumn(eco)).toBe('version')
    }
  })

  it('keeps OCI on pushed, because its version is a manifest digest', () => {
    expect(defaultSortColumn('oci')).toBe('pushed')
  })

  it('falls back to the version column before the package has loaded', () => {
    // The parent loads `pkg` asynchronously, so the table is constructed with no
    // ecosystem at all; that initial state must still be a valid sort column.
    expect(defaultSortColumn(null)).toBe('version')
    expect(defaultSortColumn(undefined)).toBe('version')
  })
})

describe('compareVersions', () => {
  it('orders numeric segments by magnitude, not lexically', () => {
    // The case a plain string sort gets wrong: "1.9.0" > "1.10.0" as text.
    expect(newestFirst(['1.9.0', '1.10.0', '1.2.0'])).toEqual(['1.10.0', '1.9.0', '1.2.0'])
  })

  it('ranks a release above its own pre-releases', () => {
    // The regression this module exists for. localeCompare(numeric) put 1.0.0-rc.1
    // at the top of this list and the stable 1.0.0 at the bottom.
    expect(newestFirst(['1.0.0', '1.0.0-beta.1', '1.0.0-alpha', '1.0.0-rc.1']))
      .toEqual(['1.0.0', '1.0.0-rc.1', '1.0.0-beta.1', '1.0.0-alpha'])
  })

  it('orders pre-release kinds dev < alpha < beta < rc', () => {
    expect(newestFirst(['1.0.0-rc.1', '1.0.0-dev.1', '1.0.0-beta.1', '1.0.0-alpha.1']))
      .toEqual(['1.0.0-rc.1', '1.0.0-beta.1', '1.0.0-alpha.1', '1.0.0-dev.1'])
  })

  it('orders numbered pre-releases within one kind', () => {
    expect(newestFirst(['1.0.0-rc.2', '1.0.0-rc.10', '1.0.0-rc.1']))
      .toEqual(['1.0.0-rc.10', '1.0.0-rc.2', '1.0.0-rc.1'])
  })

  it('handles PEP 440 suffixes written without a separator', () => {
    // PyPI attaches the marker directly: 1.0a1 / 1.0rc1 / 1.0.post1.
    expect(newestFirst(['1.0', '1.0rc1', '1.0a1', '1.0.post1']))
      .toEqual(['1.0.post1', '1.0', '1.0rc1', '1.0a1'])
  })

  it('ranks a post-release above its release but below the next release', () => {
    expect(newestFirst(['1.0', '1.0.post1', '1.0.1'])).toEqual(['1.0.1', '1.0.post1', '1.0'])
  })

  it('ranks a Maven snapshot below its release', () => {
    expect(newestFirst(['1.0', '1.0-SNAPSHOT', '1.1'])).toEqual(['1.1', '1.0', '1.0-SNAPSHOT'])
  })

  it('ignores a leading v on Go module and npm tags', () => {
    expect(newestFirst(['v1.9.0', 'v1.10.0'])).toEqual(['v1.10.0', 'v1.9.0'])
    expect(compareVersions('v1.2.3', '1.2.3')).toBe(0)
  })

  it('ignores build metadata, which carries no precedence', () => {
    expect(compareVersions('1.0.0+build.2', '1.0.0+build.1')).toBe(0)
    expect(compareVersions('1.0.0+build.2', '1.0.0')).toBe(0)
  })

  it('treats a missing trailing segment as zero', () => {
    expect(compareVersions('1.0', '1.0.0')).toBe(0)
    expect(compareVersions('1.2', '1.2.0')).toBe(0)
  })

  it('does not zero-pad inside a pre-release, where fewer identifiers rank lower', () => {
    // Zero-padding is correct for the release part but not past a pre-release
    // marker: semver ranks "16.0.0-alpha" below "16.0.0-alpha.0". Caught by
    // cross-checking this comparator against the semver package on real npm data.
    expect(compareVersions('16.0.0-alpha', '16.0.0-alpha.0')).toBeLessThan(0)
    expect(compareVersions('1.0.0-rc', '1.0.0-rc.1')).toBeLessThan(0)
    // The release-part padding it must not disturb.
    expect(compareVersions('1.0', '1.0.0')).toBe(0)
  })

  it('orders by epoch first, in both RPM and PEP 440 spellings', () => {
    // An epoch exists precisely to override the version that follows it.
    expect(compareVersions('1:1.0', '2.0')).toBeGreaterThan(0)
    expect(compareVersions('1!1.0', '2.0')).toBeGreaterThan(0)
    expect(newestFirst(['1:1.0', '2:0.1', '9.9'])).toEqual(['2:0.1', '1:1.0', '9.9'])
  })

  it('does not mistake an OCI digest for an epoch', () => {
    // "sha256:…" contains a colon but no leading digit run, so it must not parse
    // as an epoch — that would make every digest compare equal on epoch 0 anyway,
    // but a NaN epoch would poison the comparison.
    const digest = 'sha256:' + 'a'.repeat(64)
    expect(parseVersion(digest).epoch).toBe(0)
    expect(compareVersions(digest, digest)).toBe(0)
  })

  it('is a total order: never reports two different versions as equal', () => {
    const versions = ['1.0.0', '1.0.0-rc.1', '2.0.0', '1.10.0', '1.0.1', '0.9.9']
    for (const a of versions) {
      for (const b of versions) {
        if (a === b) continue
        expect(compareVersions(a, b)).not.toBe(0)
      }
    }
  })

  it('is antisymmetric', () => {
    const pairs = [
      ['1.0.0', '1.0.0-rc.1'],
      ['1.10.0', '1.9.0'],
      ['1.0.post1', '1.0'],
      ['2:0.1', '1:9.9'],
      ['1.0-SNAPSHOT', '1.0'],
    ]
    for (const [a, b] of pairs) {
      expect(Math.sign(compareVersions(a, b))).toBe(-Math.sign(compareVersions(b, a)))
    }
  })

  it('produces a stable order for unparseable or empty values', () => {
    // Never throws, and never returns an inconsistent verdict the sort could trip on.
    expect(() => newestFirst(['', null, undefined, 'latest', 'main'])).not.toThrow()
    expect(Math.sign(compareVersions('latest', 'main'))).toBe(-Math.sign(compareVersions('main', 'latest')))
  })

  it('sorts a realistic mixed release history newest-first', () => {
    const history = [
      '1.0.0-alpha.1', '1.0.0-beta.1', '1.0.0-rc.1', '1.0.0',
      '1.0.1', '1.1.0', '1.10.0', '1.9.0', '2.0.0-rc.1', '2.0.0',
    ]
    expect(newestFirst(history)).toEqual([
      '2.0.0', '2.0.0-rc.1', '1.10.0', '1.9.0', '1.1.0', '1.0.1',
      '1.0.0', '1.0.0-rc.1', '1.0.0-beta.1', '1.0.0-alpha.1',
    ])
  })
})
