import { describe, it, expect } from 'vitest'
import { buildCurlSnippet } from './curlSnippet.js'

describe('buildCurlSnippet', () => {
  it('embeds the origin, encoded project name/version, and current autoCreate/isLatest flags', () => {
    const snippet = buildCurlSnippet({
      origin: 'https://dependably.example.com',
      projectName: 'checkout service',
      projectVersion: '1.4.0+build.7',
      autoCreate: true,
      isLatest: false,
    })
    expect(snippet).toContain('https://dependably.example.com/api/v1/sbom?')
    expect(snippet).toContain('projectName=checkout%20service')
    expect(snippet).toContain('projectVersion=1.4.0%2Bbuild.7')
    expect(snippet).toContain('autoCreate=true')
    expect(snippet).toContain('isLatest=false')
  })

  it('includes all three PUT endpoints with the SBOM one first (upload-order matters)', () => {
    const snippet = buildCurlSnippet({
      origin: 'https://dependably.example.com', projectName: 'p', projectVersion: '1.0.0',
      autoCreate: true, isLatest: true,
    })
    const sbomIdx = snippet.indexOf('/api/v1/sbom?')
    const vexIdx = snippet.indexOf('/api/v1/vex?')
    const sarifIdx = snippet.indexOf('/api/v1/sarif?')
    expect(sbomIdx).toBeGreaterThan(-1)
    expect(vexIdx).toBeGreaterThan(-1)
    expect(sarifIdx).toBeGreaterThan(-1)
    expect(sbomIdx).toBeLessThan(vexIdx)
    expect(vexIdx).toBeLessThan(sarifIdx)
  })

  it('omits autoCreate/isLatest from the vex and sarif query strings', () => {
    const snippet = buildCurlSnippet({
      origin: 'https://dependably.example.com', projectName: 'p', projectVersion: '1.0.0',
      autoCreate: true, isLatest: true,
    })
    const vexLine = snippet.split('\n').find(l => l.includes('/api/v1/vex?'))
    const sarifLine = snippet.split('\n').find(l => l.includes('/api/v1/sarif?'))
    expect(vexLine).not.toContain('autoCreate')
    expect(vexLine).not.toContain('isLatest')
    expect(sarifLine).not.toContain('autoCreate')
    expect(sarifLine).not.toContain('isLatest')
  })

  it('falls back to placeholder tokens when name/version are blank', () => {
    const snippet = buildCurlSnippet({
      origin: 'https://dependably.example.com', projectName: '', projectVersion: '   ',
      autoCreate: true, isLatest: false,
    })
    expect(snippet).toContain('projectName=%3Cproject-name%3E')
    expect(snippet).toContain('projectVersion=%3Cproject-version%3E')
  })
})

describe('buildCurlSnippet — folder target', () => {
  const base = {
    origin: 'https://dep.example.com',
    projectName: 'api',
    projectVersion: '1.0.0',
    autoCreate: true,
    isLatest: false,
  }

  it('omits parentId entirely when none is given', () => {
    // The Dependency-Track-compatible CI shape: no parent named, org-wide name resolution.
    expect(buildCurlSnippet(base)).not.toContain('parentId')
  })

  it('carries parentId on all three PUTs when the modal was opened from a folder', () => {
    const snippet = buildCurlSnippet({ ...base, parentId: 'f00d' })
    // All three, not just the SBOM: VEX and SARIF resolve the project by name too, so a snippet
    // that scoped only the first would 409 on the other two the moment two folders share a name.
    expect(snippet.match(/parentId=f00d/g)).toHaveLength(3)
  })

  it('percent-encodes the parent id', () => {
    expect(buildCurlSnippet({ ...base, parentId: 'a b/c' })).toContain('parentId=a%20b%2Fc')
  })
})
