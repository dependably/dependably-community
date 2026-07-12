import { describe, it, expect } from 'vitest'
import { aliasUrl } from './advisories.js'

describe('aliasUrl', () => {
  it('links GHSA ids to the GitHub Advisory Database', () => {
    expect(aliasUrl('GHSA-abcd-1234-wxyz')).toBe('https://github.com/advisories/GHSA-abcd-1234-wxyz')
  })

  it('links CVE ids to NVD', () => {
    expect(aliasUrl('CVE-2024-12345')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-12345')
  })

  it('links RUSTSEC ids to rustsec.org', () => {
    expect(aliasUrl('RUSTSEC-2024-0001')).toBe('https://rustsec.org/advisories/RUSTSEC-2024-0001.html')
  })

  it('links GO ids to pkg.go.dev', () => {
    expect(aliasUrl('GO-2024-1234')).toBe('https://pkg.go.dev/vuln/GO-2024-1234')
  })

  it('links PYSEC ids to osv.dev', () => {
    expect(aliasUrl('PYSEC-2024-42')).toBe('https://osv.dev/vulnerability/PYSEC-2024-42')
  })

  it('returns null for unknown prefixes and empty input (caller renders a plain chip)', () => {
    expect(aliasUrl('DSA-5555-1')).toBeNull()
    expect(aliasUrl('')).toBeNull()
    expect(aliasUrl(null)).toBeNull()
    expect(aliasUrl(undefined)).toBeNull()
  })
})
