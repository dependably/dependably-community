import { describe, it, expect } from 'vitest'
import { presetToCapabilities, capabilitiesToLabel } from './tokenCapabilities.js'

describe('presetToCapabilities', () => {
  it('pull → read-only capabilities', () => {
    expect(presetToCapabilities('pull')).toEqual(['read:metadata', 'read:artifact'])
  })

  it('push → publish-only (no read)', () => {
    expect(presetToCapabilities('push')).toEqual(['publish:*'])
  })

  it('both → read + publish wildcard', () => {
    expect(presetToCapabilities('both')).toEqual(['read:metadata', 'read:artifact', 'publish:*'])
  })

  it('admin → tenant configure + read tenant', () => {
    expect(presetToCapabilities('admin')).toEqual(['tenant:configure', 'read:tenant'])
  })

  it('audit → audit-log read only', () => {
    expect(presetToCapabilities('audit')).toEqual(['read:audit'])
  })

  it('unknown preset falls back to pull (conservative default)', () => {
    expect(presetToCapabilities('something-else')).toEqual(['read:metadata', 'read:artifact'])
    expect(presetToCapabilities(undefined)).toEqual(['read:metadata', 'read:artifact'])
  })
})

describe('capabilitiesToLabel', () => {
  it('null/missing → em-dash', () => {
    expect(capabilitiesToLabel(null)).toBe('—')
    expect(capabilitiesToLabel(undefined)).toBe('—')
    expect(capabilitiesToLabel('')).toBe('—')
  })

  it('unparseable JSON → em-dash', () => {
    expect(capabilitiesToLabel('not-json')).toBe('—')
  })

  it('empty array → em-dash', () => {
    expect(capabilitiesToLabel('[]')).toBe('—')
  })

  it('non-array JSON → em-dash', () => {
    expect(capabilitiesToLabel('{"foo":1}')).toBe('—')
  })

  it('read-only → pull', () => {
    expect(capabilitiesToLabel('["read:metadata","read:artifact"]')).toBe('pull')
  })

  it('read + publish → both', () => {
    expect(capabilitiesToLabel('["read:metadata","read:artifact","publish:*"]')).toBe('both')
    expect(capabilitiesToLabel('["read:metadata","publish:npm"]')).toBe('both')
  })

  it('publish without read → push', () => {
    expect(capabilitiesToLabel('["publish:*"]')).toBe('push')
  })

  it('tenant:configure → admin', () => {
    expect(capabilitiesToLabel('["tenant:configure","read:tenant"]')).toBe('admin')
  })

  it('read:audit alone → audit', () => {
    expect(capabilitiesToLabel('["read:audit"]')).toBe('audit')
  })

  it('non-string entries ignored gracefully', () => {
    expect(capabilitiesToLabel('[1,2,3]')).toBe('custom')
  })
})
