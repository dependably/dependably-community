import { describe, it, expect } from 'vitest'
import { presetToCapabilities, capabilitiesToLabel } from './tokenCapabilities.js'

describe('presetToCapabilities', () => {
  it('pull → read-only capabilities', () => {
    expect(presetToCapabilities('pull')).toEqual(['read:metadata', 'read:artifact'])
  })

  it('push → read + publish wildcard', () => {
    expect(presetToCapabilities('push')).toEqual(['read:metadata', 'read:artifact', 'publish:*'])
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

  it('read + publish → push', () => {
    expect(capabilitiesToLabel('["read:metadata","read:artifact","publish:*"]')).toBe('push')
    expect(capabilitiesToLabel('["read:metadata","publish:npm"]')).toBe('push')
  })

  it('publish without read → custom', () => {
    expect(capabilitiesToLabel('["publish:*"]')).toBe('custom')
  })

  it('non-string entries ignored gracefully', () => {
    expect(capabilitiesToLabel('[1,2,3]')).toBe('custom')
  })
})
