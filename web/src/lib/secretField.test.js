import { describe, it, expect } from 'vitest'
import { secretPlaceholder } from './secretField.js'

describe('secretPlaceholder', () => {
  it('returns masked dots when a secret is stored', () => {
    expect(secretPlaceholder(true)).toBe('••••••••')
  })

  it('returns an empty placeholder when no secret is stored', () => {
    expect(secretPlaceholder(false)).toBe('')
  })

  it('treats a falsy has-flag (undefined) as not-set', () => {
    expect(secretPlaceholder(undefined)).toBe('')
  })

  it('never returns the literal value — only the mask or empty', () => {
    // The mask must not resemble a real secret; it is fixed-length and character-uniform.
    const mask = secretPlaceholder(true)
    expect(mask).toMatch(/^•+$/)
  })
})
