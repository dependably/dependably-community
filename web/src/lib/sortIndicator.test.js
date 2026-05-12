import { describe, it, expect } from 'vitest'
import { sortIndicator } from './sortIndicator.js'

describe('sortIndicator', () => {
  it('returns empty string when the column is not the active sort column', () => {
    expect(sortIndicator('name', 'created', 'asc')).toBe('')
    expect(sortIndicator('foo', null, 'asc')).toBe('')
  })

  it('returns ascending arrow when this column is sorted asc', () => {
    expect(sortIndicator('name', 'name', 'asc')).toBe(' ↑')
  })

  it('returns descending arrow when this column is sorted desc', () => {
    expect(sortIndicator('name', 'name', 'desc')).toBe(' ↓')
  })

  it('treats unknown directions as descending (anything that is not asc)', () => {
    expect(sortIndicator('name', 'name', 'sideways')).toBe(' ↓')
    expect(sortIndicator('name', 'name', undefined)).toBe(' ↓')
  })
})
