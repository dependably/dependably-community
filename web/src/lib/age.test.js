import { describe, it, expect } from 'vitest'
import { daysSince } from './age.js'

const NOW = new Date('2026-06-15T12:00:00Z').getTime()

describe('daysSince', () => {
  it('returns null for a missing timestamp', () => {
    expect(daysSince(null, NOW)).toBeNull()
    expect(daysSince(undefined, NOW)).toBeNull()
    expect(daysSince('', NOW)).toBeNull()
  })

  it('returns null for an unparseable timestamp rather than NaN', () => {
    expect(daysSince('not-a-date', NOW)).toBeNull()
  })

  it('floors to whole days elapsed', () => {
    expect(daysSince('2026-06-10T12:00:00Z', NOW)).toBe(5)
    expect(daysSince('2026-06-10T13:00:00Z', NOW)).toBe(4) // 23h short of 5 full days
  })

  it('never goes negative for a timestamp in the future', () => {
    expect(daysSince('2026-06-20T12:00:00Z', NOW)).toBe(0)
  })

  it('returns zero for the current instant', () => {
    expect(daysSince('2026-06-15T12:00:00Z', NOW)).toBe(0)
  })
})
