import { describe, it, expect } from 'vitest'
import { blastRadiusCell, overflowCount } from './blastRadius.js'

describe('blastRadiusCell', () => {
  it('reports a count the query answered with', () => {
    expect(blastRadiusCell({ 'npm/left-pad': 3 }, 'npm/left-pad', false))
      .toEqual({ state: 'count', count: 3 })
  })

  it('reports a real zero as its own state', () => {
    expect(blastRadiusCell({ 'npm/other': 2 }, 'npm/left-pad', false))
      .toEqual({ state: 'none', count: 0 })
  })

  it('a failed fetch is unavailable, never a zero', () => {
    // Adversarial twin. This is the whole reason the helper exists: on the quarantine queue,
    // whose help text says denying a package affects the applications shipping it, collapsing
    // "could not load" into "none" renders an outage as "affects nobody" and invites the wrong
    // decision. The mutant is `if (failed) return { state: 'none', count: 0 }`.
    expect(blastRadiusCell({}, 'npm/left-pad', true).state).toBe('unavailable')
    expect(blastRadiusCell({}, 'npm/left-pad', false).state).toBe('none')
  })

  it('a failed fetch stays unavailable even when a stale count is still in the map', () => {
    // The failure flag wins over whatever the previous page left behind: reporting a count from
    // a load that has since failed states a number nothing currently supports.
    expect(blastRadiusCell({ 'npm/left-pad': 9 }, 'npm/left-pad', true))
      .toEqual({ state: 'unavailable', count: 0 })
  })

  it('a row with no coordinate to ask about is none, not unavailable', () => {
    // Nothing failed — there was simply no question to ask, because the row carries no
    // resolvable coordinate. Rendering that as an outage would cry wolf on every such row.
    expect(blastRadiusCell({ 'npm/left-pad': 3 }, '', false).state).toBe('none')
  })

  it('tolerates a missing counts map', () => {
    expect(blastRadiusCell(null, 'npm/left-pad', false).state).toBe('none')
    expect(blastRadiusCell(undefined, 'npm/left-pad', false).state).toBe('none')
  })
})

describe('overflowCount', () => {
  it('reports how many results a capped list is not showing', () => {
    expect(overflowCount(40, 25)).toBe(15)
  })

  it('reports nothing when the list is complete', () => {
    expect(overflowCount(25, 25)).toBe(0)
  })

  it('never reports a negative overflow', () => {
    // Adversarial twin for a bare subtraction. A total smaller than the rows in hand (a row
    // added between the count and the page, or a caller passing no total at all) must render
    // nothing, not "and -3 more".
    expect(overflowCount(2, 5)).toBe(0)
    expect(overflowCount(null, 5)).toBe(0)
    expect(overflowCount(undefined, 5)).toBe(0)
  })
})
