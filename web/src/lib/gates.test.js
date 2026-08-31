import { describe, it, expect } from 'vitest'
import { BLOCK_GATES, buildPreventionCells } from './gates.js'

describe('buildPreventionCells', () => {
  it('renders every baseline gate at zero when nothing was blocked', () => {
    const cells = buildPreventionCells([])
    expect(cells.map(c => c.gate)).toEqual([...BLOCK_GATES])
    expect(cells.every(c => c.count === 0)).toBe(true)
  })

  it('treats a null or absent payload the same as an empty one', () => {
    expect(buildPreventionCells(null)).toEqual(buildPreventionCells([]))
    expect(buildPreventionCells(undefined)).toEqual(buildPreventionCells([]))
  })

  it('leads with the gates that fired, keeping the rest at zero', () => {
    const cells = buildPreventionCells([{ gate: 'kev', count: 3 }, { gate: 'malicious', count: 7 }])
    expect(cells.slice(0, 2)).toEqual([
      { gate: 'malicious', count: 7 },
      { gate: 'kev', count: 3 },
    ])
    expect(cells).toHaveLength(BLOCK_GATES.length)
    expect(cells.slice(2).every(c => c.count === 0)).toBe(true)
  })

  it('falls back to the baseline order for equal counts', () => {
    const tied = buildPreventionCells([{ gate: 'epss', count: 2 }, { gate: 'revoked', count: 2 }])
    // 'revoked' precedes 'epss' in BLOCK_GATES, so it leads despite arriving second.
    expect(tied.slice(0, 2).map(c => c.gate)).toEqual(['revoked', 'epss'])
  })

  // The repository derives gates from the 'blocked%' event prefix, so it can report an arm this
  // list has never heard of — including 'manual', which is deliberately not in the baseline.
  it('appends a gate the baseline does not know about rather than dropping it', () => {
    const cells = buildPreventionCells([{ gate: 'manual', count: 1 }])
    expect(cells).toHaveLength(BLOCK_GATES.length + 1)
    expect(cells[0]).toEqual({ gate: 'manual', count: 1 })
  })

  it('does not duplicate a gate the payload repeats', () => {
    const cells = buildPreventionCells([{ gate: 'novel', count: 0 }, { gate: 'novel', count: 0 }])
    expect(cells.filter(c => c.gate === 'novel')).toHaveLength(1)
  })

  it('never returns an empty row', () => {
    expect(buildPreventionCells([]).length).toBeGreaterThan(0)
  })
})
