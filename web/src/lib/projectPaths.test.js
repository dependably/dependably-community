import { describe, it, expect } from 'vitest'
import { collectionPath, relocationTargets, PATH_SEPARATOR } from './projectPaths.js'

/**
 * Tree used throughout:
 *   platform            (root)
 *     └── payments
 *           └── ledger
 *   infra               (root)
 */
const COLLECTIONS = [
  { id: 'platform', name: 'Platform', parentId: null },
  { id: 'payments', name: 'Payments', parentId: 'platform' },
  { id: 'ledger', name: 'Ledger', parentId: 'payments' },
  { id: 'infra', name: 'Infra', parentId: null },
]

const byId = new Map(COLLECTIONS.map((c) => [c.id, c]))

describe('collectionPath', () => {
  it('joins the whole chain root-first', () => {
    expect(collectionPath('ledger', byId)).toBe(`Platform${PATH_SEPARATOR}Payments${PATH_SEPARATOR}Ledger`)
  })

  it('returns the bare name for a root collection', () => {
    expect(collectionPath('platform', byId)).toBe('Platform')
  })

  it('degrades to the known suffix when an ancestor is missing', () => {
    const partial = new Map([['ledger', { id: 'ledger', name: 'Ledger', parentId: 'gone' }]])
    expect(collectionPath('ledger', partial)).toBe('Ledger')
  })

  it('terminates on a cyclic chain instead of hanging', () => {
    const cyclic = new Map([
      ['a', { id: 'a', name: 'A', parentId: 'b' }],
      ['b', { id: 'b', name: 'B', parentId: 'a' }],
    ])
    expect(collectionPath('a', cyclic)).toBe(`B${PATH_SEPARATOR}A`)
  })

  it('returns empty for an unknown id', () => {
    expect(collectionPath('nope', byId)).toBe('')
  })
})

describe('relocationTargets', () => {
  it('offers every collection when creating (no project to exclude)', () => {
    const labels = relocationTargets(COLLECTIONS, null).map((t) => t.label)
    expect(labels).toEqual([
      'Infra',
      'Platform',
      `Platform${PATH_SEPARATOR}Payments`,
      `Platform${PATH_SEPARATOR}Payments${PATH_SEPARATOR}Ledger`,
    ])
  })

  it('excludes the folder being moved and every folder beneath it', () => {
    // Moving `payments`: itself and `ledger` are out; `platform` (its own parent) stays, because
    // "leave it where it is" must remain selectable, and `infra` is a legal destination.
    const ids = relocationTargets(COLLECTIONS, 'payments').map((t) => t.id)
    expect(ids).toEqual(['infra', 'platform'])
  })

  it('excludes a deep descendant, not just a direct child', () => {
    const ids = relocationTargets(COLLECTIONS, 'platform').map((t) => t.id)
    expect(ids).toEqual(['infra'])
  })

  it('keeps every collection when the moved project is a leaf that contains none', () => {
    // Path order, so each folder is immediately followed by its own children.
    const ids = relocationTargets(COLLECTIONS, 'some-plain-project').map((t) => t.id)
    expect(ids).toEqual(['infra', 'platform', 'payments', 'ledger'])
  })

  it('sorts by the full path, not by the bare name', () => {
    // 'Alpha' nested under 'Zulu' must sort after root-level 'Beta' — a bare-name sort would
    // put it first and scatter each folder's children away from it in the list.
    const nested = [
      { id: 'zulu', name: 'Zulu', parentId: null },
      { id: 'alpha', name: 'Alpha', parentId: 'zulu' },
      { id: 'beta', name: 'Beta', parentId: null },
    ]
    expect(relocationTargets(nested, null).map((t) => t.label)).toEqual([
      'Beta',
      'Zulu',
      `Zulu${PATH_SEPARATOR}Alpha`,
    ])
  })

  it('does not hang on a cyclic chain while testing exclusion', () => {
    const cyclic = [
      { id: 'a', name: 'A', parentId: 'b' },
      { id: 'b', name: 'B', parentId: 'a' },
    ]
    // Both survive with a truncated label ('A / B' and 'B / A'), which is what sorts b ahead of a.
    expect(relocationTargets(cyclic, 'c').map((t) => t.id)).toEqual(['b', 'a'])
  })
})
