import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { rememberedRowCount, rememberRowCount } from './tableSize.js'

beforeEach(() => {
  sessionStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('table row-count memory', () => {
  it('a table not seen this session has no remembered count', () => {
    expect(rememberedRowCount('packages')).toBeNull()
  })

  it('remembers what a table actually held, not what it asked for', () => {
    // The point of the memory: a page-size reserve of fifty for a table holding four collapses
    // by forty-six rows when the data lands, moving everything below it.
    rememberRowCount('packages', 4)
    expect(rememberedRowCount('packages')).toBe(4)
  })

  it('keeps a count per table rather than one for all of them', () => {
    rememberRowCount('packages', 12)
    rememberRowCount('vulnerabilities', 3)
    expect(rememberedRowCount('packages')).toBe(12)
    expect(rememberedRowCount('vulnerabilities')).toBe(3)
  })

  it('caps at a viewport of rows', () => {
    // Reserving past the fold buys nothing — rows arriving below the viewport grow the document
    // without moving anything the reader can see.
    rememberRowCount('packages', 500)
    expect(rememberedRowCount('packages')).toBe(30)
  })

  it('does not record an empty table', () => {
    // An empty table renders its empty-state text, a fixed height the placeholder should not
    // try to match — and a zero reserve would collapse the table shell entirely.
    rememberRowCount('packages', 25)
    rememberRowCount('packages', 0)
    expect(rememberedRowCount('packages')).toBe(25)
  })

  it('ignores a table with no memory key', () => {
    rememberRowCount('', 10)
    expect(rememberedRowCount('')).toBeNull()
  })

  it('survives unparseable stored state', () => {
    sessionStorage.setItem('tableRowCounts', '{not json')
    expect(rememberedRowCount('packages')).toBeNull()
    // And recovers: a later write replaces the garbage rather than throwing on every render.
    rememberRowCount('packages', 7)
    expect(rememberedRowCount('packages')).toBe(7)
  })

  it('a storage write that throws does not reach the caller', () => {
    // Private-mode Safari and a full quota both throw on setItem. The memory is an optimization,
    // never a reason to fail a page render.
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    expect(() => rememberRowCount('packages', 5)).not.toThrow()
  })

  it('is a no-op when sessionStorage is unavailable', () => {
    vi.stubGlobal('sessionStorage', undefined)
    expect(() => rememberRowCount('packages', 5)).not.toThrow()
    expect(rememberedRowCount('packages')).toBeNull()
  })
})
