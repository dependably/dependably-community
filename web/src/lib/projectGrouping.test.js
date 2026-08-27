import { describe, it, expect } from 'vitest'
import { buildProjectDisplayRows } from './projectGrouping.js'

describe('buildProjectDisplayRows', () => {
  it('passes items through unindented when grouping is off (no active search)', () => {
    const items = [{ id: 'a' }, { id: 'b', parentId: 'a', parentName: 'A' }]
    expect(buildProjectDisplayRows(items, false)).toEqual([
      { id: 'a', indent: false },
      { id: 'b', parentId: 'a', parentName: 'A', indent: false },
    ])
  })

  it('groups a matched child directly under its matched parent, root first', () => {
    const items = [
      { id: 'child', parentId: 'root', parentName: 'Root' },
      { id: 'root' },
    ]
    const rows = buildProjectDisplayRows(items, true)
    expect(rows.map((r) => r.id)).toEqual(['root', 'child'])
    expect(rows[0].indent).toBe(false)
    expect(rows[1].indent).toBe(true)
  })

  it('synthesizes a header row when the parent itself did not match the search', () => {
    const items = [{ id: 'child', parentId: 'root-x', parentName: 'Root X' }]
    const rows = buildProjectDisplayRows(items, true)
    expect(rows).toEqual([
      { id: 'parent-header-root-x', isHeader: true, name: 'Root X' },
      { id: 'child', parentId: 'root-x', parentName: 'Root X', indent: true },
    ])
  })

  it('groups multiple children under the same synthesized header, preserving relative order', () => {
    const items = [
      { id: 'c1', parentId: 'root-x', parentName: 'Root X' },
      { id: 'other-root' },
      { id: 'c2', parentId: 'root-x', parentName: 'Root X' },
    ]
    const rows = buildProjectDisplayRows(items, true)
    expect(rows.map((r) => r.id)).toEqual(['other-root', 'parent-header-root-x', 'c1', 'c2'])
  })

  it('keeps unrelated root projects in their own, ungrouped slots', () => {
    const items = [{ id: 'a' }, { id: 'b' }]
    const rows = buildProjectDisplayRows(items, true)
    expect(rows.map((r) => r.id)).toEqual(['a', 'b'])
    expect(rows.every((r) => r.indent === false)).toBe(true)
  })

  it('falls back to an empty header name when parentName is missing', () => {
    const items = [{ id: 'child', parentId: 'root-x' }]
    const rows = buildProjectDisplayRows(items, true)
    expect(rows[0]).toEqual({ id: 'parent-header-root-x', isHeader: true, name: '' })
  })
})
