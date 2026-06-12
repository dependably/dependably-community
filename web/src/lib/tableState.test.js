import { describe, it, expect, beforeEach } from 'vitest'
import { readQuery, writeQuery } from './tableState.js'

beforeEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('readQuery', () => {
  it('returns defaults when the query string is empty', () => {
    window.history.replaceState(null, '', '/packages')
    expect(readQuery({ q: '', page: 1 })).toEqual({ q: '', page: 1 })
  })

  it('reads string params and coerces number params', () => {
    window.history.replaceState(null, '', '/packages?q=react&page=3&limit=25')
    expect(readQuery({ q: '', eco: '', page: 1, limit: 50 }))
      .toEqual({ q: 'react', eco: '', page: 3, limit: 25 })
  })

  it('falls back to the default for non-numeric or sub-1 number params', () => {
    window.history.replaceState(null, '', '/packages?page=banana&limit=0')
    expect(readQuery({ page: 1, limit: 50 })).toEqual({ page: 1, limit: 50 })
  })

  it('ignores params not present in defaults', () => {
    window.history.replaceState(null, '', '/packages?q=x&unrelated=1')
    expect(readQuery({ q: '' })).toEqual({ q: 'x' })
  })
})

describe('writeQuery', () => {
  it('serializes only non-default values', () => {
    window.history.replaceState(null, '', '/packages')
    writeQuery({ q: 'react', eco: '', page: 2, limit: 50 }, { q: '', eco: '', page: 1, limit: 50 })
    expect(window.location.search).toBe('?q=react&page=2')
  })

  it('produces a clean URL when everything is default', () => {
    window.history.replaceState(null, '', '/packages?q=stale')
    writeQuery({ q: '', page: 1 }, { q: '', page: 1 })
    expect(window.location.search).toBe('')
    expect(window.location.pathname).toBe('/packages')
  })

  it('preserves the existing history state object untouched', () => {
    const entryState = { page: 'packages', params: {}, idx: 3 }
    window.history.replaceState(entryState, '', '/packages')
    writeQuery({ q: 'x' }, { q: '' })
    expect(window.history.state).toEqual(entryState)
  })

  it('round-trips through readQuery', () => {
    const defaults = { q: '', eco: '', page: 1, limit: 50, sort: 'name', dir: 'asc' }
    window.history.replaceState(null, '', '/packages')
    writeQuery({ q: 'lod', eco: 'npm', page: 4, limit: 50, sort: 'downloads', dir: 'desc' }, defaults)
    expect(readQuery(defaults)).toEqual(
      { q: 'lod', eco: 'npm', page: 4, limit: 50, sort: 'downloads', dir: 'desc' })
  })
})
