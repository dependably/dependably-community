import { describe, it, expect } from 'vitest'
import { fileRowKey } from './versionFiles.js'

describe('fileRowKey', () => {
  it('distinguishes sibling files that share a version id', () => {
    // The shape the API emits for a hosted NuGet version carrying its symbol package: one
    // package_versions row, two files, so `id` repeats. Keying on `id` throws each_key_duplicate.
    const nupkg = { id: 'ver-1', filename: 'pkg.1.0.0.nupkg' }
    const snupkg = { id: 'ver-1', filename: 'pkg.1.0.0.snupkg' }

    expect(fileRowKey(nupkg)).not.toBe(fileRowKey(snupkg))
  })

  it('keys on filename, the identity ?file= addresses', () => {
    expect(fileRowKey({ id: 'ver-1', filename: 'pkg-1.0.0.tar.gz' })).toBe('pkg-1.0.0.tar.gz')
  })

  it('falls back to id when a row carries no filename', () => {
    expect(fileRowKey({ id: 'cache-7', filename: null })).toBe('cache-7')
    expect(fileRowKey({ id: 'cache-7' })).toBe('cache-7')
  })

  it('keeps proxy rows distinct through the fallback', () => {
    // Proxy rows are file-level cache_artifact rows, so their ids differ even without filenames.
    const rows = [{ id: 'cache-1', filename: null }, { id: 'cache-2', filename: null }]
    expect(new Set(rows.map(fileRowKey)).size).toBe(2)
  })
})
