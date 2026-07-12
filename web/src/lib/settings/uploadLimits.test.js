import { describe, it, expect } from 'vitest'
import { BYTES_PER_MB, bytesToMb, mbToBytes, exceedsInstanceCeiling, formatMbLabel } from './uploadLimits.js'

describe('uploadLimits — byte<->MB conversion', () => {
  it('bytesToMb converts a whole-MB byte count', () => {
    expect(bytesToMb(52428800)).toBe('50')
  })

  it('bytesToMb converts a sub-MB byte count without loss', () => {
    // 500 KB — the issue's worked example (500000 -> 0.476837158203125 MB).
    expect(bytesToMb(500000)).toBe('0.476837158203125')
  })

  it('bytesToMb treats unset values as an empty field', () => {
    expect(bytesToMb('')).toBe('')
    expect(bytesToMb(null)).toBe('')
    expect(bytesToMb(undefined)).toBe('')
  })

  it('mbToBytes converts a whole MB value back to bytes', () => {
    expect(mbToBytes('50')).toBe('52428800')
  })

  it('mbToBytes rounds fractional MB to the nearest byte', () => {
    expect(mbToBytes('0.5')).toBe(String(Math.round(0.5 * BYTES_PER_MB)))
  })

  it('mbToBytes treats an empty field as unset, not zero', () => {
    expect(mbToBytes('')).toBe('')
    expect(mbToBytes(null)).toBe('')
    expect(mbToBytes(undefined)).toBe('')
  })

  it('round-trips whole-MB and sub-MB byte counts losslessly through load -> display -> save', () => {
    for (const bytes of [52428800, 524288000, 500000, 1048576, 2048 * 1024 * 1024]) {
      expect(mbToBytes(bytesToMb(bytes))).toBe(String(bytes))
    }
  })
})

describe('uploadLimits — unit-consistent over-ceiling validation', () => {
  it('flags an MB value whose byte equivalent exceeds the instance ceiling', () => {
    // 60 MB > 50 MB ceiling.
    expect(exceedsInstanceCeiling('60', 50 * BYTES_PER_MB)).toBe(true)
  })

  it('does not flag an MB value at or under the instance ceiling', () => {
    expect(exceedsInstanceCeiling('50', 50 * BYTES_PER_MB)).toBe(false)
    expect(exceedsInstanceCeiling('49.9', 50 * BYTES_PER_MB)).toBe(false)
  })

  it('correctly flags a fractional MB value over a small ceiling — the case a naive parseInt(mbVal) > instanceMax check silently passes', () => {
    // 0.5 MB (524288 bytes) against a 400000-byte (~0.38 MB) ceiling: over the ceiling.
    // parseInt('0.5') floors to 0, which a byte-unit-only comparison would never flag —
    // exactly the bug this module exists to close.
    expect(exceedsInstanceCeiling('0.5', 400000)).toBe(true)
  })

  it('mixed batch of ecosystem fields — some under, some over the same ceiling, in one call', () => {
    const ceiling = 100 * BYTES_PER_MB
    const fields = { pypi: '50', npm: '150', nuget: '100', maven: '0.5', oci: '2048' }
    const results = Object.fromEntries(
      Object.entries(fields).map(([k, v]) => [k, exceedsInstanceCeiling(v, ceiling)])
    )
    expect(results).toEqual({ pypi: false, npm: true, nuget: false, maven: false, oci: true })
  })

  it('never flags when there is no instance ceiling', () => {
    expect(exceedsInstanceCeiling('999999', null)).toBe(false)
    expect(exceedsInstanceCeiling('999999', 0)).toBe(false)
  })

  it('never flags an empty field regardless of ceiling', () => {
    expect(exceedsInstanceCeiling('', 50 * BYTES_PER_MB)).toBe(false)
  })
})

describe('uploadLimits — display-only MB label', () => {
  it('rounds to at most 2 decimals for a clean label', () => {
    expect(formatMbLabel(500 * BYTES_PER_MB)).toBe('500')
    expect(formatMbLabel(500000)).toBe('0.48')
  })

  it('returns an empty label for an unset ceiling', () => {
    expect(formatMbLabel(null)).toBe('')
    expect(formatMbLabel(undefined)).toBe('')
    expect(formatMbLabel('')).toBe('')
  })
})
