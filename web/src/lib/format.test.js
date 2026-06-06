import { describe, it, expect, beforeEach } from 'vitest'
import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'
import { formatBytes, formatDate, formatDateShort, formatRelativeTime, formatNumber } from './format.js'

describe('format — store-pattern proof', () => {
  beforeEach(() => locale.set('en'))

  it('formatBytes renders human-friendly sizes for known thresholds', () => {
    const fmt = get(formatBytes)
    expect(fmt(0)).toBe('0 B')
    expect(fmt(null)).toBe('0 B')
    expect(fmt(1024)).toBe('1 KB')
    expect(fmt(1024 * 1024)).toBe('1 MB')
    expect(fmt(2.5 * 1024 * 1024 * 1024)).toBe('2.5 GB')
  })

  it('formatDate / formatDateShort return em-dash for null and invalid input', () => {
    const dt = get(formatDate)
    const dts = get(formatDateShort)
    expect(dt(null)).toBe('—')
    expect(dt('not-a-date')).toBe('—')
    expect(dts(null)).toBe('—')
  })

  it('formatRelativeTime returns em-dash for invalid input', () => {
    const rel = get(formatRelativeTime)
    expect(rel(null)).toBe('—')
    expect(rel('garbage')).toBe('—')
  })

  it('formatRelativeTime produces a non-empty string for a real timestamp', () => {
    const rel = get(formatRelativeTime)
    const result = rel(new Date(Date.now() - 5_000).toISOString()) // 5 seconds ago
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(1)
  })

  it('formatRelativeTime handles the minutes range (~2 minutes ago)', () => {
    const rel = get(formatRelativeTime)
    const result = rel(new Date(Date.now() - 2 * 60 * 1000).toISOString()) // 2 minutes ago
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(1)
    expect(result).toMatch(/minute/)
  })

  it('formatRelativeTime handles the hours range (~2 hours ago)', () => {
    const rel = get(formatRelativeTime)
    const result = rel(new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()) // 2 hours ago
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(1)
    expect(result).toMatch(/hour/)
  })

  it('formatRelativeTime handles the days range (~2 days ago)', () => {
    const rel = get(formatRelativeTime)
    const result = rel(new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString()) // 2 days ago
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(1)
    expect(result).toMatch(/day/)
  })

  it('formatBytes uses maximumFractionDigits=1 so 1024 → "1 KB" or "1.0 KB"', () => {
    const fmt = get(formatBytes)
    // 1.5 KB exercises the decimal path
    expect(fmt(1536)).toBe('1.5 KB')
    expect(fmt(1.5 * 1024 * 1024)).toBe('1.5 MB')
  })

  it('formatNumber renders 0 for null/undefined and groups thousands', () => {
    const fmt = get(formatNumber)
    expect(fmt(null)).toBe('0')
    expect(fmt(undefined)).toBe('0')
    expect(fmt(0)).toBe('0')
    expect(fmt(1234567)).toBe('1,234,567')
  })

  it('formatDate returns a non-empty formatted string for a valid ISO date', () => {
    const dt = get(formatDate)
    const result = dt('2024-06-15T12:00:00Z')
    expect(typeof result).toBe('string')
    expect(result).not.toBe('—')
    expect(result.length).toBeGreaterThan(3)
  })

  it('formatDateShort returns a non-empty formatted string for a valid ISO date', () => {
    const dts = get(formatDateShort)
    const result = dts('2024-06-15T12:00:00Z')
    expect(typeof result).toBe('string')
    expect(result).not.toBe('—')
    expect(result.length).toBeGreaterThan(3)
  })

  describe('locale fallback branch — $locale is falsy → uses "en"', () => {
    beforeEach(() => locale.set(null))

    it('formatDate falls back to "en" when locale store is null', () => {
      const dt = get(formatDate)
      const result = dt('2024-06-15T12:00:00Z')
      expect(typeof result).toBe('string')
      expect(result).not.toBe('—')
      expect(result.length).toBeGreaterThan(3)
    })

    it('formatDateShort falls back to "en" when locale store is null', () => {
      const dts = get(formatDateShort)
      const result = dts('2024-06-15T12:00:00Z')
      expect(typeof result).toBe('string')
      expect(result).not.toBe('—')
      expect(result.length).toBeGreaterThan(3)
    })

    it('formatRelativeTime falls back to "en" when locale store is null', () => {
      const rel = get(formatRelativeTime)
      const result = rel(new Date(Date.now() - 5_000).toISOString())
      expect(typeof result).toBe('string')
      expect(result.length).toBeGreaterThan(1)
    })

    it('formatBytes falls back to "en" when locale store is null', () => {
      const fmt = get(formatBytes)
      expect(fmt(1536)).toBe('1.5 KB')
    })
  })
})
