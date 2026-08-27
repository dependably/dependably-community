import { describe, it, expect, beforeEach } from 'vitest'
import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'
import { formatBytes, formatDate, formatDateShort, formatRelativeTime, formatNumber, formatHour24, formatTime, formattingLocale, browserLocale } from './format.js'

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

  it('formatBytes renders TB and PB for sizes at and above 1024 GB instead of clamping to GB', () => {
    const fmt = get(formatBytes)
    expect(fmt(1024 * 1024 * 1024 * 1024)).toBe('1 TB')
    expect(fmt(2 * 1024 * 1024 * 1024 * 1024)).toBe('2 TB')
    expect(fmt(1024 * 1024 * 1024 * 1024 * 1024)).toBe('1 PB')
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

// svelte-i18n stores the bare language tag, and Intl silently resolves a bare tag to that
// language's *default* region — en-US and fr-FR. Both are the wrong region for this product, and
// nothing in a key-parity check can see it: the strings are correct, only the rendered dates and
// times are foreign. These assertions pin the region, so a future refactor that hands Intl the
// bare tag again fails here rather than shipping "10:05 AM" into a Canadian English UI.
describe('regional locale resolution', () => {
  // jsdom reports its own navigator.language, so every case below sets the browser tag
  // explicitly rather than inheriting whatever the runner happens to have.
  beforeEach(() => browserLocale.set(''))

  it('defaults a bare language tag to its Canadian region', () => {
    locale.set('en')
    expect(get(formattingLocale)).toBe('en-CA')
    locale.set('fr')
    expect(get(formattingLocale)).toBe('fr-CA')
  })

  it('falls back to en-CA when the locale store is empty', () => {
    locale.set(null)
    expect(get(formattingLocale)).toBe('en-CA')
  })

  it('honours a region the reader already supplied rather than defaulting it', () => {
    // Defaulting is not overriding: en-CA applies only where no region was named. Flattening
    // these onto en-CA would tell a London or New York operator their dates are Canadian.
    for (const tag of ['en-GB', 'en-US', 'fr-CA', 'fr-FR', 'en-AU']) {
      locale.set(tag)
      expect(get(formattingLocale)).toBe(tag)
    }
  })

  it('passes an unknown bare language through untouched', () => {
    locale.set('de')
    expect(get(formattingLocale)).toBe('de')
  })

  it('renders en-GB as day-first and en-US with AM, each keeping its own convention', () => {
    locale.set('en-GB')
    const gb = get(formatDateShort)('2024-06-15T12:00:00Z')
    expect(gb).toMatch(/15 Jun 2024/)

    locale.set('en-US')
    const us = get(formatDate)('2024-06-15T16:30:00Z')
    expect(us).toMatch(/\b[AP]M\b/)
  })

  it('renders English times in the en-CA form (a.m./p.m.), not the en-US form (AM/PM)', () => {
    locale.set('en')
    const rendered = get(formatDate)('2024-06-15T16:30:00Z')
    expect(rendered).toMatch(/[ap]\.m\./)
    expect(rendered).not.toMatch(/\b[AP]M\b/)
  })

  it('renders French times in the fr-CA form ("10 h 05"), not the fr-FR form ("10:05")', () => {
    locale.set('fr')
    const rendered = get(formatDate)('2024-06-15T16:30:00Z')
    expect(rendered).toMatch(/\d\s?h\s?\d/)
  })

  it('borrows the browser region when it agrees on the language', () => {
    // /me hands back a bare 'en' at login, wiping the region off $locale. A reader on an en-GB
    // browser who never chose a region should still get en-GB dates, not the en-CA default.
    browserLocale.set('en-GB')
    locale.set('en')
    expect(get(formattingLocale)).toBe('en-GB')

    browserLocale.set('en-US')
    expect(get(formattingLocale)).toBe('en-US')
  })

  it('does not borrow a region across a language boundary', () => {
    // Choosing French must not inherit en-GB; it falls to the French default instead.
    browserLocale.set('en-GB')
    locale.set('fr')
    expect(get(formattingLocale)).toBe('fr-CA')
  })

  it('lets an explicit regional preference outrank the browser', () => {
    browserLocale.set('en-US')
    locale.set('en-GB')
    expect(get(formattingLocale)).toBe('en-GB')
  })

  it('falls to the default when the browser names no region', () => {
    browserLocale.set('en')
    locale.set('en')
    expect(get(formattingLocale)).toBe('en-CA')
  })

  it('formatHour24 and formatTime follow the locale rather than the browser', () => {
    locale.set('fr')
    expect(get(formatHour24)('2024-06-15T16:30:00Z')).toMatch(/\d{2}\s?h\s?\d{2}/)
    expect(get(formatTime)(null)).toBe('—')
    expect(get(formatHour24)('garbage')).toBe('—')
  })
})
