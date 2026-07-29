import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'
import { user } from './store.js'
import { formatDate, formatDateShort, timeZone, utcTooltip } from './format.js'

describe('timezone-aware rendering', () => {
  beforeEach(() => locale.set('en'))
  afterEach(() => user.set(null))

  it('falls back to the browser zone before /me has loaded', () => {
    user.set(null)
    expect(get(timeZone)).toBe(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  })

  it('follows the resolved profile preference once /me has loaded', () => {
    user.set({ resolvedTimezone: 'Asia/Tokyo' })
    expect(get(timeZone)).toBe('Asia/Tokyo')
  })

  it('renders the same instant in the user preferred zone', () => {
    // 2026-07-25T12:00:00Z is 08:00 in Toronto (EDT) and 21:00 in Tokyo.
    user.set({ resolvedTimezone: 'America/Toronto' })
    const toronto = get(formatDate)('2026-07-25T12:00:00Z')

    user.set({ resolvedTimezone: 'Asia/Tokyo' })
    const tokyo = get(formatDate)('2026-07-25T12:00:00Z')

    expect(toronto).toContain('8:00')
    expect(tokyo).toContain('9:00')
    expect(toronto).not.toBe(tokyo)
  })

  it('labels every absolute time with its zone', () => {
    user.set({ resolvedTimezone: 'America/Toronto' })
    expect(get(formatDate)('2026-07-25T12:00:00Z')).toMatch(/EDT|GMT-4/)
  })

  it('resolves the calendar day in the preferred zone, not the browser zone', () => {
    // 23:30Z on the 25th is already the 26th in Tokyo. A date-only render that ignored the
    // zone would show the 25th for a Tokyo user.
    user.set({ resolvedTimezone: 'Asia/Tokyo' })
    expect(get(formatDateShort)('2026-07-25T23:30:00Z')).toContain('26')

    user.set({ resolvedTimezone: 'America/Toronto' })
    expect(get(formatDateShort)('2026-07-25T23:30:00Z')).toContain('25')
  })

  it('tooltip reports the stored UTC instant, unconverted', () => {
    user.set({ resolvedTimezone: 'Asia/Tokyo' })
    expect(utcTooltip('2026-07-25T12:00:00Z')).toBe('2026-07-25T12:00:00Z')
    expect(utcTooltip(null)).toBe('')
    expect(utcTooltip('not-a-date')).toBe('')
  })
})
