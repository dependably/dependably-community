import { locale } from 'svelte-i18n'
import { derived, writable } from 'svelte/store'
import { user } from './store.js'

function toDate(d) {
  if (!d) return null
  const date = new Date(d)
  return isNaN(date.getTime()) ? null : date
}

// The zone every absolute timestamp renders in: the user's profile preference (already
// resolved server-side through the org default), falling back to the browser's own zone until
// /me has loaded. Not the raw browser zone once a preference exists — a user who set one
// expects the whole UI to follow it, not only the pages that ask for it.
export const timeZone = derived(user, $user =>
  $user?.resolvedTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')

// Intl resolves a *bare* language tag to that language's default region — 'en' becomes en-US and
// 'fr' becomes fr-FR — which is not this product's default: the English copy is Canadian English
// and the French copy targets Canadian French (OQLF). So a bare tag, which carries no regional
// intent, is given the Canadian region here; bare 'en' would otherwise render "10:05 AM" rather
// than "10:05 a.m.", and bare 'fr' "10:05 UTC-4" rather than "10 h 05 HAE".
//
// A tag that already names a region is the reader's own, and is passed through untouched —
// en-GB keeps day-first dates, en-US keeps "AM", fr-CA and fr-FR keep their own conventions.
// Defaulting is not the same as overriding, and flattening every region onto en-CA would tell a
// London operator their dates are Canadian.
const DEFAULT_REGIONS = { en: 'en-CA', fr: 'fr-CA' }

// The reader's own browser tag. Held in a store rather than read from `navigator` inside the
// resolution below, so that resolution stays a pure function of its inputs and tests can drive
// it; nothing but boot writes this.
export const browserLocale = writable(
  typeof navigator !== 'undefined' ? navigator.language || '' : '')

// `/me` returns a bare language ('en'/'fr') — AuthController.Me resolves it through
// TwoLetterISOLanguageName — and applyLocale writes that onto $locale at login. So by the time a
// user is signed in, the region their browser asked for is gone from $locale. Recover it here:
// a stored preference of "English" is a choice of language, not a decision to stop being in
// London. The browser's region is borrowed only when it agrees on the language, so picking
// French never inherits en-GB.
export const formattingLocale = derived([locale, browserLocale], ([$locale, $browser]) => {
  const tag = $locale || 'en'
  if (tag.includes('-')) return tag
  const base = tag.split('-')[0]
  if ($browser && $browser.includes('-') && $browser.split('-')[0] === base) return $browser
  return DEFAULT_REGIONS[base] ?? tag
})

// The stored instant, unconverted, for the `title` tooltip on a rendered time. An operator
// correlating the UI against a log line or an audit export reads UTC there, so the tooltip
// hands them exactly that instead of making them undo the zone conversion.
export function utcTooltip(d) {
  const date = toDate(d)
  return date ? date.toISOString().replace(/\.\d{3}Z$/, 'Z') : ''
}

// Spelled out as individual components rather than dateStyle/timeStyle: Intl rejects mixing
// those shorthands with timeZoneName, and the zone label is the point — a time without one is
// ambiguous the moment two people in different zones read the same screen. These components
// reproduce what dateStyle:'medium' + timeStyle:'short' rendered.
export const formatDate = derived([formattingLocale, timeZone], ([$locale, $timeZone]) => (d) => {
  const date = toDate(d)
  return date
    ? new Intl.DateTimeFormat($locale, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        timeZone: $timeZone,
        timeZoneName: 'short',
      }).format(date)
    : '—'
})

// Date-only, so no zone label — but still formatted *in* the resolved zone, or an instant near
// midnight lands on the wrong calendar day for anyone east or west of the browser's zone.
export const formatDateShort = derived([formattingLocale, timeZone], ([$locale, $timeZone]) => (d) => {
  const date = toDate(d)
  return date
    ? new Intl.DateTimeFormat($locale, { dateStyle: 'medium', timeZone: $timeZone }).format(date)
    : '—'
})

export const formatRelativeTime = derived(formattingLocale, $locale => (d) => {
  const date = toDate(d)
  if (!date) return '—'
  const diff = (date.getTime() - Date.now()) / 1000
  const rtf = new Intl.RelativeTimeFormat($locale, { numeric: 'auto' })
  const abs = Math.abs(diff)
  if (abs < 60) return rtf.format(Math.round(diff), 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  return rtf.format(Math.round(diff / 86400), 'day')
})

// Time-of-day only, for the "saved at" affordances and chart axis labels that previously called
// a bare toLocaleTimeString() — that reads the *browser's* locale, so a French user on an English
// browser saw two different formats on one screen. formatHour24 keeps its explicit 24-hour clock;
// neither passes a timeZone, matching what the bare calls they replace already did.
export const formatTime = derived(formattingLocale, $locale => (d) => {
  const date = toDate(d)
  return date ? new Intl.DateTimeFormat($locale, { timeStyle: 'medium' }).format(date) : '—'
})

export const formatHour24 = derived(formattingLocale, $locale => (d) => {
  const date = toDate(d)
  return date
    ? new Intl.DateTimeFormat($locale, { hour: '2-digit', minute: '2-digit', hour12: false }).format(date)
    : '—'
})

export const formatNumber = derived(formattingLocale, $locale => (n) =>
  new Intl.NumberFormat($locale).format(n ?? 0))

export const formatBytes = derived(formattingLocale, $locale => (n) => {
  if (!n || n === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const value = n / Math.pow(1024, i)
  return new Intl.NumberFormat($locale, { maximumFractionDigits: 1 }).format(value) + ' ' + units[i]
})
