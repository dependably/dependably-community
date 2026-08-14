import { locale } from 'svelte-i18n'
import { derived } from 'svelte/store'
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
export const formatDate = derived([locale, timeZone], ([$locale, $timeZone]) => (d) => {
  const date = toDate(d)
  return date
    ? new Intl.DateTimeFormat($locale || 'en', {
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
export const formatDateShort = derived([locale, timeZone], ([$locale, $timeZone]) => (d) => {
  const date = toDate(d)
  return date
    ? new Intl.DateTimeFormat($locale || 'en', { dateStyle: 'medium', timeZone: $timeZone }).format(date)
    : '—'
})

export const formatRelativeTime = derived(locale, $locale => (d) => {
  const date = toDate(d)
  if (!date) return '—'
  const diff = (date.getTime() - Date.now()) / 1000
  const rtf = new Intl.RelativeTimeFormat($locale || 'en', { numeric: 'auto' })
  const abs = Math.abs(diff)
  if (abs < 60) return rtf.format(Math.round(diff), 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  return rtf.format(Math.round(diff / 86400), 'day')
})

export const formatNumber = derived(locale, $locale => (n) =>
  new Intl.NumberFormat($locale || 'en').format(n ?? 0))

export const formatBytes = derived(locale, $locale => (n) => {
  if (!n || n === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const value = n / Math.pow(1024, i)
  return new Intl.NumberFormat($locale || 'en', { maximumFractionDigits: 1 }).format(value) + ' ' + units[i]
})
