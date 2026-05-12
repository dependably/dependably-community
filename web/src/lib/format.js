import { locale } from 'svelte-i18n'
import { derived } from 'svelte/store'

function toDate(d) {
  if (!d) return null
  const date = new Date(d)
  return isNaN(date.getTime()) ? null : date
}

export const formatDate = derived(locale, $locale => (d) => {
  const date = toDate(d)
  return date ? new Intl.DateTimeFormat($locale || 'en', { dateStyle: 'medium', timeStyle: 'short' }).format(date) : '—'
})

export const formatDateShort = derived(locale, $locale => (d) => {
  const date = toDate(d)
  return date ? new Intl.DateTimeFormat($locale || 'en', { dateStyle: 'medium' }).format(date) : '—'
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

export const formatBytes = derived(locale, $locale => (n) => {
  if (!n || n === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const value = n / Math.pow(1024, i)
  return new Intl.NumberFormat($locale || 'en', { maximumFractionDigits: 1 }).format(value) + ' ' + units[i]
})
