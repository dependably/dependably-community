import { register, init, getLocaleFromNavigator } from 'svelte-i18n'

function getLocaleFromCookie() {
  const match = document.cookie.match(/\.AspNetCore\.Culture=([^;]+)/)
  if (!match) return null
  try {
    const decoded = decodeURIComponent(match[1])
    // Accept a regional tag, not just the two-letter language: the region is what tells the
    // formatting layer whether this reader wants en-GB or en-US conventions, and a pattern that
    // only matched [a-z]{2} silently discarded it.
    const m = decoded.match(/uic=([A-Za-z]{2}(?:-[A-Za-z0-9]{2,8})*)/)
    return m ? m[1] : null
  } catch { return null }
}

register('en', () => import('../locales/en.json'))
register('fr', () => import('../locales/fr.json'))

export function setupI18n() {
  // The navigator tag is kept whole. svelte-i18n resolves 'en-GB' against the registered 'en'
  // catalogue by subtag fallback, so preserving the region costs no strings and is what lets
  // format.js honour it; splitting it off here threw the reader's region away before anything
  // downstream could see it.
  const initialLocale = getLocaleFromCookie() ?? getLocaleFromNavigator() ?? 'en'
  // index.html hardcodes lang="en" and applyLocale only runs on an explicit switch, so a
  // returning non-English user would otherwise keep the wrong lang for screen readers.
  if (typeof document !== 'undefined') document.documentElement.lang = initialLocale
  return init({
    fallbackLocale: 'en',
    initialLocale
  })
}
