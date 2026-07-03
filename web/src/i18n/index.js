import { register, init, getLocaleFromNavigator } from 'svelte-i18n'

function getLocaleFromCookie() {
  const match = document.cookie.match(/\.AspNetCore\.Culture=([^;]+)/)
  if (!match) return null
  try {
    const decoded = decodeURIComponent(match[1])
    const m = decoded.match(/uic=([a-z]{2})/)
    return m ? m[1] : null
  } catch { return null }
}

register('en', () => import('../locales/en.json'))
register('fr', () => import('../locales/fr.json'))

export function setupI18n() {
  const initialLocale = getLocaleFromCookie() ?? getLocaleFromNavigator()?.split('-')[0] ?? 'en'
  // index.html hardcodes lang="en" and applyLocale only runs on an explicit switch, so a
  // returning non-English user would otherwise keep the wrong lang for screen readers.
  if (typeof document !== 'undefined') document.documentElement.lang = initialLocale
  return init({
    fallbackLocale: 'en',
    initialLocale
  })
}
