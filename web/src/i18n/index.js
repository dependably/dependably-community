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
  return init({
    fallbackLocale: 'en',
    initialLocale: getLocaleFromCookie() ?? getLocaleFromNavigator()?.split('-')[0] ?? 'en'
  })
}
