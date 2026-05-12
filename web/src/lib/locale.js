import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'
import { user, bootstrapInfo } from './store.js'
import { api, systemApi } from './api.js'

export const locales = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' }
]

/** Apply a locale client-side: store, cookie, html[lang]. No backend call. */
export function applyLocale(code) {
  locale.set(code)
  // Cookie is what ASP.NET CookieRequestCultureProvider reads, so server-rendered errors
  // and login pages stay in the chosen language.
  const value = encodeURIComponent(`c=${code}|uic=${code}`)
  document.cookie = `.AspNetCore.Culture=${value}; path=/; max-age=31536000; SameSite=Lax`
  localStorage.setItem('locale', code)
  if (typeof document !== 'undefined') document.documentElement.lang = code
}

/**
 * Switch the active UI locale and (when signed in) persist the choice on the server so it
 * follows the user across devices. Apex (system_admin) writes to /system/me/language;
 * tenants to /users/me/language.
 */
export async function switchLocale(code) {
  applyLocale(code)
  const u = get(user)
  if (u) {
    const isApex = get(bootstrapInfo)?.isApex === true
    try { await (isApex ? systemApi : api).updateLanguage(code) } catch { /* non-fatal */ }
  }
}
