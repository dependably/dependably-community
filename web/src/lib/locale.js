import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'
import { user, bootstrapInfo } from './store.js'
import { api, systemApi } from './api.js'

export const locales = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' }
]

/**
 * Apply a locale client-side: store, cookie, html[lang]. No backend call.
 *
 * Returns the svelte-i18n load promise. It resolves once the requested dictionary has flushed,
 * and $locale — and therefore every $t — stays on the previous language until it does, so the
 * tree renders correctly for the whole round trip. Callers that must not paint in the outgoing
 * language (the boot path, which realigns to the user's stored preference) await it.
 */
export function applyLocale(code) {
  const applied = locale.set(code)
  // Cookie is what ASP.NET CookieRequestCultureProvider reads, so server-rendered errors
  // and login pages stay in the chosen language.
  const value = encodeURIComponent(`c=${code}|uic=${code}`)
  // Add Secure when served over HTTPS so the cookie can't be downgraded on a hostile network.
  // Local development (file:// or plain http://localhost) skips the flag because the browser
  // would otherwise drop the cookie entirely.
  const secure = typeof location !== 'undefined' && location.protocol === 'https:' ? '; Secure' : ''
  document.cookie = `.AspNetCore.Culture=${value}; path=/; max-age=31536000; SameSite=Lax${secure}`
  localStorage.setItem('locale', code)
  if (typeof document !== 'undefined') document.documentElement.lang = code
  return applied
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
