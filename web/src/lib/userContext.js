/**
 * Seed the session stores from a `/api/v1/auth/me` payload.
 *
 * The effective language and timezone are resolved server-side (user override → tenant
 * default → instance fallback), so the SPA learns a change to either only by re-reading this
 * payload. Anything that can change them — signing in, saving your own profile preference,
 * an admin saving the tenant defaults — funnels through here, or the UI keeps rendering the
 * previous value until the next full page load.
 *
 * Timezone needs no extra step: `formatDate` derives from the `user` store, so setting it is
 * what makes every rendered timestamp follow. Language does, because the dictionary lives in
 * svelte-i18n's own store rather than in `user`.
 */
import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'
import { user } from './store.js'
import { applyLocale } from './locale.js'

/**
 * @param {any} me the parsed /auth/me payload
 */
export async function applyUserContext(me) {
  user.set(me)
  if (me?.language && me.language !== get(locale)) {
    await applyLocale(me.language)
  }
}
