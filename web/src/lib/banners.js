import { writable } from 'svelte/store'
import { api } from './api.js'

/**
 * Active banners for the current authenticated user. Loaded once after login;
 * cleared on logout. Admin-authored body and link_label render verbatim (no i18n).
 *
 * @type {import('svelte/store').Writable<Array<{id: string, severity: 'info'|'warn'|'alert', body: string, linkUrl: string|null, linkLabel: string|null}>>}
 */
export const activeBanners = writable([])

/**
 * Loads active banners from the server. Call after authentication is confirmed
 * (i.e. after `me = await api.me()` and `user.set(me)`). One-shot — no polling.
 */
export async function loadActiveBanners() {
  try {
    const banners = await api.getActiveBanners()
    activeBanners.set(Array.isArray(banners) ? banners : [])
  } catch {
    // Silently ignore — banners are non-critical UI; a network error should not
    // prevent the rest of the app from loading.
    activeBanners.set([])
  }
}

/**
 * Dismisses a banner: posts to the server then optimistically removes it from
 * the store so the UI updates without waiting for a re-fetch.
 *
 * @param {string} id
 */
export async function dismissBanner(id) {
  activeBanners.update(list => list.filter(b => b.id !== id))
  try {
    await api.dismissBanner(id)
  } catch {
    // Dismissal is best-effort; the banner stays dismissed in local state for the
    // session even if the server call fails.
  }
}
