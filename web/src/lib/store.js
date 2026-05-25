import { writable, derived, get } from 'svelte/store'
import { pathFor, routesEqual } from './routes.js'

/**
 * @typedef {{ userId?: string, role?: string, email?: string,
 *             language?: string, tenantDefaultLanguage?: string,
 *             mustChangePassword?: boolean } & Record<string, any>} User
 *
 * @typedef {{ page: string, params: Record<string, any> }} Route
 *
 * @typedef {{ mode?: 'single' | 'multi', isApex?: boolean, apexHost?: string,
 *             tenantSlug?: string, airGapped?: boolean, insecureHttp?: boolean,
 *             capabilities?: Record<string, any> } & Record<string, any>} BootstrapInfo
 */

// ── Theme ──────────────────────────────────────────────────────────────────────
const savedTheme = typeof localStorage !== 'undefined' ? localStorage.getItem('theme') : null
export const theme = writable(savedTheme || 'light')
theme.subscribe(t => {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-theme', t)
  localStorage.setItem('theme', t)
})

// ── Auth ───────────────────────────────────────────────────────────────────────
/** @type {import('svelte/store').Writable<User | null>} */
export const user = writable(null)

// ── Navigation ─────────────────────────────────────────────────────────────────
// route: { page, params }
// pages: 'login' | 'packages' | 'version-detail' | 'activity' | 'audit' |
//        'tokens' | 'settings' | 'allowlist' | 'users' |
//        'setup' | 'join'
/** @type {import('svelte/store').Writable<Route>} */
export const route = writable({ page: 'login', params: {} })

// Return-URL after authentication. Set when an unauthenticated user lands on (or is bounced
// from) a protected route; consumed by Login/SystemLogin (or Profile/SystemProfile after a
// forced password rotation) to navigate the user back to their intended destination.
// In-memory only — does not survive a page reload, which is fine: a reload re-runs the init
// flow and resolves the URL fresh.
/** @type {import('svelte/store').Writable<Route | null>} */
export const pendingRoute = writable(null)

export function takePendingRoute() {
  const v = get(pendingRoute)
  pendingRoute.set(null)
  return v
}

// Each pushed history entry carries an `idx` field — 0 for the initial seated entry,
// incrementing for each subsequent push. The in-app Back button on VersionDetail reads
// history.state?.idx to decide whether history.back() is safe (won't leave the SPA).
// This is more reliable than maintaining a counter store, because popstate fires on both
// Back and Forward and a counter can't tell the direction.
export function navigate(page, params = {}, { replace = false, preserveSearch = false } = {}) {
  const next = { page, params }
  const sameRoute = routesEqual(get(route), next)
  const basePath = pathFor(page, params)
  const url = (preserveSearch && typeof window !== 'undefined')
    ? basePath + window.location.search
    : basePath
  if (typeof window !== 'undefined' && window.history) {
    const currentIdx = window.history.state?.idx ?? 0
    if (replace || sameRoute) {
      window.history.replaceState({ ...next, idx: currentIdx }, '', url)
    } else {
      window.history.pushState({ ...next, idx: currentIdx + 1 }, '', url)
    }
  }
  if (!sameRoute) route.set(next)
}

// ── Bootstrap info (populated once on App.svelte mount) ────────────────────────
// Shape: { mode: 'single' | 'multi', isApex: boolean, apexHost?: string, tenantSlug?: string, capabilities: object }
// Single mode: includes tenantSlug. Multi at apex: isApex=true. Multi at tenant subdomain:
// isApex=false, tenantSlug omitted (the SPA infers identity from window.location.hostname).
/** @type {import('svelte/store').Writable<BootstrapInfo | null>} */
export const bootstrapInfo = writable(null)

// ── Current tenant (derived) ──────────────────────────────────────────────────
// Each session is bound to exactly one tenant — no switcher. In single mode the slug comes
// from the bootstrap response; in multi-mode tenant subdomain the slug comes from the host.
export const currentOrg = derived(bootstrapInfo, $info => {
  if (!$info) return null
  if ($info.mode === 'single') return { slug: $info.tenantSlug }
  if ($info.mode === 'multi' && !$info.isApex) {
    const host = typeof window !== 'undefined' ? window.location.hostname : ''
    const apex = $info.apexHost || ''
    const slug = apex && host.endsWith('.' + apex) ? host.slice(0, -apex.length - 1) : null
    return slug ? { slug } : null
  }
  return null
})
