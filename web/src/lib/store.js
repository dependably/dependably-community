import { writable, derived, get } from 'svelte/store'
import { pathFor, searchFor, routesEqual } from './routes.js'

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

// ── Sidebar ─────────────────────────────────────────────────────────────────────
// Collapsed state persists per-browser (same pattern as theme). '1' = collapsed.
const savedCollapsed = typeof localStorage !== 'undefined' ? localStorage.getItem('sidebarCollapsed') : null
export const sidebarCollapsed = writable(savedCollapsed === '1')
sidebarCollapsed.subscribe(c => {
  if (typeof localStorage === 'undefined') return
  localStorage.setItem('sidebarCollapsed', c ? '1' : '0')
})

// Open-source notices modal (Licenses.svelte). Shared so both the sidebar footer
// and the Profile page trigger the single modal rendered at the App root.
export const noticesOpen = writable(false)

// ── Auth ───────────────────────────────────────────────────────────────────────
/** @type {import('svelte/store').Writable<User | null>} */
export const user = writable(null)

// Set to true when a proactive session-expiry timer fires or a focus/visibility
// re-validation detects an expired session. Consumed by Login and SystemLogin to
// show an "Your session expired" notice. Cleared on successful login or manual navigation away.
export const sessionExpired = writable(false)

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
//
// Entries also carry `scroll`: the vertical offset the user was at when they left that entry.
// history.scrollRestoration is 'manual' (App.svelte, SystemApp.svelte) because the browser's own
// restore runs before the arriving page has fetched its data and clamps the offset against the
// short document. restoreScroll() reapplies the stamped offset a frame later instead, once the
// arriving page has drawn its placeholders at the loaded page's height.
export function navigate(page, params = {}, { replace = false, preserveSearch = false } = {}) {
  const next = { page, params }
  const sameRoute = routesEqual(get(route), next)
  const basePath = pathFor(page, params)
  // Re-navigating to the page already shown replaceStates in place without remounting
  // the component, so the query string (list pages keep table state there) must ride
  // along — otherwise the URL would say "defaults" while the live component keeps its
  // filters. A fresh navigation to a different page gets a clean URL = default state.
  const keepSearch = preserveSearch || (sameRoute && !replace)
  // A fresh navigation to a different page gets a clean URL whose query string is built from
  // the page's params (searchFor) — so a deep link like navigate('vulnerabilities',
  // { sort: 'published' }) lands the list page on that sort, which it reads from the URL.
  const url = (keepSearch && typeof window !== 'undefined')
    ? basePath + window.location.search
    : basePath + searchFor(page, params)

  if (sameRoute) {
    // Landing back on the page already shown abandons any transition in flight — the user asked
    // for where they already are.
    cancelTransition()
    if (typeof window !== 'undefined' && window.history) {
      // Nothing unmounts and the viewport does not move, so the entry's recorded offset stands.
      window.history.replaceState(
        { ...next, idx: window.history.state?.idx ?? 0, scroll: window.history.state?.scroll ?? 0 },
        '', url)
    }
    return
  }

  if (replace) {
    // A redirect, not a user navigation: the initial landing, a guard bounce, a post-logout
    // reset. There is no outgoing page worth holding on screen, so commit synchronously.
    cancelTransition()
    if (typeof window !== 'undefined' && window.history) {
      window.history.replaceState(
        { ...next, idx: window.history.state?.idx ?? 0, scroll: 0 }, '', url)
    }
    route.set(next)
    scrollToTop()
    return
  }

  beginTransition(next, url)
}

// ── Deferred route commit ─────────────────────────────────────────────────────
// A user navigation does not swap the page on click. The incoming page mounts off-screen, runs
// its initial fetch, and only when it reports settled — or the budget below runs out — does
// `route` flip and the swap become visible.
//
// Swapping on click tears the loaded page down before its replacement has anything to show, so a
// fetch that resolves in a hundred milliseconds still paints a full loading state in between two
// complete pages. A shimmer that brief is too short to read as progress and reads as a flicker
// instead. Holding the loaded page until the next one is ready costs the same total wait and
// paints one transition rather than three.

/**
 * The route mounted off-screen while its data is in flight, or null when nothing is in
 * transition. RouteView mounts a second host for it, parked in a detached container; `route`
 * still names the page the user can see.
 * @type {import('svelte/store').Writable<Route | null>}
 */
export const incomingRoute = writable(null)

/**
 * The route the user has asked for — the incoming one while a transition is in flight, otherwise
 * the visible one. Nav highlighting reads this so a clicked link lights up immediately rather
 * than a beat later at commit, which is what makes a held transition read as responsive instead
 * of unresponsive.
 */
export const activeRoute = derived(
  [route, incomingRoute], ([$route, $incoming]) => $incoming ?? $route)

/** True once a transition outlives TRANSITION_GRACE_MS. Drives the top progress bar. */
export const transitionPending = writable(false)

// Past this the incoming page has taken long enough that holding the old one would read as a
// hang. Commit and let the page show its own skeleton — a loading state is the right answer once
// the wait is real.
const TRANSITION_BUDGET_MS = 400
// Below this a progress indicator is itself the flicker: it would appear and vanish within a few
// frames. A fast navigation shows nothing but the nav highlight.
const TRANSITION_GRACE_MS = 150

/**
 * The transition in flight. `claimed` records whether the incoming page declared an initial load
 * (via usePageLoad) — a page that never claims has nothing to wait for and commits on the next
 * frame, so a static page is not held for the full budget.
 *
 * `token` scopes claim/settle to the transition that is actually in flight. Both are reachable
 * from any mounted page, and the visible page keeps running: a background load finishing on the
 * page the user is leaving must not commit the page they are arriving at. A page settles only
 * the transition it was mounted for, and a stale token settles nothing.
 */
let transition = null
let transitionToken = 0

function clearTransitionTimers() {
  if (!transition) return
  if (transition.budgetTimer !== null) clearTimeout(transition.budgetTimer)
  if (transition.graceTimer !== null) clearTimeout(transition.graceTimer)
}

function beginTransition(next, url) {
  // A second click while one is in flight replaces it outright: the first destination is no
  // longer wanted, so its parked host unmounts and its fetch result is ignored.
  clearTransitionTimers()
  transition = {
    next,
    url,
    token: ++transitionToken,
    claimed: false,
    budgetTimer: setTimeout(() => commitTransition(), TRANSITION_BUDGET_MS),
    graceTimer: setTimeout(() => transitionPending.set(true), TRANSITION_GRACE_MS),
  }
  transitionPending.set(false)
  incomingRoute.set(next)
}

/** The token of the transition in flight, or null. Captured by the parked host at mount. */
export function currentTransitionToken() {
  return transition ? transition.token : null
}

/**
 * The query string of the route being mounted ('' when it has none), or null when nothing is in
 * flight and `window.location.search` is authoritative.
 *
 * A held transition mounts the incoming page *before* commitTransition writes the URL, so a list
 * page reading location.search at init would read the page it is replacing — dropping every
 * deep-link param it was navigated with (navigate('risk', { tab: 'license' }) landing on the
 * operational tab). Only the parked page initialises during a transition; the visible one keeps
 * the instance it already has. Consumed by tableState.readQuery.
 */
export function pendingSearch() {
  if (!transition) return null
  const q = transition.url.indexOf('?')
  return q === -1 ? '' : transition.url.slice(q)
}

/**
 * Declares that the incoming page has an initial fetch in flight, so it must not be committed on
 * the auto-commit frame. Reached through usePageLoad, which passes the host's token.
 */
export function claimTransition(token) {
  if (transition && transition.token === token) transition.claimed = true
}

/** The incoming page's initial data has landed (or failed) — make the swap visible. */
export function settleTransition(token) {
  if (transition && transition.token === token) commitTransition()
}

/**
 * Commits a transition whose incoming page never declared a load. Called one frame after the
 * parked host mounts: by then the page's reactive statements have run, so silence means the page
 * has no initial fetch to wait on (a form, a static panel) and holding it would only add latency.
 */
export function settleIfUnclaimed(token) {
  if (transition && transition.token === token && !transition.claimed) commitTransition()
}

/**
 * Flips the held route into view: stamps the outgoing history entry with the offset the user is
 * leaving, pushes the incoming entry, and seats the new page at the top. The URL changes here
 * rather than on click so that it never disagrees with what is on screen, and so Back during a
 * transition returns to a real entry.
 */
export function commitTransition() {
  if (!transition) return
  const { next, url } = transition
  clearTransitionTimers()
  transition = null
  if (typeof window !== 'undefined' && window.history) {
    const currentIdx = window.history.state?.idx ?? 0
    // Stamp the outgoing entry before leaving it — this is what lets Back land where the user
    // was, e.g. returning to a scrolled package list from a version-detail page.
    window.history.replaceState({ ...window.history.state, scroll: window.scrollY ?? 0 }, '')
    window.history.pushState({ ...next, idx: currentIdx + 1, scroll: 0 }, '', url)
  }
  // `route` first: RouteView keys both hosts by route identity, so the frame where the visible
  // route becomes the held one is the frame the held host survives into as the visible host,
  // keeping the data it already fetched. Clearing the incoming route first would briefly leave
  // the outgoing page as the only host and destroy the page that was just made ready.
  route.set(next)
  incomingRoute.set(null)
  transitionPending.set(false)
  scrollToTop()
}

/**
 * Drops a transition without committing it — the destination is no longer wanted. Used by
 * popstate (the user moved history themselves), logout, and a re-navigation to the visible page.
 */
export function cancelTransition() {
  if (!transition) return
  clearTransitionTimers()
  transition = null
  incomingRoute.set(null)
  transitionPending.set(false)
}

/**
 * Seats the viewport at the top of a freshly mounted page. A route change destroys and recreates
 * the page component, so carrying the previous page's offset over would land the user partway
 * down content they have not seen.
 */
export function scrollToTop() {
  if (typeof window === 'undefined' || typeof window.scrollTo !== 'function') return
  window.scrollTo(0, 0)
  // The arriving page mounts after this tick. As the outgoing page is torn down and the new
  // one's placeholders grow the document back, the browser's scroll anchoring re-applies the
  // offset that was just cleared — so a nav-link click from a scrolled page landed partway down
  // the page it opened. Re-assert once the swap has drawn.
  if (typeof window.requestAnimationFrame === 'function') {
    window.requestAnimationFrame(() => {
      if (typeof window.scrollTo === 'function') window.scrollTo(0, 0)
    })
  }
}

// Frames over which a popped entry's offset is re-applied. The arriving page mounts empty and
// grows as its placeholders and then its data land, and a scrollTo against a document that is
// still short is silently clamped — one frame is not enough to catch the final height.
const SCROLL_RESTORE_FRAMES = 10

/**
 * Reapplies a popped history entry's stamped offset, retrying across a few frames until it
 * sticks. Deferred rather than applied synchronously because the arriving page has not drawn
 * when popstate fires, so the browser would clamp the offset against an empty document — which
 * is exactly what history.scrollRestoration = 'auto' did.
 *
 * An entry left via Back/Forward rather than via navigate() carries no stamp, so returning to it
 * lands at the top. The dominant flow — scroll a list, open a detail page, go Back — is stamped.
 */
export function restoreScroll(state) {
  if (typeof window === 'undefined' || typeof window.requestAnimationFrame !== 'function') return
  const top = state?.scroll ?? 0
  if (top === 0) { scrollToTop(); return }
  let frames = 0
  const apply = () => {
    if (typeof window.scrollTo !== 'function') return
    window.scrollTo(0, top)
    // Landed, or the page never grew tall enough to hold the offset — either way, stop.
    if (Math.abs((window.scrollY ?? 0) - top) < 1 || ++frames >= SCROLL_RESTORE_FRAMES) return
    window.requestAnimationFrame(apply)
  }
  window.requestAnimationFrame(apply)
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
