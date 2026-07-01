/**
 * Proactive session-expiry watcher.
 *
 * A single timer fires when the current session JWT expires. A visibility/focus
 * listener re-validates on tab resume so laptop sleep (which stalls timers) and
 * early server-side invalidation (password change bumping token_version) are both
 * caught promptly.
 *
 * Integrators:
 *   - Call armSessionWatch(expiresAtIso, meFn) after every successful me() response.
 *   - Call disarmSessionWatch() on logout.
 */

import { get } from 'svelte/store'
import { user, route, pendingRoute, navigate, sessionExpired } from './store.js'

/** @type {ReturnType<typeof setTimeout> | null} */
let _timer = null
/** @type {(() => Promise<any>) | null} */
let _meFn = null
/** @type {number | null} */
let _expiresAt = null

/**
 * Re-arm the watcher with a new expiry instant. Called after every successful
 * me() fetch (boot, login, focus re-validation). Clears any prior timer.
 *
 * @param {string | null | undefined} expiresAtIso  ISO-8601 string from me().sessionExpiresAt.
 * @param {() => Promise<any>} meFn                 api.me or systemApi.me for re-validation.
 */
export function armSessionWatch(expiresAtIso, meFn) {
  _disarmTimer()
  if (!expiresAtIso) return

  const expiresMs = Date.parse(expiresAtIso)
  if (isNaN(expiresMs)) return

  _meFn = meFn
  _expiresAt = expiresMs

  // Skew 1 s past the server-reported expiry to guard against sub-second clock
  // drift between the browser and server. The JWT is verified server-side anyway,
  // so a 1-second overlap never grants extra access.
  const delayMs = Math.max(0, expiresMs - Date.now() + 1000)

  _timer = setTimeout(_handleExpiry, delayMs)

  if (!_listenersAttached) {
    _attachListeners()
  }
}

/**
 * Disarm the watcher — clears the timer and removes listeners. Call on logout
 * so the watcher does not fire after the user has already signed out.
 */
export function disarmSessionWatch() {
  _disarmTimer()
  _meFn = null
  _expiresAt = null
  _detachListeners()
}

// ── Internal ──────────────────────────────────────────────────────────────────

function _disarmTimer() {
  if (_timer !== null) {
    clearTimeout(_timer)
    _timer = null
  }
}

function _handleExpiry() {
  _timer = null
  _disarmTimer()
  _detachListeners()
  _meFn = null
  _expiresAt = null

  const current = get(route)
  user.set(null)
  sessionExpired.set(true)

  if (current.page !== 'login' && current.page !== 'system-login' && current.page !== 'join') {
    pendingRoute.set(current)
  }

  const isSystem = current.page.startsWith('system-')
  navigate(isSystem ? 'system-login' : 'login', {}, { replace: true })
}

/** Handles tab becoming visible or window receiving focus. */
async function _onResume() {
  if (_expiresAt === null) return

  if (Date.now() >= _expiresAt) {
    _handleExpiry()
    return
  }

  // Re-validate with the server. A 401 flows through req() in api.js which
  // already calls the global redirect. A successful response re-arms with a
  // fresh expiry (the same JWT, so the same exp — but re-arms the local timer).
  if (_meFn) {
    try {
      const me = await _meFn()
      if (me?.sessionExpiresAt) {
        armSessionWatch(me.sessionExpiresAt, _meFn)
      }
    } catch {
      // A 401 from _meFn is handled inside req() (global redirect). Other errors
      // (network down, etc.) leave the user on the current page; the timer will
      // still fire at the original expiry.
    }
  }
}

let _listenersAttached = false

function _attachListeners() {
  if (typeof document === 'undefined' || typeof window === 'undefined') return
  document.addEventListener('visibilitychange', _onVisibilityChange)
  window.addEventListener('focus', _onWindowFocus)
  _listenersAttached = true
}

function _detachListeners() {
  if (typeof document === 'undefined' || typeof window === 'undefined') return
  document.removeEventListener('visibilitychange', _onVisibilityChange)
  window.removeEventListener('focus', _onWindowFocus)
  _listenersAttached = false
}

function _onVisibilityChange() {
  if (document.visibilityState === 'visible') {
    _onResume()
  }
}

function _onWindowFocus() {
  _onResume()
}
