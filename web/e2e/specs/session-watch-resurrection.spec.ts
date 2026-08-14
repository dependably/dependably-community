import { test, expect } from '../fixtures/index.js'
import { NavPage } from '../pages/NavPage.js'
import { LoginPage } from '../pages/LoginPage.js'
import { ADMIN_EMAIL, ADMIN_PASSWORD } from '../helpers/api-client.js'

// web/src/lib/session.js's focus/visibility re-validation (_onResume) reads the module-singleton
// _meFn a second time AFTER awaiting it. If logout lands while that GET /me is still in flight,
// the stale continuation resurrects the watcher once it finally resolves — even into a freshly
// re-armed session, since armSessionWatch unconditionally clears whatever timer is currently
// running. A curl-level check cannot see this: the bug lives entirely in browser-side module
// state, not in any one HTTP response.

test.describe('Session watcher does not resurrect itself across a logout', () => {
  test('a stale focus re-validation in flight during logout does not force out a freshly re-logged-in session', async ({ adminPage: page }) => {
    const nav = new NavPage(page)
    const login = new LoginPage(page)

    // The first GET /me observed from here on is the one the focus dispatch below triggers.
    // It is held in flight (mirroring a slow network) and answers with a short — 8s — expiry,
    // standing in for whatever the pre-logout session's real expiry was. Every later GET /me
    // (the one the re-login below performs) answers immediately with a long, 60s expiry — the
    // fresh session's real one. Without the fix, the stale call's continuation re-arms the
    // watcher with the short expiry once it finally resolves, clobbering the fresh session's
    // 60s timer and forcing an unwanted logout a few seconds after re-login. The margins here
    // are generous (seconds, not milliseconds) so the assertion stays reliable even when the
    // machine running the suite is under heavy concurrent load.
    const t0 = Date.now()
    const staleExpiryIso = new Date(t0 + 8_000).toISOString()
    const freshExpiryIso = new Date(t0 + 60_000).toISOString()
    let meCalls = 0
    await page.route('**/api/v1/auth/me', async (route) => {
      meCalls++
      const isStale = meCalls === 1
      const response = await route.fetch()
      const original = await response.json()
      if (isStale) await new Promise((resolve) => setTimeout(resolve, 1_500))
      await route.fulfill({
        response,
        json: { ...original, sessionExpiresAt: isStale ? staleExpiryIso : freshExpiryIso },
      })
    })

    // Fires session.js's visibilitychange/focus listener, which starts the stale, delayed GET
    // /me above and does not await it here — the app continues running while it is in flight.
    await page.evaluate(() => window.dispatchEvent(new Event('focus')))

    // Log out well before the stale GET /me above resolves (its 1.5s delay hasn't elapsed).
    await nav.signOut()
    await expect(page.locator('input[type="email"]')).toBeVisible({ timeout: 5_000 })

    // Log back in — a real, fresh session with a real 60s expiry (mocked above as the second
    // GET /me response).
    await login.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    await login.expectNavVisible()

    expect(meCalls, 'expected exactly two GET /me calls: the stale focus re-validation and the fresh re-login').toBe(2)

    // Give the stale GET /me (delayed 1.5s from a point before logout) time to resolve, and its
    // resurrected timer — if any — time to fire. A resurrected watcher fires ~8s after the
    // stale call was issued; staying well past that without a forced logout proves it did not.
    await page.waitForTimeout(10_000)

    // The freshly re-logged-in session must still be live — no unexpected bounce to login.
    await expect(page.locator('nav.sidebar')).toBeVisible()
    await expect(page.locator('input[type="email"]')).toHaveCount(0)
  })
})
