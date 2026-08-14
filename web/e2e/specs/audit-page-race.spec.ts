import { test, expect } from '../fixtures/index.js'
import { NavPage } from '../pages/NavPage.js'

// Audit.svelte's Lifecycle tab fires a fresh GET /api/v1/activity on every page/filter/search
// change without cancelling the previous in-flight request. If the responses land out of order
// (an earlier filter change resolving after a later one that was fired shortly after it), the
// stale response must not be allowed to overwrite the table with data the user already
// navigated away from. This intercepts the network layer to force exactly that ordering
// deterministically, rather than relying on real backend timing.
//
// The page's own deferred-navigation mechanism (reportPageLoad/pageToken — see Audit.svelte's
// comments) holds the route swap into this page until its very first load resolves, so the race
// has to be staged AFTER that first, real load completes: the interception below only starts
// once the page has already mounted, and the race is between two filter-triggered reloads.

test.describe('Audit page — out-of-order async responses do not overwrite fresher state', () => {
  test('an earlier filter reload does not clobber a later one that resolves first', async ({ adminPage: page }) => {
    const nav = new NavPage(page)
    await nav.goToAudit()

    // The first GET /activity observed after this point (the reload triggered by selecting
    // "push" below) is held for 700ms and answers with a row tagged "stale". Every later
    // request (the reload triggered by immediately selecting "delete" after it) answers
    // immediately with a row tagged "fresh". Without a request-sequence guard, the slow
    // "stale" response — landing after "fresh" has already rendered — silently overwrites
    // the table.
    let seen = 0
    await page.route('**/api/v1/activity?*', async (route) => {
      seen++
      const isFirst = seen === 1
      const body = {
        items: [{
          createdAt: new Date().toISOString(),
          eventType: isFirst ? 'push' : 'delete',
          purl: isFirst ? 'pkg:npm/race-marker-stale' : 'pkg:npm/race-marker-fresh',
          detail: null,
          sourceIp: null,
          actorEmail: 'admin@dependably.local',
        }],
        total: 1,
        totalCapped: false,
      }
      if (isFirst) await new Promise((resolve) => setTimeout(resolve, 700))
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
    })

    const filterSelect = page.locator('select.event-select').first()
    // lcOnFilterChange fires loadLifecycle() on every change without awaiting the previous
    // call, so these two dispatch overlapping requests: the first is the slow one above, the
    // second — fired immediately after, while the first is still in flight — is the fast one.
    await filterSelect.selectOption('push')
    await filterSelect.selectOption('delete')

    // Give both the fast and the slow response time to land.
    await page.waitForTimeout(1000)
    expect(seen, 'expected exactly two /activity requests: one per filter change').toBe(2)

    await expect(page.locator('.purl-cell', { hasText: 'race-marker-fresh' })).toBeVisible()
    await expect(page.locator('.purl-cell', { hasText: 'race-marker-stale' })).toHaveCount(0)
  })
})
