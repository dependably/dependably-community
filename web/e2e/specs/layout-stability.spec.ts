import { test, expect } from '../fixtures/index.js'

// Switching pages must not move anything already on screen, and must not paint a loading state
// for a load that was never slow. A navigation holds the visible page while the incoming one
// mounts off-screen and fetches, committing when that page reports its data has landed or when the
// transition budget runs out; past the budget the arriving page draws its real chrome — page
// header, toolbar, table head, pagination — at the loaded page's height, and html carries
// scrollbar-gutter: stable. Either path should register essentially no layout shift.
//
// The suite's other specs only assert that a spinner *clears*, which these pages no longer render
// at all — that assertion now passes vacuously. This is the spec that actually holds the line.
//
// Known coverage limit, verified by running this file against the pre-fix build: on a registry
// with no packages the four CLS cases pass either way, because a page with nothing in it has
// nothing to collapse. They bite on an instance with data. The reserve, hold, and scroll cases
// below do fail without the fix on an empty instance, so those are the ones gating CI today;
// seeding packages in the e2e fixture would put real teeth on the CLS four.
//
// PerformanceObserver's 'layout-shift' entry type is Chromium-only; the api project has no
// browser and the optional firefox/webkit projects do not implement it.
test.describe('layout stability across navigation', () => {
  // A capability gate, not a disabled test: chromium is the default project, so this runs on
  // skip-ok: every pipeline, and only opts out of the optional firefox/webkit projects.
  test.skip(({ browserName }) => browserName !== 'chromium', 'layout-shift entries are Chromium-only')

  // Deliberately spans a full-bleed list page, the centered dashboard well, and a form page:
  // the three page widths in app.css, which is where a width-driven shift would show up.
  const ROUTES = ['Packages', 'Vulnerabilities', 'Risk', 'Settings'] as const

  async function armShiftObserver(page: import('@playwright/test').Page) {
    await page.evaluate(() => {
      const w = window as unknown as { __cls: number, __obs?: PerformanceObserver }
      w.__cls = 0
      w.__obs?.disconnect()
      w.__obs = new PerformanceObserver((list) => {
        for (const entry of list.getEntries() as (PerformanceEntry & { value: number, hadRecentInput: boolean })[]) {
          // hadRecentInput excludes shifts the user caused themselves (the nav click).
          if (!entry.hadRecentInput) w.__cls += entry.value
        }
      })
      w.__obs.observe({ type: 'layout-shift', buffered: false })
    })
  }

  const readCls = (page: import('@playwright/test').Page) =>
    page.evaluate(() => (window as unknown as { __cls: number }).__cls)

  for (const link of ROUTES) {
    test(`navigating to ${link} shifts nothing already on screen`, async ({ adminPage }) => {
      // Start from a loaded list page so the outgoing page is tall — the case that used to
      // collapse to a handful of placeholder rows and drag the layout up with it.
      await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
      await expect(adminPage.locator('main.main-content h1')).toBeVisible({ timeout: 10_000 })
      await adminPage.waitForLoadState('networkidle')

      await armShiftObserver(adminPage)
      await adminPage.locator('nav.sidebar button.nav-link', { hasText: link }).click()
      await expect(adminPage.locator('main.main-content h1')).toBeVisible({ timeout: 10_000 })
      // Let the fetch resolve and any shift it causes land before sampling.
      await adminPage.waitForLoadState('networkidle')
      await adminPage.waitForTimeout(1_000)

      // Not 0: font swap and a first-load pagination footer can contribute a hair. It is far
      // below the 0.1 "good CLS" threshold, and well below what a collapsing page body scores.
      expect(await readCls(adminPage)).toBeLessThan(0.02)
    })
  }

  test('the chrome stays mounted across a navigation', async ({ adminPage }) => {
    // The sidebar and topbar are siblings of <main>, so a route change must not touch them.
    // Losing them for a frame is what the root i18n gate used to do on a locale switch.
    const sidebar = adminPage.locator('nav.sidebar')
    await expect(sidebar).toBeVisible()
    const before = await sidebar.boundingBox()

    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    await expect(adminPage.locator('main.main-content h1')).toBeVisible({ timeout: 10_000 })
    await expect(adminPage.locator('.app-loading')).toHaveCount(0)

    expect(await sidebar.boundingBox()).toEqual(before)
  })

  test('a list page reserves its loaded height while the rows are in flight', async ({ adminPage }) => {
    // Hold the packages response open so the placeholder state can be measured, then compare the
    // document height before and after the rows land. Equal heights are the whole fix: the page
    // no longer shrinks to a few rows and then grows back.
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    await expect(adminPage.locator('main.main-content table tbody tr').first()).toBeVisible({ timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')
    const loadedHeight = await adminPage.evaluate(() => document.documentElement.scrollHeight)

    // Delay the response rather than gating it on the test body: a handler still awaiting when
    // the test unroutes throws "Route is already handled".
    await adminPage.route('**/api/v1/packages?**', async (route) => {
      await new Promise((r) => setTimeout(r, 3_000))
      await route.continue()
    })

    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Vulnerabilities' }).click()
    await expect(adminPage.locator('main.main-content h1')).toBeVisible({ timeout: 10_000 })
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()

    // Placeholder rows are up, data is not.
    await expect(adminPage.locator('main.main-content tr.skeleton-row').first()).toBeVisible({ timeout: 10_000 })
    const reserved = await adminPage.evaluate(() => ({
      height: document.documentElement.scrollHeight,
      viewport: window.innerHeight,
    }))
    // The page header and column headers are drawn before the rows arrive, not after them.
    await expect(adminPage.locator('main.main-content h1')).toBeVisible()
    await expect(adminPage.locator('main.main-content table thead')).toBeVisible()

    // Let the held response land before removing the handler.
    await expect(adminPage.locator('main.main-content tr.skeleton-row')).toHaveCount(0, { timeout: 10_000 })
    await adminPage.unroute('**/api/v1/packages?**')

    // The loading page must cover everything the loaded page put on screen. Asserting against
    // the viewport rather than the loaded height on purpose: the reserve is capped at a
    // viewport's worth, so a long list legitimately grows below the fold — that growth moves
    // nothing the reader can see. What must never happen is the body collapsing, which is what
    // a handful of placeholder rows under a fifty-row page used to do.
    expect(reserved.height).toBeGreaterThanOrEqual(Math.min(loadedHeight, reserved.viewport) - 4)
  })

  test('a fast navigation never paints a loading state', async ({ adminPage }) => {
    // The flicker this transition exists to prevent: a loading state painted between two
    // complete pages for a fetch that resolves in a hundred milliseconds. A placeholder
    // appearing at all on a fetch this fast is the regression.
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    await expect(adminPage).toHaveURL(/\/packages/, { timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')

    // Serve the arriving page's data from a captured copy so the fetch is instant regardless of
    // what else is hitting the server. Without this the assertion measures machine load: a real
    // request that happens to outrun the transition budget commits to a placeholder legitimately,
    // and the suite runs alongside the api project pushing artefacts at the same instance.
    const captured = new Map<string, { status: number, contentType: string, body: string }>()
    adminPage.on('response', async (res) => {
      const url = res.url()
      if (!url.includes('/api/v1/') || captured.has(url) || !res.ok()) return
      try {
        captured.set(url, {
          status: res.status(),
          contentType: res.headers()['content-type'] ?? 'application/json',
          body: await res.text(),
        })
      } catch { /* body already consumed or navigation raced it — fall through to the live call */ }
    })
    // One warm visit populates the cache, then return to the page under test's starting point.
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Vulnerabilities' }).click()
    await expect(adminPage).toHaveURL(/\/vulnerabilities/, { timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    await expect(adminPage).toHaveURL(/\/packages/, { timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')

    await adminPage.route('**/api/v1/**', async (route) => {
      const hit = captured.get(route.request().url())
      if (hit) await route.fulfill({ status: hit.status, contentType: hit.contentType, body: hit.body })
      else await route.continue()
    })

    await adminPage.evaluate(() => {
      const w = window as unknown as { __sawSkeleton: boolean, __sampling: boolean }
      // Scoped to <main>: the held page draws its own placeholders while it loads, but it is
      // parked in a detached container, so those were never on screen and do not count.
      const visiblePlaceholder = () =>
        document.querySelector('main.main-content .skeleton-row, main.main-content .skeleton') !== null
      // Sampled once per frame rather than watched via MutationObserver: the commit moves the
      // held page into <main> and its rows replace its placeholders within the same flush, so a
      // mutation-level watcher reports a placeholder that no frame ever painted. What matters is
      // whether one survived to a paint.
      w.__sawSkeleton = visiblePlaceholder()
      w.__sampling = true
      const sample = () => {
        if (!w.__sampling) return
        if (visiblePlaceholder()) w.__sawSkeleton = true
        requestAnimationFrame(sample)
      }
      requestAnimationFrame(sample)
    })

    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Vulnerabilities' }).click()
    await expect(adminPage).toHaveURL(/\/vulnerabilities/, { timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')
    await adminPage.waitForTimeout(500)

    const sawSkeleton = await adminPage.evaluate(() => {
      const w = window as unknown as { __sawSkeleton: boolean, __sampling: boolean }
      w.__sampling = false
      return w.__sawSkeleton
    })
    await adminPage.unroute('**/api/v1/**')
    expect(
      sawSkeleton,
      'a served-from-cache fetch resolves well inside the transition budget, so no placeholder should ever be painted',
    ).toBe(false)
  })

  test('the outgoing page stays on screen while the next one loads', async ({ adminPage }) => {
    // Holding the loaded page is what removes the blank-then-shimmer beat. The click still has to
    // register instantly, which is the sidebar highlight's job, not the page swap's.
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Vulnerabilities' }).click()
    await expect(adminPage).toHaveURL(/\/vulnerabilities/, { timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')
    const outgoingHeading = await adminPage.locator('main.main-content h1').textContent()

    await adminPage.route('**/api/v1/packages?**', async (route) => {
      await new Promise((r) => setTimeout(r, 3_000))
      await route.continue()
    })

    // Recorded per frame inside the page rather than asserted from here after the click: a
    // round-trip from the test runner can easily outlast the transition budget on a loaded
    // machine, and would then be measuring the harness rather than the hold. The click is issued
    // in the same evaluate as the arming, so the first sampled frame is already a post-click one
    // — no frame from before the navigation can leak into the assertions below.
    await adminPage.evaluate(() => {
      const w = window as unknown as { __frames: string[], __sampling: boolean }
      w.__frames = []
      w.__sampling = true
      const sample = () => {
        if (!w.__sampling) return
        const heading = document.querySelector('main.main-content h1')?.textContent ?? ''
        const lit = [...document.querySelectorAll('nav.sidebar button.nav-link.active')]
          .map((b) => b.textContent?.trim()).join(',')
        w.__frames.push(`${location.pathname}|${heading}|${lit}`)
        requestAnimationFrame(sample)
      }
      requestAnimationFrame(sample)
      const link = [...document.querySelectorAll('nav.sidebar button.nav-link')]
        .find((b) => b.textContent?.trim() === 'Packages')
      ;(link as HTMLButtonElement).click()
    })
    await expect(adminPage).toHaveURL(/\/packages/, { timeout: 10_000 })

    const frames = await adminPage.evaluate(() => {
      const w = window as unknown as { __frames: string[], __sampling: boolean }
      w.__sampling = false
      return w.__frames
    })
    // Frames where the swap had not happened yet: the outgoing page is still the one on screen,
    // and its URL is still the one in the address bar, so neither ever disagrees with the other.
    const held = frames.filter((f) => f.startsWith('/vulnerabilities|'))
    expect(held.length, 'the outgoing page should stay on screen while the next one loads').toBeGreaterThan(0)
    expect(held.every((f) => f.includes(`|${outgoingHeading}|`))).toBe(true)
    // And through every one of them the destination is already lit, so the click reads as
    // registered even though nothing has swapped.
    expect(held.every((f) => f.endsWith('|Packages'))).toBe(true)

    // Past the budget the hold gives way rather than stranding the user on the page they left,
    // and the arriving page then shows its own placeholders — a loading state is the right answer
    // once the wait is real.
    await expect(adminPage.locator('main.main-content tr.skeleton-row').first()).toBeVisible({ timeout: 10_000 })
    await expect(adminPage.locator('main.main-content tr.skeleton-row')).toHaveCount(0, { timeout: 10_000 })
    await adminPage.unroute('**/api/v1/packages?**')
  })

  test('back returns to where the page was left', async ({ adminPage }) => {
    // navigate() stamps the outgoing scroll offset on its history entry and restoreScroll()
    // re-applies it over the frames the arriving page takes to grow. scrollRestoration is
    // 'manual' precisely because the browser's own restore runs too early against a page that
    // has not fetched yet, and the clamped offset is then lost.
    //
    // Setup rather than a list page: its content is static instructions, so this scrolls on a
    // brand-new registry too. A data-dependent page would quietly skip on an empty instance —
    // which is exactly what CI runs against.
    await adminPage.setViewportSize({ width: 1000, height: 400 })
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Setup' }).click()
    // Wait for the URL, not the heading: the heading assertion would pass against the outgoing
    // page, which is still on screen while the navigation is held. The URL changes at the commit,
    // and the commit is what seats the arriving page at the top — scrolling before it lands would
    // be scrolling a page the user is about to leave.
    await expect(adminPage).toHaveURL(/\/setup/, { timeout: 10_000 })
    await adminPage.waitForLoadState('networkidle')

    await adminPage.evaluate(() => window.scrollTo(0, 250))
    // Read the offset back rather than asserting the requested one: the page is still settling,
    // and what matters is the offset the user is actually left at.
    await adminPage.waitForTimeout(300)
    const leftAt = await adminPage.evaluate(() => window.scrollY)
    expect(leftAt, 'the page must be scrollable for this assertion to mean anything').toBeGreaterThan(80)

    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    await expect(adminPage).toHaveURL(/\/packages/, { timeout: 10_000 })
    // A freshly mounted page starts at the top rather than inheriting the previous offset.
    await expect.poll(
      () => adminPage.evaluate(() => window.scrollY),
      { timeout: 3_000, message: 'a new page should be seated at the top' },
    ).toBe(0)

    await adminPage.goBack()
    await expect(adminPage).toHaveURL(/\/setup/, { timeout: 10_000 })
    await expect.poll(
      () => adminPage.evaluate(() => window.scrollY),
      { timeout: 5_000, message: 'back should restore the offset the page was left at' },
    ).toBeGreaterThan(leftAt - 40)
  })
})
