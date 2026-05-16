import { test, expect, type Page } from '../fixtures/index.js'

// Covers the SAML control-redundancy fix in the OrgSettings Authentication tab:
//  - the SAML toggle is disabled until IdP metadata + a recent successful test exist
//  - the methods toggles commit immediately (no Save click required) and revert on failure
//  - the bottom Save button is scoped to the connection fields only
//
// Backend-free: GET/PUT /auth-config are intercepted with page.route, so the three
// readiness states are simulated without DB seeding.

const baseConfig = {
  enabled: false,
  formsLoginEnabled: true,
  idpEntityId: null as string | null,
  idpSsoUrl: null as string | null,
  idpSigningCertThumbprint: null as string | null,
  lastTestAt: null as string | null,
  lastTestEmail: null as string | null,
  buttonLabel: null as string | null,
  emailAttribute: null as string | null,
  spEntityId: null as string | null,
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  spInfo: {
    acsUrl: 'https://tenant.example.test/saml/acs',
    defaultSpEntityId: 'https://tenant.example.test/saml/metadata',
    metadataUrl: 'https://tenant.example.test/saml/metadata',
  },
}

const idpFields = {
  idpEntityId: 'https://idp.example.test/entity',
  idpSsoUrl: 'https://idp.example.test/sso',
  idpSigningCertThumbprint: 'AA:BB:CC',
}

// Registers a route for GET/PUT /auth-config. GET returns baseConfig + overrides;
// PUT echoes the merged config (or fails with 500 when failPut is set).
//
// Also stubs the four bootstrap GETs OrgSettings.svelte fires from onMount
// (settings, retention, instance/settings, proxy-settings). Without these
// stubs the page's `loading` flag stays true on a contended CI backend until
// all four real responses arrive — and the tab buttons never render. We don't
// exercise those tabs here, so empty payloads are fine.
async function mockAuthConfig(
  page: Page,
  { config = {}, failPut = false }: { config?: Record<string, unknown>; failPut?: boolean } = {},
) {
  const emptyJson = (route: import('@playwright/test').Route) =>
    route.request().method() === 'GET'
      ? route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
      : route.fallback()
  await page.route('**/api/v1/settings', emptyJson)
  await page.route('**/api/v1/retention', emptyJson)
  await page.route('**/api/v1/proxy-settings', emptyJson)
  await page.route('**/api/v1/instance/settings', emptyJson)

  const cfg: Record<string, unknown> = {
    ...baseConfig,
    ...config,
    spInfo: { ...baseConfig.spInfo, ...((config as any).spInfo ?? {}) },
  }
  await page.route('**/api/v1/auth-config', async (route) => {
    const method = route.request().method()
    if (method === 'GET') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(cfg) })
    } else if (method === 'PUT') {
      if (failPut) {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ title: 'Server Error' }),
        })
        return
      }
      Object.assign(cfg, JSON.parse(route.request().postData() ?? '{}'))
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(cfg) })
    } else {
      await route.fallback()
    }
  })
}

function waitForAuthPut(page: Page) {
  return page.waitForRequest(
    (r) => r.url().includes('/api/v1/auth-config') && r.method() === 'PUT',
  )
}

async function openAuthTab(page: Page) {
  await page.goto('/settings')
  // Use the testid (language-agnostic). The hasText form would miss when
  // a sibling test left the admin in French ("Authentification").
  await page.getByTestId('tab-authentication').click()
  await expect(page.locator('h3', { hasText: /sign-in methods/i })).toBeVisible()
}

test.describe('OrgSettings · Authentication tab', () => {
  // Reset the admin's server-stored language to English before each test —
  // i18n.spec.ts switches it to French and never switches back, which would
  // make every text-based assertion in this file fail.
  test.beforeEach(async ({ adminPage }) => {
    await adminPage.evaluate(async () => {
      await fetch('/api/v1/users/me/language', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ language: 'en' }),
      })
    })
  })


  test('SAML toggle is disabled until IdP metadata is uploaded', async ({ adminPage }) => {
    await mockAuthConfig(adminPage)
    await openAuthTab(adminPage)

    await expect(adminPage.getByTestId('saml-toggle')).toBeDisabled()
    await expect(adminPage.locator('.badge', { hasText: /not configured/i })).toBeVisible()
    await expect(
      adminPage.locator('.method .desc', { hasText: /upload idp metadata/i }),
    ).toBeVisible()
  })

  test('SAML toggle stays disabled after metadata upload until a recent test', async ({
    adminPage,
  }) => {
    await mockAuthConfig(adminPage, { config: { ...idpFields, lastTestAt: null } })
    await openAuthTab(adminPage)

    await expect(adminPage.getByTestId('saml-toggle')).toBeDisabled()
    await expect(adminPage.locator('.badge', { hasText: /not yet ready/i })).toBeVisible()
    await expect(
      adminPage.locator('.method .desc', { hasText: /run a successful saml test/i }),
    ).toBeVisible()
  })

  test('once enabled, the toggle stays operable and pill stays green after the test window expires', async ({
    adminPage,
  }) => {
    // Stale lastTestAt (1 hour ago) — well outside the 10-minute recency window. The fix
    // says: an already-enabled config must still be toggleable off, and the pill should
    // continue to reflect the DB state, not the test recency.
    const staleTestAt = new Date(Date.now() - 60 * 60 * 1000).toISOString()
    await mockAuthConfig(adminPage, {
      config: { ...idpFields, enabled: true, lastTestAt: staleTestAt, lastTestEmail: 'tester@example.test' },
    })
    await openAuthTab(adminPage)

    const samlToggle = adminPage.getByTestId('saml-toggle')
    await expect(samlToggle).toBeEnabled()
    await expect(samlToggle).toBeChecked()
    await expect(adminPage.locator('.badge', { hasText: /^enabled$/i })).toBeVisible()

    // And the toggle-off path actually works — PUT fires with enabled=false.
    const putRequest = waitForAuthPut(adminPage)
    await adminPage.locator('label.toggle', { has: samlToggle }).click()
    expect((await putRequest).postDataJSON().enabled).toBe(false)
  })

  test('methods toggle commits immediately — no Save click required', async ({ adminPage }) => {
    await mockAuthConfig(adminPage, {
      config: { ...idpFields, lastTestAt: new Date().toISOString(), lastTestEmail: 'tester@example.test' },
    })
    await openAuthTab(adminPage)

    const samlToggle = adminPage.getByTestId('saml-toggle')
    // The input is visually hidden (opacity:0) behind the styled .track; click
    // the wrapping label, which is what a user actually interacts with.
    const samlToggleLabel = adminPage.locator('label.toggle', { has: samlToggle })
    await expect(samlToggle).toBeEnabled()
    await expect(adminPage.locator('.badge', { hasText: /ready · not enabled/i })).toBeVisible()

    const putRequest = waitForAuthPut(adminPage)
    await samlToggleLabel.click()
    expect((await putRequest).postDataJSON().enabled).toBe(true)

    await expect(samlToggle).toBeChecked()
    await expect(adminPage.locator('.badge', { hasText: /^enabled$/i })).toBeVisible()
  })

  test('Save button persists connection fields only', async ({ adminPage }) => {
    await mockAuthConfig(adminPage, {
      config: { ...idpFields, lastTestAt: new Date().toISOString() },
    })
    await openAuthTab(adminPage)

    // The connection fields live inside the collapsed Advanced disclosure.
    await adminPage.locator('summary', { hasText: /advanced saml settings/i }).click()
    await adminPage.locator('input[placeholder*="Sign in with"]').fill('Sign in with Acme SSO')

    const putRequest = waitForAuthPut(adminPage)
    // Scope to the disclosure's Save (the sticky save bar also carries one).
    await adminPage.locator('.save-row button.primary').click()
    expect((await putRequest).postDataJSON().buttonLabel).toBe('Sign in with Acme SSO')
  })

  test('sticky save bar surfaces on a connection-field edit and clears on save', async ({
    adminPage,
  }) => {
    await mockAuthConfig(adminPage, {
      config: { ...idpFields, lastTestAt: new Date().toISOString() },
    })
    await openAuthTab(adminPage)

    const saveBar = adminPage.locator('.save-bar')
    await expect(saveBar).toBeHidden() // clean on load

    await adminPage.locator('summary', { hasText: /advanced saml settings/i }).click()
    await adminPage.locator('input[placeholder*="Sign in with"]').fill('Sign in with Acme SSO')
    await expect(saveBar).toBeVisible() // dirty → bar appears

    const putRequest = waitForAuthPut(adminPage)
    await saveBar.getByRole('button', { name: /save connection settings/i }).click()
    await putRequest
    await expect(saveBar).toBeHidden() // saved → snapshot refreshed, bar clears
  })

  test('toggle flip refreshes the pristine snapshot — bar clears even with dirty fields', async ({
    adminPage,
  }) => {
    await mockAuthConfig(adminPage, {
      config: { ...idpFields, lastTestAt: new Date().toISOString() },
    })
    await openAuthTab(adminPage)
    await adminPage.locator('summary', { hasText: /advanced saml settings/i }).click()
    await adminPage.locator('input[placeholder*="Sign in with"]').fill('Sign in with Acme SSO')
    await expect(adminPage.locator('.save-bar')).toBeVisible()

    // Flipping the SAML toggle PUTs the dirty fields too; the bar must clear.
    const samlToggle = adminPage.getByTestId('saml-toggle')
    const putRequest = waitForAuthPut(adminPage)
    await adminPage.locator('label.toggle', { has: samlToggle }).click()
    expect((await putRequest).postDataJSON().buttonLabel).toBe('Sign in with Acme SSO')
    await expect(adminPage.locator('.save-bar')).toBeHidden()
  })

  test('SAML toggle reverts on API failure', async ({ adminPage }) => {
    await mockAuthConfig(adminPage, {
      config: { ...idpFields, lastTestAt: new Date().toISOString() },
      failPut: true,
    })
    await openAuthTab(adminPage)

    const samlToggle = adminPage.getByTestId('saml-toggle')
    await adminPage.locator('label.toggle', { has: samlToggle }).click()

    await expect(samlToggle).not.toBeChecked()
    await expect(adminPage.locator('.error-msg')).toContainText(/reverted/i)
  })

  test('Test SAML button launches the round-trip in a popup window, not a new tab', async ({
    adminPage,
  }) => {
    // Pins the popup feature string. Per HTML spec the `popup` window feature is a
    // keyword presence (or numeric 1) — Chromium versions in the wild don't parse
    // `popup=true` reliably and fall back to a new tab, breaking the postMessage
    // handoff to the settings page. The test spies on window.open via a same-page
    // override before clicking; we don't need the popup to actually navigate, only
    // to capture the invocation.
    await mockAuthConfig(adminPage, { config: { ...idpFields } })
    await openAuthTab(adminPage)

    await adminPage.evaluate(() => {
      // @ts-ignore — stash original so the monkey-patch only sees one click.
      window.__originalOpen = window.open
      // @ts-ignore — capture call args on the page so the test can assert them.
      window.__lastOpen = null
      window.open = function (...args: any[]) {
        // @ts-ignore
        window.__lastOpen = { url: args[0], target: args[1], features: args[2] }
        return null  // we don't need a real popup; the page just shows the popup-blocked banner.
      }
    })

    await adminPage.getByTestId('saml-test-button').click()

    const call = await adminPage.evaluate(() => (window as any).__lastOpen)
    expect(call).not.toBeNull()
    expect(call.url).toBe('/saml/login?test=1')
    // Target name carries "popup" so it can't collide with a cached tab slot from a
    // previously-broken click.
    expect(call.target).toBe('dependably-saml-test-popup')
    // Feature string is the spec-canonical minimum: bare `popup` keyword + width/height.
    // left/top intentionally omitted so the browser centres on the primary screen
    // (multi-monitor coordinates can bias popup heuristics toward tab mode).
    expect(call.features).toMatch(/(^|,)popup(=1|=yes|,|$)/)
    expect(call.features).toMatch(/width=\d+/)
    expect(call.features).toMatch(/height=\d+/)
  })
})
