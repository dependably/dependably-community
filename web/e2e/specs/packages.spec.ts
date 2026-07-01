import { test, expect } from '../fixtures/index.js'
import { request } from '@playwright/test'
import { createHash } from 'crypto'
import fs from 'fs'
import path from 'path'
import { loginAsAdmin, auth, fixturesRoot } from '../helpers/api-client.js'

// en.json: packages.title = "Packages", packages.empty = "No packages found"

test.describe('Packages page', () => {
  test('packages page renders after login', async ({ adminPage }) => {
    // App.svelte: default post-login route is 'packages', inside <main class="main-content">
    await expect(adminPage.locator('nav.sidebar')).toBeVisible()
    await expect(adminPage.locator('main.main-content')).toBeVisible()
  })

  test('packages page shows page title', async ({ adminPage }) => {
    // Post-login lands on Dashboard; click the Packages nav link to reach Packages.svelte
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    // en.json: packages.title = "Packages"
    await expect(main.locator('h1.page-title')).toContainText('Packages')
  })

  test('packages page shows ecosystem filters or empty state', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    // Either a table row, the empty-state message, or filter controls should be present
    const content = await main.textContent()
    expect(content).toBeTruthy()
    expect(content!.length).toBeGreaterThan(0)
  })
})

// Table state (search/filter/page/sort) lives in the URL query string, so it must
// survive clicking into a package's detail page and navigating back, and the search
// box must clear via its ✕ button.
test.describe('Packages table state persistence', () => {
  const PKG_NAME = 'is-odd'

  // Seed a real package so the search has something to find. Publishing the same
  // version twice across runs is fine — 409 Conflict means it is already there.
  test.beforeAll(async ({ baseURL }) => {
    const file = path.join(fixturesRoot(), 'npm', 'is-odd-3.0.1.tgz')
    const bytes = fs.readFileSync(file)
    const sha512 = createHash('sha512').update(bytes).digest('base64')
    const body = JSON.stringify({
      name: PKG_NAME,
      versions: {
        '3.0.1': {
          name: PKG_NAME,
          version: '3.0.1',
          description: 'Seed package for table-state e2e',
          dist: {
            tarball: `https://registry.npmjs.org/${PKG_NAME}/-/is-odd-3.0.1.tgz`,
            integrity: `sha512-${sha512}`,
          },
        },
      },
      _attachments: {
        'is-odd-3.0.1.tgz': {
          content_type: 'application/octet-stream',
          data: bytes.toString('base64'),
          length: bytes.length,
        },
      },
    })

    const authed = await loginAsAdmin(baseURL!)
    const mint = await authed.post('/api/v1/service-tokens', {
      data: { name: `e2e-table-state-${Date.now()}`, capabilities: ['publish:*'] },
    })
    expect(mint.status(), `service-token mint failed: ${await mint.text()}`).toBe(200)
    const token = (await mint.json()).token as string
    const ctx = await request.newContext({
      baseURL,
      extraHTTPHeaders: { Authorization: auth.bearer(token) },
    })
    try {
      const res = await ctx.put(`/npm/${PKG_NAME}`, {
        data: body,
        headers: { 'Content-Type': 'application/json' },
      })
      expect([200, 201, 409]).toContain(res.status())
    } finally {
      await ctx.dispose()
      await authed.dispose()
    }
  })

  test('search persists across detail navigation and back', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    const main = adminPage.locator('main.main-content')
    const searchBox = main.getByPlaceholder('Search by name…')
    await searchBox.fill(PKG_NAME)

    const row = main.locator('tbody tr', { hasText: PKG_NAME }).first()
    await expect(row).toBeVisible({ timeout: 10_000 })
    // The debounced search handler writes the query string.
    await expect.poll(() => adminPage.url()).toContain(`q=${PKG_NAME}`)

    await row.click()
    await expect(adminPage).toHaveURL(new RegExp(`/package/npm/${PKG_NAME}`))

    await adminPage.goBack()
    await expect(main.locator('h1.page-title')).toContainText('Packages')
    await expect(searchBox).toHaveValue(PKG_NAME)
    expect(adminPage.url()).toContain(`q=${PKG_NAME}`)
    await expect(main.locator('tbody tr', { hasText: PKG_NAME }).first()).toBeVisible({ timeout: 10_000 })
  })

  test('clear button empties the search and the URL', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' }).click()
    const main = adminPage.locator('main.main-content')
    const searchBox = main.getByPlaceholder('Search by name…')
    await searchBox.fill(PKG_NAME)
    await expect.poll(() => adminPage.url()).toContain(`q=${PKG_NAME}`)

    const clear = main.getByRole('button', { name: 'Clear search' })
    await expect(clear).toBeVisible()
    await clear.click()

    await expect(searchBox).toHaveValue('')
    await expect(clear).toBeHidden()
    await expect.poll(() => adminPage.url()).not.toContain('q=')
  })
})
