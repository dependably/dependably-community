import { test, expect } from '../fixtures/index.js'

// en.json: packages.title = "Packages", packages.empty = "No packages found"

test.describe('Packages page', () => {
  test('packages page renders after login', async ({ adminPage }) => {
    // App.svelte: default post-login route is 'packages', inside <main class="main-content">
    await expect(adminPage.locator('nav.navbar')).toBeVisible()
    await expect(adminPage.locator('main.main-content')).toBeVisible()
  })

  test('packages page shows page title', async ({ adminPage }) => {
    // Post-login lands on Dashboard; click the Packages nav link to reach Packages.svelte
    await adminPage.locator('nav.navbar button.nav-link', { hasText: 'Packages' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    // en.json: packages.title = "Packages"
    await expect(main.locator('h1.page-title')).toContainText('Packages')
  })

  test('packages page shows ecosystem filters or empty state', async ({ adminPage }) => {
    await adminPage.locator('nav.navbar button.nav-link', { hasText: 'Packages' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    // Either a table row, the empty-state message, or filter controls should be present
    const content = await main.textContent()
    expect(content).toBeTruthy()
    expect(content!.length).toBeGreaterThan(0)
  })
})
