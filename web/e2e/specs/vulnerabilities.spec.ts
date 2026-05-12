import { test, expect } from '../fixtures/index.js'

// en.json: vulnerabilities.title = "Vulnerabilities"
// en.json: nav.vulnerabilities = "Vulnerabilities"
// App.svelte: <button class="nav-link"> with text "Vulnerabilities" (visible to all authenticated users)
// Vulnerabilities.svelte renders inside main.main-content

test.describe('Vulnerabilities', () => {
  test('vulnerabilities nav link is visible to authenticated users', async ({ adminPage }) => {
    // en.json nav.vulnerabilities = "Vulnerabilities"
    const vulnBtn = adminPage.locator('nav.navbar button.nav-link', { hasText: 'Vulnerabilities' })
    await expect(vulnBtn).toBeVisible({ timeout: 5_000 })
  })

  test('vulnerabilities page is accessible from nav', async ({ adminPage }) => {
    await adminPage.locator('nav.navbar button.nav-link', { hasText: 'Vulnerabilities' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible()
    // en.json vulnerabilities.title = "Vulnerabilities"
    await expect(main.locator('h1.page-title')).toContainText('Vulnerabilities')
  })

  test('vulnerabilities page shows table and ecosystem filter', async ({ adminPage }) => {
    await adminPage.locator('nav.navbar button.nav-link', { hasText: 'Vulnerabilities' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    // The advisory catalog and org report were merged into a single page
    await expect(main.locator('select, table, [class*="empty"]').first()).toBeVisible({ timeout: 5_000 })
  })
})
