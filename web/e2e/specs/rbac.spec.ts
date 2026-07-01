import { test, expect } from '../fixtures/index.js'

// App.svelte RBAC rules (post strict-multi-tenancy refactor):
//   - nav-links "Users" + "Settings": visible when role === 'admin' || role === 'owner'
//   - system_admin lives at the apex SPA (multi mode only) — no Admin link inside the tenant SPA
// admin@dependably.local is seeded by FirstBootService in single mode as the tenant 'owner'.

test.describe('RBAC visibility', () => {
  test('owner sees Users nav link', async ({ adminPage }) => {
    // en.json nav.users = "Users" — shown for admin + owner
    const usersLink = adminPage.locator('nav.sidebar .nav-links button.nav-link', { hasText: 'Users' })
    await expect(usersLink).toBeVisible({ timeout: 5_000 })
  })

  test('owner sees Settings nav link', async ({ adminPage }) => {
    // en.json nav.settings = "Settings" — shown for admin + owner
    const settingsLink = adminPage.locator('nav.sidebar .nav-links button.nav-link', { hasText: 'Settings' })
    await expect(settingsLink).toBeVisible({ timeout: 5_000 })
  })

  test('settings page is accessible to owner', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Settings' }).click()
    await expect(adminPage.locator('main.main-content')).toBeVisible()
    // en.json settings.title = "Settings"
    await expect(adminPage.locator('h1.page-title')).toContainText('Settings')
  })
})
