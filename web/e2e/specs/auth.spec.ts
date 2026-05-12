import { test, expect } from '../fixtures/index.js'
import { LoginPage } from '../pages/LoginPage.js'

// Credentials are injected by global-setup.ts
const ADMIN_EMAIL = process.env.DEPENDABLY_E2E_ADMIN_EMAIL ?? 'admin@dependably.local'
const ADMIN_PASSWORD = process.env.DEPENDABLY_E2E_ADMIN_PASSWORD ?? 'E2eTestPassword123!'

test.describe('Authentication', () => {
  test('valid credentials navigate to dashboard', async ({ page }) => {
    const login = new LoginPage(page)
    await login.goto()
    await login.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    // App.svelte: after login, routes to 'packages' and renders <nav class="navbar">
    await login.expectNavVisible()
  })

  test('invalid credentials show error message', async ({ page }) => {
    const login = new LoginPage(page)
    await login.goto()
    await login.login(ADMIN_EMAIL, 'wrongpassword')
    // Login.svelte: <div class="error-msg">{error}</div>
    await login.expectError()
  })

  test('sign out returns to login page', async ({ adminPage }) => {
    // App.svelte: <button on:click={logout}>{$t('nav.signOut')}</button>  => "Sign out"
    // The sign-out button is in .nav-actions, not a .nav-link, so use a broader selector
    await adminPage.locator('nav.navbar .nav-actions button', { hasText: /sign out/i }).click()
    // After logout, navigate('login') is called, showing the login form
    await expect(adminPage.locator('input[type="email"]')).toBeVisible({ timeout: 5_000 })
  })
})
