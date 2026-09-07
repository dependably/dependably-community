import { test as base, expect, Page } from '@playwright/test'

const ADMIN_EMAIL = process.env.DEPENDABLY_E2E_ADMIN_EMAIL ?? 'admin@dependably.local'
const ADMIN_PASSWORD = process.env.DEPENDABLY_E2E_ADMIN_PASSWORD ?? 'E2eTestPassword123!'

/**
 * Signs one page in through the login form.
 *
 * Exported so a spec whose cases all need the same session can log in once in a `beforeAll`
 * and share the page, rather than paying a login per test. Every login counts against the
 * per-IP login rate limiter, and with ~90 cases in the suite that budget is not comfortably
 * large — a spec that adds several cases can tip the whole run into 429s that surface as
 * unrelated tests timing out on `nav.sidebar`.
 */
export async function loginAs(page: Page, email = ADMIN_EMAIL, password = ADMIN_PASSWORD) {
  await page.goto('/')
  // Wait for the login form — the app shows a spinner until initialized
  await page.waitForSelector('input[type="email"]', { timeout: 15_000 })
  await page.fill('input[type="email"]', email)
  await page.fill('input[type="password"]', password)
  await page.click('button[type="submit"]')
  // Wait for the sticky navbar to appear (successful login routes to dashboard)
  await page.waitForSelector('nav.sidebar', { timeout: 10_000 })
}

export const test = base.extend<{
  adminPage: Page
  authedPage: Page
}>({
  adminPage: async ({ page }, use) => {
    await loginAs(page, ADMIN_EMAIL, ADMIN_PASSWORD)
    await use(page)
  },
  authedPage: async ({ page }, use) => {
    await loginAs(page, ADMIN_EMAIL, ADMIN_PASSWORD)
    await use(page)
  },
})

export { expect }
