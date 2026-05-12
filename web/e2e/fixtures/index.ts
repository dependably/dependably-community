import { test as base, expect, Page } from '@playwright/test'

const ADMIN_EMAIL = process.env.DEPENDABLY_E2E_ADMIN_EMAIL ?? 'admin@dependably.local'
const ADMIN_PASSWORD = process.env.DEPENDABLY_E2E_ADMIN_PASSWORD ?? 'E2eTestPassword123!'

async function loginAs(page: Page, email: string, password: string) {
  await page.goto('/')
  // Wait for the login form — the app shows a spinner until initialized
  await page.waitForSelector('input[type="email"]', { timeout: 15_000 })
  await page.fill('input[type="email"]', email)
  await page.fill('input[type="password"]', password)
  await page.click('button[type="submit"]')
  // Wait for the sticky navbar to appear (successful login routes to dashboard)
  await page.waitForSelector('nav.navbar', { timeout: 10_000 })
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
