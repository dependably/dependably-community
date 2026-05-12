import { Page, expect } from '@playwright/test'

export class LoginPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/')
    // Wait past the initialization spinner to reach the login form
    await this.page.waitForSelector('input[type="email"]', { timeout: 15_000 })
  }

  async login(email: string, password: string) {
    await this.page.fill('input[type="email"]', email)
    await this.page.fill('input[type="password"]', password)
    // Login.svelte: <button type="submit" class="primary" ...>
    await this.page.click('button[type="submit"]')
  }

  async expectError() {
    // Login.svelte renders errors in <div class="error-msg">
    await expect(this.page.locator('.error-msg').first()).toBeVisible({ timeout: 5_000 })
  }

  async expectNavVisible() {
    // App.svelte: <nav class="navbar"> (sticky, always present when logged in)
    await expect(this.page.locator('nav.navbar')).toBeVisible({ timeout: 10_000 })
  }
}
