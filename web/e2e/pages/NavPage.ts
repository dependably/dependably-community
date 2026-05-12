import { Page } from '@playwright/test'

// App.svelte nav structure:
//   <nav class="navbar">
//     <div class="nav-links">
//       <button class="nav-link">Packages</button>
//       <button class="nav-link">Activity</button>
//       <button class="nav-link">Tokens</button>
//       <button class="nav-link">Users</button>     (admin/instance_admin only)
//       <button class="nav-link">Settings</button>  (admin/instance_admin only)
//       <button class="nav-link">Vulnerabilities</button>
//       <button class="nav-link">Setup</button>
//     </div>
//     <div class="nav-actions">
//       <button class="nav-link">Profile</button>
//       <button>Sign out</button>
//     </div>
//   </nav>
// Locale + theme controls live on the Profile page, not the navbar.

export class NavPage {
  constructor(private page: Page) {}

  private navLink(text: string) {
    return this.page.locator('nav.navbar button.nav-link', { hasText: text })
  }

  async goToPackages() {
    await this.navLink('Packages').click()
  }

  async goToActivity() {
    await this.navLink('Activity').click()
  }

  async goToTokens() {
    await this.navLink('Tokens').click()
  }

  async goToUsers() {
    await this.navLink('Users').click()
  }

  async goToSettings() {
    await this.navLink('Settings').click()
  }

  async goToVulnerabilities() {
    await this.navLink('Vulnerabilities').click()
  }

  async goToAdmin() {
    await this.navLink('Admin').click()
  }

  async signOut() {
    // App.svelte: <button on:click={logout}>{$t('nav.signOut')}</button>
    // i18n key nav.signOut — default English value is "Sign out"
    await this.page.locator('nav.navbar .nav-actions button', { hasText: /sign out/i }).click()
  }
}
