import { test, expect } from '../fixtures/index.js'

// en.json: tokens.title = "Access Tokens", tokens.newToken = "New token"
// Tokens.svelte: <div class="page"> with <div class="page-header"><h1 class="page-title">
// Modal: <div class="modal-backdrop"><div class="modal">
// Scope select: <select bind:value={newScope}> with options "pull" / "push"
// Create button in modal: <button class="primary" on:click={create}>Create</button>

test.describe('Tokens', () => {
  test('tokens page is accessible from nav', async ({ adminPage }) => {
    // App.svelte nav-links: <button class="nav-link"> with text from en.json nav.tokens = "Tokens"
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Tokens' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible()
    // Tokens.svelte page-title
    await expect(main.locator('h1.page-title')).toContainText('Access Tokens')
  })

  test('can open create token modal', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Tokens' }).click()
    // Tokens.svelte: <button class="primary" on:click={() => showCreate = true}>{$t('tokens.newToken')}</button>
    // en.json tokens.newToken = "New token"
    await adminPage.locator('.page-header button.primary', { hasText: 'New token' }).click()
    // Modal appears: <div class="modal-backdrop"><div class="modal"><h3>New Access Token</h3>
    await expect(adminPage.locator('.modal-backdrop .modal')).toBeVisible({ timeout: 5_000 })
    await expect(adminPage.locator('.modal h3')).toContainText('New Access Token')
  })

  test('can create a personal access token', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Tokens' }).click()
    await adminPage.locator('.page-header button.primary', { hasText: 'New token' }).click()
    await expect(adminPage.locator('.modal-backdrop .modal')).toBeVisible()

    // Tokens.svelte scope select: options "pull" and "push"
    await adminPage.locator('.modal select').selectOption('pull')

    // en.json common.actions.create = "Create"
    await adminPage.locator('.modal button.primary', { hasText: 'Create' }).click()

    // After creation, newTokenValue is set and displayed in a .copy-block
    // en.json tokens.tokenCreated = "Token created — copy it now..."
    await expect(adminPage.locator('.copy-block')).toBeVisible({ timeout: 5_000 })
  })

  test('tokens table is shown or empty state displayed', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Tokens' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible()
    // Wait for spinner to clear (loading = false)
    await expect(main.locator('.spinner')).toHaveCount(0, { timeout: 10_000 })
    // Either a <table> or the empty cell is present
    await expect(main.locator('table')).toBeVisible()
  })

  // Regression: #37 — clicking a different sortable header must move the arrow.
  // The bug was that sortIndicator() read sortCol/sortDir only inside its function
  // body, so Svelte 5 (legacy mode) never wrapped them as signals and the indicator
  // template effect never re-ran. The fix passes sortCol/sortDir into a shared
  // helper from the template so the compiler tracks them.
  test('sort indicator arrow moves when a different column header is clicked', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Tokens' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main.locator('.spinner')).toHaveCount(0, { timeout: 10_000 })

    // Tokens.svelte default sort: sortCol='createdAt', sortDir='desc' → "Created ↓"
    const createdHeader = main.locator('th.sortable', { hasText: 'Created' })
    const scopeHeader = main.locator('th.sortable', { hasText: 'Scope' })

    await expect(createdHeader).toContainText('↓')

    await scopeHeader.click()

    // After clicking Scope, the arrow must have moved off Created and onto Scope.
    await expect(createdHeader).not.toContainText('↓')
    await expect(createdHeader).not.toContainText('↑')
    await expect(scopeHeader).toContainText(/[↑↓]/)
  })
})
