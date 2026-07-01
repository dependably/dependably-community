import { test, expect } from '../fixtures/index.js'

// en.json: users.title = "Users & Invites", users.inviteUser = "Invite user"
// Users.svelte: <div class="page"> with .page-header, .tabs, table
// Tabs: <button class="tab"> with "Members ({count})" and "Pending Invites ({count})"
// Users nav link only visible for role admin or instance_admin (admin@dependably.local is instance_admin)

test.describe('Users / Members', () => {
  test('users page is accessible to admin', async ({ adminPage }) => {
    // App.svelte: users nav link only shown for admin/instance_admin
    const usersBtn = adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Users' })
    await expect(usersBtn).toBeVisible({ timeout: 5_000 })
    await usersBtn.click()
    await expect(adminPage.locator('main.main-content')).toBeVisible()
    // en.json users.title = "Users & Invites"
    await expect(adminPage.locator('h1.page-title')).toContainText('Users & Invites')
  })

  test('admin sees member management controls', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Users' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })

    // Users.svelte: invite button in page-header
    // en.json users.inviteUser = "Invite user"
    await expect(main.locator('.page-header button.primary', { hasText: 'Invite user' })).toBeVisible()

    // Tab buttons exist: "Members" and "Pending Invites"
    await expect(main.locator('.tabs button.tab').first()).toBeVisible()
  })

  test('members table is visible by default', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Users' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible()
    // Default tab is 'members', wait for spinner to clear
    await expect(main.locator('.spinner')).toHaveCount(0, { timeout: 10_000 })
    // Members table should render (admin@dependably.local is at least one member)
    await expect(main.locator('table')).toBeVisible()
  })

  test('can switch to pending invites tab', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Users' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main.locator('.spinner')).toHaveCount(0, { timeout: 10_000 })
    // en.json users.tabs.pendingInvites = "Pending Invites ({count})"
    await main.locator('.tabs button.tab', { hasText: /Pending Invites/ }).click()
    // Invites table should now be visible
    await expect(main.locator('table')).toBeVisible()
  })
})
