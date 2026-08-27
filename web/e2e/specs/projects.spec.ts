import { test, expect } from '../fixtures/index.js'

// en.json: nav.projects = "Projects", projects.title = "Projects"

test.describe('Projects page', () => {
  test('projects nav link renders the list page', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Projects' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    // en.json: projects.title = "Projects"
    await expect(main.locator('h1.page-title')).toContainText('Projects')
  })

  test('projects page shows a table or the empty state', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Projects' }).click()
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 5_000 })
    const content = await main.textContent()
    expect(content).toBeTruthy()
    expect(content!.length).toBeGreaterThan(0)
  })
})

// Table state (search/page) lives in the URL query string, same convention as Packages —
// it must survive clicking into a project's detail page and navigating back.
test.describe('Projects table state persistence', () => {
  test('search writes the URL and clears via the search box', async ({ adminPage }) => {
    await adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Projects' }).click()
    const main = adminPage.locator('main.main-content')
    const searchBox = main.getByPlaceholder('Search projects…')
    await expect(searchBox).toBeVisible({ timeout: 5_000 })

    await searchBox.fill('no-such-project-xyz')
    await expect.poll(() => adminPage.url()).toContain('q=no-such-project-xyz')

    const clear = main.getByRole('button', { name: 'Clear search' })
    await expect(clear).toBeVisible()
    await clear.click()

    await expect(searchBox).toHaveValue('')
    await expect.poll(() => adminPage.url()).not.toContain('q=')
  })
})
