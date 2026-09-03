import type { APIRequestContext } from '@playwright/test'
import { randomUUID } from 'crypto'
import path from 'path'
import { test, expect } from '../fixtures/index.js'
import { loginAsAdmin } from '../helpers/api-client.js'
import { sbomFixturesRoot } from '../helpers/sbom-seed.js'

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

/**
 * A batch is ordered SBOM-first, but ordering alone does not make it coherent: nothing used to
 * read whether the SBOM leg actually succeeded, so a rejected SBOM still let the VEX/SARIF legs
 * fire against a version that was never created. The server answered them truthfully with
 * "No such project version", which landed on the SARIF row and read as if the SARIF were at
 * fault, while the real cause sat in a different row.
 *
 * SELECTORS ARE STRUCTURAL, not label-based: the suite shares one admin account whose language
 * i18n.spec.ts switches, so an English label is a race. Row state is carried by the
 * `outcome-<status>` class the outcome table already sets.
 */
test.describe('SBOM upload batch coherence', () => {
  let api: APIRequestContext

  test.beforeAll(async ({ baseURL }) => {
    api = await loginAsAdmin(baseURL!)
  })

  test.afterAll(async () => {
    await api.dispose()
  })

  test('a rejected SBOM skips its batch dependents instead of 404ing them individually', async ({ adminPage }) => {
    const projectName = `e2e-cascade-${randomUUID().slice(0, 8)}`

    await adminPage.goto('/projects')
    await adminPage.locator('main.main-content [data-testid="upload"]').click()
    const dialog = adminPage.getByRole('dialog')
    await expect(dialog).toBeVisible()

    await dialog.locator('input[type="file"]').setInputFiles([
      path.join(sbomFixturesRoot(), 'cyclonedx-1.6-inventory.json'),
      path.join(sbomFixturesRoot(), 'sarif-2.1.0-sbom-reach.json'),
    ])

    // New project name, then version — the two text inputs new-project mode exposes, in order.
    const textInputs = dialog.locator('input[type="text"]')
    await textInputs.nth(0).fill(projectName)
    await textInputs.nth(1).fill('1.0.0')

    // Uncheck "create project/version if missing" — the first of the two checkboxes. That makes
    // the SBOM PUT a deterministic 404 (a miss is a 404 by design) without needing a malformed
    // fixture, which is the prerequisite failure the batch has to survive coherently.
    const autoCreate = dialog.locator('label.checkbox-row input[type="checkbox"]').nth(0)
    await expect(autoCreate).toBeChecked()
    await autoCreate.uncheck()

    await dialog.locator('button.upload-submit').click()

    // The SBOM is rejected on its own merits; the SARIF is never sent.
    await expect(dialog.locator('tr.outcome-rejected')).toHaveCount(1, { timeout: 20_000 })
    await expect(dialog.locator('tr.outcome-rejected')).toContainText('cyclonedx-1.6-inventory.json')
    await expect(dialog.locator('tr.outcome-skipped')).toHaveCount(1)
    await expect(dialog.locator('tr.outcome-skipped')).toContainText('sarif-2.1.0-sbom-reach.json')

    // The adversarial half, and the reason skipping is safe rather than merely quieter: nothing
    // was created, so there was never a version for that SARIF to attach to.
    const listed = await (await api.get('/api/v1/projects?limit=200')).json()
    expect((listed.items as Array<{ name: string }>).map((p) => p.name)).not.toContain(projectName)
  })
})
