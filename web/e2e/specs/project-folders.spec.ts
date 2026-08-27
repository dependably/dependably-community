import type { APIRequestContext } from '@playwright/test'
import { randomUUID } from 'crypto'
import { test, expect } from '../fixtures/index.js'
import { loginAsAdmin } from '../helpers/api-client.js'
import { seedProjectVersion, sbomFixturesRoot } from '../helpers/sbom-seed.js'
import path from 'path'

/**
 * Filing projects into folders, and climbing back out of one.
 *
 * A "folder" is a `kind: 'collection'` project. Both halves of this feature are invisible to
 * every other layer of the suite: the vitest tests cover `lib/projectPaths.js` in isolation (this
 * repo has no Svelte component-render harness), and the backend tests cover PATCH's semantics
 * without ever rendering a row. Whether the kebab actually reaches the endpoint, and whether the
 * breadcrumb the detail pages build from `ancestors` actually navigates, are only observable here.
 *
 * Each test creates its own randomly-named tree, so nothing depends on run order or on a
 * previous run's leftovers in a local database.
 *
 * SELECTORS HERE ARE DELIBERATELY STRUCTURAL, not label-based. The UI language is a server-side
 * preference on the single admin account the whole suite shares, `i18n.spec.ts` switches it to
 * French, and CI runs two workers — so a selector keyed on an English label is a race this spec
 * loses at random. The names it does match on (`uniqueName(...)`) are random strings the UI never
 * translates. `data-testid="new-folder"` exists for the same reason.

/** A folder name unique to this run, so two runs against one database never collide on 409. */
function uniqueName(stem: string): string {
  return `e2e-${stem}-${randomUUID().slice(0, 8)}`
}

async function openProjectsPage(page: import('@playwright/test').Page) {
  // goto rather than clicking the sidebar: the nav label is localized, the table is not — and a
  // click has no wait of its own, so it races the sidebar's nav-links, which render only once the
  // user store rehydrates after a cold navigation (a plain goto, or any full page load reached
  // from outside the SPA's own router). The explicit toBeVisible below tolerates that hydration
  // delay and turns a stuck goto into a clear assertion failure instead of an opaque click timeout.
  await page.goto('/projects')
  const main = page.locator('main.main-content')
  await expect(main.locator('table')).toBeVisible({ timeout: 10_000 })
  return main
}

/** The dialog's confirm button. `.primary` is the only styling the footer distinguishes by. */
function saveButton(page: import('@playwright/test').Page) {
  return page.getByRole('dialog').locator('footer button.primary')
}

test.describe('Project folders', () => {
  let api: APIRequestContext

  test.beforeAll(async ({ baseURL }) => {
    api = await loginAsAdmin(baseURL!)
  })

  test.afterAll(async () => {
    await api.dispose()
  })

  test('New folder creates a collection that lists with its badge', async ({ adminPage }) => {
    const main = await openProjectsPage(adminPage)
    const folderName = uniqueName('folder')

    await main.locator('[data-testid="new-folder"]').click()
    const dialog = adminPage.getByRole('dialog')
    await expect(dialog).toBeVisible()
    await dialog.locator('input[type="text"]').first().fill(folderName)
    await saveButton(adminPage).click()

    await expect(dialog).toBeHidden()
    const row = main.locator('tr', { hasText: folderName })
    await expect(row).toBeVisible({ timeout: 10_000 })
    // Not merely "a row appeared" — a collection is what was created, and the badge is the only
    // thing on the row that distinguishes one from a plain project. Matched by its icon class,
    // which the list uses for nothing else, rather than by its translated text.
    await expect(row.locator('.badge.has-icon')).toBeVisible()
  })

  test('the row kebab relocates a project into a folder and back to the top level', async ({ adminPage }) => {
    const folderName = uniqueName('destination')
    const projectName = uniqueName('movable')
    const folder = await api.post('/api/v1/projects', {
      data: { name: folderName, kind: 'collection' },
    })
    expect(folder.status(), await folder.text()).toBe(201)
    const project = await api.post('/api/v1/projects', {
      data: { name: projectName, kind: 'project' },
    })
    expect(project.status(), await project.text()).toBe(201)
    const projectId = (await project.json()).id as string

    const main = await openProjectsPage(adminPage)
    const projectRow = main.locator('tr', { hasText: projectName })
    await expect(projectRow).toBeVisible({ timeout: 10_000 })

    await projectRow.locator('button.kebab-btn').click()
    // First popover item is Edit; the second is Delete, separated by a divider.
    await adminPage.getByRole('menu').locator('.popover-item').first().click()

    const dialog = adminPage.getByRole('dialog')
    await expect(dialog).toBeVisible()
    // The select is disabled until the folder list and the project's own record have both
    // loaded, so selecting the option is itself the wait for that hydration.
    await dialog.locator('select').selectOption({ label: folderName })
    await saveButton(adminPage).click()
    await expect(dialog).toBeHidden()

    // The unfiltered list is root-level only, so a moved project leaves it entirely. Asserting
    // the row is gone is what proves the move landed rather than the dialog merely closing.
    await expect(main.locator('tr', { hasText: projectName })).toHaveCount(0, { timeout: 10_000 })

    // And the round trip: back to the top level, where the row returns.
    await adminPage.goto(`/project/${projectId}`)
    await expect(adminPage.locator('main.main-content h1.page-title')).toContainText(projectName)
    const back = await api.patch(`/api/v1/projects/${projectId}`, { data: { parentId: null } })
    expect(back.status(), await back.text()).toBe(200)
    const returned = await openProjectsPage(adminPage)
    await expect(returned.locator('tr', { hasText: projectName })).toBeVisible({ timeout: 10_000 })
  })

  test('the detail breadcrumb climbs out of a nested folder', async ({ adminPage }) => {
    const outerName = uniqueName('outer')
    const innerName = uniqueName('inner')
    const projectName = uniqueName('nested')

    const outer = await api.post('/api/v1/projects', { data: { name: outerName, kind: 'collection' } })
    const outerId = (await outer.json()).id as string
    const inner = await api.post('/api/v1/projects', {
      data: { name: innerName, kind: 'collection', parentId: outerId },
    })
    const innerId = (await inner.json()).id as string
    const project = await api.post('/api/v1/projects', {
      data: { name: projectName, kind: 'project', parentId: innerId },
    })
    const projectId = (await project.json()).id as string

    await adminPage.goto(`/project/${projectId}`)
    const crumbs = adminPage.locator('nav.breadcrumbs')
    await expect(crumbs).toBeVisible({ timeout: 10_000 })
    // Root first, every containing folder, then the page itself — and the last crumb is text,
    // not a link, so a reader never clicks through to the page they are already on.
    // Each non-terminal crumb carries its own trailing separator span, which Playwright's
    // normalized text renders as " /".
    // The root crumb's label is translated, so assert its position and link-ness rather than its
      // text; the three that follow are this test's own random names.
    await expect(crumbs.locator('li')).toHaveCount(4)
    await expect(crumbs.locator('li').nth(1)).toContainText(outerName)
    await expect(crumbs.locator('li').nth(2)).toContainText(innerName)
    await expect(crumbs.locator('li').nth(3)).toHaveText(projectName)
    await expect(crumbs.locator('a')).toHaveCount(3)

    await crumbs.getByRole('link', { name: outerName }).click()
    await expect(adminPage).toHaveURL(new RegExp(`/project/${outerId}$`))
    await expect(adminPage.locator('main.main-content h1.page-title')).toContainText(outerName)
  })

  test('a child row is deleted from its folder, and the page has no delete button of its own', async ({ adminPage }) => {
    const folderName = uniqueName('holder')
    const doomedName = uniqueName('doomed')
    const keeperName = uniqueName('keeper')
    const folder = await api.post('/api/v1/projects', { data: { name: folderName, kind: 'collection' } })
    const folderId = (await folder.json()).id as string
    for (const name of [doomedName, keeperName]) {
      const res = await api.post('/api/v1/projects', {
        data: { name, kind: 'project', parentId: folderId },
      })
      expect(res.status(), await res.text()).toBe(201)
    }

    await adminPage.goto(`/project/${folderId}`)
    const main = adminPage.locator('main.main-content')
    await expect(main.locator('tr', { hasText: doomedName })).toBeVisible({ timeout: 10_000 })

    // The page-level destructive button is gone: deleting a row is offered by the table that
    // lists it, never by the page that IS it.
    await expect(main.locator('.page-header button.danger')).toHaveCount(0)

    // confirm() blocks the page, so accept it rather than letting it hang the run.
    adminPage.once('dialog', (d) => d.accept())
    await main.locator('tr', { hasText: doomedName }).locator('button.kebab-btn').click()
    // Delete is the first popover item; Edit follows it after the divider.
    await adminPage.getByRole('menu').locator('.popover-item').first().click()

    await expect(main.locator('tr', { hasText: doomedName })).toHaveCount(0, { timeout: 10_000 })
    // The adversarial half: only the row that was asked for went. A cascade that took the sibling
    // with it would still satisfy the assertion above.
    await expect(main.locator('tr', { hasText: keeperName })).toBeVisible()
  })

  test('deleting a child folder is confirmed in the folder wording, and declining changes nothing', async ({ adminPage }) => {
    const outerName = uniqueName('outer')
    const innerName = uniqueName('inner')
    const outer = await api.post('/api/v1/projects', { data: { name: outerName, kind: 'collection' } })
    const outerId = (await outer.json()).id as string
    const inner = await api.post('/api/v1/projects', {
      data: { name: innerName, kind: 'collection', parentId: outerId },
    })
    const innerId = (await inner.json()).id as string
    await api.post('/api/v1/projects', {
      data: { name: uniqueName('buried'), kind: 'project', parentId: innerId },
    })

    await adminPage.goto(`/project/${outerId}`)
    const main = adminPage.locator('main.main-content')
    await expect(main.locator('tr', { hasText: innerName })).toBeVisible({ timeout: 10_000 })

    // Dismiss, not accept — a confirm that deleted anyway is the failure that matters here, and it
    // is invisible to a test that only ever says yes.
    let prompt = ''
    adminPage.once('dialog', (d) => { prompt = d.message(); return d.dismiss() })
    await main.locator('tr', { hasText: innerName }).locator('button.kebab-btn').click()
    await adminPage.getByRole('menu').locator('.popover-item').first().click()

    // The cascade is what makes a folder's confirmation a bigger statement than a project's, so
    // the wording has to say so. Matched on the name it interpolates plus the em dash the folder
    // string carries and the project string does not — neither is translated away.
    await expect.poll(() => prompt).toContain(innerName)
    expect(prompt).toContain('—')
    await expect(main.locator('tr', { hasText: innerName })).toBeVisible()
  })

  test('uploading from a folder files the new project inside that folder', async ({ adminPage }) => {
    const folderName = uniqueName('inbox')
    const folder = await api.post('/api/v1/projects', { data: { name: folderName, kind: 'collection' } })
    const folderId = (await folder.json()).id as string
    const projectName = uniqueName('uploaded')

    await adminPage.goto(`/project/${folderId}`)
    await adminPage.locator('main.main-content [data-testid="upload"]').click()
    const dialog = adminPage.getByRole('dialog')
    await expect(dialog).toBeVisible()

    // The form says where this lands, which is the only place the folder target is visible.
    await expect(dialog).toContainText(folderName)

    await dialog.locator('input[type="file"]').setInputFiles(
      path.join(sbomFixturesRoot(), 'cyclonedx-1.6-inventory.json'))
    // Project name, then version — the two text inputs the form exposes, in order.
    const textInputs = dialog.locator('input[type="text"]')
    await textInputs.nth(0).fill(projectName)
    await textInputs.nth(1).fill('1.0.0')
    await dialog.locator('button.upload-submit').click()

    // The row appears in THIS folder's table, which is the whole claim: without parentId the
    // server resolves the name in the root scope and the project lands at the top level instead.
    await expect(adminPage.locator('main.main-content tr', { hasText: projectName }))
      .toBeVisible({ timeout: 20_000 })

    const listed = await api.get(`/api/v1/projects/${folderId}`)
    const children = (await listed.json()).children as Array<{ name: string }>
    expect(children.map((c) => c.name)).toContain(projectName)
  })

  test('uploading from a project page targets that project rather than asking again', async ({ adminPage }) => {
    const seeded = await seedProjectVersion(api, 'preset')

    await adminPage.goto(`/project/${seeded.projectId}`)
    await adminPage.locator('main.main-content [data-testid="upload"]').click()
    const dialog = adminPage.getByRole('dialog')
    await expect(dialog).toBeVisible()

    // Preset to this project: the picker is a select showing it, not an empty "new project" box,
    // so an upload launched from a project adds a version instead of creating a second project.
    await expect(dialog.locator('select')).toHaveCount(1)
    await expect(dialog.locator('select')).toContainText(seeded.projectName)
  })

  test('the version breadcrumb goes back to the project versions table', async ({ adminPage }) => {
    const seeded = await seedProjectVersion(api, 'breadcrumb')

    await adminPage.goto(seeded.detailPath())
    const crumbs = adminPage.locator('nav.breadcrumbs')
    await expect(crumbs).toBeVisible({ timeout: 15_000 })
    await expect(crumbs.locator('li').last()).toHaveText(seeded.versionLabel)

    // This is the affordance the page had none of: from a deep link there is no history entry to
    // go back to, so the project crumb is the only route back to the versions table.
    await crumbs.getByRole('link', { name: seeded.projectName }).click()
    await expect(adminPage).toHaveURL(new RegExp(`/project/${seeded.projectId}$`))
    // The versions table itself, not its translated heading.
    await expect(adminPage.locator('main.main-content table')).toBeVisible({ timeout: 10_000 })
  })
})
