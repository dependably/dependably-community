import { test, expect } from '../fixtures/index.js'
import fs from 'fs'
import path from 'path'
import { loginAsAdmin, fixturesRoot } from '../helpers/api-client.js'

/**
 * A hosted version can hold several artifacts — PyPI's sdist + wheel, NuGet's .nupkg + .snupkg.
 * The management view expands those into one row per file, and the expanded detail panel lists
 * each with its own checksum, size and download button.
 *
 * This is the only layer that renders a Svelte component. vitest.config.js deliberately carries
 * no Svelte plugin ("better served by the existing Playwright e2e suite"), so a markup defect is
 * invisible to every other gate — the frontend suite tests pure-JS modules and the backend suite
 * never renders. A keyed `{#each}` whose key repeats is exactly that class of defect: Svelte
 * throws `each_key_duplicate` in production builds as well as dev, and sibling files of one
 * version share the version's `id`, so keying on it blanks this panel on every multi-file
 * version. `pageerror` is captured rather than only asserting on the rows, so that failure
 * reports as the runtime throw it is instead of as a missing element.
 */
test.describe('Multi-file version detail panel', () => {
  const PKG = 'mypy-extensions'
  const VERSION = '1.0.0'
  const WHEEL = 'mypy_extensions-1.0.0-py3-none-any.whl'
  const SDIST = 'mypy_extensions-1.0.0.tar.gz'

  // Upload both artifacts of one release through the admin upload endpoint — the same surface the
  // drag-and-drop page posts to. Re-running against an existing instance is fine: the endpoint
  // reports per-file outcomes and an already-present file is not an error for this test's purpose.
  test.beforeAll(async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const dir = path.join(fixturesRoot(), 'pypi')
      const res = await authed.post('/api/v1/admin/upload', {
        multipart: {
          files: {
            name: WHEEL,
            mimeType: 'application/octet-stream',
            buffer: fs.readFileSync(path.join(dir, WHEEL)),
          },
        },
      })
      expect([200, 409], `wheel upload failed: ${await res.text()}`).toContain(res.status())

      const res2 = await authed.post('/api/v1/admin/upload', {
        multipart: {
          files: {
            name: SDIST,
            mimeType: 'application/octet-stream',
            buffer: fs.readFileSync(path.join(dir, SDIST)),
          },
        },
      })
      expect([200, 409], `sdist upload failed: ${await res2.text()}`).toContain(res2.status())
    } finally {
      await authed.dispose()
    }
  })

  test('lists every file of the version, each with its own download', async ({ adminPage }) => {
    const pageErrors: string[] = []
    adminPage.on('pageerror', (e) => pageErrors.push(e.message))

    await adminPage.goto(`/package/pypi/${PKG}`)
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 10_000 })

    // Expand the version row — the per-file breakdown lives only in the detail panel.
    const row = main.locator('tbody tr', { hasText: VERSION }).first()
    await expect(row).toBeVisible({ timeout: 10_000 })
    await row.click()

    const files = main.locator('.files-table')
    try {
      await expect(files).toBeVisible({ timeout: 5_000 })

      // Both artifacts, each as its own row.
      await expect(files.locator('tbody tr')).toHaveCount(2)
      await expect(files).toContainText(WHEEL)
      await expect(files).toContainText(SDIST)
    } finally {
      // Checked even when the assertions above failed, and deliberately allowed to replace their
      // error: a render-time throw shows up first as an element that never appears, which is a
      // misleading diagnosis. Verified by reverting the key to the version id — without this the
      // failure reads only "locator.toBeVisible failed".
      expect(pageErrors, `uncaught page error while rendering the files panel: ${pageErrors.join('; ')}`)
        .toEqual([])
    }
  })
})
