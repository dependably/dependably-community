import { test, expect } from '../fixtures/index.js'
import fs from 'fs'
import path from 'path'
import { loginAsAdmin, fixturesRoot } from '../helpers/api-client.js'

/**
 * Copyable install commands: one per version inside the expanded detail panel, and the unpinned
 * package-level one in the packages-list row menu.
 *
 * The per-ecosystem command text is pinned exhaustively by src/lib/installCommand.test.js. What
 * that suite CANNOT see is whether the markup renders at all — vitest.config.js carries no
 * Svelte plugin, so Playwright is the only layer that renders a component. The per-version block
 * sits behind an `{@const}` whose placement Svelte validates structurally (it must be the
 * immediate child of a block, not of a plain element — putting it inside the .detail-panel div
 * is a compile error, not a runtime one). `pageerror` is captured so a render-time throw reports
 * as itself rather than as an element that never appeared.
 */
test.describe('Install commands', () => {
  const PKG = 'mypy-extensions'
  const VERSION = '1.0.0'
  const WHEEL = 'mypy_extensions-1.0.0-py3-none-any.whl'

  test.beforeAll(async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const res = await authed.post('/api/v1/admin/upload', {
        multipart: {
          files: {
            name: WHEEL,
            mimeType: 'application/octet-stream',
            buffer: fs.readFileSync(path.join(fixturesRoot(), 'pypi', WHEEL)),
          },
        },
      })
      expect([200, 409], `wheel upload failed: ${await res.text()}`).toContain(res.status())
    } finally {
      await authed.dispose()
    }
  })

  test('offers a version-pinned command in the expanded row', async ({ adminPage, baseURL }) => {
    const pageErrors: string[] = []
    adminPage.on('pageerror', (e) => pageErrors.push(e.message))

    await adminPage.goto(`/package/pypi/${PKG}`)
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 10_000 })

    try {
      // The package page carries no unpinned command of its own — the release history is the
      // only place it offers one, pinned to the row you expanded.
      await expect(main.locator('.install-block')).toHaveCount(0)

      const row = main.locator('tbody tr', { hasText: VERSION }).first()
      await expect(row).toBeVisible({ timeout: 10_000 })
      await row.click()

      // Pinned, and carrying the index URL that makes it work without a pip.conf.
      const installCmd = main.locator('.detail-panel .install-cmd')
      await expect(installCmd).toBeVisible({ timeout: 5_000 })
      await expect(installCmd).toHaveText(new RegExp(`pip install ${PKG}==${VERSION.replace(/\./g, '\\.')}`))
      await expect(installCmd).toContainText(`${new URL(baseURL!).host}/simple/`)
    } finally {
      expect(pageErrors, `uncaught page error while rendering install commands: ${pageErrors.join('; ')}`)
        .toEqual([])
    }
  })

  test('offers the command from the packages list without opening the package', async ({ adminPage }) => {
    const pageErrors: string[] = []
    adminPage.on('pageerror', (e) => pageErrors.push(e.message))

    await adminPage.goto('/packages?q=mypy-extensions')
    const main = adminPage.locator('main.main-content')
    await expect(main).toBeVisible({ timeout: 10_000 })

    try {
      // The actions column renders for every viewer now, not just when an overwrite policy
      // makes its admin items relevant — the install command is the reason it is always there.
      const row = main.locator('tbody tr', { hasText: PKG }).first()
      await expect(row).toBeVisible({ timeout: 10_000 })
      await row.locator('.actions-cell .kebab-btn').click()

      const item = main.locator('.popover-item', { hasText: 'Copy install command' })
      await expect(item).toBeVisible({ timeout: 5_000 })
      await item.click()
      await expect(main.locator('.popover-item', { hasText: /Copied/i })).toBeVisible({ timeout: 5_000 })
    } finally {
      expect(pageErrors, `uncaught page error on the packages list: ${pageErrors.join('; ')}`)
        .toEqual([])
    }
  })
})
