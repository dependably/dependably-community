import { test, expect } from '../fixtures/index.js'
import fs from 'fs'
import path from 'path'
import { loginAsAdmin, fixturesRoot } from '../helpers/api-client.js'

/**
 * The package detail page's three-pillar risk strip reports the state of ONE version — the one
 * `resolveStateVersion` picks — and names it, rather than aggregating the worst value across the
 * whole release history. Aggregating made the strip describe a version nobody installs: a package
 * whose current release is clean read MEDIUM because a years-old release carries an advisory, and
 * the operational pillar reported a large versions-behind count directly above a banner saying
 * the latest version was cached.
 *
 * Which version gets picked is unit-tested in `packageRisk.test.js` across every branch (upstream
 * latest cached, stale, hosted-only, pre-release-only, OCI digests). What no other gate can see is
 * the binding: vitest.config.js carries no Svelte plugin, so the markup reading those values is
 * rendered nowhere but here. A pillar left wired to a stale variable, or a caption naming a
 * version the pillars do not describe, is invisible to every other layer.
 *
 * Two versions are uploaded because one proves nothing — with a single version every candidate
 * rule agrees. The subject caption is the observable evidence of which one the pillars describe.
 */
test.describe('Package risk pillars', () => {
  const PKG = 'is-odd'
  const OLD = { version: '2.0.0', file: 'is-odd-2.0.0.tgz' }
  const CURRENT = { version: '3.0.1', file: 'is-odd-3.0.1.tgz' }

  test.beforeAll(async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      for (const { file } of [OLD, CURRENT]) {
        const res = await authed.post('/api/v1/admin/upload', {
          multipart: {
            files: {
              name: file,
              mimeType: 'application/octet-stream',
              buffer: fs.readFileSync(path.join(fixturesRoot(), 'npm', file)),
            },
          },
        })
        // 409 = already uploaded by an earlier run against this instance; either way it is present.
        expect([200, 409], `${file} upload failed: ${await res.text()}`).toContain(res.status())
      }
    } finally {
      await authed.dispose()
    }
  })

  test('describes the newest version, not the worst across the history', async ({ adminPage }) => {
    const pageErrors: string[] = []
    adminPage.on('pageerror', (e) => pageErrors.push(e.message))

    await adminPage.goto(`/package/npm/${PKG}`)
    const main = adminPage.locator('main.main-content')
    const pillars = main.locator('.risk-pillars')

    try {
      await expect(pillars).toBeVisible({ timeout: 10_000 })

      // Both versions are on the page — so the caption below is a choice, not the only option.
      await expect(main.locator('tbody tr', { hasText: OLD.version }).first()).toBeVisible()
      await expect(main.locator('tbody tr', { hasText: CURRENT.version }).first()).toBeVisible()

      // The subject caption is what makes a clean headline unambiguous: without it a reader
      // cannot tell "nothing in this package has an advisory" from "the current release has none".
      const subject = pillars.locator('.pillar-subject')
      await expect(subject).toContainText(CURRENT.version)
      await expect(subject).not.toContainText(OLD.version)

      // Neither fixture carries an advisory or a blocklisted license, so the security and licence
      // pillars both read clean for the version named above — asserted on the rendered STATE
      // (the clean modifier) rather than on the English copy, because the suite shares one admin
      // whose language preference another spec may have changed, and this test is about which
      // version the pillars describe, not about what language they describe it in. Operational is
      // deliberately excluded: a hosted-only package has no upstream baseline, so it renders
      // unscored rather than clean.
      await expect(pillars.locator('.pillar-clean')).toHaveCount(2)
    } finally {
      // Checked even when the assertions above failed, and deliberately allowed to replace their
      // error: a render-time throw surfaces first as an element that never appears, which is a
      // misleading diagnosis.
      expect(pageErrors, `uncaught page error while rendering the risk pillars: ${pageErrors.join('; ')}`)
        .toEqual([])
    }
  })
})
