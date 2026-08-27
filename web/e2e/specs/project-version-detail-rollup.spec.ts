import type { APIRequestContext, Page } from '@playwright/test'
import { test, expect } from '../fixtures/index.js'
import { inviteFreshAdmin, loginAsAdmin } from '../helpers/api-client.js'
import { LoginPage } from '../pages/LoginPage.js'
import {
  seedInheritedTriage,
  seedProjectVersion,
  SeededProjectVersion,
} from '../helpers/sbom-seed.js'

/**
 * Version-wide rollup surfaces on the project-version detail page: the priority ribbon, the
 * licence pillar's version-wide count, the scope-suppressed chip, the on-demand rescan button,
 * and the orphan-analysis table's expandable edit row.
 *
 * Every number asserted below is derived by hand from the committed fixture trio
 * (`tests/Dependably.Tests/Fixtures/sbom/`) against `EffectivePriority.Derive`'s documented rules
 * — not copied from the running page — so a regression in the rollup computation itself, not just
 * in its rendering, would fail these specs. The harness runs no vulnerability scan, so every
 * advisory reaching a component is unscored (cvss=null): priority is decided entirely by VEX state
 * and SARIF reachability.
 *
 *   attend (2): minimist (exploitable, reachable), qs (in_triage, reachable)
 *   track  (2): System.Text.Encodings.Web (SARIF-only, not-observed), certifi (resolved_with_pedigree, no SARIF result)
 *   suppressed (3): requests (not_affected), urllib3 (resolved), Newtonsoft.Json (false_positive)
 *   act (0): nothing in this fixture is KEV or high-EPSS
 *
 * Licences (13 components): MIT×8, Apache-2.0×2 (requests, Serilog), BSD-3-Clause×1 (qs),
 * MPL-2.0×1 (certifi), undeclared×1 (charset-normalizer) — total 13, declared 12, undeclared 1.
 *
 * Serilog is the SBOM's only `scope=excluded` component (scopeSuppressedCount=1), and every
 * component carries a scannable npm/pypi/nuget purl (unscannableCount=0) — the two counts the
 * ribbon renders side by side must not be conflated.
 *
 * The VEX document's seventh statement (GHSA-mh6f-8j2x-4483, on pkg:npm/event-stream) names a
 * product this SBOM does not list at all — the one orphan row the "Unmatched analysis" table
 * renders.
 */

let seeder: APIRequestContext
let freshAdmin: { email: string; password: string }

test.beforeAll(async ({ baseURL }) => {
  seeder = await loginAsAdmin(baseURL!)
  freshAdmin = await inviteFreshAdmin(seeder, baseURL!)
})

test.afterAll(async () => {
  await seeder?.dispose()
})

async function signIn(page: Page) {
  const login = new LoginPage(page)
  await login.goto()
  await login.login(freshAdmin.email, freshAdmin.password)
  await login.expectNavVisible()
}

async function seedAndSignIn(page: Page, label: string): Promise<SeededProjectVersion> {
  const seeded = await seedProjectVersion(seeder, label)
  await signIn(page)
  return seeded
}

async function openDetail(page: Page, seeded: SeededProjectVersion, query = '') {
  await page.goto(seeded.detailPath(query))
  await expect(page.locator('main.main-content')).toBeVisible({ timeout: 15_000 })
  await expect(page.locator('main.main-content tr.component-row .comp-name').first())
    .toBeVisible({ timeout: 15_000 })
}

test.describe('Project version detail — version-wide rollup', () => {
  test('the priority ribbon reports server-computed counts, not a page-scoped tally', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'priority-ribbon')
    await openDetail(page, seeded, '?limit=5') // a page smaller than the version, on purpose

    const ribbon = page.locator('.ribbon')
    // Structural, not text-filtered: the priority ribbon renders a second, unrelated "excluded
    // from build" chip (see the scope-suppressed test below), and matching by visible text alone
    // is exactly what let the two collide under one word before that chip was renamed. Each
    // priority split is keyed by its own `b.prio-<bucket>` class, which no other chip carries.
    const splitFor = (bucket: string) => ribbon.locator(`.split.prio-split:has(b.prio-${bucket})`)

    await expect(splitFor('act')).toContainText('0')
    await expect(splitFor('attend')).toContainText('2')
    await expect(splitFor('track')).toContainText('2')
    await expect(splitFor('suppressed')).toContainText('3')

    // A 5-row page cannot itself contain all 7 advisory-bearing components — the ribbon's "2"s
    // and "3" are provably not a count of what is on screen.
    await expect(page.locator('main.main-content tr.component-row')).toHaveCount(5)
  })

  test('the licence pillar counts the whole version and offers a per-identifier breakdown', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'license-rollup')
    await openDetail(page, seeded, '?limit=5')

    const licensePillar = page.locator('.pillar', { hasText: 'Licence' })
    // 1 undeclared (charset-normalizer) + 0 blocklisted (no org licence blocklist configured
    // here) = 1 to review — a number the 5-row page alone cannot produce if it landed on the
    // wrong page of the 13-component version.
    await expect(licensePillar.locator('.pillar-value')).toContainText('1 to review')

    // The breakdown tooltip is built from the rollup's byIdentifier tally, sorted desc — MIT (8)
    // must lead. The stale "does not report a version-wide licence count" hover text this
    // replaced must be gone entirely.
    const title = await licensePillar.locator('.pillar-value').getAttribute('title')
    expect(title).toContain('MIT (8)')
    expect(title).not.toContain('does not report a version-wide')
  })

  test('excluded-by-scope and unscannable are reported as two separate counts', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'excluded-by-scope')
    await openDetail(page, seeded)

    const ribbon = page.locator('.ribbon')
    // Structural: this chip renders "excluded from build", deliberately never "suppressed" —
    // that word is reserved for the priority ribbon's own Suppressed bucket (a VEX statement, a
    // different fact from a producer's scope declaration). The two chips colliding under one
    // label is the bug this test — and the class-based locator below — exists to catch.
    const excludedChip = ribbon.locator('.split.excluded-by-scope-split')
    await expect(excludedChip).toHaveCount(1)
    await expect(excludedChip).toContainText('1')
    await expect(excludedChip).not.toContainText('Suppressed')

    // Serilog is the only excluded-scope component; nothing in the fixture is unscannable, so
    // that split must not render at all (unscannableNote is null at zero).
    await expect(ribbon.locator('.split', { hasText: 'unscannable' })).toHaveCount(0)
  })

  test('rescan on a never-scanned version enqueues, and a second click is also allowed', async ({ page }) => {
    // MAX(vuln_checked_at) reads NULL until a component is actually scanned, and
    // SbomScanController.CooldownRemainingAsync treats NULL as "never scanned", not "just
    // scanned" — deliberately, so a version whose scan was deferred by an unreachable advisory
    // source stays immediately retriable rather than locked out for an hour by a scan that never
    // ran. Two consecutive clicks here are both legitimately 202; see the stamped-component test
    // below for the case that actually is cooled down.
    const seeded = await seedAndSignIn(page, 'rescan-unscanned')
    await openDetail(page, seeded)

    await expect(page.getByText('Never scanned')).toBeVisible()

    const first = page.waitForResponse(res =>
      res.request().method() === 'POST' && res.url().includes('/rescan'))
    await page.locator('button.rescan-btn').click()
    expect((await first).status()).toBe(202)

    const second = page.waitForResponse(res =>
      res.request().method() === 'POST' && res.url().includes('/rescan'))
    await page.locator('button.rescan-btn').click()
    expect((await second).status()).toBe(202)
  })

  test('a 429 from the rescan endpoint is surfaced, not silently swallowed', async ({ page }) => {
    // The server's own cooldown rule — NULL vuln_checked_at is "never scanned" and stays
    // immediately retriable, a recent stamp is "cooled down" and 429s — is pinned server-side in
    // SbomScanControllerTests.cs (Rescan_WithinCooldownWindow_Returns429WithRetryAfter and
    // Rescan_NeverScanned_SecondConsecutiveEnqueueIsStillAllowed, the latter with a mutant twin
    // for a cooldown that treats NULL as "just scanned"). Reproducing that here would need a
    // stamped component, and the harness disables the sbom-scan background job for the whole
    // suite (determinism: every severity/CVSS/priority the page renders must come from the
    // fixture documents, not a live scan), so no public endpoint can ever produce one — this
    // spec owns a narrower, purely client-side question instead: given a 429, does the page
    // surface it rather than pretending the click did nothing. Playwright's route interception
    // is the right tool for exactly that question, with no server cooldown state required.
    const seeded = await seedAndSignIn(page, 'rescan-429')
    await openDetail(page, seeded)

    await page.route('**/rescan', route => route.fulfill({
      status: 429,
      headers: { 'Retry-After': '1800' },
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'Scanned recently. Try again later.', retry_after_seconds: 1800 }),
    }))

    const cooled = page.waitForResponse(res =>
      res.request().method() === 'POST' && res.url().includes('/rescan'))
    await page.locator('button.rescan-btn').click()
    expect((await cooled).status()).toBe(429)

    // The click must not silently no-op: the page surfaces the refusal rather than pretending
    // nothing happened.
    await expect(page.locator('.page-error[role="alert"]').first()).toBeVisible({ timeout: 5_000 })
  })

  test('the orphan row is editable and correcting it removes it from Unmatched analysis', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'orphan-edit')
    await openDetail(page, seeded)

    const orphanCard = page.locator('.orphan-card')
    await expect(orphanCard).toBeVisible()
    const orphanRow = orphanCard.locator('tbody tr').filter({ hasText: 'GHSA-mh6f-8j2x-4483' })
    await expect(orphanRow).toContainText('pkg:npm/event-stream')
    // The VEX document recorded this statement as in_triage — an open question, not yet a
    // decision, which is exactly the state this test edits below.
    await expect(orphanRow).toContainText('In triage')

    await orphanRow.locator('td').first().click()
    const detail = orphanCard.locator('tr.detail-row .orphan-detail')
    await expect(detail).toBeVisible()

    await detail.getByRole('button', { name: 'Edit analysis' }).click()
    const form = detail.locator('.vex-form')
    await form.getByRole('combobox', { name: 'State', exact: true }).selectOption('false_positive')

    const saved = page.waitForResponse(res =>
      res.request().method() === 'PUT' && res.url().includes('/analysis'))
    await form.getByRole('button', { name: 'Save', exact: true }).click()
    expect((await saved).status()).toBe(200)

    // The orphan is still an orphan after the edit — event-stream is genuinely absent from this
    // SBOM — but the row now carries the corrected state instead of "No state recorded".
    await expect(page.locator('.orphan-card tbody tr', { hasText: 'GHSA-mh6f-8j2x-4483' }))
      .toContainText('False positive')
  })

  test('a manual triage carried forward from an earlier version reads as inherited', async ({ page }) => {
    // Reproduces the wiring bug directly: this page is reached by concrete version id (the SPA's
    // only route into it, same as sbom-seed.ts's own detailPath()), never by the `latest` alias,
    // so this is the path SbomAnalysisRepository.ResolveVersionAsync's explicit-id branch has to
    // supply created_at on for the badge to ever appear.
    const { second } = await seedInheritedTriage(seeder, 'inherited-triage')
    await signIn(page)
    await openDetail(page, second)

    const main = page.locator('main.main-content')
    // The PURL no longer renders in the row (it moved into the expanded detail panel), so the
    // component name is what identifies the row now — unique across this fixture's inventory.
    const row = main.locator('tr.component-row').filter({ hasText: 'qs' })
    await row.locator('td.name-cell').click()
    const panel = main.locator('.detail-panel')
    await expect(panel.locator('.advisory-id')).toHaveText('CVE-2022-24999')

    // The decision was made on version 1.0.0, not this 2.0.0 release, so the badge must say so
    // rather than rendering as a fresh call made for this version.
    await expect(panel.locator('.vex-inherited')).toContainText('Inherited')
  })
})
