import type { APIRequestContext, Page } from '@playwright/test'
import { test, expect } from '../fixtures/index.js'
import { inviteFreshAdmin, loginAsAdmin } from '../helpers/api-client.js'
import { LoginPage } from '../pages/LoginPage.js'
import { seedProjectVersion, SeededProjectVersion } from '../helpers/sbom-seed.js'

/**
 * The project-version detail page — the SBOM component table, its filters, its sort, its
 * pagination and the VEX triage editor.
 *
 * This page is server-side filtered, sorted and paged: the browser sends the table state and
 * renders whatever comes back. A change to the filter contract or to the payload shape therefore
 * produces a page that renders cleanly and shows the WRONG ROWS — no console error, no build
 * failure, and no failing unit test, because the vitest suite covers `lib/sbom/analysis.js`'s
 * pure mapping in isolation and this repo has no Svelte component-render harness. These specs are
 * the only layer that exercises the page as assembled against a real server.
 *
 * Every expectation below is grounded in the committed fixture trio
 * (`tests/Dependably.Tests/Fixtures/sbom/`), which is deliberately cross-consistent: 13
 * components, one VEX statement per advisory covering the whole analysis-state vocabulary, and a
 * SARIF supplying reachability plus the dev/runtime split. Each test seeds its own project
 * version, so no test depends on another's data or on the order they run in.
 *
 * Determinism: the harness disables the `sbom-scan` background job, so no advisory feed is
 * consulted and the derived state is a pure function of those three documents. Waits are on a
 * specific response or on a settled DOM state — never a bare timeout.
 */

// Component names in the page's default order: sort=priority, dir=desc. The two `attend` rows
// come first (an exploitable/in-triage advisory on a reachable component), then the two `track`
// rows, then every row with no visible advisory, tie-broken by ordinal name — uppercase before
// lowercase, which is the server's ordering and not the browser's.
const DEFAULT_ORDER = [
  'minimist', 'qs', 'System.Text.Encodings.Web', 'certifi', '@babel/core', 'Newtonsoft.Json',
  'Serilog', 'base64-js', 'charset-normalizer', 'eslint', 'lodash', 'requests', 'urllib3',
]

// Prod = dependency_scope != 'dev' AND sbom_scope != 'excluded'. `minimist` is the SARIF's only
// dev result and `Serilog` is the SBOM's only excluded component, so both drop out — and the
// seven components no SARIF result mentions stay visible at `unknown`, which is the point of the
// predicate: unclassified is not the same as dev.
const PROD_ORDER = DEFAULT_ORDER.filter(name => name !== 'minimist' && name !== 'Serilog')
const DEV_ORDER = ['minimist']

// sort=name, dir=asc, limit=5 — ordinal, so the uppercase names sort ahead of the lowercase ones.
const NAME_ASC_PAGE_1 = ['@babel/core', 'Newtonsoft.Json', 'Serilog', 'System.Text.Encodings.Web', 'base64-js']
const NAME_ASC_PAGE_2 = ['certifi', 'charset-normalizer', 'eslint', 'lodash', 'minimist']

// The two components the SARIF reports as reachable on a non-suppressed advisory.
const REACHABLE_ORDER = ['minimist', 'qs']

/**
 * One brand-new tenant admin and one seeded version per test, both provisioned through a single
 * admin API session for the whole file.
 *
 * The account is fresh rather than the shared `admin@dependably.local` because the locators below
 * read English UI text, and that account's language is not this spec's to assume — `i18n.spec.ts`
 * persists a French override to it through the Profile locale switcher, so an interleaved run
 * boots this page into a French session and every label-based locator misses. A freshly invited
 * admin has no override of its own and renders the tenant default; `admin` is also the role the
 * triage editor requires.
 *
 * The account is shared across this file's tests while the SEEDED DATA is not: each test owns a
 * distinct project version, so nothing here depends on what another test did. Reusing the one
 * account keeps this file's login count at one per test, which matters because the whole suite
 * authenticates from one IP against a single login budget.
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

async function seedAndSignIn(page: Page, label: string): Promise<SeededProjectVersion> {
  const seeded = await seedProjectVersion(seeder, label)
  const login = new LoginPage(page)
  await login.goto()
  await login.login(freshAdmin.email, freshAdmin.password)
  await login.expectNavVisible()
  return seeded
}

function componentNames(page: Page) {
  return page.locator('main.main-content tr.component-row .comp-name')
}

/** Opens the seeded version's detail page and waits for the first analysis page to render. */
async function openDetail(page: Page, seeded: SeededProjectVersion, query = '') {
  await page.goto(seeded.detailPath(query))
  await expect(page.locator('main.main-content')).toBeVisible({ timeout: 15_000 })
  await expect(componentNames(page).first()).toBeVisible({ timeout: 15_000 })
}

test.describe('Project version detail — filter, sort and pagination round-trip', () => {
  test('scope chips and the severity filter drive the server and survive a reload', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'scope')
    await openDetail(page, seeded)

    // The server orders the page; DataTable's local sort is neutralized. Asserting the whole
    // sequence — not just the row count — is what catches a client that re-sorts what arrived.
    await expect(componentNames(page)).toHaveText(DEFAULT_ORDER)

    const main = page.locator('main.main-content')
    const scopeChips = main.getByRole('group', { name: 'Filter by scope' })
    const severityChips = main.getByRole('group', { name: 'Filter by severity' })

    await scopeChips.getByRole('button', { name: 'Prod', exact: true }).click()
    await expect(componentNames(page)).toHaveText(PROD_ORDER)
    await expect.poll(() => page.url()).toContain('scope=prod')

    await scopeChips.getByRole('button', { name: 'Dev', exact: true }).click()
    await expect(componentNames(page)).toHaveText(DEV_ORDER)
    await expect.poll(() => page.url()).toContain('scope=dev')

    await scopeChips.getByRole('button', { name: 'All', exact: true }).click()
    await expect(componentNames(page)).toHaveText(DEFAULT_ORDER)
    await expect.poll(() => page.url()).not.toContain('scope=')

    // Severity is a scan-fed fact, and the harness runs no scan: every advisory the fixtures
    // carry is unscored, which the Security pillar states outright. Asserting the pillar first
    // makes the next assertion diagnosable — a severity filter that returned rows here would
    // mean the harness grew an advisory feed, not that the filter is broken.
    await expect(main.locator('.pillar', { hasText: 'Security' }).locator('.pillar-value'))
      .toHaveText('UNSCORED')

    await severityChips.getByRole('button', { name: 'Critical', exact: true }).click()
    await expect.poll(() => page.url()).toContain('sev=critical')
    await expect(componentNames(page)).toHaveCount(0)
    // Scoped to the component table: the page also renders an orphan-analysis table and a
    // documents table, which the filters do not govern.
    await expect(main.locator('table').first()).toContainText('No components match these filters.')

    await severityChips.getByRole('button', { name: 'All', exact: true }).click()
    await expect(componentNames(page)).toHaveText(DEFAULT_ORDER)

    // The reachability filter is the same contract with a non-empty answer: SARIF-fed, so it
    // does return rows, which proves a filtered page is not merely an empty one.
    await main.getByLabel('Filter by reachability').selectOption('reachable')
    await expect(componentNames(page)).toHaveText(REACHABLE_ORDER)
    await expect.poll(() => page.url()).toContain('reach=reachable')

    // Scope and reachability compose, and the pair survives a reload through the URL.
    await scopeChips.getByRole('button', { name: 'Dev', exact: true }).click()
    await expect(componentNames(page)).toHaveText(DEV_ORDER)

    await page.reload()
    await expect(componentNames(page).first()).toBeVisible({ timeout: 15_000 })
    await expect(componentNames(page)).toHaveText(DEV_ORDER)
    await expect(scopeChips.getByRole('button', { name: 'Dev', exact: true })).toHaveClass(/active/)
    await expect(main.getByLabel('Filter by reachability')).toHaveValue('reachable')
  })

  test('a sort and a page selection round-trip and survive a reload', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'paging')
    // A five-row page over thirteen components: three pages, so page 2 is a real middle page
    // rather than the tail. `limit` is read straight off the URL, same as every other table.
    await openDetail(page, seeded, '?limit=5')

    const main = page.locator('main.main-content')
    await main.locator('th.sortable', { hasText: 'Component' }).click()
    await expect(componentNames(page)).toHaveText(NAME_ASC_PAGE_1)
    await expect.poll(() => page.url()).toContain('sort=name')
    await expect.poll(() => page.url()).toContain('dir=asc')

    const pagination = main.locator('.pagination')
    await pagination.getByRole('button', { name: '2', exact: true }).click()
    await expect(componentNames(page)).toHaveText(NAME_ASC_PAGE_2)
    await expect.poll(() => page.url()).toContain('page=2')

    // The whole table state — sort, direction, page size and page — is carried by the URL, so a
    // reload lands the reader on the same rows rather than back on page one.
    await page.reload()
    await expect(componentNames(page).first()).toBeVisible({ timeout: 15_000 })
    await expect(componentNames(page)).toHaveText(NAME_ASC_PAGE_2)
    await expect(pagination.getByRole('button', { name: '2', exact: true })).toHaveAttribute('aria-current', 'page')
  })
})

test.describe('Project version detail — VEX triage', () => {
  test('a manual triage suppresses the advisory and updates the row in place', async ({ page }) => {
    const seeded = await seedAndSignIn(page, 'triage')
    await openDetail(page, seeded)

    const main = page.locator('main.main-content')
    // `qs` carries exactly one advisory (CVE-2022-24999, VEX `in_triage`, SARIF `reachable`),
    // which the server buckets as `attend`. Triaging it to `not_affected` is the one edit that
    // moves it into the suppressed bucket, so both derived readings on the row have to change.
    // The PURL no longer renders in the row (it moved into the expanded detail panel), so the
    // component name is what identifies the row now — unique across this fixture's inventory.
    const row = main.locator('tr.component-row').filter({ hasText: 'qs' })
    await expect(row.locator('.badge.prio-attend')).toHaveText('Attend')
    await expect(row.locator('td.vuln-cell .hidden-count')).toHaveCount(0)

    // The name cell rather than the row's centre: any cell click expands the row, and the name
    // cell has no handler of its own to conflict with the row's.
    await row.locator('td.name-cell').click()
    const panel = main.locator('.detail-panel')
    await expect(panel.locator('.advisory-id')).toHaveText('CVE-2022-24999')

    await panel.getByRole('button', { name: 'Edit analysis' }).click()
    const form = panel.locator('.vex-form')
    await form.getByRole('combobox', { name: 'State', exact: true }).selectOption('not_affected')
    // Enabled only by the state above: CycloneDX defines a justification for not_affected alone.
    await form.getByRole('combobox', { name: 'Justification', exact: true }).selectOption('code_not_reachable')

    // A full page load would clear this; the save path is supposed to patch the row and refetch
    // quietly, not navigate.
    await page.evaluate(() => { (window as unknown as Record<string, string>).__e2eLoadMark = 'kept' })

    const saved = page.waitForResponse(res =>
      res.request().method() === 'PUT' && res.url().includes('/analysis'))
    await form.getByRole('button', { name: 'Save', exact: true }).click()
    expect((await saved).status()).toBe(200)

    // The two derived readings, not the request: the priority badge is gone (the row's only
    // advisory is no longer visible) and the suppressed-count chip states how many were hidden.
    await expect(row.locator('.badge[class*="prio-"]')).toHaveCount(0)
    const hidden = row.locator('td.vuln-cell .hidden-count')
    await expect(hidden).toHaveText('+1')
    await expect(hidden).toHaveAttribute('title', /1 suppressed/)

    // The expanded panel is still open on the same row, now reporting why it shows nothing.
    await expect(panel).toContainText('Every advisory on this component is suppressed.')

    expect(await page.evaluate(
      () => (window as unknown as Record<string, string>).__e2eLoadMark)).toBe('kept')

    // Turning suppressed advisories back on returns the advisory with its recorded decision —
    // the same state the server now holds, read back through the filter that hides it by default.
    // The Toggle's real checkbox is visually hidden, so the click goes to its wrapping label —
    // the same affordance an operator clicks.
    await main.locator('.filter-toggle', { hasText: 'Show suppressed' }).locator('label.toggle').click()
    await expect(row.locator('.badge.prio-suppressed')).toHaveText('Suppressed')
    await expect(panel).toContainText('Not affected')
    await expect(panel).toContainText('Code not reachable')
  })
})
