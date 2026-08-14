import { Page } from '@playwright/test'
import { test, expect } from '../fixtures/index.js'
import { loginAsAdmin, inviteFreshAdmin } from '../helpers/api-client.js'
import { LoginPage } from '../pages/LoginPage.js'
import { NavPage } from '../pages/NavPage.js'
import { randomUUID } from 'crypto'

// The effective timezone and language are resolved server-side (user override → tenant default
// → instance fallback) into the /api/v1/auth/me payload and cached in the `user` store —
// web/src/lib/format.js derives every rendered `timeZone` from `$user.resolvedTimezone`, and
// App.svelte seeds `$user` from `applyUserContext` (web/src/lib/userContext.js). A save handler
// that writes the setting but never re-reads /me produces a correct database write, a 204, and
// a UI that keeps rendering the old value until the next full page load — invisible to every
// other gate, since curl and the backend suite both re-read /me on every request by construction.
//
// i18n.spec.ts already proves the CLIENT-SIDE locale switcher (Profile page's language select,
// which sets svelte-i18n's `locale` store directly) re-renders nav labels. These specs cover the
// different, narrower mechanism: a preference resolved server-side and cached on `user`, through
// the three call sites applyUserContext unifies — Profile.svelte's timezone save and
// OrgSettings.svelte's tenant-default save. No `page.reload()` and no re-login appear anywhere
// below; a reload would mask this entire defect class by re-running the boot-time /me read that
// always works.

const FORMAT_OPTIONS: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  timeZoneName: 'short',
}

// Fixed-offset IANA zones with no DST, so the expected rendered string is stable regardless of
// the calendar date the suite happens to run on.
// Both must appear verbatim in Intl.supportedValuesOf('timeZone') — the timezone <select>'s
// option values — which excludes some legacy-but-valid IANA names (e.g. 'Asia/Kolkata' resolves
// fine as an Intl.DateTimeFormat timeZone but is not itself in that enumeration; 'Asia/Calcutta',
// its pre-1995 link target, is).
const ZONE_A = 'Asia/Tokyo' // UTC+9, no DST
const ZONE_B = 'Asia/Dubai' // UTC+4, no DST

/**
 * Computes the exact string format.js's `formatDate` would render for `iso` in `timeZone`,
 * using the SAME engine (Chromium) the SPA itself renders with — an assertion this can compare
 * against exactly, not a tolerance.
 */
async function expectedFormattedText(page: Page, iso: string, timeZone: string, locale = 'en'): Promise<string> {
  return page.evaluate(
    ({ iso, timeZone, locale, options }) =>
      new Intl.DateTimeFormat(locale, { ...options, timeZone }).format(new Date(iso)),
    { iso, timeZone, locale, options: FORMAT_OPTIONS },
  )
}

/**
 * Creates a deterministic, uniquely-searchable Admin Actions row (an allowlist addition) and
 * returns its exact `createdAt` instant, read back from the API rather than assumed — the
 * "existing timestamp" each spec below re-renders after a preference save. The marker embeds a
 * fresh UUID so `search=<marker>` (AuditRepository.ListAuditAsync matches against
 * `audit_log.detail`) finds only this row, however much other traffic the shared instance is
 * carrying.
 */
async function createMarkerAuditRow(page: Page): Promise<{ marker: string; createdAt: string }> {
  const marker = `pkg:npm/e2e-pref-marker-${randomUUID()}`
  const created = await page.request.post('/api/v1/allowlist', { data: { purlPattern: marker } })
  expect(created.ok(), await created.text()).toBeTruthy()
  const listed = await page.request.get(
    `/api/v1/audit?action=allowlist_added&search=${encodeURIComponent(marker)}`,
  )
  expect(listed.ok()).toBeTruthy()
  const body = await listed.json()
  expect(body.items.length, JSON.stringify(body)).toBeGreaterThan(0)
  return { marker, createdAt: body.items[0].createdAt }
}

async function openAuditAdminActionsTab(page: Page, nav: NavPage) {
  await nav.goToAudit()
  // Audit.svelte: role="tab" strip, adminActions label = "Configuration"
  await page.locator('button.tab[role="tab"]', { hasText: 'Configuration' }).click()
}

/** The marker row's rendered timestamp cell — the first <td> of the row whose detail JSON
 *  contains the marker. */
function markerTimestampCell(page: Page, marker: string) {
  return page
    .locator('tr', { has: page.locator('.audit-detail-cell', { hasText: marker }) })
    .locator('td')
    .first()
}

async function searchAdminActions(page: Page, marker: string) {
  await page.getByPlaceholder(/Search action, actor, PURL, detail/).fill(marker)
  await expect(markerTimestampCell(page, marker)).toBeVisible({ timeout: 10_000 })
}

// UpdateOrgSettingsRequest's own field set (OrgRequests.cs) — the PUT model binds with
// UnmappedMemberHandling.Disallow, so a restore payload built from the raw GET response (which
// also carries read-only fields like `orgId`/`airGappedEnforced`/`rpmUpstreamModeEffective`)
// gets rejected with a 400. This is the exact allow-list api.js's own updateOrgSettings sends,
// plus `maxUploadBytesCargo`, which the request model accepts but the current SPA does not send.
const ORG_SETTINGS_PUT_FIELDS = [
  'anonymousPull', 'allowlistMode',
  'maxUploadBytes', 'maxUploadBytesPyPi', 'maxUploadBytesNpm', 'maxUploadBytesNuGet',
  'maxUploadBytesMaven', 'maxUploadBytesRpm', 'maxUploadBytesOci', 'maxUploadBytesCargo',
  'defaultLanguage', 'defaultTimezone',
  'allowVersionOverwrite', 'versionOverwritePolicy', 'airGapped', 'requireMfa',
]

/**
 * Snapshots `/api/v1/settings` (single-mode's one org, shared by the whole instance — including
 * `admin@dependably.local` and every other spec file's `adminPage`) and returns a restore
 * function. The tenant-default specs below mutate `defaultTimezone`/`defaultLanguage` on that
 * shared org through the real Settings → General save path, so a leftover 'fr' default would
 * otherwise leak into any other spec whose account has no personal language override of its own.
 */
async function snapshotOrgSettings(page: Page): Promise<() => Promise<void>> {
  const res = await page.request.get('/api/v1/settings')
  expect(res.ok()).toBeTruthy()
  const original = await res.json()
  const restorePayload = Object.fromEntries(
    ORG_SETTINGS_PUT_FIELDS.map(key => [key, original[key]]),
  )
  return async () => {
    const restore = await page.request.put('/api/v1/settings', { data: restorePayload })
    expect(restore.ok(), await restore.text()).toBeTruthy()
  }
}

/** Logs the given page into a brand-new tenant admin invited by `admin@dependably.local`. */
async function loginAsFreshAdmin(page: Page, baseURL: string) {
  const authedAdmin = await loginAsAdmin(baseURL)
  const fresh = await inviteFreshAdmin(authedAdmin, baseURL)
  await authedAdmin.dispose()

  const login = new LoginPage(page)
  await login.goto()
  await login.login(fresh.email, fresh.password)
  await login.expectNavVisible()
}

test.describe('Server-resolved preferences take effect without a reload', () => {
  test('saving a personal timezone override re-renders an existing timestamp', async ({ page, baseURL }) => {
    // A freshly-invited admin, not the shared `admin@dependably.local` — this spec's locators
    // read English UI text, and that shared account's language is not this spec's to assume:
    // i18n.spec.ts persists a French override to it via the Profile locale switcher, and a run
    // interleaved with that one would otherwise boot straight into a French-rendered session.
    await loginAsFreshAdmin(page, baseURL!)
    const nav = new NavPage(page)
    const { marker, createdAt } = await createMarkerAuditRow(page)

    // Whichever zone is currently cached in $user, pick a target that differs — a save handler
    // that never re-reads /me keeps rendering this stale value instead of the target's.
    const meBefore = await (await page.request.get('/api/v1/auth/me')).json()
    const staleZone = meBefore.resolvedTimezone
    const target = staleZone === ZONE_A ? ZONE_B : ZONE_A
    const expectedAfter = await expectedFormattedText(page, createdAt, target)

    await openAuditAdminActionsTab(page, nav)
    await searchAdminActions(page, marker)
    await expect(markerTimestampCell(page, marker)).not.toHaveText(expectedAfter)

    // Save a personal timezone override on the Profile page — in-app navigation only.
    await page.locator('.topbar .nav-actions button.nav-link', { hasText: 'Profile' }).click()
    const tzSelect = page.locator('select[aria-label="Timezone"]')
    await tzSelect.selectOption(target)
    await expect(tzSelect).toHaveValue(target)

    // Back to Audit — in-app navigation, no reload, no re-login — and assert the SAME
    // already-existing row now renders in the new zone.
    await openAuditAdminActionsTab(page, nav)
    await searchAdminActions(page, marker)
    await expect(markerTimestampCell(page, marker)).toHaveText(expectedAfter, { timeout: 10_000 })
  })

  test('saving the tenant default timezone re-renders an existing timestamp for the inheriting admin', async ({ page, baseURL }) => {
    await loginAsFreshAdmin(page, baseURL!)
    const nav = new NavPage(page)
    const restoreOrgSettings = await snapshotOrgSettings(page)

    try {
      const { marker, createdAt } = await createMarkerAuditRow(page)

      // The acting admin is a freshly-invited account with no personal timezone override, so the
      // tenant default is what they inherit.
      const meBefore = await (await page.request.get('/api/v1/auth/me')).json()
      const staleZone = meBefore.resolvedTimezone
      const target = staleZone === ZONE_A ? ZONE_B : ZONE_A
      const expectedAfter = await expectedFormattedText(page, createdAt, target)

      await openAuditAdminActionsTab(page, nav)
      await searchAdminActions(page, marker)
      await expect(markerTimestampCell(page, marker)).not.toHaveText(expectedAfter)

      // Settings → General → Default timezone, then Save — in-app navigation only.
      await nav.goToSettings()
      await page.locator('[data-testid="tab-general"]').click()
      const tzRow = page.locator('.form-row-inline', { hasText: 'Default timezone' })
      await tzRow.locator('select').selectOption(target)
      await page.locator('.card-narrow button.primary', { hasText: 'Save' }).click()
      await expect(page.locator('.text-success')).toHaveText('Settings saved.')

      await openAuditAdminActionsTab(page, nav)
      await searchAdminActions(page, marker)
      await expect(markerTimestampCell(page, marker)).toHaveText(expectedAfter, { timeout: 10_000 })
    } finally {
      await restoreOrgSettings()
    }
  })

  test('saving the tenant default language re-renders nav labels for the inheriting admin', async ({ page, baseURL }) => {
    // /me's language resolution ranks a negotiated request culture (query string / cookie /
    // Accept-Language, via RequestLocalization) ABOVE the tenant default for a user with no
    // personal override (AuthController.Me) — deliberately, so a French browser is not snapped
    // back to English right after login. Chromium's default Accept-Language ("en-US,en") would
    // otherwise resolve to 'en' every time regardless of what the tenant default is set to, so
    // this test's premise — the admin inheriting the tenant default — needs no provider to
    // match, which an unsupported header value guarantees (only en/fr are configured).
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'xx' })
    await loginAsFreshAdmin(page, baseURL!)
    const nav = new NavPage(page)
    const restoreOrgSettings = await snapshotOrgSettings(page)

    try {
      // en.json nav.packages = "Packages"; fr.json = "Paquets" — the same nav label i18n.spec.ts
      // checks for the client-side switcher, arriving here through the server-resolved /me
      // payload instead. The sidebar is app chrome, mounted once — no navigation is needed to
      // observe it.
      await expect(page.locator('nav.sidebar button.nav-link', { hasText: 'Packages' })).toBeVisible()

      // Settings → General → Default language, then Save — in-app navigation only.
      await nav.goToSettings()
      await page.locator('[data-testid="tab-general"]').click()
      const langRow = page.locator('.form-row-inline', { hasText: 'Default language' })
      await langRow.locator('select').selectOption('fr')
      await page.locator('.card-narrow button.primary', { hasText: 'Save' }).click()
      await expect(page.locator('.text-success')).toHaveText('Settings saved.')

      await expect(
        page.locator('nav.sidebar button.nav-link', { hasText: 'Paquets' }),
      ).toBeVisible({ timeout: 10_000 })
    } finally {
      await restoreOrgSettings()
    }
  })
})
