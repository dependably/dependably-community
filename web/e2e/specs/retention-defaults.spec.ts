import type { Page, Route } from '@playwright/test'
import { test, expect } from '../fixtures/index.js'

// Guards the one claim the Retention tab makes that is NOT uniform across its four fields:
// keep_versions / keep_days / purge_unlisted_after_days are opt-in, so an empty input really
// does mean unlimited, and the placeholder says so. activity_retention_days is not — a NULL
// there resolves to the ACTIVITY_RETENTION_DAYS instance default (90), enforced daily by the
// retention GC, because activity rows carry per-download IP/actor data and are bounded by
// design. The field used to render the same "unlimited" placeholder as its three neighbours,
// which told the operator the opposite of what the GC does.
//
// Nothing else pins this. There is no Svelte component-render harness in the repo, and the
// backend tests cannot see a placeholder, so a rename of activity_retention_default_days or a
// revert to the shared placeholder would ship silently. That is what this spec exists to catch.
//
// Backend-free: GET /retention is intercepted, so the assertion is about what the form renders
// for a given payload, not about which default this instance happens to be configured with.

const RETENTION_ALL_EMPTY = {
  keep_versions: null,
  keep_days: null,
  activity_retention_days: null,
  purge_unlisted_after_days: null,
  activity_retention_default_days: 90,
}

// OrgSettings.svelte fires four bootstrap GETs on mount; the tab strip does not render until
// they settle. Stub the three we do not exercise so a contended CI backend cannot stall the
// page, and serve our own payload for the fourth.
async function mockRetention(page: Page, retention: Record<string, unknown>) {
  const emptyJson = (route: Route) =>
    route.request().method() === 'GET'
      ? route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
      : route.fallback()
  await page.route('**/api/v1/settings', emptyJson)
  await page.route('**/api/v1/proxy-settings', emptyJson)
  await page.route('**/api/v1/instance/settings', emptyJson)
  await page.route('**/api/v1/retention', (route) =>
    route.request().method() === 'GET'
      ? route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(retention),
        })
      : route.fallback(),
  )
}

async function openStorageTab(page: Page) {
  await page.goto('/settings')
  // testid, not label text — i18n.spec.ts can leave the admin in French.
  await page.getByTestId('tab-storage').click()
  await expect(page.getByTestId('retention-activity-days')).toBeVisible()
}

test.describe('OrgSettings · Retention placeholders', () => {
  // i18n.spec.ts switches the admin to French and never switches back; every text assertion
  // below would fail behind it.
  test.beforeEach(async ({ adminPage }) => {
    await adminPage.evaluate(async () => {
      await fetch('/api/v1/users/me/language', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ language: 'en' }),
      })
    })
  })

  test('activity retention shows the instance default, never "unlimited"', async ({ adminPage }) => {
    await mockRetention(adminPage, RETENTION_ALL_EMPTY)
    await openStorageTab(adminPage)

    const activity = adminPage.getByTestId('retention-activity-days')
    const placeholder = await activity.getAttribute('placeholder')

    // The regression, stated directly: this field must not claim unlimited.
    expect(placeholder ?? '').not.toMatch(/unlimited/i)
    // and it must surface the number the GC will actually enforce.
    expect(placeholder ?? '').toContain('90')

    await expect(adminPage.getByTestId('retention-activity-hint')).toContainText(
      /ACTIVITY_RETENTION_DAYS/,
    )
  })

  // The must-NOT twin: the other three are genuinely opt-in, so "unlimited" is correct there.
  // Without this, a fix that simply removed the word everywhere would still pass the test above
  // while making three accurate labels wrong.
  test('the three opt-in fields still say unlimited', async ({ adminPage }) => {
    await mockRetention(adminPage, RETENTION_ALL_EMPTY)
    await openStorageTab(adminPage)

    for (const id of ['retention-keep-versions', 'retention-keep-days', 'retention-purge-unlisted']) {
      const placeholder = await adminPage.getByTestId(id).getAttribute('placeholder')
      expect(placeholder ?? '', `${id} placeholder`).toMatch(/unlimited/i)
    }
  })

  // An explicitly configured window must win over the default hint — otherwise the field would
  // read as "not configured" to an operator who did configure it.
  test('an explicit activity window is shown as the value, not the default', async ({ adminPage }) => {
    await mockRetention(adminPage, { ...RETENTION_ALL_EMPTY, activity_retention_days: 30 })
    await openStorageTab(adminPage)

    await expect(adminPage.getByTestId('retention-activity-days')).toHaveValue('30')
  })

  // If the server ever stops sending the effective default, the placeholder must go BLANK
  // rather than falling back to the shared "unlimited" string. Uninformative is acceptable;
  // untrue is not.
  test('a missing default renders blank, never "unlimited"', async ({ adminPage }) => {
    const { activity_retention_default_days: _omitted, ...withoutDefault } = RETENTION_ALL_EMPTY
    await mockRetention(adminPage, withoutDefault)
    await openStorageTab(adminPage)

    const placeholder = await adminPage.getByTestId('retention-activity-days').getAttribute('placeholder')
    expect(placeholder ?? '').not.toMatch(/unlimited/i)
  })
})
