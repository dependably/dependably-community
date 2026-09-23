import { test, expect, loginAs } from '../fixtures/index.js'
import { request, APIRequestContext } from '@playwright/test'
import { randomUUID } from 'crypto'
import { loginAsAdmin } from '../helpers/api-client.js'

/**
 * GET /api/v1/policies gates on read:packages, so a plain member — not just an admin — can open
 * the Policies page's Controls tab and see the gate posture that governs their own downloads.
 * This is the one thing no vitest suite can see: vitest.config.js carries no Svelte plugin (see
 * risk-pillars.spec.ts), so PolicyControls.svelte's actual DOM, reached by a non-admin session,
 * is observable nowhere but here.
 */
test.describe('Policies page — member access', () => {
  let memberEmail: string
  let memberPassword: string

  test.beforeAll(async ({ baseURL }) => {
    const admin = await loginAsAdmin(baseURL!)
    try {
      memberEmail = `e2e-policies-member-${randomUUID()}@dependably.local`
      memberPassword = 'E2ePoliciesMember123!'
      const res = await admin.post('/api/v1/invites', {
        data: { email: memberEmail, role: 'member' },
      })
      expect(res.ok(), `member invite failed: ${res.status()} ${await res.text()}`).toBeTruthy()
      const body = await res.json()
      const link: string | null = body.invite_link ?? null
      expect(link, 'invite response carried no invite_link — is SMTP configured in this harness?')
        .toBeTruthy()
      const token = new URL(link!).searchParams.get('token')
      expect(token, `invite_link had no token: ${link}`).toBeTruthy()

      const acceptCtx: APIRequestContext = await request.newContext({ baseURL })
      try {
        const acceptRes = await acceptCtx.post('/api/v1/invites/accept', {
          data: { token, password: memberPassword },
        })
        expect(acceptRes.ok(), `invite accept failed: ${acceptRes.status()} ${await acceptRes.text()}`)
          .toBeTruthy()
      } finally {
        await acceptCtx.dispose()
      }
    } finally {
      await admin.dispose()
    }
  })

  test('a member opens /policies?tab=controls and sees the gate values', async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (e) => pageErrors.push(e.message))

    await loginAs(page, memberEmail, memberPassword)
    await page.goto('/policies?tab=controls')

    // The sidebar link exists for this role (the page is not role-restricted) …
    await expect(page.locator('nav.sidebar')).toContainText(/Policies|Politiques/)

    // … and the Controls tab is the one selected, not the default Licences tab.
    const controlsTab = page.getByRole('tab', { name: /Controls|Contrôles/ })
    await expect(controlsTab).toHaveAttribute('aria-selected', 'true')

    // A control row from each group renders, proving the member's read:packages session
    // actually reached GET /api/v1/policies rather than being bounced. Each row's hover tip ends
    // with the reason token the 403 X-Dependably-Block-Reason header carries, and InfoTip mirrors
    // its text into aria-label, so the token is how a row is found.
    const main = page.locator('main.main-content')
    for (const token of ['malicious', 'vuln_score', 'provenance']) {
      await expect(main.getByRole('button', { name: new RegExp(`: ${token}\\.$`) }).first())
        .toBeVisible({ timeout: 10_000 })
    }

    // A human-readable name renders, not a raw i18n key — a missing policies.controls.<token>.name
    // key renders as the key string, not an error, so only a real DOM (which vitest's
    // Svelte-plugin-less setup cannot mount) can tell the two apart.
    await expect(main.locator('.control-name', { hasText: /Malicious package|Paquet malveillant/ }).first())
      .toBeVisible()

    // A row's hover tip is actually painted, not clipped by the table's .table-scroll wrapper
    // (overflow-x: auto clips vertically too). elementFromPoint at the bubble's centre returns
    // the bubble only if nothing clips or covers it there.
    const tipButton = main.getByRole('button', { name: /: vuln_score\.$/ }).first()
    await tipButton.hover()
    const bubble = tipButton.locator('xpath=following-sibling::*[@role="tooltip"]')
    await expect(bubble).toBeVisible()
    // The bubble is pointer-events: none, which elementFromPoint skips, so it is re-enabled for
    // the probe only.
    const painted = await bubble.evaluate((el: HTMLElement) => {
      el.style.pointerEvents = 'auto'
      const r = el.getBoundingClientRect()
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2)
      el.style.pointerEvents = ''
      return r.height > 0 && (hit === el || el.contains(hit))
    })
    expect(painted, 'InfoTip bubble in a Controls row is clipped or covered').toBe(true)

    expect(pageErrors, `uncaught page error on the Policies Controls tab: ${pageErrors.join('; ')}`)
      .toEqual([])
  })
})
