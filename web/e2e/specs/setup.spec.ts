import type { Page } from '@playwright/test'
import { test, expect, loginAs } from '../fixtures/index.js'

/**
 * The Setup page's two tabs and its step ordering.
 *
 * What no other layer sees: vitest.config.js carries no Svelte plugin, so the markup that
 * binds the axes to the steps is rendered nowhere but here. A control left wired to the
 * component it used to live in, a tab that does not survive a reload, or a skill shortcut
 * offered for a cell that has no skill are all invisible to the unit suite — `skills.test.js`
 * proves the lookup returns null, not that the page then renders nothing.
 *
 * Each assertion is paired with the negative that makes it mean something: the operation
 * control is in step 1 AND not in step 2, the shortcut appears for npm/project AND not for a
 * cell with no skill.
 *
 * One login for the whole file, not one per case. Every login counts against the per-IP login
 * rate limiter and the suite already sits close to that budget; eight more were enough to push
 * a run over it, which surfaces as *other* specs timing out on `nav.sidebar` rather than as
 * anything pointing here. Serial mode is what makes sharing the page safe; each case navigates
 * to the surface it needs, so none depends on another's end state.
 */
test.describe('Setup', () => {
  test.describe.configure({ mode: 'serial' })

  let page: Page

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage()
    await loginAs(page)
  })

  test.afterAll(async () => {
    await page.close()
  })

  /** The step card carrying a given number, so an assertion can say which step it looked in. */
  const step = (page: import('@playwright/test').Page, n: number) =>
    page.locator('.step').filter({ has: page.locator('.num', { hasText: String(n) }) })

  test('renders both tabs, defaulting to Connect', async () => {
    await page.goto('/setup')
    await expect(page.getByTestId('tab-connect')).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByTestId('tab-skills')).toHaveAttribute('aria-selected', 'false')
    await expect(step(page, 1)).toBeVisible()
  })

  test('the skills tab deep-links and survives a reload', async () => {
    await page.goto('/setup')
    await page.getByTestId('tab-skills').click()
    await expect(page).toHaveURL(/[?&]tab=skills/)

    // The wizard is gone, and the remediation skills are listed with an install one-liner.
    await expect(step(page, 1)).toHaveCount(0)
    await expect(page.locator('.skill-block').first()).toBeVisible()
    await expect(page.locator('.skill-block').first()).toContainText('curl -fsSL')
    await expect(page.locator('.skill-block').first()).toContainText('/api/v1/skills/')

    await page.reload()
    await expect(page.getByTestId('tab-skills')).toHaveAttribute('aria-selected', 'true')
    await expect(page.locator('.skill-block').first()).toBeVisible()

    // And back: the default tab leaves no tab parameter behind.
    await page.getByTestId('tab-connect').click()
    await expect(page).not.toHaveURL(/[?&]tab=skills/)
    await expect(step(page, 1)).toBeVisible()
  })

  test('the skills tab offers the whole set two ways', async () => {
    await page.goto('/setup?tab=skills')
    await page.waitForSelector('.skill-block')

    // One command installing every skill, not nine.
    const bulk = page.locator('.bulk .copy-block-text')
    await expect(bulk).toContainText('for s in fix-')
    await expect(bulk).toContainText('~/.claude/skills/')

    // Switching assistant rewrites it in place, so the command never disagrees with the picker.
    await page.getByRole('button', { name: 'OpenAI Codex' }).first().click()
    await expect(bulk).toContainText('~/.codex/prompts/')
    await expect(bulk).not.toContainText('~/.claude/skills/')

    const zip = page.getByTestId('download-all-skills')
    await expect(zip).toHaveAttribute('href', '/api/v1/skills/bundle?family=remediation')
    await expect(zip).toHaveAttribute('download', '')
  })

  test('a skill name opens the document, with copy and download', async () => {
    await page.goto('/setup?tab=skills')
    await page.waitForSelector('.skill-block')

    const dialog = page.getByRole('dialog')
    await expect(dialog).toHaveCount(0)

    await page.locator('.skill-name', { hasText: 'fix-xss' }).click()
    await expect(dialog).toBeVisible()

    // Rendered, not raw: the markdown source markers must not survive to the screen.
    const body = dialog.locator('.markdown')
    await expect(body.locator('h2').first()).toBeVisible()
    await expect(body).not.toContainText('## When to use this')
    await expect(body.locator('script')).toHaveCount(0)

    // And the frontmatter is not spilled into the body — the header already carries those
    // two values, and Markdown would otherwise render the block as prose under a stray rule.
    await expect(body).not.toContainText('name: fix-xss')
    await expect(body).not.toContainText('description:')
    await expect(body.locator('hr').first()).toHaveCount(0)

    await expect(dialog.getByRole('link', { name: /Download SKILL\.md/ }))
      .toHaveAttribute('href', '/api/v1/skills/fix-xss')
    await expect(dialog.getByRole('button', { name: /Copy Markdown/ })).toBeVisible()

    await page.keyboard.press('Escape')
    await expect(dialog).toHaveCount(0)
  })

  test('the config skill in step 3 is readable too', async () => {
    await page.goto('/setup')
    const three = step(page, 3)
    await three.getByRole('tab', { name: 'This project' }).click()

    await three.locator('.skill-name', { hasText: 'npm-configure-project' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()
    await expect(dialog.locator('.markdown')).toContainText('npm')
    await expect(dialog.getByRole('link', { name: /Download SKILL\.md/ }))
      .toHaveAttribute('href', '/api/v1/skills/npm-configure-project')
  })

  test('the operation axis sits with the token, not with the package manager', async () => {
    await page.goto('/setup')
    const one = step(page, 1)
    const two = step(page, 2)

    await expect(one.getByRole('tab', { name: 'Install packages' })).toBeVisible()
    await expect(one.getByRole('tab', { name: 'Publish packages' })).toBeVisible()
    await expect(two.getByRole('tab', { name: 'Install packages' })).toHaveCount(0)

    // Step 2 is the package manager alone.
    await expect(two.locator('#setup-ecosystem')).toBeVisible()
    await expect(two.getByRole('tablist')).toHaveCount(0)
  })

  test('the scope axis sits with the configuration it reshapes', async () => {
    await page.goto('/setup')
    const three = step(page, 3)

    await expect(three.getByRole('tab', { name: 'This project' })).toBeVisible()
    await expect(three.getByRole('tab', { name: 'My machine' })).toBeVisible()
    await expect(step(page, 2).getByRole('tab', { name: 'This project' })).toHaveCount(0)
  })

  test('offers the curated skill for a cell that has one, and nothing for a cell that does not', async () => {
    await page.goto('/setup')
    const three = step(page, 3)

    // npm/project has a skill.
    await three.getByRole('tab', { name: 'This project' }).click()
    await expect(three.locator('.skill-block')).toContainText('npm-configure-project')
    await expect(three.locator('.skill-block')).toContainText('/api/v1/skills/npm-configure-project')

    // Terraform is machine-scope only and its one cell has a skill; OCI project scope does not
    // exist at all, so switching to OCI must leave the shortcut naming the global skill and
    // never an npm one.
    await page.locator('#setup-ecosystem').selectOption('oci')
    await expect(three.locator('.skill-block')).toContainText('docker-configure-global')
    await expect(three.locator('.skill-block')).not.toContainText('npm-configure')
  })
})
