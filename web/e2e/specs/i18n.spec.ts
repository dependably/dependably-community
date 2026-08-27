import { test, expect } from '../fixtures/index.js'

// Locale switcher lives on the Profile page (Profile.svelte → Language settings row):
//   <select aria-label={$t('profile.rows.languageTitle')} ...>
//     <option value="en">English</option>
//     <option value="fr">Français</option>
//   </select>
// en.json profile.rows.languageTitle = "Language"; fr.json = "Langue"
// en.json nav.brand = "Dependably"; nav.packages = "Packages" (fr: "Paquets")

test.describe('i18n', () => {
  test('page renders with English text by default', async ({ adminPage }) => {
    const nav = adminPage.locator('nav.sidebar')
    await expect(nav).toBeVisible()
    await expect(nav.locator('.brand-text')).toContainText('Dependably')
    await expect(nav.locator('button.nav-link', { hasText: 'Packages' })).toBeVisible()
  })

  test('locale switcher is present on the Profile page', async ({ adminPage }) => {
    await adminPage.locator('.topbar .nav-actions button.nav-link', { hasText: 'Profile' }).click()
    const localeSwitcher = adminPage.locator('select[aria-label="Language"]')
    await expect(localeSwitcher).toBeVisible({ timeout: 5_000 })
  })

  test('locale switcher has English and French options', async ({ adminPage }) => {
    await adminPage.locator('.topbar .nav-actions button.nav-link', { hasText: 'Profile' }).click()
    const localeSwitcher = adminPage.locator('select[aria-label="Language"]')
    await expect(localeSwitcher.locator('option[value="en"]')).toHaveText('English')
    await expect(localeSwitcher.locator('option[value="fr"]')).toHaveText('Français')
  })

  test('switching to French updates nav labels', async ({ adminPage }) => {
    await adminPage.locator('.topbar .nav-actions button.nav-link', { hasText: 'Profile' }).click()
    const localeSwitcher = adminPage.locator('select[aria-label="Language"]')
    await localeSwitcher.selectOption('fr')
    // After switching, the Packages nav link should render in French ("Paquets").
    await expect(
      adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Paquets' })
    ).toBeVisible({ timeout: 5_000 })

    // Switch back. The language is a SERVER-SIDE preference on the one admin account the whole
    // suite shares, so leaving it on French hands every later spec a French UI and breaks any
    // selector keyed on an English label. Restoring narrows that window to this test's own
    // duration; it cannot close it entirely (CI runs two workers against the same account), which
    // is why locale-sensitive specs should use structural selectors rather than rely on this.
    //
    // Re-located by the options it carries, not by aria-label: that label is itself translated
    // ("Langue"), so the English-named locator above no longer matches the element it just used.
    await adminPage.locator('select:has(option[value="fr"])').selectOption('en')
    await expect(
      adminPage.locator('nav.sidebar button.nav-link', { hasText: 'Packages' })
    ).toBeVisible({ timeout: 5_000 })
  })
})
