import { describe, it, expect, beforeAll } from 'vitest'
import { get } from 'svelte/store'
import { addMessages, init, locale, t } from 'svelte-i18n'
import en from '../locales/en.json'
import fr from '../locales/fr.json'

// Formats the real locale files through svelte-i18n's ICU engine, so a plural block
// with a syntax error or a non-ICU "(s)" regression fails here instead of rendering
// garbage at runtime. French CLDR treats 0 as singular ("0 jour"), English does not.
beforeAll(async () => {
  addMessages('en', en)
  addMessages('fr', fr)
  await init({ fallbackLocale: 'en', initialLocale: 'en' })
})

function render(loc, key, values) {
  locale.set(loc)
  return get(t)(key, { values })
}

describe('ICU plural keys', () => {
  it('renders English recovery-code counts', () => {
    expect(render('en', 'profile.mfa.rowHelpOn', { count: 1 }))
      .toBe('Two-factor authentication is active. 1 recovery code remaining.')
    expect(render('en', 'profile.mfa.rowHelpOn', { count: 0 }))
      .toBe('Two-factor authentication is active. 0 recovery codes remaining.')
    expect(render('en', 'profile.mfa.rowHelpOn', { count: 8 }))
      .toBe('Two-factor authentication is active. 8 recovery codes remaining.')
  })

  it('renders French recovery-code counts with 0 as singular', () => {
    expect(render('fr', 'profile.mfa.rowHelpOn', { count: 0 }))
      .toBe("L'authentification à deux facteurs est active. 0 code de récupération restant.")
    expect(render('fr', 'profile.mfa.rowHelpOn', { count: 1 }))
      .toBe("L'authentification à deux facteurs est active. 1 code de récupération restant.")
    expect(render('fr', 'profile.mfa.rowHelpOn', { count: 5 }))
      .toBe("L'authentification à deux facteurs est active. 5 codes de récupération restants.")
  })

  it('renders SAML certificate day counts in both locales', () => {
    expect(render('en', 'dashboard.samlCertDays', { days: 1 })).toBe('1 day remaining')
    expect(render('en', 'dashboard.samlCertDays', { days: 30 })).toBe('30 days remaining')
    expect(render('fr', 'dashboard.samlCertDays', { days: 1 })).toBe('1 jour restant')
    expect(render('fr', 'dashboard.samlCertDays', { days: 30 })).toBe('30 jours restants')
  })

  it('renders the certificate expiry warning with day pluralization and notAfter intact', () => {
    expect(render('en', 'settings.auth.certExpiryWarningBody', { days: 1, notAfter: '2026-07-03' }))
      .toContain('expires in 1 day (2026-07-03)')
    expect(render('fr', 'settings.auth.certExpiryWarningBody', { days: 14, notAfter: '2026-07-16' }))
      .toContain('expire dans 14 jours (2026-07-16)')
  })

  it('keeps the existing upload.selected ICU block working', () => {
    expect(render('en', 'upload.selected', { count: 0 })).toBe('No files selected')
    expect(render('fr', 'upload.selected', { count: 2 })).toBe('2 fichiers sélectionnés')
  })
})
