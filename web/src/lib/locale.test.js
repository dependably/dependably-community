import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { get } from 'svelte/store'
import { locale } from 'svelte-i18n'

// Mock the api module before importing locale.js so switchLocale picks up the spies.
vi.mock('./api.js', () => ({
  api: { updateLanguage: vi.fn().mockResolvedValue(undefined) },
  systemApi: { updateLanguage: vi.fn().mockResolvedValue(undefined) },
}))

import { applyLocale, switchLocale, locales } from './locale.js'
import { user, bootstrapInfo } from './store.js'
import { api, systemApi } from './api.js'

beforeEach(() => {
  locale.set('en')
  user.set(null)
  bootstrapInfo.set(null)
  document.cookie = ''
  document.documentElement.lang = ''
  localStorage.clear()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('applyLocale', () => {
  it('updates the i18n store', () => {
    applyLocale('fr')
    expect(get(locale)).toBe('fr')
  })

  it('writes the ASP.NET culture cookie', () => {
    applyLocale('fr')
    // encodeURIComponent('c=fr|uic=fr') = 'c%3Dfr%7Cuic%3Dfr'
    expect(document.cookie).toContain('.AspNetCore.Culture=c%3Dfr%7Cuic%3Dfr')
  })

  it('persists to localStorage and html[lang]', () => {
    applyLocale('fr')
    expect(localStorage.getItem('locale')).toBe('fr')
    expect(document.documentElement.lang).toBe('fr')
  })
})

describe('switchLocale', () => {
  it('skips server persist when signed out', async () => {
    await switchLocale('fr')
    expect(api.updateLanguage).not.toHaveBeenCalled()
    expect(systemApi.updateLanguage).not.toHaveBeenCalled()
    expect(get(locale)).toBe('fr')
  })

  it('uses the tenant api when signed in on a tenant', async () => {
    user.set({ userId: 'u1' })
    bootstrapInfo.set({ isApex: false })

    await switchLocale('fr')

    expect(api.updateLanguage).toHaveBeenCalledWith('fr')
    expect(systemApi.updateLanguage).not.toHaveBeenCalled()
  })

  it('uses the system api when signed in at apex', async () => {
    user.set({ userId: 'sys' })
    bootstrapInfo.set({ isApex: true })

    await switchLocale('fr')

    expect(systemApi.updateLanguage).toHaveBeenCalledWith('fr')
    expect(api.updateLanguage).not.toHaveBeenCalled()
  })

  it('swallows server errors silently', async () => {
    user.set({ userId: 'u1' })
    bootstrapInfo.set({ isApex: false })
    vi.mocked(api.updateLanguage).mockRejectedValueOnce(new Error('500'))

    // Must not throw — locale change is non-fatal.
    await expect(switchLocale('fr')).resolves.toBeUndefined()
    expect(get(locale)).toBe('fr')
  })
})

describe('locales export', () => {
  it('lists English and French', () => {
    expect(locales.map((l) => l.code)).toEqual(['en', 'fr'])
  })
})
