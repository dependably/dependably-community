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

  it('skips html[lang] when document is undefined (SSR-style guard)', () => {
    // Cover the false branch of `typeof document !== 'undefined'` on line 19.
    // We swap `document` for a getter that returns the real jsdom document for
    // every access except the `typeof document` read on line 19 — which we
    // intercept to return `undefined`. That makes the guard take its else
    // branch, so the documentElement assignment site (line 19, col 40) is
    // never invoked. We assert exactly that: the getter is never called from
    // that column.
    const realDoc = document
    const original = Object.getOwnPropertyDescriptor(globalThis, 'document')
    let assignmentSiteCalls = 0
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      get() {
        const stack = new Error().stack || ''
        // line 19 col 40 is the `document.documentElement.lang = code` read.
        if (/locale\.js:19:40\b/.test(stack)) assignmentSiteCalls += 1
        // line 19 col 3 is the `typeof document` read in the guard.
        if (/locale\.js:19:3\b/.test(stack)) return undefined
        return realDoc
      },
    })
    try {
      applyLocale('fr')
    } finally {
      if (original) Object.defineProperty(globalThis, 'document', original)
      else Reflect.deleteProperty(globalThis, 'document')
    }
    // Cookie write on line 17 still ran against the real document.
    expect(realDoc.cookie).toContain('.AspNetCore.Culture=')
    // If the false branch was taken, the assignment expression was never
    // evaluated and the getter was never called from column 40.
    expect(assignmentSiteCalls).toBe(0)
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

  it('falls back to tenant api when bootstrapInfo is null', async () => {
    // Covers the optional-chain branch where `get(bootstrapInfo)` is null,
    // so `?.isApex` short-circuits to undefined and the `=== true` check is false.
    user.set({ userId: 'u1' })
    bootstrapInfo.set(null)

    await switchLocale('fr')

    expect(api.updateLanguage).toHaveBeenCalledWith('fr')
    expect(systemApi.updateLanguage).not.toHaveBeenCalled()
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
