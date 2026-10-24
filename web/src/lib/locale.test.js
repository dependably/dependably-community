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
    // The first `document` read after the cookie write is the `typeof document` guard. Once the
    // cookie setter has run, the global reports undefined for exactly one read, which takes the
    // guard's else branch, so html[lang] must be left as it was.
    const realDoc = document
    const original = Object.getOwnPropertyDescriptor(globalThis, 'document')
    const writes = []
    vi.spyOn(realDoc, 'cookie', 'set').mockImplementation((v) => { writes.push(v) })
    let armed = false
    let hidden = 0
    Object.defineProperty(globalThis, 'document', {
      configurable: true,
      get() {
        if (armed) {
          armed = false
          hidden += 1
          return undefined
        }
        return realDoc
      },
    })
    realDoc.documentElement.lang = 'en'
    writes.push = (v) => { armed = true; return Array.prototype.push.call(writes, v) }
    try {
      applyLocale('fr')
    } finally {
      Object.defineProperty(globalThis, 'document', /** @type {PropertyDescriptor} */ (original))
    }
    expect(writes).toHaveLength(1)
    expect(writes[0]).toContain('.AspNetCore.Culture=')
    // The guard saw no document and returned without touching it. (html[lang] itself cannot be
    // asserted here: svelte-i18n's own locale store also writes it on every locale.set.)
    expect(hidden).toBe(1)
    expect(armed).toBe(false)
  })

  describe('cookie Secure attribute', () => {
    function captureCookieWrites() {
      const writes = []
      vi.spyOn(document, 'cookie', 'set').mockImplementation((v) => { writes.push(v) })
      return writes
    }

    it('adds Secure when served over https', () => {
      vi.stubGlobal('location', { protocol: 'https:' })
      const writes = captureCookieWrites()
      applyLocale('fr')
      vi.unstubAllGlobals()
      expect(writes).toEqual([
        '.AspNetCore.Culture=c%3Dfr%7Cuic%3Dfr; path=/; max-age=31536000; SameSite=Lax; Secure',
      ])
    })

    it('omits Secure over plain http', () => {
      vi.stubGlobal('location', { protocol: 'http:' })
      const writes = captureCookieWrites()
      applyLocale('fr')
      vi.unstubAllGlobals()
      expect(writes).toEqual([
        '.AspNetCore.Culture=c%3Dfr%7Cuic%3Dfr; path=/; max-age=31536000; SameSite=Lax',
      ])
    })

    it('omits Secure when there is no location', () => {
      vi.stubGlobal('location', undefined)
      const writes = captureCookieWrites()
      applyLocale('fr')
      vi.unstubAllGlobals()
      expect(writes[0]).not.toContain('Secure')
    })
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
