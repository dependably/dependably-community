import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// Hoisted spies so vi.mock factory can reference them.
const { registerSpy, initSpy, getLocaleFromNavigatorSpy } = vi.hoisted(() => ({
  registerSpy: vi.fn(),
  initSpy: vi.fn().mockReturnValue(Promise.resolve()),
  getLocaleFromNavigatorSpy: vi.fn(),
}))

vi.mock('svelte-i18n', () => ({
  register: registerSpy,
  init: initSpy,
  getLocaleFromNavigator: getLocaleFromNavigatorSpy,
}))

// Clear the .AspNetCore.Culture cookie between tests by expiring it.
function clearCultureCookie() {
  document.cookie = '.AspNetCore.Culture=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
}

beforeEach(() => {
  vi.resetModules()
  registerSpy.mockClear()
  initSpy.mockClear()
  initSpy.mockReturnValue(Promise.resolve())
  getLocaleFromNavigatorSpy.mockReset()
  clearCultureCookie()
})

afterEach(() => {
  clearCultureCookie()
})

describe('module side effects', () => {
  it('registers en and fr loaders on import', async () => {
    await import('./index.js')
    const codes = registerSpy.mock.calls.map((c) => c[0])
    expect(codes).toContain('en')
    expect(codes).toContain('fr')
    // Each register call gets a loader function as second arg.
    for (const call of registerSpy.mock.calls) {
      expect(typeof call[1]).toBe('function')
    }
  })
})

describe('setupI18n - locale resolution', () => {
  it('uses locale from .AspNetCore.Culture cookie when present', async () => {
    // Cookie value as written by the server: "c=fr|uic=fr" URL-encoded.
    document.cookie = `.AspNetCore.Culture=${encodeURIComponent('c=fr|uic=fr')}; path=/`
    getLocaleFromNavigatorSpy.mockReturnValue('de-DE')

    const { setupI18n } = await import('./index.js')
    setupI18n()

    expect(initSpy).toHaveBeenCalledTimes(1)
    expect(initSpy).toHaveBeenCalledWith({
      fallbackLocale: 'en',
      initialLocale: 'fr',
    })
    // Cookie wins over navigator.
    expect(getLocaleFromNavigatorSpy).not.toHaveBeenCalled()
  })

  it('falls back to navigator locale when no cookie is set', async () => {
    getLocaleFromNavigatorSpy.mockReturnValue('fr-CA')

    const { setupI18n } = await import('./index.js')
    setupI18n()

    expect(initSpy).toHaveBeenCalledWith({
      fallbackLocale: 'en',
      initialLocale: 'fr',
    })
  })

  it('falls back to "en" when neither cookie nor navigator yields a locale', async () => {
    getLocaleFromNavigatorSpy.mockReturnValue(null)

    const { setupI18n } = await import('./index.js')
    setupI18n()

    expect(initSpy).toHaveBeenCalledWith({
      fallbackLocale: 'en',
      initialLocale: 'en',
    })
  })

  it('falls back to "en" when navigator returns undefined', async () => {
    getLocaleFromNavigatorSpy.mockReturnValue(undefined)

    const { setupI18n } = await import('./index.js')
    setupI18n()

    expect(initSpy).toHaveBeenCalledWith({
      fallbackLocale: 'en',
      initialLocale: 'en',
    })
  })

  it('ignores cookie when present but lacks a uic=xx segment', async () => {
    // Cookie present but without the expected uic= subfield.
    document.cookie = `.AspNetCore.Culture=${encodeURIComponent('c=fr')}; path=/`
    getLocaleFromNavigatorSpy.mockReturnValue('it-IT')

    const { setupI18n } = await import('./index.js')
    setupI18n()

    // Cookie didn't parse to a uic locale, so we fell through to navigator.
    expect(initSpy).toHaveBeenCalledWith({
      fallbackLocale: 'en',
      initialLocale: 'it',
    })
  })

  it('treats a malformed (un-decodable) cookie value as no cookie', async () => {
    // %E0%A4%A is an incomplete percent escape and throws in decodeURIComponent.
    document.cookie = '.AspNetCore.Culture=%E0%A4%A; path=/'
    getLocaleFromNavigatorSpy.mockReturnValue('es-ES')

    const { setupI18n } = await import('./index.js')
    setupI18n()

    expect(initSpy).toHaveBeenCalledWith({
      fallbackLocale: 'en',
      initialLocale: 'es',
    })
  })

  it('returns the init() promise to the caller', async () => {
    const sentinel = Promise.resolve('init-done')
    initSpy.mockReturnValueOnce(sentinel)
    getLocaleFromNavigatorSpy.mockReturnValue('en-US')

    const { setupI18n } = await import('./index.js')
    const result = setupI18n()

    expect(result).toBe(sentinel)
    await expect(result).resolves.toBe('init-done')
  })

  it('surfaces errors thrown synchronously by svelte-i18n init', async () => {
    initSpy.mockImplementationOnce(() => {
      throw new Error('boom')
    })
    getLocaleFromNavigatorSpy.mockReturnValue('en-US')

    const { setupI18n } = await import('./index.js')
    expect(() => setupI18n()).toThrow('boom')
  })
})
