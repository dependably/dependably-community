import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { get } from 'svelte/store'

// store.js initialises theme + reads from localStorage at module load — clear it before each test.
beforeEach(() => {
  localStorage.clear()
  // jsdom keeps history state between tests; reset to a fresh page.
  if (typeof window !== 'undefined') {
    window.history.replaceState(null, '', '/')
  }
  vi.resetModules()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('currentOrg (derived)', () => {
  it('null when bootstrapInfo is null', async () => {
    const { currentOrg, bootstrapInfo } = await import('./store.js')
    bootstrapInfo.set(null)
    expect(get(currentOrg)).toBeNull()
  })

  it('single mode reads tenantSlug straight from bootstrap', async () => {
    const { currentOrg, bootstrapInfo } = await import('./store.js')
    bootstrapInfo.set({ mode: 'single', tenantSlug: 'acme' })
    expect(get(currentOrg)).toEqual({ slug: 'acme' })
  })

  it('multi mode apex → no current tenant', async () => {
    const { currentOrg, bootstrapInfo } = await import('./store.js')
    bootstrapInfo.set({ mode: 'multi', isApex: true, apexHost: 'dependably.example.com' })
    expect(get(currentOrg)).toBeNull()
  })

  it('multi mode tenant subdomain derives slug from window.location.hostname', async () => {
    // window.location.hostname can't be set directly in jsdom; stub it via defineProperty.
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { hostname: 'acme.dependably.example.com' },
    })

    const { currentOrg, bootstrapInfo } = await import('./store.js')
    bootstrapInfo.set({
      mode: 'multi', isApex: false, apexHost: 'dependably.example.com',
    })
    expect(get(currentOrg)).toEqual({ slug: 'acme' })
  })

  it('multi mode tenant subdomain returns null when host does not end with apex', async () => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { hostname: 'unrelated.host' },
    })

    const { currentOrg, bootstrapInfo } = await import('./store.js')
    bootstrapInfo.set({
      mode: 'multi', isApex: false, apexHost: 'dependably.example.com',
    })
    expect(get(currentOrg)).toBeNull()
  })
})

describe('theme store', () => {
  it('falls back to "light" when localStorage has nothing', async () => {
    const { theme } = await import('./store.js')
    expect(get(theme)).toBe('light')
  })

  it('reads persisted theme from localStorage on load', async () => {
    localStorage.setItem('theme', 'dark')
    const { theme } = await import('./store.js')
    expect(get(theme)).toBe('dark')
  })

  it('writes back to localStorage when theme changes', async () => {
    const { theme } = await import('./store.js')
    theme.set('dark')
    expect(localStorage.getItem('theme')).toBe('dark')
    // Reflected on the html element too.
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })
})

describe('navigate + takePendingRoute', () => {
  it('pushState increments idx and updates route store', async () => {
    const { navigate, route } = await import('./store.js')
    navigate('packages', { search: 'foo' })
    expect(get(route)).toEqual({ page: 'packages', params: { search: 'foo' } })
    expect(window.history.state?.idx).toBeGreaterThanOrEqual(1)
  })

  it('replace: true uses replaceState and does not bump idx', async () => {
    const { navigate, route } = await import('./store.js')
    navigate('packages', {})            // push #1, idx=1
    const beforeIdx = window.history.state?.idx
    navigate('audit', {}, { replace: true })
    expect(get(route).page).toBe('audit')
    expect(window.history.state?.idx).toBe(beforeIdx)
  })

  it('navigating to the same route does not re-set the store', async () => {
    const { navigate, route } = await import('./store.js')
    navigate('packages', { q: 'x' })
    let calls = 0
    const unsub = route.subscribe(() => calls++)
    calls = 0
    navigate('packages', { q: 'x' })
    unsub()
    expect(calls).toBe(0)
  })

  it('takePendingRoute returns and clears the value', async () => {
    const { pendingRoute, takePendingRoute } = await import('./store.js')
    pendingRoute.set({ page: 'audit', params: {} })
    const taken = takePendingRoute()
    expect(taken).toEqual({ page: 'audit', params: {} })
    expect(get(pendingRoute)).toBeNull()
  })

  it('takePendingRoute returns null when nothing stashed', async () => {
    const { takePendingRoute } = await import('./store.js')
    expect(takePendingRoute()).toBeNull()
  })
})
