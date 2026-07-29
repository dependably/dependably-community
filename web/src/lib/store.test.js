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
  vi.unstubAllGlobals()
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

describe('sidebarCollapsed store', () => {
  it('defaults to false (expanded) when localStorage has nothing', async () => {
    const { sidebarCollapsed } = await import('./store.js')
    expect(get(sidebarCollapsed)).toBe(false)
  })

  it('reads persisted "1" from localStorage as collapsed', async () => {
    localStorage.setItem('sidebarCollapsed', '1')
    const { sidebarCollapsed } = await import('./store.js')
    expect(get(sidebarCollapsed)).toBe(true)
  })

  it('persists "1"/"0" to localStorage when toggled', async () => {
    const { sidebarCollapsed } = await import('./store.js')
    sidebarCollapsed.set(true)
    expect(localStorage.getItem('sidebarCollapsed')).toBe('1')
    sidebarCollapsed.set(false)
    expect(localStorage.getItem('sidebarCollapsed')).toBe('0')
  })
})

describe('navigate + takePendingRoute', () => {
  // A user navigation is deferred: it mounts the incoming page hidden and commits when that page
  // reports its data has landed. Tests that care about the committed side drive the commit
  // themselves, standing in for the page that would have settled it.
  const commit = (store) => store.commitTransition()

  it('pushState increments idx and updates route store', async () => {
    const store = await import('./store.js')
    store.navigate('packages', { search: 'foo' })
    commit(store)
    expect(get(store.route)).toEqual({ page: 'packages', params: { search: 'foo' } })
    expect(window.history.state?.idx).toBeGreaterThanOrEqual(1)
  })

  it('a forward navigation holds the visible page until the arriving one settles', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)
    const pushSpy = vi.spyOn(window.history, 'pushState')

    store.navigate('vulnerabilities', {})
    // Nothing has swapped: the package list is still what the user is looking at, its URL is
    // still the one in the address bar, and no history entry has been created for a page that
    // may yet be abandoned.
    expect(get(store.route).page).toBe('packages')
    expect(pushSpy).not.toHaveBeenCalled()
    // The incoming page is mounted (hidden) so it can fetch, and nav highlighting follows it.
    expect(get(store.incomingRoute)?.page).toBe('vulnerabilities')
    expect(get(store.activeRoute).page).toBe('vulnerabilities')

    store.settleTransition(store.currentTransitionToken())
    expect(get(store.route).page).toBe('vulnerabilities')
    expect(get(store.incomingRoute)).toBeNull()
    expect(pushSpy).toHaveBeenCalled()
  })

  it('a page that never declares a load commits on the auto-commit frame', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)

    store.navigate('upload', {})
    // RouteHost calls this a frame after mounting. A page with no initial fetch has nothing to
    // wait for, so holding it for the full budget would make static pages the slowest in the app.
    store.settleIfUnclaimed(store.currentTransitionToken())
    expect(get(store.route).page).toBe('upload')
  })

  it('a page that declares a load is not committed by the auto-commit frame', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)

    store.navigate('vulnerabilities', {})
    const token = store.currentTransitionToken()
    store.claimTransition(token)
    store.settleIfUnclaimed(token)
    expect(get(store.route).page).toBe('packages')

    store.settleTransition(token)
    expect(get(store.route).page).toBe('vulnerabilities')
  })

  it('a stale token settles nothing', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)

    // The user clicks through to a second destination before the first has loaded. The first
    // page's fetch still resolves — and must not commit the page the user is now waiting on.
    store.navigate('vulnerabilities', {})
    const abandoned = store.currentTransitionToken()
    store.navigate('audit', {})
    expect(get(store.incomingRoute)?.page).toBe('audit')

    store.settleTransition(abandoned)
    expect(get(store.route).page).toBe('packages')
    expect(get(store.incomingRoute)?.page).toBe('audit')

    store.settleTransition(store.currentTransitionToken())
    expect(get(store.route).page).toBe('audit')
  })

  it('the visible page finishing a background load does not commit the incoming one', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)
    // The page being left was mounted outside any transition, so it holds no token at all —
    // its later loads (a poll, a row action's refetch) report against null and settle nothing.
    store.navigate('audit', {})
    store.settleTransition(null)
    expect(get(store.route).page).toBe('packages')
  })

  it('a transition commits on its own once the budget runs out', async () => {
    vi.useFakeTimers()
    try {
      const store = await import('./store.js')
      store.navigate('packages', {})
      commit(store)

      store.navigate('vulnerabilities', {})
      store.claimTransition(store.currentTransitionToken())
      // Held while the fetch is plausibly still in flight...
      vi.advanceTimersByTime(399)
      expect(get(store.route).page).toBe('packages')
      // ...but a page that never lands must not strand the user on the page they left.
      vi.advanceTimersByTime(1)
      expect(get(store.route).page).toBe('vulnerabilities')
    } finally {
      vi.useRealTimers()
    }
  })

  it('the progress strip stays dark through a fast navigation', async () => {
    vi.useFakeTimers()
    try {
      const store = await import('./store.js')
      store.navigate('packages', {})
      commit(store)

      store.navigate('vulnerabilities', {})
      store.claimTransition(store.currentTransitionToken())
      // A bar that appeared here would itself be the flicker — it would show and vanish inside
      // a few frames on a fetch that was never slow.
      vi.advanceTimersByTime(149)
      expect(get(store.transitionPending)).toBe(false)
      store.settleTransition(store.currentTransitionToken())
      vi.advanceTimersByTime(1000)
      expect(get(store.transitionPending)).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('the progress strip lights up for a navigation that outlives the grace period', async () => {
    vi.useFakeTimers()
    try {
      const store = await import('./store.js')
      store.navigate('packages', {})
      commit(store)

      store.navigate('vulnerabilities', {})
      store.claimTransition(store.currentTransitionToken())
      vi.advanceTimersByTime(150)
      expect(get(store.transitionPending)).toBe(true)
      store.settleTransition(store.currentTransitionToken())
      expect(get(store.transitionPending)).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('cancelTransition drops the held route without touching history', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)
    const pushSpy = vi.spyOn(window.history, 'pushState')

    // popstate: the user moved history themselves, so the destination being held is not where
    // they are going.
    store.navigate('vulnerabilities', {})
    store.cancelTransition()
    expect(get(store.incomingRoute)).toBeNull()
    expect(get(store.route).page).toBe('packages')
    expect(get(store.activeRoute).page).toBe('packages')
    expect(pushSpy).not.toHaveBeenCalled()
    // The abandoned page's fetch resolving afterwards settles nothing.
    store.settleTransition(1)
    expect(get(store.route).page).toBe('packages')
  })

  it('a cancelled transition stops its own budget timer', async () => {
    vi.useFakeTimers()
    try {
      const store = await import('./store.js')
      store.navigate('packages', {})
      commit(store)

      store.navigate('vulnerabilities', {})
      store.cancelTransition()
      vi.advanceTimersByTime(5000)
      expect(get(store.route).page).toBe('packages')
      expect(get(store.transitionPending)).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('re-navigating to the visible page abandons the transition in flight', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)

    store.navigate('vulnerabilities', {})
    // The user changes their mind and clicks back onto the page already on screen.
    store.navigate('packages', {})
    expect(get(store.incomingRoute)).toBeNull()
    expect(get(store.route).page).toBe('packages')
  })

  it('a replace navigation commits immediately rather than holding', async () => {
    const store = await import('./store.js')
    // Redirects — the initial landing, a guard bounce, a post-logout reset — have no outgoing
    // page worth holding, and deferring one would only delay the bounce.
    store.navigate('profile', {}, { replace: true })
    expect(get(store.route).page).toBe('profile')
    expect(get(store.incomingRoute)).toBeNull()
  })

  it('a replace navigation cancels a transition in flight', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)

    store.navigate('settings', {})
    // A guard rejects the held route before it is ever shown.
    store.navigate('dashboard', {}, { replace: true })
    expect(get(store.route).page).toBe('dashboard')
    expect(get(store.incomingRoute)).toBeNull()
    // The rejected page's fetch landing afterwards must not resurrect it.
    store.settleTransition(store.currentTransitionToken())
    expect(get(store.route).page).toBe('dashboard')
  })

  it('a fresh navigation serializes params into the URL query string', async () => {
    // The dashboard ribbon deep-links the vulnerabilities list to a non-default sort; the
    // list page reads that sort from window.location.search on mount, so navigate() must put
    // the params there (not just in the route store).
    const store = await import('./store.js')
    const spy = vi.spyOn(window.history, 'pushState')
    store.navigate('vulnerabilities', { sort: 'published', dir: 'desc' })
    commit(store)
    const url = spy.mock.calls[spy.mock.calls.length - 1][2]
    expect(url).toBe('/vulnerabilities?sort=published&dir=desc')
  })

  it('replace: true uses replaceState and does not bump idx', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})            // push #1, idx=1
    commit(store)
    const beforeIdx = window.history.state?.idx
    store.navigate('audit', {}, { replace: true })
    expect(get(store.route).page).toBe('audit')
    expect(window.history.state?.idx).toBe(beforeIdx)
  })

  it('navigating to the same route does not re-set the store', async () => {
    const store = await import('./store.js')
    store.navigate('packages', { q: 'x' })
    commit(store)
    let calls = 0
    const unsub = store.route.subscribe(() => calls++)
    calls = 0
    store.navigate('packages', { q: 'x' })
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

  it('preserveSearch: true appends window.location.search to the URL', async () => {
    // jsdom's history.replaceState doesn't propagate to window.location.search reliably,
    // so stub the location object directly.
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { hostname: 'localhost', search: '?foo=bar' },
    })
    const store = await import('./store.js')
    const spy = vi.spyOn(window.history, 'pushState')
    store.navigate('packages', {}, { preserveSearch: true })
    commit(store)
    expect(spy).toHaveBeenCalled()
    const url = spy.mock.calls[spy.mock.calls.length - 1][2]
    expect(url).toContain('?foo=bar')
  })

  it('re-navigating to the current route keeps the query string', async () => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { hostname: 'localhost', search: '?q=react&page=2' },
    })
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)
    const spy = vi.spyOn(window.history, 'replaceState')
    // Same route again (nav-link click on the page already shown): the component is
    // not remounted, so the table-state query params must survive in the URL.
    store.navigate('packages', {})
    expect(spy).toHaveBeenCalled()
    const url = spy.mock.calls[spy.mock.calls.length - 1][2]
    expect(url).toContain('?q=react&page=2')
  })

  it('a forward navigation seats the new page at the top', async () => {
    const store = await import('./store.js')
    const frames = []
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => { frames.push(cb); return 1 })
    const spy = vi.spyOn(window, 'scrollTo')
    store.navigate('packages', {})
    // Seated at the commit, not the click: while the transition is held the user is still
    // reading the outgoing page and moving them would be moving a page they did not leave.
    expect(spy).not.toHaveBeenCalled()
    commit(store)
    expect(spy).toHaveBeenCalledWith(0, 0)
    // Re-asserted after the page swap draws, because scroll anchoring restores the offset as
    // the arriving page's placeholders grow the document back.
    spy.mockClear()
    frames.forEach(cb => cb(0))
    expect(spy).toHaveBeenCalledWith(0, 0)
  })

  it('a forward navigation stamps the outgoing offset and starts the new entry at 0', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)
    // The user scrolled the package list before drilling into a version. The offset is read at
    // the commit, so scrolling further while the version page loads is still captured.
    vi.spyOn(window, 'scrollY', 'get').mockReturnValue(420)
    const replaceSpy = vi.spyOn(window.history, 'replaceState')
    const pushSpy = vi.spyOn(window.history, 'pushState')
    store.navigate('version-detail', { ecosystem: 'npm', name: 'left-pad' })
    commit(store)
    // Outgoing entry keeps the offset so Back lands where the user was...
    expect(replaceSpy.mock.calls[0][0]).toMatchObject({ page: 'packages', scroll: 420 })
    // ...while the arriving entry starts at the top.
    expect(pushSpy.mock.calls[0][0]).toMatchObject({ page: 'version-detail', scroll: 0 })
  })

  it('a same-route navigation neither scrolls nor clobbers the recorded offset', async () => {
    const store = await import('./store.js')
    store.navigate('packages', {})
    commit(store)
    window.history.replaceState({ ...window.history.state, scroll: 300 }, '')
    const scrollSpy = vi.spyOn(window, 'scrollTo')
    const replaceSpy = vi.spyOn(window.history, 'replaceState')
    // Nav-link click on the page already shown: nothing unmounts, so the viewport must not move.
    store.navigate('packages', {})
    expect(scrollSpy).not.toHaveBeenCalled()
    expect(replaceSpy.mock.calls[0][0]).toMatchObject({ page: 'packages', scroll: 300 })
  })

  it('restoreScroll reapplies a popped entry offset on the next frame', async () => {
    const { restoreScroll } = await import('./store.js')
    const frames = []
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => { frames.push(cb); return 1 })
    const spy = vi.spyOn(window, 'scrollTo')
    // The offset sticks on the first try — the page is already tall enough.
    vi.spyOn(window, 'scrollY', 'get').mockReturnValue(320)
    restoreScroll({ scroll: 320 })
    // Deferred: the arriving page must draw its placeholders before the offset is applied,
    // otherwise the browser clamps it against a document that is still a few lines tall.
    expect(spy).not.toHaveBeenCalled()
    frames.shift()(0)
    expect(spy).toHaveBeenCalledWith(0, 320)
    // Landed, so it stops rather than burning the remaining frames.
    expect(frames).toHaveLength(0)
  })

  it('restoreScroll retries while the arriving page is still too short to hold the offset', async () => {
    const { restoreScroll } = await import('./store.js')
    const frames = []
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => { frames.push(cb); return 1 })
    const spy = vi.spyOn(window, 'scrollTo')
    // The document is short, so every scrollTo is clamped back to 0 — the exact failure that
    // made a single deferred frame land Back at the top of a list the user had scrolled.
    vi.spyOn(window, 'scrollY', 'get').mockReturnValue(0)
    restoreScroll({ scroll: 900 })
    let ticks = 0
    while (frames.length && ticks < 50) { frames.shift()(0); ticks++ }
    expect(spy).toHaveBeenCalledWith(0, 900)
    // Bounded: it gives up rather than re-arming forever on a page that never grows.
    expect(spy.mock.calls.length).toBe(10)
  })

  it('restoreScroll falls back to the top for an entry with no stamped offset', async () => {
    const { restoreScroll } = await import('./store.js')
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => { cb(0); return 1 })
    const spy = vi.spyOn(window, 'scrollTo')
    restoreScroll(null)
    expect(spy).toHaveBeenCalledWith(0, 0)
  })

  it('navigate is a no-op on history when window.history is unavailable', async () => {
    const originalHistory = window.history
    // Force `window.history` to be falsy so the history branch is skipped.
    Object.defineProperty(window, 'history', { configurable: true, value: undefined })
    try {
      const store = await import('./store.js')
      store.navigate('audit', {})
      commit(store)
      // Store still updates even though history is unavailable.
      expect(get(store.route).page).toBe('audit')
    } finally {
      Object.defineProperty(window, 'history', { configurable: true, value: originalHistory })
    }
  })
})

describe('SSR-safe module load (no window/localStorage/document)', () => {
  it('module load tolerates missing localStorage (theme falls back to "light")', async () => {
    // Strip both localStorage (covers the module-init guard on line 17) and document
    // (so the subscribe-time write-back bails out cleanly — line 20).
    vi.stubGlobal('localStorage', undefined)
    vi.stubGlobal('document', undefined)
    const { theme } = await import('./store.js')
    expect(get(theme)).toBe('light')
  })

  it('theme subscriber bails out when document is undefined', async () => {
    vi.stubGlobal('document', undefined)
    const { theme } = await import('./store.js')
    // Setting a new theme must not throw despite document being undefined.
    expect(() => theme.set('dark')).not.toThrow()
    // And the write to localStorage on line 22 is skipped by the early return.
    expect(localStorage.getItem('theme')).toBeNull()
  })
})

describe('currentOrg multi-mode edge cases', () => {
  it('returns null when apexHost is missing (apex branch false)', async () => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { hostname: 'acme.dependably.example.com' },
    })
    const { currentOrg, bootstrapInfo } = await import('./store.js')
    // No apexHost → apex is '' → the endsWith check short-circuits to null.
    bootstrapInfo.set({ mode: 'multi', isApex: false })
    expect(get(currentOrg)).toBeNull()
  })
})
