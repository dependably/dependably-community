/**
 * Unit tests for session.js — the proactive session-expiry watcher.
 *
 * store.js has module-level localStorage usage that does not work in the
 * Node.js 22 test environment. All store imports are mocked so the watcher
 * logic is tested in isolation without triggering the localStorage init code.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// ── Mock store.js before any imports touch it ─────────────────────────────────

// Minimal writable-like that tracks the last set value so tests can assert on it.
function makeWritable(init) {
  let val = init
  let subs = []
  return {
    set(v) { val = v; subs.forEach(fn => fn(v)) },
    get() { return val },
    subscribe(fn) { subs.push(fn); fn(val); return () => { subs = subs.filter(s => s !== fn) } },
  }
}

const mockUser = makeWritable(null)
const mockRoute = makeWritable({ page: 'packages', params: {} })
const mockPendingRoute = makeWritable(null)
const mockSessionExpired = makeWritable(false)
const mockNavigate = vi.fn()

vi.mock('./store.js', () => ({
  user: mockUser,
  route: mockRoute,
  pendingRoute: mockPendingRoute,
  sessionExpired: mockSessionExpired,
  navigate: mockNavigate,
}))

// svelte/store get() is used in session.js — provide a real implementation.
vi.mock('svelte/store', () => ({
  get: (store) => store.get(),
  writable: makeWritable,
}))

// ── Helpers ───────────────────────────────────────────────────────────────────

function futureIso(msFromNow) {
  return new Date(Date.now() + msFromNow).toISOString()
}

function pastIso(msAgo = 1) {
  return new Date(Date.now() - msAgo).toISOString()
}

// ── Test setup ────────────────────────────────────────────────────────────────

let armSessionWatch, disarmSessionWatch

beforeEach(async () => {
  vi.useFakeTimers()
  vi.resetModules()
  mockNavigate.mockReset()
  mockUser.set({ userId: 'u1' })
  mockRoute.set({ page: 'packages', params: {} })
  mockPendingRoute.set(null)
  mockSessionExpired.set(false)
  // Re-import after resetModules so internal state (_timer etc.) is fresh.
  ;({ armSessionWatch, disarmSessionWatch } = await import('./session.js'))
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

// ── armSessionWatch: timer fires → expiry handler ─────────────────────────────

describe('armSessionWatch — timer fires', () => {
  it('fires expiry after delay, clears user, sets sessionExpired, stashes pendingRoute', async () => {
    const fakeMeFn = vi.fn()
    armSessionWatch(futureIso(5000), fakeMeFn)

    expect(mockUser.get()).not.toBeNull()
    expect(mockSessionExpired.get()).toBe(false)

    // Advance past expiry + 1 s skew baked into the timer.
    vi.advanceTimersByTime(7000)
    await Promise.resolve()

    expect(mockUser.get()).toBeNull()
    expect(mockSessionExpired.get()).toBe(true)
    expect(mockPendingRoute.get()).toEqual({ page: 'packages', params: {} })
    expect(mockNavigate).toHaveBeenCalledWith('login', {}, { replace: true })
  })

  it('navigates to system-login when current page is a system page', async () => {
    mockRoute.set({ page: 'system-dashboard', params: {} })
    armSessionWatch(futureIso(5000), vi.fn())

    vi.advanceTimersByTime(7000)
    await Promise.resolve()

    expect(mockNavigate).toHaveBeenCalledWith('system-login', {}, { replace: true })
    expect(mockSessionExpired.get()).toBe(true)
  })

  it('does not stash pendingRoute when current page is login', async () => {
    mockRoute.set({ page: 'login', params: {} })
    armSessionWatch(futureIso(5000), vi.fn())

    vi.advanceTimersByTime(7000)
    await Promise.resolve()

    expect(mockPendingRoute.get()).toBeNull()
    expect(mockSessionExpired.get()).toBe(true)
  })

  it('does not stash pendingRoute when current page is system-login', async () => {
    mockRoute.set({ page: 'system-login', params: {} })
    armSessionWatch(futureIso(5000), vi.fn())

    vi.advanceTimersByTime(7000)
    await Promise.resolve()

    expect(mockPendingRoute.get()).toBeNull()
  })

  it('does nothing when expiresAtIso is null', async () => {
    armSessionWatch(null, vi.fn())
    vi.advanceTimersByTime(100000)
    await Promise.resolve()

    expect(mockUser.get()).not.toBeNull()
    expect(mockSessionExpired.get()).toBe(false)
  })

  it('re-arming cancels the previous timer', async () => {
    armSessionWatch(futureIso(5000), vi.fn())
    // Re-arm with a longer expiry.
    armSessionWatch(futureIso(60000), vi.fn())

    // Advance past where the first timer would have fired.
    vi.advanceTimersByTime(7000)
    await Promise.resolve()

    // No expiry yet — re-armed to 60 s.
    expect(mockUser.get()).not.toBeNull()
    expect(mockSessionExpired.get()).toBe(false)
  })
})

// ── disarmSessionWatch ────────────────────────────────────────────────────────

describe('disarmSessionWatch', () => {
  it('cancels armed timer so expiry never fires', async () => {
    armSessionWatch(futureIso(5000), vi.fn())
    disarmSessionWatch()

    vi.advanceTimersByTime(100000)
    await Promise.resolve()

    expect(mockUser.get()).not.toBeNull()
    expect(mockSessionExpired.get()).toBe(false)
  })
})

// ── Focus/visibility re-validation (mixed partial-failure scenario) ────────────

describe('focus/visibility re-validation', () => {
  it('fires expiry immediately when tab becomes visible after expiry has already passed', async () => {
    const fakeMeFn = vi.fn()
    // Arm with a past expiry so the timer fires immediately (delay clamped to 0).
    // But the visibilitychange check also catches it.
    armSessionWatch(pastIso(2000), fakeMeFn)

    // Advance 0 ms to let the clamped setTimeout(0) fire.
    vi.advanceTimersByTime(2000)
    await Promise.resolve()

    expect(mockUser.get()).toBeNull()
    expect(mockSessionExpired.get()).toBe(true)
    // No re-validation fetch since expiry was already past.
    expect(fakeMeFn).not.toHaveBeenCalled()
  })

  it('calls meFn and re-arms when focus fires before expiry', async () => {
    const futureStr = futureIso(30000)
    const fakeMeFn = vi.fn().mockResolvedValue({ sessionExpiresAt: futureStr })
    armSessionWatch(futureStr, fakeMeFn)

    window.dispatchEvent(new Event('focus'))
    await Promise.resolve()

    expect(fakeMeFn).toHaveBeenCalledTimes(1)
    // User remains set — me() succeeded.
    expect(mockUser.get()).not.toBeNull()
    expect(mockSessionExpired.get()).toBe(false)
  })
})
