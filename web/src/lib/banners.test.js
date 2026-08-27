import { describe, it, expect, beforeEach, vi } from 'vitest'
import { get } from 'svelte/store'

// Mocked before banners.js is imported so its module-level `api` binding picks up the spies.
vi.mock('./api.js', () => ({
  api: {
    getActiveBanners: vi.fn(),
    dismissBanner: vi.fn(),
  },
}))

import { activeBanners, loadActiveBanners, dismissBanner } from './banners.js'
import { api } from './api.js'

/**
 * @param {string} id
 * @param {'info'|'warn'|'alert'} [severity]
 * @returns {{ id: string, severity: 'info'|'warn'|'alert', body: string, linkUrl: string|null, linkLabel: string|null }}
 */
const banner = (id, severity = 'info') => ({
  id, severity, body: `body-${id}`, linkUrl: null, linkLabel: null,
})

beforeEach(() => {
  vi.clearAllMocks()
  activeBanners.set([])
})

describe('loadActiveBanners', () => {
  it('publishes what the server returned', async () => {
    const rows = [banner('a'), banner('b', 'alert')]
    vi.mocked(api.getActiveBanners).mockResolvedValueOnce(rows)

    await loadActiveBanners()

    expect(get(activeBanners)).toEqual(rows)
  })

  it('empties the store rather than throwing when the fetch fails', async () => {
    activeBanners.set([banner('stale')])
    vi.mocked(api.getActiveBanners).mockRejectedValueOnce(new Error('offline'))

    await expect(loadActiveBanners()).resolves.toBeUndefined()

    // Banners are non-critical UI: a network error must not leave a stale banner on screen
    // and must not prevent the rest of the app from loading.
    expect(get(activeBanners)).toEqual([])
  })

  it('treats a non-array payload as no banners', async () => {
    // The server is trusted to send an array; anything else is a contract break, and rendering
    // it would put a non-iterable in an {#each}.
    for (const payload of [null, undefined, { banners: [] }, 'nope']) {
      activeBanners.set([banner('stale')])
      vi.mocked(api.getActiveBanners).mockResolvedValueOnce(payload)

      await loadActiveBanners()

      expect(get(activeBanners)).toEqual([])
    }
  })
})

describe('dismissBanner', () => {
  it('removes the banner optimistically and tells the server', async () => {
    vi.mocked(api.dismissBanner).mockResolvedValueOnce(undefined)
    activeBanners.set([banner('a'), banner('b'), banner('c')])

    await dismissBanner('b')

    expect(get(activeBanners).map(b => b.id)).toEqual(['a', 'c'])
    expect(api.dismissBanner).toHaveBeenCalledWith('b')
  })

  it('keeps the banner dismissed locally when the server call fails', async () => {
    vi.mocked(api.dismissBanner).mockRejectedValueOnce(new Error('500'))
    activeBanners.set([banner('a'), banner('b')])

    await expect(dismissBanner('b')).resolves.toBeUndefined()

    expect(get(activeBanners).map(b => b.id)).toEqual(['a'])
  })

  it('removes before awaiting, so the UI does not wait on the round trip', async () => {
    /** @type {(value?: any) => void} */
    let release = () => {}
    vi.mocked(api.dismissBanner).mockReturnValueOnce(new Promise(r => { release = r }))
    activeBanners.set([banner('a')])

    const pending = dismissBanner('a')
    expect(get(activeBanners)).toEqual([])   // gone already, request still in flight

    release()
    await pending
  })

  it('leaves the list alone for an id it does not hold', async () => {
    vi.mocked(api.dismissBanner).mockResolvedValueOnce(undefined)
    activeBanners.set([banner('a')])

    await dismissBanner('missing')

    expect(get(activeBanners).map(b => b.id)).toEqual(['a'])
  })
})
