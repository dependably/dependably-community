import { describe, it, expect, beforeEach, vi } from 'vitest'
import { get } from 'svelte/store'
import { user } from './store.js'
import { timeZone, formatDate } from './format.js'
import { applyUserContext } from './userContext.js'

// The effective zone and language are resolved server-side, so the only way the SPA learns
// either changed is by re-reading /me and pushing it through here. These cover the push; what
// they cannot cover is a call site that forgets to call it — the repo has no Svelte
// component-render harness, so OrgSettings' own save path is verified by hand.
describe('applyUserContext', () => {
  beforeEach(() => user.set(null))

  it('makes a changed resolvedTimezone take effect without a reload', async () => {
    await applyUserContext({ resolvedTimezone: 'UTC', language: 'en' })
    expect(get(timeZone)).toBe('UTC')
    const before = get(formatDate)('2026-07-25T12:00:00Z')

    // What an admin saving the tenant default, or a user saving their own preference, sees:
    // a fresh /me payload and nothing else.
    await applyUserContext({ resolvedTimezone: 'Europe/Paris', language: 'en' })

    expect(get(timeZone)).toBe('Europe/Paris')
    expect(get(formatDate)('2026-07-25T12:00:00Z')).not.toBe(before)
  })

  it('leaves the locale alone when the payload matches what is already rendered', async () => {
    const applyLocale = vi.fn()
    vi.doMock('./locale.js', () => ({ applyLocale }))
    await applyUserContext({ resolvedTimezone: 'UTC', language: 'en' })
    expect(applyLocale).not.toHaveBeenCalled()
    vi.doUnmock('./locale.js')
  })

  it('seeds the user store so every consumer of it re-renders', async () => {
    await applyUserContext({ userId: 'u1', resolvedTimezone: 'Asia/Tokyo', language: 'en' })
    expect(get(user)).toMatchObject({ userId: 'u1', resolvedTimezone: 'Asia/Tokyo' })
  })
})
