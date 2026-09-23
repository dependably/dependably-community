import { describe, it, expect } from 'vitest'
import orgSettingsSrc from '../pages/OrgSettings.svelte?raw'

// OrgSettings.svelte cannot be mounted here (vitest runs without the Svelte plugin — see
// vitest.config.js and navAccess.parity.test.js's own note), so this pins the deep-link wiring
// by reading the real source, the same idiom navAccess.parity.test.js uses. What it proves:
// the page reads ?tab= exactly once at mount (not on every render, which would fight a manual
// tab click) and validates the requested tab against the role/mode-gated tabKeys list before
// switching — a requested tab this session cannot see must fall back to the 'general' default
// rather than switching into a tab whose form would then error.
describe('OrgSettings ?tab= deep link', () => {
  it('reads the requested tab once via readQuery, not on every render', () => {
    expect(orgSettingsSrc).toContain('const TAB_DEFAULTS = { tab:')
    expect(orgSettingsSrc).toContain('const requestedTab = readQuery(TAB_DEFAULTS).tab')
    expect(orgSettingsSrc).toContain('let appliedRequestedTab = false')
  })

  it('writes the current tab back through switchTab, so ?tab= tracks the tab actually on screen', () => {
    // Without this, a deep link's ?tab= value survives every later manual tab click — a reload
    // after switching to a different tab would silently jump back to the one the page opened on.
    const fn = orgSettingsSrc.match(/async function switchTab\(key\) \{([\s\S]*?)\n {2}\}/)
    expect(fn, 'switchTab was not found — renamed or reshaped?').toBeTruthy()
    expect(fn?.[1] ?? '').toContain('writeQuery({ tab: key }, TAB_DEFAULTS)')
  })

  it('gates the switch on tabKeys — never trusts the query string alone', () => {
    const guard = orgSettingsSrc.match(
      /\$: if \(!appliedRequestedTab && tabKeys\.length > 0\) \{([\s\S]*?)\n {2}\}/,
    )
    expect(guard, 'the one-shot ?tab= apply block was not found — renamed or reshaped?').toBeTruthy()
    const body = guard?.[1] ?? ''
    expect(body).toContain('appliedRequestedTab = true')
    expect(body).toContain("requestedTab !== 'general'")
    expect(body).toContain('tabKeys.some(k => k.key === requestedTab)')
    expect(body).toContain('switchTab(requestedTab)')
  })

  it('is a one-shot: the guard flips appliedRequestedTab before it can re-fire', () => {
    // A regression that dropped the `appliedRequestedTab = true` write (or moved it outside the
    // reactive block) would make every future render re-evaluate the ?tab= value, overriding a
    // user's own subsequent tab click back to whatever page they deep-linked in on.
    const idx = orgSettingsSrc.indexOf('appliedRequestedTab = true')
    const guardStart = orgSettingsSrc.indexOf('$: if (!appliedRequestedTab && tabKeys.length > 0)')
    expect(idx).toBeGreaterThan(guardStart)
  })
})
