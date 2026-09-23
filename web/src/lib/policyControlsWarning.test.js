import { describe, it, expect } from 'vitest'
import policyControlsSrc from './policies/PolicyControls.svelte?raw'

// PolicyControls.svelte cannot be mounted here (vitest runs without the Svelte plugin — see
// vitest.config.js and navAccess.parity.test.js's own note), so this pins the "not refreshing"
// warning's gating condition by reading the real source. The warning must cover every
// non-provenance row whose control carries an `active` field — kev/kev_ransomware/epss/
// epss_percentile included, not just malicious_live/ssvc_exploitation — because active=false
// means the same thing on every one of them: the control's data source stopped refreshing, but
// it still enforces on whatever it last recorded.
describe('PolicyControls "not refreshing" warning', () => {
  it('is gated on active === false && effect !== "off", not a fixed token allow-list', () => {
    expect(policyControlsSrc).toContain("c.active === false && c.effect !== 'off'")
    // The old per-token allow-list this replaced — its presence would mean the gate regressed
    // back to covering only two of the seven active-bearing controls.
    expect(policyControlsSrc).not.toMatch(
      /row\.token === 'malicious_live'\s*\|\|\s*row\.token === 'ssvc_exploitation'/,
    )
  })

  it('keeps the provenance anchorsConfigured warning on its own branch', () => {
    expect(policyControlsSrc).toContain("c.mode === 'block' && !c.anchorsConfigured")
  })
})
