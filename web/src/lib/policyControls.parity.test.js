import { describe, it, expect } from 'vitest'
import { POLICY_CONTROL_TOKENS } from './policies/policyControlTokens.js'
import en from '../locales/en.json'
import fr from '../locales/fr.json'

// Every token PolicyControls.svelte actually renders a row for (POLICY_CONTROL_TOKENS — the same
// source of truth the component itself builds its rows from, see policyControlTokens.js) needs a
// full policies.controls.<token>.{name,what} entry in every locale: `name` is the
// Control column's label, `what` the control's hover tip. Deliberately tests
// against POLICY_CONTROL_TOKENS rather than gates.js's BLOCK_GATES — BLOCK_GATES is a display
// baseline for a different surface (the dashboard Prevention panel) that is missing three tokens
// this page renders (malicious_live, ssvc_exploitation, epss_percentile), so asserting against it
// would leave those three permanently unchecked.
describe('PolicyControls tokens ↔ policies.controls parity', () => {
  it('POLICY_CONTROL_TOKENS is non-empty — a reflection/import regression here would make the checks below vacuous', () => {
    expect(POLICY_CONTROL_TOKENS.length).toBeGreaterThan(0)
  })

  it.each([
    ['en', en],
    ['fr', fr],
  ])('%s: every PolicyControls token has a name and a what', (_name, locale) => {
    for (const token of POLICY_CONTROL_TOKENS) {
      const entry = locale.policies?.controls?.[token]
      expect(entry, `policies.controls.${token} missing in ${_name}`).toBeDefined()
      for (const field of ['name', 'what']) {
        expect(typeof entry[field], `policies.controls.${token}.${field} missing in ${_name}`).toBe('string')
        expect(entry[field].length, `policies.controls.${token}.${field} is empty in ${_name}`).toBeGreaterThan(0)
      }
    }
  })
})
