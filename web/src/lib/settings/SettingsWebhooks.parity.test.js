import { describe, it, expect } from 'vitest'
import componentSrc from './SettingsWebhooks.svelte?raw'

// SettingsWebhooks.svelte's ALL_EVENT_TYPES is declared inside a <script> block, and this
// project's vitest config runs without the Svelte plugin (component-level assertions are the
// Playwright e2e suite's job — see vite.config.js), so it cannot be `import`ed here. Importing
// the component source as text via Vite's `?raw` (the same idiom remediation.test.js uses,
// typed through the vite/client reference in global.d.ts) means this test actually reads what
// SettingsWebhooks.svelte declares — a hardcoded copy would pass whether or not the component
// agreed with it, which is exactly the tautology this replaced.

const arrayLiteralMatch = componentSrc.match(/const ALL_EVENT_TYPES = \[([\s\S]*?)\]/)
if (!arrayLiteralMatch) {
  throw new Error(
    'SettingsWebhooks.svelte: could not find "const ALL_EVENT_TYPES = [...]" — ' +
      'has the declaration been renamed or reshaped?',
  )
}
const allEventTypes = [...arrayLiteralMatch[1].matchAll(/'([^']+)'/g)].map(m => m[1])

// Mirrors WebhookController.ValidEventTypes exactly — see that field's own comment pointing
// back here and at this file. The two lists cannot be compared cross-language at test time, so
// each side is independently pinned to the same literal set; keep this list,
// SettingsWebhooks.svelte's ALL_EVENT_TYPES, and WebhookController.ValidEventTypes in lockstep
// by hand whenever a subscribable event type is added, renamed, or removed.
const expectedSubscribableEventTypes = [
  'package.publish',
  'package.replace',
  'package.import',
  'package.unlist',
  'package.yank',
  'package.vuln',
  'package.blocked',
]

describe('SettingsWebhooks ALL_EVENT_TYPES parity', () => {
  it('matches the pinned subscribable event-type set exactly', () => {
    expect(new Set(allEventTypes)).toEqual(new Set(expectedSubscribableEventTypes))
    // Catches a duplicate entry the Set comparison above would otherwise hide.
    expect(allEventTypes.length).toBe(expectedSubscribableEventTypes.length)
  })

  it('uses package.vuln, not package.vulnerability — the backend constant is package.vuln', () => {
    // Regression guard for the specific drift this parity check was added to catch: the UI
    // literal previously read 'package.vulnerability', which does not match
    // PackageEvents.TypeVuln = "package.vuln", so ticking that checkbox 422ed the whole save.
    expect(allEventTypes).toContain('package.vuln')
    expect(allEventTypes).not.toContain('package.vulnerability')
  })
})
