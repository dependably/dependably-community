import { describe, it, expect } from 'vitest'
import { IntlMessageFormat } from 'intl-messageformat'
import riskSrc from '../pages/Risk.svelte?raw'
import en from '../locales/en.json'
import fr from '../locales/fr.json'

// This project's vitest config runs without the Svelte plugin (component rendering is the
// Playwright e2e suite's job — see vite.config.js), so the page cannot be mounted here. The
// intro is instead reproduced from its two real inputs: the `$t` call site read out of
// Risk.svelte via Vite's `?raw`, and each locale's `risk.intro.operational` message formatted
// by the same ICU engine svelte-i18n uses. A call site that stops passing `threshold` — the
// exact regression this pins — formats to the literal placeholder and fails below.

const introCall = riskSrc.match(/<p class="intro">\{\$t\(`risk\.intro\.\$\{activeTab\}`(.*?)\)\}<\/p>/)
if (!introCall) {
  throw new Error('Risk.svelte: could not find the <p class="intro"> $t(`risk.intro.${activeTab}`) call site')
}
// Everything after the key inside the $t(...) call — the options argument, or '' when absent.
const introCallOptions = introCall[1]

// The values the component binds at that call site, mirroring what the page holds after
// GET /api/v1/risk/operational returns (threshold comes from the response body).
function renderedIntro(locale, activeTab, threshold) {
  const passesThreshold = /values:\s*\{[^}]*\bthreshold\b/.test(introCallOptions)
  const values = passesThreshold ? { threshold } : {}
  const message = locale.risk.intro[activeTab]
  return new IntlMessageFormat(message, locale === fr ? 'fr' : 'en').format(values)
}

describe('Risk page intro interpolation', () => {
  it.each([
    ['en', en],
    ['fr', fr],
  ])('%s: risk.intro.operational declares the {threshold} placeholder', (_name, locale) => {
    expect(locale.risk.intro.operational).toContain('{threshold}')
  })

  it.each([
    ['en', en],
    ['fr', fr],
  ])('%s: the rendered operational intro contains no literal {threshold}', (_name, locale) => {
    const rendered = renderedIntro(locale, 'operational', 5)
    expect(rendered).not.toContain('{threshold}')
    expect(rendered).toContain('5')
  })

  it('the licence intro renders unchanged under the shared values bag', () => {
    const rendered = renderedIntro(en, 'license', 5)
    expect(rendered).toBe(en.risk.intro.license)
  })
})
