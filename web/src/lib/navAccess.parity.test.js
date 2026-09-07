import { describe, it, expect } from 'vitest'
import sidebarSrc from './Sidebar.svelte?raw'
import appSrc from '../App.svelte?raw'
import dashboardSrc from '../pages/Dashboard.svelte?raw'
import { RESTRICTED_PAGES } from './routes.js'

// The sidebar's restrictedItems and routes.js's RESTRICTED_PAGES must name the same pages: a
// page listed in one but not the other either shows a link its role gets bounced off, or bounces
// a role that has no way to reach the page anyway. Components cannot be imported here (vitest
// runs without the Svelte plugin — see vitest.config.js), so the sources are read as text via
// Vite's `?raw`, the same idiom SettingsWebhooks.parity.test.js uses.

const itemsMatch = sidebarSrc.match(
  /const restrictedItems = \[([\s\S]*?)\n {2}\]/,
)
if (!itemsMatch) {
  throw new Error(
    'Sidebar.svelte: could not find "const restrictedItems = [...]" — renamed or reshaped?',
  )
}
const sidebarRestrictedPages = [
  ...itemsMatch[1].matchAll(/page: '([^']+)'/g),
].map((m) => m[1])

describe('Sidebar restrictedItems ↔ routes.js RESTRICTED_PAGES parity', () => {
  it('lists exactly the pages RESTRICTED_PAGES restricts', () => {
    expect(new Set(sidebarRestrictedPages)).toEqual(
      new Set(RESTRICTED_PAGES.keys()),
    )
    expect(sidebarRestrictedPages.length).toBe(RESTRICTED_PAGES.size)
  })

  it('renders each link through canAccessPage rather than a hard-coded admin/owner check', () => {
    // The auditor reaches the audit link only because the filter consults the per-page
    // allow-list; a reintroduced `role === 'admin' || role === 'owner'` gate would hide it again.
    expect(sidebarSrc).toMatch(
      /restrictedItems\.filter\(\(item\) => canAccessPage\(item\.page, \$user\?\.role\)\)/,
    )
    expect(sidebarSrc).not.toMatch(
      /role === 'admin' \|\| \$user\?\.role === 'owner'/,
    )
  })
})

describe('App.svelte route guards use the same allow-list', () => {
  it('bounces on canAccessPage in both the reactive guard and the mount-time landing', () => {
    // One for navigations after boot, one for the deep link the user arrived on.
    const calls =
      appSrc.match(
        /!canAccessPage\((\$activeRoute|intended)\.page, (\$user|me)\.role\)/g,
      ) ?? []
    expect(calls).toEqual([
      '!canAccessPage($activeRoute.page, $user.role)',
      '!canAccessPage(intended.page, me.role)',
    ])
  })

  it('no longer carries its own admin/owner role test for page access', () => {
    expect(appSrc).not.toMatch(/role === 'admin' \|\| .*role === 'owner'/)
    expect(appSrc).not.toContain('ADMIN_ONLY_PAGES')
  })
})

describe('Dashboard audit drill-downs follow the audit allow-list', () => {
  it("gates every navigate('audit', …) tile on canOpenAudit, not isAdmin", () => {
    // Each tile is `{#if <flag>} <button … on:click={() => navigate('audit', …)}`; the flag on
    // an audit tile must be the one derived from canAccessPage('audit', role), so an auditor
    // who can open the page also gets the link into it.
    const tiles = [
      ...dashboardSrc.matchAll(
        /\{#if (\w+)\}\s*<button[^>]*?on:click=\{\(\) => navigate\('audit'/g,
      ),
    ]
    expect(tiles.length).toBeGreaterThan(0)
    for (const m of tiles) expect(m[1]).toBe('canOpenAudit')
    expect(dashboardSrc).toContain(
      "$: canOpenAudit = canAccessPage('audit', $user?.role)",
    )
  })
})
