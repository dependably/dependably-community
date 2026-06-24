// URL ↔ route mapping for the SPA. URL is the source of truth; navigate() pushes via
// history.pushState, popstate restores by reading event.state (with routeFor() as a fallback
// when state is null — hard reloads, manual URL entry, some cross-origin returns).

let activeTable = 'tenant'

export function useRouter(which) {
  if (which !== 'tenant' && which !== 'system') throw new Error(`unknown router: ${which}`)
  activeTable = which
}

// Static page → canonical path. The first matching entry on parse wins; aliases are listed
// after the canonical entry but produce the same page.
const TENANT_STATIC = [
  ['dashboard',         '/'],
  ['login',             '/login'],
  ['packages',          '/packages'],
  ['audit',             '/audit'],
  ['tokens',            '/tokens'],
  ['settings',          '/settings'],
  ['users',             '/users'],
  ['setup',             '/setup'],
  ['upload',            '/upload'],
  ['vulnerabilities',   '/vulnerabilities'],
  ['quarantine',        '/quarantine'],
  ['license-policy',    '/license-policy'],
  ['profile',           '/profile'],
  ['join',              '/join'],
  ['saml-test-result',  '/saml-test-result'],
  ['dashboard',         '/dashboard'], // alias — canonical is '/'
]

const SYSTEM_STATIC = [
  ['system-dashboard',     '/'],
  ['system-login',         '/login'],
  ['system-users',         '/users'],
  ['system-audit',         '/audit'],
  ['system-settings',      '/settings'],
  ['system-profile',       '/profile'],
  ['system-admins',        '/admins'],
  ['system-tenants',       '/tenants'],
  ['system-banners',       '/banners'],
]

function staticTable() {
  return activeTable === 'system' ? SYSTEM_STATIC : TENANT_STATIC
}

// pathFor: page → URL. Uses the first canonical entry for the given page (aliases are skipped
// because the canonical entry is listed first and we return on first match).
export function pathFor(page, params = {}) {
  if (activeTable === 'tenant' && page === 'version-detail') {
    const eco = encodeURIComponent(params.ecosystem ?? '')
    const name = String(params.name ?? '').split('/').map(encodeURIComponent).join('/')
    return `/package/${eco}/${name}`
  }
  for (const [p, path] of staticTable()) {
    if (p === page) return path
  }
  return '/'
}

// searchFor: page → query string ('' or '?a=b&c=d'). version-detail carries its params in the
// path (see pathFor), so it never contributes a query string. Every other page serializes its
// params into the query string — which is how list pages (vulnerabilities, packages…) read their
// initial table state on mount (lib/tableState.js readQuery). This lets navigate() deep-link a
// list page with a non-default filter/sort, e.g. navigate('vulnerabilities', { sort: 'published' }).
// Empty/nullish values are dropped so a bare navigation still yields a clean URL = default state.
export function searchFor(page, params = {}) {
  if (activeTable === 'tenant' && page === 'version-detail') return ''
  const sp = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    sp.set(key, String(value))
  }
  const qs = sp.toString()
  return qs ? `?${qs}` : ''
}

// routeFor: pathname → { page, params } | null. Trailing slashes are normalized away.
// Segments are decodeURIComponent'd. Matching is case-sensitive against the canonical lowercase
// paths in the tables.
export function routeFor(pathname) {
  if (typeof pathname !== 'string') return null
  let path = pathname
  if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1)

  if (activeTable === 'tenant') {
    const m = /^\/package\/([^/]+)\/(.+)$/.exec(path)
    if (m) {
      return {
        page: 'version-detail',
        params: {
          ecosystem: decodeURIComponent(m[1]),
          name: m[2].split('/').map(decodeURIComponent).join('/'),
        },
      }
    }
  }

  for (const [page, p] of staticTable()) {
    if (p === path) return { page, params: {} }
  }
  return null
}

export function routesEqual(a, b) {
  if (!a || !b) return false
  if (a.page !== b.page) return false
  const pa = a.params ?? {}
  const pb = b.params ?? {}
  const ka = Object.keys(pa)
  const kb = Object.keys(pb)
  if (ka.length !== kb.length) return false
  for (const k of ka) if (pa[k] !== pb[k]) return false
  return true
}
