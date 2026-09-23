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
  ['projects',          '/projects'],
  ['audit',             '/audit'],
  ['tokens',            '/tokens'],
  ['settings',          '/settings'],
  ['users',             '/users'],
  ['setup',             '/setup'],
  ['upload',            '/upload'],
  ['vulnerabilities',   '/vulnerabilities'],
  ['quarantine',        '/quarantine'],
  ['risk',              '/risk'],
  ['policies',          '/policies'],
  ['policies',          '/license-policy'], // alias — canonical is '/policies'
  ['lookup',            '/lookup'],
  ['profile',           '/profile'],
  ['join',              '/join'],
  ['reset',             '/reset'],
  ['saml-test-result',  '/saml-test-result'],
  ['dashboard',         '/dashboard'], // alias — canonical is '/'
]

// Role-restricted pages: page → the roles allowed to open it. Any page not listed here is open
// to every authenticated role. Sidebar.svelte renders a listed page's nav link only for those
// roles (restrictedItems), and App.svelte bounces any other role that deep-links or bookmarks one
// of these URLs to the dashboard, so a restricted page never mounts and surfaces a raw backend 403.
// The role sets mirror the backend capability grants (Capabilities.cs): 'audit' admits 'auditor'
// because AuditorCaps carries read:audit, which is all GET /api/v1/audit and /activity gate on;
// the other four stay admin/owner-only (member holds ReaderCaps, auditor read:audit — neither
// reaches quarantine, users, upload, or settings). This is UX routing, not the security
// boundary — the backend remains the authority. Keep the page set
// in sync with the sidebar's restrictedItems (navAccess.parity.test.js pins it). (setup is
// intentionally excluded — it is shown to every user.)
const ADMIN_ROLES = Object.freeze(['admin', 'owner'])
export const RESTRICTED_PAGES = new Map([
  ['quarantine', ADMIN_ROLES],
  ['users', ADMIN_ROLES],
  ['audit', Object.freeze([...ADMIN_ROLES, 'auditor'])],
  ['upload', ADMIN_ROLES],
  ['settings', ADMIN_ROLES],
])

// canAccessPage: may a user with `role` open `page`? Unlisted pages are open to every role; a
// listed page requires an exact role match, so a missing/unknown role is denied there.
export function canAccessPage(page, role) {
  const roles = RESTRICTED_PAGES.get(page)
  return roles === undefined || roles.includes(role)
}

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
  // Projects epic: GUIDs in the path (labels are opaque user strings that may contain '/',
  // so — unlike version-detail's name segments — there is no multi-segment-encode dance here).
  if (activeTable === 'tenant' && page === 'project-version') {
    const id = encodeURIComponent(params.id ?? '')
    const versionId = encodeURIComponent(params.versionId ?? '')
    return `/project/${id}/version/${versionId}`
  }
  if (activeTable === 'tenant' && page === 'project-detail') {
    return `/project/${encodeURIComponent(params.id ?? '')}`
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
  // project-detail/project-version carry their identity as path GUIDs (see pathFor). A page
  // with its own URL-persisted table state (the project-version component table) writes its
  // query string directly via tableState.js's readQuery/writeQuery once mounted, independent of
  // navigate() — the same relationship Packages.svelte has with the plain 'packages' page.
  if (activeTable === 'tenant' && (page === 'project-detail' || page === 'project-version')) return ''
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

    // versionId also matches the literal 'latest' — a server-resolved alias, not a GUID; the
    // route layer passes whatever string is in the path through untouched.
    const mv = /^\/project\/([^/]+)\/version\/([^/]+)$/.exec(path)
    if (mv) {
      return {
        page: 'project-version',
        params: { id: decodeURIComponent(mv[1]), versionId: decodeURIComponent(mv[2]) },
      }
    }
    const mp = /^\/project\/([^/]+)$/.exec(path)
    if (mp) {
      return { page: 'project-detail', params: { id: decodeURIComponent(mp[1]) } }
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
