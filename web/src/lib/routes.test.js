import { describe, it, expect, beforeEach } from 'vitest'
import { useRouter, pathFor, searchFor, routeFor, routesEqual, RESTRICTED_PAGES, canAccessPage } from './routes.js'

describe('routes — tenant table', () => {
  beforeEach(() => useRouter('tenant'))

  it('round-trips the risk page, which the dashboard risk tiles link into', () => {
    expect(pathFor('risk')).toBe('/risk')
    expect(routeFor('/risk')).toEqual({ page: 'risk', params: {} })
  })

  it('risk is not role-restricted — every role can open the rows behind a tile it can see', () => {
    // The drill-down endpoints gate on read:packages, the same capability that serves the
    // dashboard tiles. Listing 'risk' would bounce members off their own risk data.
    expect(RESTRICTED_PAGES.has('risk')).toBe(false)
    expect(canAccessPage('risk', 'member')).toBe(true)
  })

  it('deep-links the risk tabs and the blocked-pull audit window the dashboard tiles use', () => {
    expect(searchFor('risk', { tab: 'license' })).toBe('?tab=license')
    expect(searchFor('audit', { tab: 'lifecycle', type: 'blocked', since: '30d' }))
      .toBe('?tab=lifecycle&type=blocked&since=30d')
  })

  it('round-trips the policies page, and /license-policy aliases to it', () => {
    expect(pathFor('policies')).toBe('/policies')
    expect(routeFor('/policies')).toEqual({ page: 'policies', params: {} })
    expect(routeFor('/license-policy')).toEqual({ page: 'policies', params: {} })
  })

  it('policies is not role-restricted — both tabs gate on read:packages', () => {
    expect(RESTRICTED_PAGES.has('policies')).toBe(false)
    expect(canAccessPage('policies', 'member')).toBe(true)
  })

  it('deep-links the policies Controls tab', () => {
    expect(searchFor('policies', { tab: 'controls' })).toBe('?tab=controls')
  })

  it('pathFor returns the canonical path for a tenant page', () => {
    expect(pathFor('dashboard')).toBe('/')
    expect(pathFor('packages')).toBe('/packages')
    expect(pathFor('users')).toBe('/users')
  })

  it('pathFor builds the version-detail path with URL-encoded params', () => {
    const url = pathFor('version-detail', { ecosystem: 'npm', name: '@scope/pkg' })
    expect(url).toBe('/package/npm/%40scope/pkg')
  })

  it('pathFor falls back to "/" for unknown pages', () => {
    expect(pathFor('does-not-exist')).toBe('/')
  })

  it('pathFor("version-detail") with no params yields empty segments via nullish coalescing', () => {
    // Exercises the `params.ecosystem ?? ''` and `params.name ?? ''` branches.
    expect(pathFor('version-detail')).toBe('/package//')
  })

  it('pathFor("version-detail") with explicit nullish param values still falls back to empty string', () => {
    expect(pathFor('version-detail', { ecosystem: null, name: undefined })).toBe('/package//')
  })

  it('routeFor parses static paths back to (page, params)', () => {
    expect(routeFor('/packages')).toEqual({ page: 'packages', params: {} })
    expect(routeFor('/packages/')).toEqual({ page: 'packages', params: {} }) // trailing slash normalised
  })

  it('routeFor("/") returns dashboard without stripping the trailing slash', () => {
    // Hits the `path.length > 1` short-circuit (false) in the trailing-slash normaliser.
    expect(routeFor('/')).toEqual({ page: 'dashboard', params: {} })
  })

  it('routeFor parses version-detail paths and decodes the params', () => {
    expect(routeFor('/package/npm/%40scope/pkg')).toEqual({
      page: 'version-detail',
      params: { ecosystem: 'npm', name: '@scope/pkg' },
    })
  })

  it('routeFor returns null for unknown paths or non-strings', () => {
    expect(routeFor('/totally-bogus')).toBeNull()
    expect(routeFor(undefined)).toBeNull()
  })

  it('searchFor serializes params into a query string for list pages', () => {
    expect(searchFor('vulnerabilities', { sort: 'published', dir: 'desc' }))
      .toBe('?sort=published&dir=desc')
  })

  it('searchFor returns "" when there are no params', () => {
    expect(searchFor('vulnerabilities')).toBe('')
    expect(searchFor('packages', {})).toBe('')
  })

  it('searchFor drops empty/nullish values so a bare nav stays a clean URL', () => {
    expect(searchFor('vulnerabilities', { sort: '', eco: null, page: undefined })).toBe('')
    expect(searchFor('vulnerabilities', { sort: 'severity', eco: '' })).toBe('?sort=severity')
  })

  it('searchFor returns "" for version-detail — its params live in the path', () => {
    expect(searchFor('version-detail', { ecosystem: 'npm', name: 'foo' })).toBe('')
  })

  it('projects is not role-restricted — read visibility for every member', () => {
    expect(RESTRICTED_PAGES.has('projects')).toBe(false)
    expect(RESTRICTED_PAGES.has('project-detail')).toBe(false)
    expect(RESTRICTED_PAGES.has('project-version')).toBe(false)
    expect(canAccessPage('projects', 'member')).toBe(true)
    expect(canAccessPage('project-detail', 'auditor')).toBe(true)
  })

  it('pathFor round-trips the projects list', () => {
    expect(pathFor('projects')).toBe('/projects')
    expect(routeFor('/projects')).toEqual({ page: 'projects', params: {} })
  })

  it('pathFor builds the project-detail path with a URL-encoded GUID', () => {
    expect(pathFor('project-detail', { id: 'a b/c' })).toBe('/project/a%20b%2Fc')
  })

  it('pathFor builds the project-version path with two URL-encoded GUID segments', () => {
    expect(pathFor('project-version', { id: 'proj-1', versionId: 'ver-1' }))
      .toBe('/project/proj-1/version/ver-1')
  })

  it('pathFor("project-version") accepts the literal "latest" alias for versionId', () => {
    expect(pathFor('project-version', { id: 'proj-1', versionId: 'latest' }))
      .toBe('/project/proj-1/version/latest')
  })

  it('pathFor falls back to empty segments for project-detail/project-version with no params', () => {
    expect(pathFor('project-detail')).toBe('/project/')
    expect(pathFor('project-version')).toBe('/project//version/')
  })

  it('routeFor parses project-detail paths and decodes the id', () => {
    expect(routeFor('/project/proj-1')).toEqual({ page: 'project-detail', params: { id: 'proj-1' } })
    expect(routeFor('/project/a%20b')).toEqual({ page: 'project-detail', params: { id: 'a b' } })
  })

  it('routeFor parses project-version paths and decodes both ids', () => {
    expect(routeFor('/project/proj-1/version/ver-1')).toEqual({
      page: 'project-version',
      params: { id: 'proj-1', versionId: 'ver-1' },
    })
  })

  it('routeFor parses project-version with the literal "latest" versionId', () => {
    expect(routeFor('/project/proj-1/version/latest')).toEqual({
      page: 'project-version',
      params: { id: 'proj-1', versionId: 'latest' },
    })
  })

  it('searchFor returns "" for project-detail and project-version — their params live in the path', () => {
    expect(searchFor('project-detail', { id: 'proj-1' })).toBe('')
    expect(searchFor('project-version', { id: 'proj-1', versionId: 'latest' })).toBe('')
  })
})

describe('routes — system table', () => {
  beforeEach(() => useRouter('system'))

  it('pathFor and routeFor use the system page set when active', () => {
    // Canonical home is the operator dashboard; system-tenants lives at /tenants.
    expect(pathFor('system-dashboard')).toBe('/')
    expect(pathFor('system-tenants')).toBe('/tenants')
    expect(routeFor('/')).toEqual({ page: 'system-dashboard', params: {} })
    expect(routeFor('/tenants')).toEqual({ page: 'system-tenants', params: {} })
    expect(routeFor('/users')).toEqual({ page: 'system-users', params: {} })
  })

  it('pathFor("version-detail") in system mode does not match the tenant-only branch', () => {
    // Hits the `activeTable === 'tenant'` short-circuit (false) in pathFor; falls through to
    // the static lookup and ultimately the '/' fallback since version-detail isn't a system page.
    expect(pathFor('version-detail', { ecosystem: 'npm', name: 'foo' })).toBe('/')
  })

  it('routeFor("/package/...") in system mode falls through to static lookup', () => {
    // Exercises the `activeTable === 'tenant'` guard around the version-detail regex.
    expect(routeFor('/package/npm/foo')).toBeNull()
  })

  it('project-detail/project-version do not resolve in system mode', () => {
    expect(routeFor('/project/proj-1')).toBeNull()
    expect(routeFor('/project/proj-1/version/ver-1')).toBeNull()
    expect(pathFor('project-detail', { id: 'proj-1' })).toBe('/')
  })
})

describe('canAccessPage — role-restricted pages', () => {
  const restricted = ['quarantine', 'users', 'audit', 'upload', 'settings']

  it('restricts exactly the five pages the sidebar files under the Admin section', () => {
    expect([...RESTRICTED_PAGES.keys()].sort()).toEqual([...restricted].sort())
  })

  it('admits admin and owner to every restricted page', () => {
    for (const page of restricted) {
      expect(canAccessPage(page, 'admin'), page).toBe(true)
      expect(canAccessPage(page, 'owner'), page).toBe(true)
    }
  })

  it('keeps members off every restricted page', () => {
    for (const page of restricted) expect(canAccessPage(page, 'member'), page).toBe(false)
  })

  it('admits the auditor to the audit log and nothing else', () => {
    // AuditorCaps (Capabilities.cs) is read:audit + tokens:manage_own, and GET /api/v1/audit
    // and /activity gate on read:audit alone — so the audit page is the one restricted page an
    // auditor can actually use. The other four need capabilities the role does not hold.
    expect(canAccessPage('audit', 'auditor')).toBe(true)
    for (const page of restricted.filter((p) => p !== 'audit')) {
      expect(canAccessPage(page, 'auditor'), page).toBe(false)
    }
  })

  it('denies a missing or unknown role on a restricted page — no default-allow', () => {
    expect(canAccessPage('audit', undefined)).toBe(false)
    expect(canAccessPage('audit', null)).toBe(false)
    expect(canAccessPage('settings', 'system_admin')).toBe(false)
  })

  it('opens unlisted pages to every role, including one that is not yet resolved', () => {
    expect(canAccessPage('packages', 'member')).toBe(true)
    expect(canAccessPage('packages', undefined)).toBe(true)
    expect(canAccessPage('dashboard', 'auditor')).toBe(true)
    expect(canAccessPage('setup', 'member')).toBe(true)
  })

  it('the allow-lists are frozen — a page cannot be widened by mutation at a call site', () => {
    for (const roles of RESTRICTED_PAGES.values()) expect(Object.isFrozen(roles)).toBe(true)
  })
})

describe('routes — useRouter', () => {
  it('rejects unknown router names', () => {
    expect(() => useRouter('marketing')).toThrow(/unknown router/)
  })
})

describe('routesEqual', () => {
  it('treats nullish routes as not-equal', () => {
    expect(routesEqual(null, { page: 'x' })).toBe(false)
    expect(routesEqual({ page: 'x' }, undefined)).toBe(false)
    expect(routesEqual(null, null)).toBe(false)
  })

  it('compares pages and parameter shapes structurally', () => {
    const a = { page: 'version-detail', params: { ecosystem: 'npm', name: 'foo' } }
    const b = { page: 'version-detail', params: { ecosystem: 'npm', name: 'foo' } }
    const c = { page: 'version-detail', params: { ecosystem: 'pypi', name: 'foo' } }
    expect(routesEqual(a, b)).toBe(true)
    expect(routesEqual(a, c)).toBe(false)
  })

  it('returns false when param key sets differ in size', () => {
    const a = { page: 'p', params: { x: 1 } }
    const b = { page: 'p', params: { x: 1, y: 2 } }
    expect(routesEqual(a, b)).toBe(false)
  })

  it('treats missing params as an empty object (nullish coalescing branch)', () => {
    // Hits the `a.params ?? {}` and `b.params ?? {}` branches when params is absent.
    expect(routesEqual({ page: 'p' }, { page: 'p' })).toBe(true)
    expect(routesEqual({ page: 'p' }, { page: 'p', params: { x: 1 } })).toBe(false)
  })

  it('returns false when pages match but a param value differs at the same key', () => {
    const a = { page: 'p', params: { x: 1 } }
    const b = { page: 'p', params: { x: 2 } }
    expect(routesEqual(a, b)).toBe(false)
  })
})
