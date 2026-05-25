import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { get } from 'svelte/store'

// Real stores are reused so we can observe state transitions (user/pendingRoute/route)
// without mocking the whole module. fetch is the only thing we stub.
import { user, route, pendingRoute } from './store.js'

let api, ApiError
/** @type {import('vitest').Mock} */
let fetchMock

function jsonResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (h) => headers[h] ?? null },
    json: async () => body,
  }
}

beforeEach(async () => {
  // Each test starts from a clean slate of stores and a fresh fetch stub.
  user.set({ userId: 'u1', email: 'a@b' })
  route.set({ page: 'packages', params: {} })
  pendingRoute.set(null)
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  // Re-import so any cached fetch reference inside api.js (there isn't one, but be safe).
  ;({ api, ApiError } = await import('./api.js'))
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('req — happy path', () => {
  it('returns null on 204', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(204, null))
    const result = await api.logout()
    expect(result).toBeNull()
  })

  it('returns parsed JSON on 2xx', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { mode: 'single' }))
    const result = await api.getBootstrap()
    expect(result).toEqual({ mode: 'single' })
  })

  it('sets Content-Type, credentials, and serializes the body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ok: true }))
    await api.login('a@b', 'pw')
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/v1/auth/login')
    expect(opts.method).toBe('POST')
    expect(opts.credentials).toBe('include')
    expect(opts.headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(opts.body)).toEqual({ email: 'a@b', password: 'pw' })
  })

  it('omits the body on GET', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, []))
    await api.me()
    expect(fetchMock.mock.calls[0][1].body).toBeUndefined()
  })
})

describe('req — error path', () => {
  it('throws ApiError carrying status + retryAfter + detail', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(429, { detail: 'slow down' }, { 'Retry-After': '30' }),
    )

    const err = await api.me().catch((e) => e)

    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(429)
    expect(err.retryAfter).toBe('30')
    expect(err.message).toBe('slow down')
  })

  it('falls back to title then statusText when detail is missing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(500, { title: 'boom' }))
    let err = await api.me().catch((e) => e)
    expect(err.message).toBe('boom')

    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      headers: { get: () => null },
      json: async () => null,
    })
    err = await api.me().catch((e) => e)
    expect(err.message).toBe('Bad Gateway')
  })

  it('401 on /auth/login does NOT clear user or navigate', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'bad creds' }))

    await api.login('a@b', 'wrong').catch(() => {})

    // user remains set, no redirect.
    expect(get(user)).not.toBeNull()
    expect(get(route).page).toBe('packages')
  })

  it('401 elsewhere clears user and stashes pendingRoute', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'expired' }))

    await api.me().catch(() => {})

    expect(get(user)).toBeNull()
    expect(get(pendingRoute)).toEqual({ page: 'packages', params: {} })
    expect(get(route).page).toBe('login')
  })

  it('401 from /system/* path navigates to system-login', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'expired' }))
    // The system api endpoints all live under /system/.
    const { systemApi } = await import('./api.js')

    await systemApi.me().catch(() => {})

    expect(get(route).page).toBe('system-login')
  })

  it('401 from login/system-login/join routes does NOT stash pendingRoute', async () => {
    // If the current page is already one of the auth pages, there's nowhere meaningful
    // to send the user back to.
    route.set({ page: 'login', params: {} })
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'expired' }))

    await api.me().catch(() => {})

    expect(get(pendingRoute)).toBeNull()
  })
})

describe('endpoint contract', () => {
  // Each entry: [label, invocation, expectedMethod, expectedPathPredicate].
  // These are 1-line wrappers around req() so a single assertion per method (URL + method)
  // is enough to prove the wiring is correct without re-testing req()'s internals.
  /** @type {Array<[string, () => Promise<any>, string, string]>} */
  const cases = [
    ['getLicenses', () => api.getLicenses(), 'GET', '/api/v1/licenses'],
    ['logout', () => api.logout(), 'POST', '/api/v1/auth/logout'],
    ['me', () => api.me(), 'GET', '/api/v1/auth/me'],
    ['changePassword', () => api.changePassword('a', 'b'), 'POST', '/api/v1/users/me/password'],
    ['updateLanguage', () => api.updateLanguage('fr'), 'POST', '/api/v1/users/me/language'],
    ['getAuthMethods', () => api.getAuthMethods(), 'GET', '/api/v1/auth/methods'],
    ['getAuthConfig', () => api.getAuthConfig(), 'GET', '/api/v1/auth-config'],
    ['putAuthConfig', () => api.putAuthConfig({}), 'PUT', '/api/v1/auth-config'],
    ['uploadSamlMetadata', () => api.uploadSamlMetadata('<xml/>'), 'POST', '/api/v1/auth-config/metadata'],
    ['deleteAuthConfig', () => api.deleteAuthConfig(), 'DELETE', '/api/v1/auth-config'],
    ['getInstanceSettings', () => api.getInstanceSettings(), 'GET', '/api/v1/instance/settings'],
    ['getOrgSettings', () => api.getOrgSettings(), 'GET', '/api/v1/settings'],
    ['updateOrgSettings', () => api.updateOrgSettings({}), 'PUT', '/api/v1/settings'],
    ['getRetention', () => api.getRetention(), 'GET', '/api/v1/retention'],
    ['updateRetention', () => api.updateRetention({}), 'PUT', '/api/v1/retention'],
    ['getProxySettings', () => api.getProxySettings(), 'GET', '/api/v1/proxy-settings'],
    ['updateProxySettings', () => api.updateProxySettings({}), 'PUT', '/api/v1/proxy-settings'],
    ['getPackage', () => api.getPackage('npm', '@scope/pkg'), 'GET', '/api/v1/packages/npm/@scope%2Fpkg'],
    ['deleteVersion', () => api.deleteVersion('npm', '@scope/pkg', '1.0.0'), 'DELETE', '/api/v1/packages/npm/@scope%2Fpkg/1.0.0'],
    ['getActivity', () => api.getActivity(), 'GET', '/api/v1/activity?'],
    ['listClaims', () => api.listClaims(), 'GET', '/api/v1/admin/claims'],
    ['listClaimsWithParams', () => api.listClaims({ state: 'open' }), 'GET', '/api/v1/admin/claims?state=open'],
    ['getClaim', () => api.getClaim('npm', 'pkg'), 'GET', '/api/v1/admin/claims/npm/pkg'],
    ['createClaim', () => api.createClaim({}), 'POST', '/api/v1/admin/claims'],
    ['transitionClaim', () => api.transitionClaim('npm', 'pkg', {}), 'PATCH', '/api/v1/admin/claims/npm/pkg'],
    ['releaseClaim', () => api.releaseClaim('npm', 'pkg'), 'DELETE', '/api/v1/admin/claims/npm/pkg'],
    ['releaseClaimWithReason', () => api.releaseClaim('npm', 'pkg', 'abandoned'), 'DELETE', '/api/v1/admin/claims/npm/pkg?reason=abandoned'],
    ['getAudit', () => api.getAudit(), 'GET', '/api/v1/audit?'],
    ['getAllowlist', () => api.getAllowlist(), 'GET', '/api/v1/allowlist'],
    ['addAllowlist', () => api.addAllowlist('npm', 'foo*'), 'POST', '/api/v1/allowlist'],
    ['deleteAllowlist', () => api.deleteAllowlist('id-1'), 'DELETE', '/api/v1/allowlist/id-1'],
    ['getBlocklist', () => api.getBlocklist(), 'GET', '/api/v1/blocklist'],
    ['addBlocklist', () => api.addBlocklist('npm', 'bad*'), 'POST', '/api/v1/blocklist'],
    ['deleteBlocklist', () => api.deleteBlocklist('id-1'), 'DELETE', '/api/v1/blocklist/id-1'],
    ['listTokens', () => api.listTokens(), 'GET', '/api/v1/tokens'],
    ['createToken', () => api.createToken(['read:metadata'], null), 'POST', '/api/v1/tokens'],
    ['deleteToken', () => api.deleteToken('id-1'), 'DELETE', '/api/v1/tokens/id-1'],
    ['listServiceTokens', () => api.listServiceTokens(), 'GET', '/api/v1/service-tokens'],
    ['createServiceToken', () => api.createServiceToken('n', ['read:metadata'], null), 'POST', '/api/v1/service-tokens'],
    ['deleteServiceToken', () => api.deleteServiceToken('id'), 'DELETE', '/api/v1/service-tokens/id'],
    ['listInvites', () => api.listInvites(), 'GET', '/api/v1/invites'],
    ['createInvite', () => api.createInvite('a@b'), 'POST', '/api/v1/invites'],
    ['deleteInvite', () => api.deleteInvite('id'), 'DELETE', '/api/v1/invites/id'],
    ['listUsers', () => api.listUsers(), 'GET', '/api/v1/users'],
    ['removeUser', () => api.removeUser('u1'), 'DELETE', '/api/v1/users/u1'],
    ['updateUserRole', () => api.updateUserRole('u1', 'admin'), 'PATCH', '/api/v1/users/u1/role'],
    ['getSetup', () => api.getSetup('npm'), 'GET', '/api/v1/setup/npm'],
    ['getLicensePolicy', () => api.getLicensePolicy(), 'GET', '/api/v1/license-policy'],
    ['setLicenseMode', () => api.setLicenseMode('block'), 'PUT', '/api/v1/license-policy/mode'],
    ['addLicenseAllow', () => api.addLicenseAllow('MIT'), 'POST', '/api/v1/license-policy/allowlist'],
    ['removeLicenseAllow', () => api.removeLicenseAllow('MIT'), 'DELETE', '/api/v1/license-policy/allowlist/MIT'],
    ['addLicenseBlock', () => api.addLicenseBlock('GPL-3.0'), 'POST', '/api/v1/license-policy/blocklist'],
    ['removeLicenseBlock', () => api.removeLicenseBlock('GPL-3.0'), 'DELETE', '/api/v1/license-policy/blocklist/GPL-3.0'],
    ['getVulnReport', () => api.getVulnReport(), 'GET', '/api/v1/vuln-report?'],
    ['rescanVersion', () => api.rescanVersion('npm', '@scope/pkg', '1.0.0'), 'POST', '/api/v1/packages/npm/@scope%2Fpkg/1.0.0/rescan'],
    ['blockVersion', () => api.blockVersion('npm', 'pkg', '1.0.0'), 'POST', '/api/v1/packages/npm/pkg/1.0.0/block'],
    ['unblockVersion', () => api.unblockVersion('npm', 'pkg', '1.0.0'), 'POST', '/api/v1/packages/npm/pkg/1.0.0/unblock'],
    ['getStats', () => api.getStats(), 'GET', '/api/v1/stats'],
  ]

  it.each(cases)('%s — %s %s', async (_label, invoke, expectedMethod, expectedPathFragment) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, {}))
    await invoke().catch(() => {})
    const [url, opts] = fetchMock.mock.calls[0]
    expect(opts.method).toBe(expectedMethod)
    expect(url).toContain(expectedPathFragment)
  })
})

describe('systemApi contract', () => {
  it('listTenants paginates with explicit args', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, {}))
    const { systemApi } = await import('./api.js')
    await systemApi.listTenants(2, 25)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/system/tenants?page=2&limit=25')
  })

  /** @type {Array<[string, (s: any) => Promise<any>, string, string]>} */
  const systemCases = [
    ['createTenant', (s) => s.createTenant('acme', 'a@b'), 'POST', '/api/v1/system/tenants'],
    ['softDeleteTenant', (s) => s.softDeleteTenant('acme'), 'DELETE', '/api/v1/system/tenants/acme'],
    ['restoreTenant', (s) => s.restoreTenant('acme'), 'PATCH', '/api/v1/system/tenants/acme/restore'],
    ['listAudit', (s) => s.listAudit(), 'GET', '/api/v1/system/audit?'],
    ['getSettings', (s) => s.getSettings(), 'GET', '/api/v1/system/settings'],
    ['updateSettings', (s) => s.updateSettings({}), 'PUT', '/api/v1/system/settings'],
    ['setAccountStatus', (s) => s.setAccountStatus('a@b', 'acme', 'locked'), 'PATCH', '/api/v1/system/users/a%40b/account-status'],
    ['issuePasswordReset', (s) => s.issuePasswordReset('a@b', 'acme'), 'POST', '/api/v1/system/users/a%40b/password-reset'],
    ['changePassword', (s) => s.changePassword('a', 'b'), 'POST', '/api/v1/system/me/password'],
    ['updateLanguage', (s) => s.updateLanguage('fr'), 'POST', '/api/v1/system/me/language'],
  ]

  it.each(systemCases)('%s — %s %s', async (_label, invoke, expectedMethod, expectedPathFragment) => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, {}))
    const { systemApi } = await import('./api.js')
    await invoke(systemApi).catch(() => {})
    const [url, opts] = fetchMock.mock.calls[0]
    expect(opts.method).toBe(expectedMethod)
    expect(url).toContain(expectedPathFragment)
  })

  it('lookupUsers builds query with email + tenantSlug', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, {}))
    const { systemApi } = await import('./api.js')
    await systemApi.lookupUsers({ email: 'a@b', tenantSlug: 'acme', limit: 10 })
    const url = fetchMock.mock.calls[0][0]
    expect(url).toContain('email=a%40b')
    expect(url).toContain('tenantSlug=acme')
    expect(url).toContain('limit=10')
  })
})

describe('upload (multipart bypass)', () => {
  it('POSTs FormData and returns parsed body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { accepted: 1, rejected: 0 }))
    const file = new File(['payload'], 'a.tgz', { type: 'application/gzip' })

    const result = await api.upload([file])

    expect(result).toEqual({ accepted: 1, rejected: 0 })
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/v1/admin/upload')
    expect(opts.method).toBe('POST')
    expect(opts.credentials).toBe('include')
    expect(opts.body).toBeInstanceOf(FormData)
  })

  it('throws ApiError with body on non-OK', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(422, { detail: 'bad batch', outcomes: [] }))
    const file = new File(['payload'], 'a.tgz')

    const err = await api.upload([file]).catch((e) => e)

    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(422)
    expect(err.body).toEqual({ detail: 'bad batch', outcomes: [] })
  })
})

describe('qs (via listPackages)', () => {
  it('skips null params and keeps defaults', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, []))

    await api.listPackages({ search: 'foo', ecosystem: null })

    const url = fetchMock.mock.calls[0][0]
    expect(url).toContain('limit=50') // default
    expect(url).toContain('page=1')   // default
    expect(url).toContain('search=foo')
    expect(url).not.toContain('ecosystem') // null was skipped
  })

  it('caller-supplied undefined overrides spread defaults to nothing', async () => {
    // Mirrors how the impl threads params: spread happens after the defaults, so explicit
    // undefined wins. This is correct behavior; documenting it as a guardrail test.
    fetchMock.mockResolvedValueOnce(jsonResponse(200, []))

    await api.listPackages({ page: undefined })

    const url = fetchMock.mock.calls[0][0]
    expect(url).not.toContain('page=')
  })
})
