import { get } from 'svelte/store'
import { user, route, navigate, pendingRoute } from './store.js'

const BASE = '/api/v1'

/** Error subclass carrying the HTTP status + parsed body so callers can route on `.status`. */
export class ApiError extends Error {
  /** @param {string} message
   *  @param {{ status: number, retryAfter?: string | null, body?: any }} extra */
  constructor(message, extra) {
    super(message)
    this.name = 'ApiError'
    this.status = extra.status
    this.retryAfter = extra.retryAfter ?? null
    this.body = extra.body
  }
}

/** Build a URLSearchParams string from a record whose values may be numbers. */
function qs(params) {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue
    u.set(k, String(v))
  }
  return u.toString()
}

/**
 * Download a CSV from `path` with the given query params. Builds a Blob and triggers
 * a synthetic <a download> so the browser saves the file. Throws ApiError on non-OK
 * so callers can render errors uniformly.
 */
async function downloadCsv(path, params, fallbackBaseName) {
  const q = qs(params)
  const res = await fetch(`${BASE}${path}${q ? '?' + q : ''}`, { credentials: 'include' })
  if (!res.ok) {
    const data = await res.json().catch(() => null)
    throw new ApiError(data?.detail || data?.title || res.statusText, {
      status: res.status,
      retryAfter: res.headers.get('Retry-After'),
      body: data,
    })
  }
  const blob = await res.blob()
  // Prefer server-provided filename when present in Content-Disposition.
  const cd = res.headers.get('Content-Disposition') ?? ''
  const m = /filename="?([^";]+)"?/.exec(cd)
  const filename = m?.[1] ?? `${fallbackBaseName}-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`

  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    URL.revokeObjectURL(url)
  }
}

async function req(method, path, body) {
  /** @type {RequestInit} */
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  }
  if (body !== undefined) opts.body = JSON.stringify(body)
  const res = await fetch(BASE + path, opts)
  if (res.status === 204) return null
  const data = await res.json().catch(() => null)
  if (!res.ok) {
    // Bad credentials on /auth/login is also 401; let Login.svelte render that inline.
    if (res.status === 401 && path !== '/auth/login') {
      user.set(null)
      // Stash where the user was so post-login returns them there.
      const current = get(route)
      if (current.page !== 'login' && current.page !== 'system-login' && current.page !== 'join') {
        pendingRoute.set(current)
      }
      navigate(path.startsWith('/system/') ? 'system-login' : 'login', {}, { replace: true })
    }
    throw new ApiError(data?.detail || data?.title || res.statusText, {
      status: res.status,
      retryAfter: res.headers.get('Retry-After'),
    })
  }
  return data
}

// All tenant-scoped endpoints are now host-implicit: the server resolves the tenant from the
// request host (multi mode) or the single-tenant resolver (single mode). The frontend no
// longer carries `org` in URLs. System-admin endpoints are at /api/v1/system/* and only
// reachable from the apex host (multi mode).
export const api = {
  // Bootstrap — public, unauthenticated. Returns { mode, isApex, apexHost?, tenantSlug?, capabilities }.
  getBootstrap: () => req('GET', '/bootstrap'),

  // Third-party attribution data (CycloneDX subset). Public, unauthenticated. May return
  // { devModeStub: true, count: 0, ... } when running `dotnet run` without a Docker build.
  getLicenses: () => req('GET', '/licenses'),

  // Auth
  login: (email, password) => req('POST', '/auth/login', { email, password }),
  logout: () => req('POST', '/auth/logout'),
  me: () => req('GET', '/auth/me'),
  changePassword: (currentPassword, newPassword) =>
    req('POST', '/users/me/password', { currentPassword, newPassword }),
  updateLanguage: (language) => req('POST', '/users/me/language', { language }),

  // Auth method discovery — anonymous; tells the login page whether to render forms, SAML, or both.
  // Shape: { forms: bool, saml: bool, samlButtonLabel: string|null }
  getAuthMethods: () => req('GET', '/auth/methods'),

  // Per-tenant SAML config (admin/owner only). Shape includes spInfo (acsUrl, metadataUrl,
  // defaultSpEntityId) so the IdP admin gets the values they need without leaving the page.
  getAuthConfig: () => req('GET', '/auth-config'),
  putAuthConfig: (cfg) => req('PUT', '/auth-config', cfg),
  uploadSamlMetadata: (metadataXml) => req('POST', '/auth-config/metadata', { metadataXml }),
  deleteAuthConfig: () => req('DELETE', '/auth-config'),

  // Instance settings (single-mode tenant owner; multi-mode equivalent lives under /system/)
  getInstanceSettings: () => req('GET', '/instance/settings'),
  updateInstanceSettings: (s) => req('PUT', '/instance/settings', s),

  // Tenant settings (per-org config)
  getOrgSettings: () => req('GET', '/settings'),
  updateOrgSettings: (s) => req('PUT', '/settings', {
    anonymousPull: s.anonymousPull,
    allowlistMode: s.allowlistMode,
    maxUploadBytes: s.maxUploadBytes,
    maxUploadBytesPyPi: s.maxUploadBytesPyPi,
    maxUploadBytesNpm: s.maxUploadBytesNpm,
    maxUploadBytesNuGet: s.maxUploadBytesNuGet,
    defaultLanguage: s.defaultLanguage,
    allowVersionOverwrite: s.allowVersionOverwrite,
  }),
  getRetention: () => req('GET', '/retention'),
  updateRetention: (r) => req('PUT', '/retention', r),
  getProxySettings: () => req('GET', '/proxy-settings'),
  updateProxySettings: (s) => req('PUT', '/proxy-settings', s),

  // Packages
  listPackages: (params = {}) => {
    const q = qs({ limit: 50, page: 1, ...params })
    return req('GET', `/packages?${q}`)
  },
  getPackage: (eco, name) => req('GET', `/packages/${eco}/${name.replaceAll('/', '%2F')}`),
  deleteVersion: (eco, name, ver) => req('DELETE', `/packages/${eco}/${name.replaceAll('/', '%2F')}/${ver}`),

  // Activity
  getActivity: (params = {}) => {
    const q = qs({ limit: 50, page: 1, ...params })
    return req('GET', `/activity?${q}`)
  },
  exportActivity: (params = {}) => downloadCsv('/activity', { ...params, format: 'csv' }, 'activity'),

  // Claims (#47) — admin only. State machine on the server enforces the legal transitions;
  // 4xx responses contain a structured `detail` that the UI surfaces verbatim.
  listClaims: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return req('GET', q ? `/admin/claims?${q}` : '/admin/claims')
  },
  getClaim: (eco, name) => req('GET', `/admin/claims/${eco}/${encodeURIComponent(name)}`),
  createClaim: (body) => req('POST', '/admin/claims', body),
  transitionClaim: (eco, name, body) => req('PATCH', `/admin/claims/${eco}/${encodeURIComponent(name)}`, body),
  releaseClaim: (eco, name, reason) => {
    const suffix = reason ? `?reason=${encodeURIComponent(reason)}` : ''
    return req('DELETE', `/admin/claims/${eco}/${encodeURIComponent(name)}${suffix}`)
  },

  // Admin upload — multipart/form-data with N files of any supported ecosystem. The server
  // detects each file's ecosystem from content (magic bytes + required manifest entry), so
  // there's no ecosystem field. Returns a per-file outcome summary keyed by filename.
  // Bypasses the JSON req() helper because we need multipart and don't want to re-encode bytes.
  upload: async (files) => {
    const fd = new FormData()
    for (const f of files) fd.append('files', f, f.name)
    const res = await fetch(`${BASE}/admin/upload`, {
      method: 'POST',
      credentials: 'include',
      body: fd,
    })
    const data = await res.json().catch(() => null)
    if (!res.ok) {
      throw new ApiError(data?.detail || data?.title || res.statusText, {
        status: res.status,
        body: data,
      })
    }
    return data
  },

  // Audit log (tenant scope; admin/owner only)
  getAudit: (params = {}) => {
    const q = qs({ limit: 50, page: 1, ...params })
    return req('GET', `/audit?${q}`)
  },
  exportAudit: (params = {}) => downloadCsv('/audit', { ...params, format: 'csv' }, 'audit'),

  // Allowlist
  getAllowlist: () => req('GET', '/allowlist'),
  addAllowlist: (purlPattern) => req('POST', '/allowlist', { purlPattern }),
  deleteAllowlist: (id) => req('DELETE', `/allowlist/${id}`),

  // Blocklist
  getBlocklist: () => req('GET', '/blocklist'),
  addBlocklist: (pattern) => req('POST', '/blocklist', { pattern }),
  deleteBlocklist: (id) => req('DELETE', `/blocklist/${id}`),

  // User tokens. capabilities is an array like ["read:metadata", "publish:*"];
  // the server rejects the retired `scope` field with a 400.
  listTokens: () => req('GET', '/tokens'),
  createToken: (capabilities, expiresAt) => req('POST', '/tokens', { capabilities, expiresAt }),
  deleteToken: (id) => req('DELETE', `/tokens/${id}`),

  // CI/CD tokens. Same capabilities shape as user tokens; `name` distinguishes the row.
  listCicdTokens: () => req('GET', '/cicd-tokens'),
  createCicdToken: (name, capabilities, expiresAt) =>
    req('POST', '/cicd-tokens', { name, capabilities, expiresAt }),
  deleteCicdToken: (id) => req('DELETE', `/cicd-tokens/${id}`),

  // Invites
  listInvites: () => req('GET', '/invites'),
  createInvite: (email, role = 'member') => req('POST', '/invites', { email, role }),
  deleteInvite: (id) => req('DELETE', `/invites/${id}`),

  // Users / members
  listUsers: () => req('GET', '/users'),
  removeUser: (userId) => req('DELETE', `/users/${userId}`),
  updateUserRole: (userId, role) => req('PATCH', `/users/${userId}/role`, { role }),

  // Setup snippets
  getSetup: (ecosystem) => req('GET', `/setup/${ecosystem}`),

  // License policy (#21). Mode is one of 'off' | 'warn' | 'block'. Allow/block lists are
  // SPDX identifiers; DELETE keys on the SPDX itself (not an opaque id).
  getLicensePolicy: () => req('GET', '/license-policy'),
  setLicenseMode: (mode) => req('PUT', '/license-policy/mode', { mode }),
  addLicenseAllow: (spdx) => req('POST', '/license-policy/allowlist', { licenseSpdx: spdx }),
  removeLicenseAllow: (spdx) => req('DELETE', `/license-policy/allowlist/${encodeURIComponent(spdx)}`),
  addLicenseBlock: (spdx) => req('POST', '/license-policy/blocklist', { licenseSpdx: spdx }),
  removeLicenseBlock: (spdx) => req('DELETE', `/license-policy/blocklist/${encodeURIComponent(spdx)}`),
  // SPDX reference data (seeded from license-list-data 3.28.0). q is a case-insensitive
  // identifier+name substring filter; includeDeprecated surfaces retired SPDX IDs.
  searchSpdx: (q = '', includeDeprecated = false, limit = 50) =>
    req('GET', `/spdx-licenses?${qs({ q, includeDeprecated, limit })}`),
  getSpdx: (identifier) => req('GET', `/spdx-licenses/${encodeURIComponent(identifier)}`),
  // Review queue: SPDX IDs seen during ingestion but not yet on allow/block. Admin-only.
  getLicenseReview: (includeDeprecated = false) =>
    req('GET', `/license-policy/review?${qs({ includeDeprecated })}`),

  // Vulnerabilities
  getVulnReport: (params = {}) => {
    const q = qs({ limit: 50, page: 1, ...params })
    return req('GET', `/vuln-report?${q}`)
  },
  rescanVersion: (eco, name, version) =>
    req('POST', `/packages/${eco}/${name.replaceAll('/', '%2F')}/${version}/rescan`),
  blockVersion: (eco, name, version) =>
    req('POST', `/packages/${eco}/${name.replaceAll('/', '%2F')}/${version}/block`),
  unblockVersion: (eco, name, version) =>
    req('POST', `/packages/${eco}/${name.replaceAll('/', '%2F')}/${version}/unblock`),

  // Stats
  getStats: () => req('GET', '/stats'),
}

// System-admin surface (apex host, multi-mode only). All routes require scope=system JWT
// and are 404'd by RouteScopeFilter from anywhere except the apex host.
export const systemApi = {
  // Tenant lifecycle
  listTenants: (page = 1, limit = 50) => req('GET', `/system/tenants?page=${page}&limit=${limit}`),
  createTenant: (slug, ownerEmail) => req('POST', '/system/tenants', { slug, ownerEmail }),
  softDeleteTenant: (slug) => req('DELETE', `/system/tenants/${slug}`),
  restoreTenant: (slug) => req('PATCH', `/system/tenants/${slug}/restore`),

  // Minimal user lookup — control-plane metadata only.
  /** @param {{ email?: string, tenantSlug?: string, limit?: number }} params */
  lookupUsers: ({ email, tenantSlug, limit = 50 } = {}) => {
    const q = new URLSearchParams()
    if (email) q.set('email', email)
    if (tenantSlug) q.set('tenantSlug', tenantSlug)
    q.set('limit', String(limit))
    return req('GET', `/system/users?${q}`)
  },

  // System audit log (scope='system' events).
  listAudit: (page = 1, limit = 50) => req('GET', `/system/audit?page=${page}&limit=${limit}`),

  // Instance settings.
  getSettings: () => req('GET', '/system/settings'),
  updateSettings: (settings) => req('PUT', '/system/settings', settings),

  // Support flows: lock/unlock account + force password reset.
  setAccountStatus: (email, tenantSlug, accountStatus) =>
    req('PATCH', `/system/users/${encodeURIComponent(email)}/account-status`, { tenantSlug, accountStatus }),
  issuePasswordReset: (email, tenantSlug) =>
    req('POST', `/system/users/${encodeURIComponent(email)}/password-reset`, { tenantSlug }),

  // system_admin self
  me: () => req('GET', '/system/me'),
  changePassword: (currentPassword, newPassword) =>
    req('POST', '/system/me/password', { currentPassword, newPassword }),
  updateLanguage: (language) => req('POST', '/system/me/language', { language }),
}
