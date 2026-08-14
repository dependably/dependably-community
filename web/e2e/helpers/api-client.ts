import { APIRequestContext, request, expect } from '@playwright/test'
import { fileURLToPath } from 'url'
import path from 'path'
import { randomUUID } from 'crypto'

export const ADMIN_EMAIL = process.env.DEPENDABLY_E2E_ADMIN_EMAIL ?? 'admin@dependably.local'
export const ADMIN_PASSWORD = process.env.DEPENDABLY_E2E_ADMIN_PASSWORD ?? 'E2eTestPassword123!'

/**
 * Named presets over the real capability vocabulary (`Dependably.Security.Capabilities`).
 * The server retired the flat `scope` column — `POST /api/v1/tokens` and
 * `POST /api/v1/service-tokens` now take an explicit `capabilities` array and reject a
 * `scope` field outright (`error.token.scopeRetired`). These presets mirror the ones the
 * Settings UI offers (`web/src/lib/tokenCapabilities.js`), with one deliberate difference:
 * the UI's `push` preset is publish-only, but every e2e push test here also reads back what
 * it just published (packument/tarball GET, `/simple/` index, flatcontainer index) over the
 * same token, and `read:artifact`/`read:metadata` are enforced on those reads whenever a
 * token is present (see `NpmTarballHandler`, `PyPiDownloadHandler`) — so `push` here is the
 * UI's `both` preset in substance.
 */
export type Scope = 'pull' | 'push' | 'siem:read'

const SCOPE_CAPABILITIES: Record<Scope, string[]> = {
  pull: ['read:metadata', 'read:artifact'],
  push: ['read:metadata', 'read:artifact', 'publish:*'],
  'siem:read': ['read:audit'],
}

/**
 * Returns an APIRequestContext carrying the admin's session cookie.
 * Caller owns disposal.
 */
export async function loginAsAdmin(baseURL: string): Promise<APIRequestContext> {
  // Origin is sent because this context stands in for the SPA, and a browser always sends it (or
  // Sec-Fetch-Site) on a same-origin state-changing request. APIRequestContext sends neither, so
  // without this a cookie-authenticated form-encoded or multipart POST — the drag-and-drop upload
  // surface, for one — looks exactly like a cross-site form post to CsrfDefenseMiddleware and is
  // refused 403. Scripted callers that are genuinely not browsers should authenticate with a
  // token instead: an Authorization header skips the CSRF check outright.
  const ctx = await request.newContext({ baseURL, extraHTTPHeaders: { Origin: baseURL } })
  const res = await ctx.post('/api/v1/auth/login', {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  })
  expect(res.status(), `admin login failed: ${res.status()} ${await res.text()}`).toBe(200)
  return ctx
}

/**
 * Creates a user-scoped access token. Returns the raw bearer string.
 * `authed` must already be logged in (cookie present).
 */
export async function mintUserToken(authed: APIRequestContext, scope: Scope): Promise<string> {
  const capabilities = SCOPE_CAPABILITIES[scope]
  const res = await authed.post('/api/v1/tokens', { data: { capabilities } })
  expect(res.status(), `mintUserToken(${scope}) failed: ${await res.text()}`).toBe(200)
  const body = await res.json()
  return body.token as string
}

/**
 * Creates a service token. Requires admin role. Returns the raw bearer string.
 */
export async function mintServiceToken(
  authed: APIRequestContext,
  name: string,
  scope: Scope,
): Promise<string> {
  const capabilities = SCOPE_CAPABILITIES[scope]
  const res = await authed.post('/api/v1/service-tokens', { data: { name, capabilities } })
  expect(res.status(), `mintServiceToken(${scope}) failed: ${await res.text()}`).toBe(200)
  const body = await res.json()
  return body.token as string
}

/**
 * Returns Authorization header value formats used across ecosystems.
 */
export const auth = {
  bearer: (token: string) => `Bearer ${token}`,
  basic: (token: string, user = 'user') =>
    `Basic ${Buffer.from(`${user}:${token}`).toString('base64')}`,
}

/**
 * Reads bootstrap metadata. Used to skip multi-mode-only specs in single-mode runs.
 */
export async function getBootstrap(baseURL: string): Promise<{
  mode: 'single' | 'multi'
  isApex?: boolean
  tenantSlug?: string
  apexHost?: string
}> {
  const ctx = await request.newContext({ baseURL })
  try {
    const res = await ctx.get('/api/v1/bootstrap')
    expect(res.ok()).toBe(true)
    return await res.json()
  } finally {
    await ctx.dispose()
  }
}

export interface FreshTenantAdmin {
  email: string
  password: string
}

/**
 * Invites a brand-new tenant admin, accepts the invite, and returns their credentials.
 *
 * A freshly created account's timezone/language overrides are guaranteed unset — no prior spec,
 * and no earlier run of this same spec against a persistent local DB, can have touched them.
 * That is the deterministic "inherits the tenant default" baseline a preference-inheritance
 * assertion needs: `admin@dependably.local`'s own language override cannot be assumed unset,
 * because `i18n.spec.ts` persists one to that shared account via the Profile locale switcher.
 *
 * Requires SMTP to be unconfigured in the test harness (true for the e2e boot config) so the
 * invite response carries `invite_link` with the raw token instead of only emailing it.
 */
export async function inviteFreshAdmin(
  authedAsAdmin: APIRequestContext,
  baseURL: string,
): Promise<FreshTenantAdmin> {
  const email = `e2e-pref-${randomUUID()}@dependably.local`
  const password = 'E2ePrefTest123!'
  const res = await authedAsAdmin.post('/api/v1/invites', { data: { email, role: 'admin' } })
  expect(res.ok(), `invite create failed: ${res.status()} ${await res.text()}`).toBeTruthy()
  const body = await res.json()
  const link: string | null = body.invite_link ?? null
  expect(link, 'invite response carried no invite_link — is SMTP configured in this harness?').toBeTruthy()
  const token = new URL(link!).searchParams.get('token')
  expect(token, `invite_link had no token: ${link}`).toBeTruthy()

  const acceptCtx = await request.newContext({ baseURL })
  try {
    const acceptRes = await acceptCtx.post('/api/v1/invites/accept', { data: { token, password } })
    expect(acceptRes.ok(), `invite accept failed: ${acceptRes.status()} ${await acceptRes.text()}`).toBeTruthy()
  } finally {
    await acceptCtx.dispose()
  }
  return { email, password }
}

/**
 * Resolves the absolute filesystem path of the shared package fixtures
 * under tests/Dependably.Tests/Fixtures/packages.
 */
export function fixturesRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '../../../tests/Dependably.Tests/Fixtures/packages')
}

/**
 * Builds a valid `PUT /api/v1/settings` body from a `GET /api/v1/settings` response.
 * `UpdateOrgSettingsRequest` accepts only a fixed field subset — `GET` also returns
 * server-computed fields (`orgId`, `proxyPassthroughEffective`, `rpmUpstreamModeEffective`,
 * …) that `PUT` does not declare, and the controller's `UnmappedMemberHandling.Disallow`
 * stance rejects the whole body with 400 if one is echoed back. Spreading the raw `GET`
 * response into a `PUT` call — the shape this whitelist replaces — has never round-tripped
 * under that stance. Mirrors the field list `web/src/lib/api.js`'s `updateOrgSettings` sends.
 */
export function toUpdateOrgSettingsRequest(
  settings: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const fields = [
    'anonymousPull', 'allowlistMode', 'maxUploadBytes', 'maxUploadBytesPyPi',
    'maxUploadBytesNpm', 'maxUploadBytesNuGet', 'maxUploadBytesMaven', 'maxUploadBytesRpm',
    'maxUploadBytesOci', 'defaultLanguage', 'defaultTimezone', 'allowVersionOverwrite',
    'versionOverwritePolicy', 'airGapped', 'requireMfa',
  ]
  const body: Record<string, unknown> = {}
  for (const field of fields) {
    body[field] = settings[field] ?? null
  }
  return { ...body, ...overrides }
}
