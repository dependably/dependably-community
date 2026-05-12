import { APIRequestContext, request, expect } from '@playwright/test'
import { fileURLToPath } from 'url'
import path from 'path'

export const ADMIN_EMAIL = process.env.DEPENDABLY_E2E_ADMIN_EMAIL ?? 'admin@dependably.local'
export const ADMIN_PASSWORD = process.env.DEPENDABLY_E2E_ADMIN_PASSWORD ?? 'E2eTestPassword123!'

export type Scope = 'pull' | 'push' | 'siem:read'

/**
 * Returns an APIRequestContext carrying the admin's session cookie.
 * Caller owns disposal.
 */
export async function loginAsAdmin(baseURL: string): Promise<APIRequestContext> {
  const ctx = await request.newContext({ baseURL })
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
  const res = await authed.post('/api/v1/tokens', { data: { scope } })
  expect(res.status(), `mintUserToken(${scope}) failed: ${await res.text()}`).toBe(200)
  const body = await res.json()
  return body.token as string
}

/**
 * Creates a CI/CD token. Requires admin role. Returns the raw bearer string.
 */
export async function mintCicdToken(
  authed: APIRequestContext,
  name: string,
  scope: Scope,
): Promise<string> {
  const res = await authed.post('/api/v1/cicd-tokens', { data: { name, scope } })
  expect(res.status(), `mintCicdToken(${scope}) failed: ${await res.text()}`).toBe(200)
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

/**
 * Resolves the absolute filesystem path of the shared package fixtures
 * under tests/Dependably.Tests/Fixtures/packages.
 */
export function fixturesRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '../../../tests/Dependably.Tests/Fixtures/packages')
}
