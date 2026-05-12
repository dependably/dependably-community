import { test, expect, request } from '@playwright/test'
import { ADMIN_EMAIL, ADMIN_PASSWORD, loginAsAdmin } from '../../helpers/api-client.js'

test.describe('API: auth', () => {
  test('login with valid credentials sets a session cookie', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    const res = await ctx.post('/api/v1/auth/login', {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    })
    expect(res.status()).toBe(200)
    const setCookie = res.headers()['set-cookie'] ?? ''
    expect(setCookie).toMatch(/dependably_session=/)
    expect(setCookie).toMatch(/HttpOnly/i)
    expect(setCookie).toMatch(/SameSite=Strict/i)
    await ctx.dispose()
  })

  test('login with bad credentials returns 401', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    const res = await ctx.post('/api/v1/auth/login', {
      data: { email: ADMIN_EMAIL, password: 'wrong-password' },
    })
    expect(res.status()).toBe(401)
    await ctx.dispose()
  })

  test('GET /auth/me returns identity when authed', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    const res = await authed.get('/api/v1/auth/me')
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body.userId).toBeTruthy()
    expect(body.orgId).toBeTruthy()
    expect(['owner', 'admin', 'member']).toContain(body.role)
    await authed.dispose()
  })

  test('GET /auth/me returns 401 when anonymous', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    const res = await ctx.get('/api/v1/auth/me')
    expect(res.status()).toBe(401)
    await ctx.dispose()
  })

  test('logout invalidates the session cookie', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    const logout = await authed.post('/api/v1/auth/logout')
    expect([200, 204]).toContain(logout.status())

    const after = await authed.get('/api/v1/auth/me')
    expect(after.status()).toBe(401)
    await authed.dispose()
  })
})
