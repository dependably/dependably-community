import { test, expect, request } from '@playwright/test'
import {
  loginAsAdmin,
  mintServiceToken,
  mintUserToken,
  auth,
} from '../../helpers/api-client.js'

test.describe('API: token CRUD + scope enforcement', () => {
  test('user token: create → list → revoke', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const create = await authed.post('/api/v1/tokens', { data: { scope: 'pull' } })
      expect(create.status()).toBe(200)
      const { token, record } = await create.json()
      expect(typeof token).toBe('string')
      expect(record.id).toBeTruthy()
      expect(record.scope).toBe('pull')

      const list = await authed.get('/api/v1/tokens')
      expect(list.status()).toBe(200)
      const tokens = await list.json()
      expect(Array.isArray(tokens)).toBe(true)
      expect(tokens.find((t: { id: string }) => t.id === record.id)).toBeTruthy()

      const del = await authed.delete(`/api/v1/tokens/${record.id}`)
      expect([200, 204]).toContain(del.status())
    } finally {
      await authed.dispose()
    }
  })

  test('service token: create → list → revoke', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const name = `e2e-svc-${Date.now()}`
      const create = await authed.post('/api/v1/service-tokens', {
        data: { name, scope: 'push' },
      })
      expect(create.status()).toBe(200)
      const { token, record } = await create.json()
      expect(typeof token).toBe('string')
      expect(record.name).toBe(name)
      expect(record.scope).toBe('push')

      const list = await authed.get('/api/v1/service-tokens')
      expect(list.status()).toBe(200)
      const tokens = await list.json()
      expect(tokens.find((t: { id: string }) => t.id === record.id)).toBeTruthy()

      const del = await authed.delete(`/api/v1/service-tokens/${record.id}`)
      expect([200, 204]).toContain(del.status())
    } finally {
      await authed.dispose()
    }
  })

  test('rejects invalid scope on create', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const res = await authed.post('/api/v1/tokens', { data: { scope: 'admin' } })
      // RFC 7807 ProblemDetails: 422 for semantic validation; 400 also acceptable.
      expect([400, 422]).toContain(res.status())
    } finally {
      await authed.dispose()
    }
  })

  test('pull token cannot push (npm publish denied)', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pullToken = await mintServiceToken(authed, `e2e-pull-${Date.now()}`, 'pull')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.bearer(pullToken) },
      })
      // PUT /npm/{pkg} with empty body — auth check fires before body parsing.
      const res = await ctx.put('/npm/scope-test-pkg', {
        data: { name: 'scope-test-pkg', versions: {} },
        headers: { 'Content-Type': 'application/json' },
      })
      expect(res.status()).toBe(403)
      await ctx.dispose()
    } finally {
      await authed.dispose()
    }
  })

  test('pull token can read (npm metadata succeeds for pull scope)', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pullToken = await mintUserToken(authed, 'pull')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.bearer(pullToken) },
      })
      // Unknown package: pull-scoped token should pass auth, miss should be 404 (not 401/403).
      const res = await ctx.get('/npm/this-package-does-not-exist-' + Date.now())
      expect([200, 404]).toContain(res.status())
      expect(res.status()).not.toBe(401)
      expect(res.status()).not.toBe(403)
      await ctx.dispose()
    } finally {
      await authed.dispose()
    }
  })
})
