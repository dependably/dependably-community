import { test, expect, request } from '@playwright/test'
import { loginAsAdmin, mintServiceToken, auth } from '../../helpers/api-client.js'

// These specs assert that auth boundaries fire correctly at the deployed pipeline
// across endpoint families. Per-ecosystem push/pull specs cover the happy paths;
// this spec consolidates the negative-auth coverage.

const ANON_REJECTED_ROUTES: Array<{ name: string; req: (ctx: import('@playwright/test').APIRequestContext) => Promise<{ status: number }>}> = [
  {
    name: 'GET /api/v1/auth/me',
    req: async ctx => ({ status: (await ctx.get('/api/v1/auth/me')).status() }),
  },
  {
    name: 'GET /api/v1/settings (cookie auth)',
    req: async ctx => ({ status: (await ctx.get('/api/v1/settings')).status() }),
  },
  {
    name: 'GET /api/v1/tokens',
    req: async ctx => ({ status: (await ctx.get('/api/v1/tokens')).status() }),
  },
  {
    name: 'GET /api/v1/service-tokens',
    req: async ctx => ({ status: (await ctx.get('/api/v1/service-tokens')).status() }),
  },
  {
    name: 'GET /api/v1/instance/settings',
    req: async ctx => ({ status: (await ctx.get('/api/v1/instance/settings')).status() }),
  },
  {
    name: 'POST /pypi/legacy/',
    req: async ctx => ({
      status: (
        await ctx.post('/pypi/legacy/', {
          multipart: { ':action': 'file_upload', name: 'x', version: '1.0' },
        })
      ).status(),
    }),
  },
  {
    name: 'PUT /npm/anything',
    req: async ctx => ({
      status: (
        await ctx.put('/npm/anything', {
          data: '{}',
          headers: { 'Content-Type': 'application/json' },
        })
      ).status(),
    }),
  },
  {
    name: 'PUT /nuget/publish',
    req: async ctx => ({
      status: (
        await ctx.put('/nuget/publish', {
          multipart: {
            package: { name: 'x.nupkg', mimeType: 'application/octet-stream', buffer: Buffer.from('x') },
          },
        })
      ).status(),
    }),
  },
]

test.describe('API: auth-matrix anonymous rejection', () => {
  for (const { name, req } of ANON_REJECTED_ROUTES) {
    test(`anonymous → 401: ${name}`, async ({ baseURL }) => {
      const ctx = await request.newContext({ baseURL })
      try {
        const { status } = await req(ctx)
        expect(status).toBe(401)
      } finally {
        await ctx.dispose()
      }
    })
  }
})

// Note: TokenAuthExtensions.ResolveTokenAsync resolves both Bearer and Basic on
// every protected route, so cross-scheme requests are not a rejection boundary.
// We only assert on rejection boundaries that actually exist: anonymous (401),
// wrong scope (403), and garbage tokens (401).

test.describe('API: auth-matrix wrong-scope rejection', () => {
  test('siem:read token cannot push npm → 403', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const token = await mintServiceToken(authed, `e2e-mat-siem-${Date.now()}`, 'siem:read')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.bearer(token) },
      })
      try {
        const res = await ctx.put('/npm/whatever', {
          data: '{}',
          headers: { 'Content-Type': 'application/json' },
        })
        expect(res.status()).toBe(403)
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('pull token cannot unlist NuGet (DELETE) → 403', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const token = await mintServiceToken(authed, `e2e-mat-pull-${Date.now()}`, 'pull')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { 'X-NuGet-ApiKey': token },
      })
      try {
        const res = await ctx.delete('/nuget/publish/AnyId/1.0.0')
        expect(res.status()).toBe(403)
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('garbage token rejected with 401', async ({ baseURL }) => {
    const ctx = await request.newContext({
      baseURL,
      extraHTTPHeaders: { Authorization: auth.bearer('not-a-real-token-' + Date.now()) },
    })
    try {
      const res = await ctx.put('/npm/whatever', {
        data: '{}',
        headers: { 'Content-Type': 'application/json' },
      })
      expect(res.status()).toBe(401)
    } finally {
      await ctx.dispose()
    }
  })
})
