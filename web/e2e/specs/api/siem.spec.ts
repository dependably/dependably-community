import { test, expect, request } from '@playwright/test'
import { loginAsAdmin, mintServiceToken, auth } from '../../helpers/api-client.js'

test.describe('API: SIEM', () => {
  test('Bearer siem:read token can read auth events as JSON', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const token = await mintServiceToken(authed, `e2e-siem-${Date.now()}`, 'siem:read')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.bearer(token) },
      })
      try {
        const res = await ctx.get('/api/v1/siem/events/auth')
        expect(res.status()).toBe(200)
        expect(res.headers()['content-type']).toMatch(/json/i)
        const body = await res.json()
        expect(Array.isArray(body) || typeof body === 'object').toBe(true)
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('Accept: application/x-ndjson returns NDJSON', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const token = await mintServiceToken(authed, `e2e-siem-ndjson-${Date.now()}`, 'siem:read')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: {
          Authorization: auth.bearer(token),
          Accept: 'application/x-ndjson',
        },
      })
      try {
        const res = await ctx.get('/api/v1/siem/events/auth')
        expect(res.status()).toBe(200)
        expect(res.headers()['content-type']).toMatch(/x-ndjson/i)
        const text = await res.text()
        // Each non-empty line must parse as JSON
        for (const line of text.split('\n').filter(l => l.length > 0)) {
          expect(() => JSON.parse(line)).not.toThrow()
        }
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('Accept: application/x-cef returns CEF lines', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const token = await mintServiceToken(authed, `e2e-siem-cef-${Date.now()}`, 'siem:read')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: {
          Authorization: auth.bearer(token),
          Accept: 'application/x-cef',
        },
      })
      try {
        const res = await ctx.get('/api/v1/siem/events/auth')
        expect(res.status()).toBe(200)
        expect(res.headers()['content-type']).toMatch(/x-cef/i)
        const text = await res.text()
        // CEF records start with "CEF:" — body may be empty if no events have been logged yet,
        // but if any line is present it must conform.
        for (const line of text.split('\n').filter(l => l.length > 0)) {
          expect(line).toMatch(/^CEF:/)
        }
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('anonymous request is rejected', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    try {
      const res = await ctx.get('/api/v1/siem/events/auth')
      expect(res.status()).toBe(401)
    } finally {
      await ctx.dispose()
    }
  })

  test('pull-scoped Bearer token cannot read SIEM', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pull = await mintServiceToken(authed, `e2e-siem-wrong-${Date.now()}`, 'pull')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.bearer(pull) },
      })
      try {
        const res = await ctx.get('/api/v1/siem/events/auth')
        expect([401, 403]).toContain(res.status())
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })
})
