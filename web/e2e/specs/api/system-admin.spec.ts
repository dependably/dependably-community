import { test, expect, request } from '@playwright/test'
import { getBootstrap, ADMIN_EMAIL, ADMIN_PASSWORD } from '../../helpers/api-client.js'

// System-admin endpoints exist only in multi-tenant mode and require a system_admin
// JWT issued at the apex host. The single-mode webServer in this project does not
// expose them, so these specs skip unless the bootstrap response indicates multi mode.

async function ensureMulti(baseURL: string): Promise<void> {
  const bootstrap = await getBootstrap(baseURL)
  // skip-ok: conditional runtime skip — these specs run only against a multi-mode deployment.
  test.skip(bootstrap.mode !== 'multi', 'system-admin specs require multi-mode deployment')
}

async function loginAsSystemAdmin(baseURL: string) {
  const ctx = await request.newContext({ baseURL })
  const res = await ctx.post('/api/v1/auth/login', {
    data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  })
  expect(res.status()).toBe(200)
  return ctx
}

test.describe('API: system admin (multi-mode only)', () => {
  test.beforeEach(async ({ baseURL }) => {
    await ensureMulti(baseURL!)
  })

  test('list tenants returns array', async ({ baseURL }) => {
    const ctx = await loginAsSystemAdmin(baseURL!)
    try {
      const res = await ctx.get('/api/v1/system/tenants')
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(Array.isArray(body) || Array.isArray(body.items)).toBe(true)
    } finally {
      await ctx.dispose()
    }
  })

  test('create → soft-delete → restore tenant', async ({ baseURL }) => {
    const ctx = await loginAsSystemAdmin(baseURL!)
    const slug = `e2e-tenant-${Date.now()}`
    try {
      const create = await ctx.post('/api/v1/system/tenants', {
        data: {
          slug,
          ownerEmail: `owner-${Date.now()}@e2e.local`,
        },
      })
      expect([200, 201]).toContain(create.status())

      const del = await ctx.delete(`/api/v1/system/tenants/${slug}`)
      expect([200, 204]).toContain(del.status())

      const restore = await ctx.patch(`/api/v1/system/tenants/${slug}/restore`)
      expect([200, 204]).toContain(restore.status())
    } finally {
      await ctx.dispose()
    }
  })

  test('anonymous cannot list tenants', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    try {
      const res = await ctx.get('/api/v1/system/tenants')
      expect(res.status()).toBe(401)
    } finally {
      await ctx.dispose()
    }
  })
})
