import { test, expect, request } from '@playwright/test'
import { createHash } from 'crypto'
import fs from 'fs'
import path from 'path'
import {
  loginAsAdmin,
  mintServiceToken,
  mintUserToken,
  auth,
  fixturesRoot,
} from '../../helpers/api-client.js'

// Real tarball: tests/Dependably.Tests/Fixtures/packages/npm/is-odd-3.0.1.tgz
const PKG_NAME = 'is-odd'
const PKG_VERSION = '3.0.1'
const TARBALL_FILENAME = 'is-odd-3.0.1.tgz'

function loadTarball(): { bytes: Buffer; sha256: string; integrity: string } {
  const file = path.join(fixturesRoot(), 'npm', TARBALL_FILENAME)
  const bytes = fs.readFileSync(file)
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  const sha512 = createHash('sha512').update(bytes).digest('base64')
  return { bytes, sha256, integrity: `sha512-${sha512}` }
}

function buildPublishBody(bytes: Buffer, integrity: string): string {
  const base64 = bytes.toString('base64')
  return JSON.stringify({
    name: PKG_NAME,
    versions: {
      [PKG_VERSION]: {
        name: PKG_NAME,
        version: PKG_VERSION,
        description: 'Synthetic test push',
        dist: {
          tarball: `https://registry.npmjs.org/${PKG_NAME}/-/${TARBALL_FILENAME}`,
          integrity,
        },
      },
    },
    _attachments: {
      [TARBALL_FILENAME]: {
        content_type: 'application/octet-stream',
        data: base64,
        length: bytes.length,
      },
    },
  })
}

async function pushTarball(baseURL: string, token: string, body: string) {
  const ctx = await request.newContext({
    baseURL,
    extraHTTPHeaders: { Authorization: auth.bearer(token) },
  })
  try {
    return await ctx.put(`/npm/${PKG_NAME}`, {
      data: body,
      headers: { 'Content-Type': 'application/json' },
    })
  } finally {
    await ctx.dispose()
  }
}

test.describe('API: npm push/pull', () => {
  test('PUT publish → GET metadata → GET tarball bytes match', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pushToken = await mintServiceToken(authed, `e2e-npm-push-${Date.now()}`, 'push')
      const { bytes, sha256, integrity } = loadTarball()

      const push = await pushTarball(baseURL!, pushToken, buildPublishBody(bytes, integrity))
      expect([200, 201, 409]).toContain(push.status())

      const readCtx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.bearer(pushToken) },
      })
      try {
        // Metadata: CouchDB-format envelope
        const meta = await readCtx.get(`/npm/${PKG_NAME}`)
        expect(meta.status()).toBe(200)
        const metaJson = await meta.json()
        expect(metaJson.name).toBe(PKG_NAME)
        expect(metaJson.versions).toBeTruthy()
        expect(metaJson.versions[PKG_VERSION]).toBeTruthy()

        // Tarball URL is rewritten to point at this server. Resolve it relative to baseURL.
        const tarballUrl: string = metaJson.versions[PKG_VERSION].dist.tarball
        // Strip the host so we hit the same baseURL.
        const tarballPath = tarballUrl.replace(/^https?:\/\/[^/]+/, '')
        expect(tarballPath).toMatch(/\/npm\/tarballs\//)

        const pull = await readCtx.get(tarballPath)
        expect(pull.status()).toBe(200)
        const pulledHash = createHash('sha256').update(await pull.body()).digest('hex')
        expect(pulledHash).toBe(sha256)
      } finally {
        await readCtx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('anonymous push is rejected', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    try {
      const res = await ctx.put(`/npm/${PKG_NAME}`, {
        data: '{}',
        headers: { 'Content-Type': 'application/json' },
      })
      expect(res.status()).toBe(401)
    } finally {
      await ctx.dispose()
    }
  })

  test('pull-scoped token cannot push', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pullToken = await mintUserToken(authed, 'pull')
      const { bytes, integrity } = loadTarball()
      const res = await pushTarball(baseURL!, pullToken, buildPublishBody(bytes, integrity))
      expect(res.status()).toBe(403)
    } finally {
      await authed.dispose()
    }
  })

  test('413 when upload exceeds org npm limit', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    // npm controller reads org-level MaxUploadBytesNpm only (no instance fallback).
    const current = await (await authed.get('/api/v1/settings')).json()
    const restore = { ...current, maxUploadBytesNpm: null }
    const lowered = { ...current, maxUploadBytesNpm: 128 }
    try {
      const setLow = await authed.put('/api/v1/settings', { data: lowered })
      expect([200, 204]).toContain(setLow.status())

      const pushToken = await mintServiceToken(authed, `e2e-npm-413-${Date.now()}`, 'push')
      const { bytes, integrity } = loadTarball()
      expect(bytes.length).toBeGreaterThan(128)

      const res = await pushTarball(baseURL!, pushToken, buildPublishBody(bytes, integrity))
      expect(res.status()).toBe(413)
    } finally {
      await authed.put('/api/v1/settings', { data: restore })
      await authed.dispose()
    }
  })
})
