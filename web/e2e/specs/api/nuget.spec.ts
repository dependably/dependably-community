import { test, expect, request } from '@playwright/test'
import { createHash } from 'crypto'
import fs from 'fs'
import path from 'path'
import {
  loginAsAdmin,
  mintCicdToken,
  mintUserToken,
  auth,
  fixturesRoot,
} from '../../helpers/api-client.js'

// Real nupkg: tests/Dependably.Tests/Fixtures/packages/nuget/Newtonsoft.Json.13.0.3.nupkg
const PKG_ID = 'Newtonsoft.Json'
const PKG_VERSION = '13.0.3'
const NUPKG_FILENAME = 'Newtonsoft.Json.13.0.3.nupkg'
const ID_LOWER = PKG_ID.toLowerCase()

function loadNupkg(): { bytes: Buffer; sha256: string } {
  const file = path.join(fixturesRoot(), 'nuget', NUPKG_FILENAME)
  const bytes = fs.readFileSync(file)
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  return { bytes, sha256 }
}

async function pushNupkg(baseURL: string, apiKey: string, bytes: Buffer) {
  const ctx = await request.newContext({
    baseURL,
    extraHTTPHeaders: { 'X-NuGet-ApiKey': apiKey },
  })
  try {
    return await ctx.put('/nuget/publish', {
      multipart: {
        package: { name: NUPKG_FILENAME, mimeType: 'application/octet-stream', buffer: bytes },
      },
    })
  } finally {
    await ctx.dispose()
  }
}

test.describe('API: NuGet push/pull/unlist', () => {
  test('push nupkg → flatcontainer index lists it → pull bytes match', async ({
    baseURL,
  }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pushToken = await mintCicdToken(authed, `e2e-nuget-push-${Date.now()}`, 'push')
      const { bytes, sha256 } = loadNupkg()

      const push = await pushNupkg(baseURL!, pushToken, bytes)
      expect([200, 201, 409]).toContain(push.status())

      const readCtx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.basic(pushToken) },
      })
      try {
        // Flatcontainer version index (case-insensitive id, lowercase URL)
        const idx = await readCtx.get(`/nuget/flatcontainer/${ID_LOWER}/index.json`)
        expect(idx.status()).toBe(200)
        const idxJson = await idx.json()
        expect(Array.isArray(idxJson.versions)).toBe(true)
        expect(idxJson.versions).toContain(PKG_VERSION)

        // Pull the actual nupkg blob
        const pull = await readCtx.get(
          `/nuget/flatcontainer/${ID_LOWER}/${PKG_VERSION}/${ID_LOWER}.${PKG_VERSION}.nupkg`,
        )
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

  // Unlist is destructive (yanks the only available version of our shared fixture),
  // so we can't pair it with the happy-path test on a server that survives between
  // runs. Cover the auth boundary instead — a real unlist flow needs a synthetic
  // fixture, which the bigger CLI-integration test layer can provide.
  test('unlist requires push scope', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pullToken = await mintCicdToken(authed, `e2e-nuget-pull-${Date.now()}`, 'pull')
      const ctx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { 'X-NuGet-ApiKey': pullToken },
      })
      try {
        const res = await ctx.delete(`/nuget/publish/${PKG_ID}/${PKG_VERSION}`)
        expect(res.status()).toBe(403)
      } finally {
        await ctx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('anonymous push is rejected', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    try {
      const res = await ctx.put('/nuget/publish', {
        multipart: {
          package: { name: NUPKG_FILENAME, mimeType: 'application/octet-stream', buffer: Buffer.from('x') },
        },
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
      const { bytes } = loadNupkg()
      const res = await pushNupkg(baseURL!, pullToken, bytes)
      expect(res.status()).toBe(403)
    } finally {
      await authed.dispose()
    }
  })

  test('413 when upload exceeds org nuget limit', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    // NuGet controller reads org-level MaxUploadBytesNuGet only (no instance fallback).
    const current = await (await authed.get('/api/v1/settings')).json()
    const restore = { ...current, maxUploadBytesNuGet: null }
    const lowered = { ...current, maxUploadBytesNuGet: 128 }
    try {
      const setLow = await authed.put('/api/v1/settings', { data: lowered })
      expect([200, 204]).toContain(setLow.status())

      const pushToken = await mintCicdToken(authed, `e2e-nuget-413-${Date.now()}`, 'push')
      const { bytes } = loadNupkg()
      expect(bytes.length).toBeGreaterThan(128)

      const res = await pushNupkg(baseURL!, pushToken, bytes)
      expect(res.status()).toBe(413)
    } finally {
      await authed.put('/api/v1/settings', { data: restore })
      await authed.dispose()
    }
  })
})
