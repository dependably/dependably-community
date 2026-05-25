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

// Real wheel: tests/Dependably.Tests/Fixtures/packages/pypi/mypy_extensions-1.0.0-py3-none-any.whl
const WHEEL_NAME = 'mypy_extensions'
const WHEEL_VERSION = '1.0.0'
const WHEEL_FILENAME = 'mypy_extensions-1.0.0-py3-none-any.whl'
const NORMALIZED_NAME = 'mypy-extensions' // PEP 503

function loadWheel(): { bytes: Buffer; sha256: string } {
  const file = path.join(fixturesRoot(), 'pypi', WHEEL_FILENAME)
  const bytes = fs.readFileSync(file)
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  return { bytes, sha256 }
}

async function pushWheel(baseURL: string, token: string, fileBytes: Buffer, sha256: string) {
  const ctx = await request.newContext({
    baseURL,
    extraHTTPHeaders: { Authorization: auth.basic(token) },
  })
  try {
    const res = await ctx.post('/pypi/legacy/', {
      multipart: {
        ':action': 'file_upload',
        metadata_version: '2.1',
        name: WHEEL_NAME,
        version: WHEEL_VERSION,
        sha256_digest: sha256,
        content: { name: WHEEL_FILENAME, mimeType: 'application/octet-stream', buffer: fileBytes },
      },
    })
    return res
  } finally {
    await ctx.dispose()
  }
}

test.describe('API: PyPI push/pull', () => {
  test('push wheel → /simple/ index lists it → /packages/ pull bytes match', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    try {
      const pushToken = await mintServiceToken(authed, `e2e-pypi-push-${Date.now()}`, 'push')
      const { bytes, sha256 } = loadWheel()

      const push = await pushWheel(baseURL!, pushToken, bytes, sha256)
      // First fresh CI run → 200; rerun against persistent dev server → 409 conflict.
      expect([200, 201, 409]).toContain(push.status())

      // /simple/ index lists the package
      const indexCtx = await request.newContext({
        baseURL,
        extraHTTPHeaders: { Authorization: auth.basic(pushToken) },
      })
      try {
        const idx = await indexCtx.get(`/simple/${NORMALIZED_NAME}/`)
        expect(idx.status()).toBe(200)
        const html = await idx.text()
        expect(html).toContain(WHEEL_FILENAME)

        // Pull blob, verify SHA-256 matches the original
        const pull = await indexCtx.get(`/packages/${WHEEL_FILENAME}`)
        expect(pull.status()).toBe(200)
        const pulledBytes = await pull.body()
        const pulledHash = createHash('sha256').update(pulledBytes).digest('hex')
        expect(pulledHash).toBe(sha256)
      } finally {
        await indexCtx.dispose()
      }
    } finally {
      await authed.dispose()
    }
  })

  test('anonymous push is rejected', async ({ baseURL }) => {
    const ctx = await request.newContext({ baseURL })
    try {
      const res = await ctx.post('/pypi/legacy/', {
        multipart: {
          ':action': 'file_upload',
          name: WHEEL_NAME,
          version: WHEEL_VERSION,
          content: { name: WHEEL_FILENAME, mimeType: 'application/octet-stream', buffer: Buffer.from('x') },
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
      const { bytes, sha256 } = loadWheel()
      const res = await pushWheel(baseURL!, pullToken, bytes, sha256)
      expect(res.status()).toBe(403)
    } finally {
      await authed.dispose()
    }
  })

  test('413 when upload exceeds instance pypi limit', async ({ baseURL }) => {
    const authed = await loginAsAdmin(baseURL!)
    const SMALL_LIMIT = '128'
    const RESTORE = '1073741824' // 1 GiB
    try {
      const setLow = await authed.put('/api/v1/instance/settings', {
        data: { max_upload_bytes_pypi: SMALL_LIMIT },
      })
      expect([200, 204]).toContain(setLow.status())

      const pushToken = await mintServiceToken(authed, `e2e-pypi-413-${Date.now()}`, 'push')
      const { bytes, sha256 } = loadWheel()
      // Wheel is ~5KB, well above 128B.
      expect(bytes.length).toBeGreaterThan(128)

      const res = await pushWheel(baseURL!, pushToken, bytes, sha256)
      expect(res.status()).toBe(413)
    } finally {
      // Always restore so other specs aren't poisoned.
      await authed.put('/api/v1/instance/settings', {
        data: { max_upload_bytes_pypi: RESTORE },
      })
      await authed.dispose()
    }
  })
})
