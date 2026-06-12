import type { FullConfig } from '@playwright/test'

async function waitForServer(base: string) {
  for (let i = 0; i < 30; i++) {
    try {
      const r = await fetch(`${base}/health`)
      if (r.ok) return
    } catch {}
    await new Promise(r => setTimeout(r, 2000))
  }
  throw new Error('Server did not start')
}

async function findAdminPassword(): Promise<string> {
  return process.env.E2E_ADMIN_PASSWORD ?? 'E2eTestPassword123!'
}

// First-boot admin starts with must_change_password = 1 (issue #34). Rotate it
// once at suite startup so per-test fixtures get an admin who can navigate freely.
async function clearForcedRotation(base: string, email: string, password: string) {
  const login = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!login.ok) throw new Error(`E2E setup: admin login failed (${login.status})`)
  const cookie = login.headers.get('set-cookie') ?? ''

  const me = await fetch(`${base}/api/v1/auth/me`, { headers: { Cookie: cookie } })
  if (!me.ok) return
  const meBody = await me.json()
  if (!meBody.mustChangePassword) return

  const rotate = await fetch(`${base}/api/v1/users/me/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({ currentPassword: password, newPassword: password + '!Rotated' }),
  })
  if (!rotate.ok) throw new Error(`E2E setup: forced rotation failed (${rotate.status})`)
  // A password change invalidates every session minted under the old password and
  // re-issues the caller's cookie on the response — the restore call must use the
  // fresh cookie, not the pre-rotation login cookie.
  const rotatedCookie = rotate.headers.get('set-cookie') ?? cookie
  // Restore the canonical password so per-test logins still match what fixtures expect.
  const restore = await fetch(`${base}/api/v1/users/me/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: rotatedCookie },
    body: JSON.stringify({ currentPassword: password + '!Rotated', newPassword: password }),
  })
  if (!restore.ok) throw new Error(`E2E setup: password restore failed (${restore.status})`)
}

export default async function globalSetup(config: FullConfig) {
  const base = process.env.PLAYWRIGHT_BASE_URL
    ?? config.projects[0].use.baseURL
    ?? 'http://localhost:8080'
  await waitForServer(base)
  const email = 'admin@dependably.local'
  const password = await findAdminPassword()
  await clearForcedRotation(base, email, password)
  process.env.DEPENDABLY_E2E_ADMIN_EMAIL = email
  process.env.DEPENDABLY_E2E_ADMIN_PASSWORD = password
}
