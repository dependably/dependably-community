import { defineConfig, devices } from '@playwright/test'
import { fileURLToPath } from 'url'
import os from 'os'
import path from 'path'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '../..')
const tmpDir = path.join(os.tmpdir(), `dependably-e2e-${Date.now()}`)
const CI = !!process.env.CI
const serverUrl = process.env.PLAYWRIGHT_BASE_URL
  ?? (CI ? 'http://localhost:5221' : 'http://localhost:8080')

export default defineConfig({
  testDir: './specs',
  timeout: 30_000,
  retries: CI ? 1 : 0,
  workers: CI ? 2 : undefined,
  forbidOnly: CI,
  reporter: CI
    ? [['html', { open: 'never' }], ['junit', { outputFile: 'test-results/junit.xml' }]]
    : [['html', { open: 'on-failure' }]],
  use: {
    baseURL: serverUrl,
    trace: 'on-first-retry',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'api',
      testDir: './specs/api',
      use: { baseURL: serverUrl },
    },
    { name: 'chromium', testIgnore: /specs\/api\//, use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', testIgnore: /specs\/api\//, use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', testIgnore: /specs\/api\//, use: { ...devices['Desktop Safari'] } },
  ],
  webServer: CI ? {
    command: `mkdir -p ${tmpDir}/blobs && ${repoRoot}/src/Dependably/bin/Release/net10.0/linux-x64/publish/Dependably`,
    url: `${serverUrl}/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      DB_PATH: `${tmpDir}/dependably.db`,
      LOCAL_STORAGE_PATH: `${tmpDir}/blobs`,
      STORAGE_BACKEND: 'local',
      ASPNETCORE_URLS: serverUrl,
      FIRST_BOOT_ADMIN_PASSWORD: 'E2eTestPassword123!',
      LOGIN_RATE_LIMIT_PERMITS: '100',
      TOKEN_CREATE_RATE_LIMIT_PERMITS: '1000',
    },
  } : undefined,
  globalSetup: './global-setup.ts',
})
