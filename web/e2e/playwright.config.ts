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

// Cross-browser coverage is opt-in. By default only chromium runs: a fresh-profile
// Firefox contacts Mozilla Remote Settings on every browser context and pulls large
// settings attachments from *.cdn.mozilla.net (intermediate-CA preload, blocklist,
// tracking-protection lists), which floods CI runners with requests and egress. Set
// E2E_ALL_BROWSERS=1 to also run firefox + webkit; the firefoxUserPrefs below keep
// that opt-in path from phoning home.
const allBrowsers = !!process.env.E2E_ALL_BROWSERS

export default defineConfig({
  testDir: './specs',
  timeout: 30_000,
  retries: CI ? 1 : 0,
  workers: CI ? 2 : undefined,
  forbidOnly: CI,
  reporter: CI
    // A reporter outputFile resolves relative to the config dir (web/e2e), but the
    // html report and the test-artifact outputDir resolve relative to cwd (web). Left
    // as 'test-results/junit.xml' the report lands in web/e2e/test-results while CI's
    // artifact paths look in web/test-results — so the JUnit report never uploaded.
    // Anchor it under web/test-results alongside the traces the pipeline already collects.
    ? [['html', { open: 'never' }], ['junit', { outputFile: path.resolve(__dirname, '../test-results/junit.xml') }]]
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
    ...(allBrowsers ? [
      {
        name: 'firefox',
        testIgnore: /specs\/api\//,
        use: {
          ...devices['Desktop Firefox'],
          launchOptions: {
            // Silence Firefox's phone-home so the firefox project never pulls from
            // *.cdn.mozilla.net / *.services.mozilla.com during a test run.
            firefoxUserPrefs: {
              'services.settings.server': '',                  // disables Remote Settings sync (the cdn.mozilla.net attachment pulls)
              'app.update.enabled': false,                     // no update checks (aus5.mozilla.org)
              'extensions.blocklist.enabled': false,           // no add-on blocklist fetch
              'datareporting.healthreport.uploadEnabled': false,
              'datareporting.policy.dataSubmissionEnabled': false,
              'toolkit.telemetry.enabled': false,
              'toolkit.telemetry.unified': false,
              'network.captive-portal-service.enabled': false,
              'browser.safebrowsing.malware.enabled': false,
              'browser.safebrowsing.phishing.enabled': false,
            },
          },
        },
      },
      { name: 'webkit', testIgnore: /specs\/api\//, use: { ...devices['Desktop Safari'] } },
    ] : []),
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
      DISABLE_BACKGROUND_JOBS: 'vuln-scan,vuln-rescan,deprecation-refresh,threat-feed',
    },
  } : undefined,
  globalSetup: './global-setup.ts',
})
