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
  // CI shares its host with other heavy jobs (integration suites, DAST, Sonar), and under that
  // load the app's writes slow to several seconds each: a spec that seeds a project and an SBOM
  // trio can spend half a 30s budget before its first navigation. Sized for a loaded runner so
  // the timeout catches a hang, not a busy host.
  timeout: CI ? 60_000 : 30_000,
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
      // Every spec signs in through the adminPage fixture, and the login limiter is a fixed
      // one-minute window per IP. On an idle runner the chromium project finishes its ~90 logins
      // (plus global-setup and the retry of any failed spec) inside a single window, so the last
      // specs to run are refused with "Too many attempts" and time out waiting for the sidebar.
      // Lifted to the .app_boot value for the same bounded-internal-client reason as the budgets
      // below; no spec pins the login limiter itself.
      LOGIN_RATE_LIMIT_PERMITS: '100000',
      TOKEN_CREATE_RATE_LIMIT_PERMITS: '1000',
      // The whole suite authenticates as one admin from one IP, so every browser session shares
      // a single per-principal bucket — the shape RateLimitCeilings calls out as the bounded
      // internal client (its other example being a DAST scan). At the 300/min default the budget
      // is spent partway through the run and the next page load 429s, which surfaces as a login
      // page that never becomes the app rather than as anything resembling a rate limit. High,
      // not unlimited: a runaway loop in a spec should still be bounded.
      MANAGEMENT_RATE_LIMIT_PERMITS: '100000',
      ANON_RATE_LIMIT_PERMITS: '100000',
      // Specs seed fixtures through POST /api/v1/admin/upload, which runs under the import
      // limiter (5/min per token, QueueLimit = 0), not the push limiter. Several specs upload
      // two or more artefacts each, so a fast runner crosses 5 within one window and the
      // surplus uploads are refused outright. No spec pins the limiter itself.
      IMPORT_RATE_LIMIT_PERMITS: '100000',
      // inviteFreshAdmin mints an account per spec from one IP; the invite limiter is 20 per hour
      // per IP and the on-demand rescan limiter is 20 per minute per caller.
      INVITE_RATE_LIMIT_PERMITS: '100000',
      RESCAN_RATE_LIMIT_PERMITS: '100000',
      // The SBOM specs upload a document trio per test against one admin principal, which is
      // most of the 30/min default in a single burst. Lifted for the same bounded-internal-client
      // reason as the management budget above; the limiter itself is not what those specs pin.
      SBOM_UPLOAD_RATE_LIMIT_PERMITS: '100000',
      // license-backfill is disabled too, matching .gitlab-ci.yml: it stamps
      // cache_artifact.license_checked_at at boot, a state change the specs must not depend on.
      // sbom-scan is disabled alongside the package scanners: it queries the OSV advisory feed
      // over the network, and every severity, CVSS and priority the project-version detail page
      // renders is derived from what it finds. Left enabled, an upload's derived state depends on
      // whether the runner has egress and on when the drain loop lands — the specs assert exact
      // rows and buckets, so the fixture documents have to be the only input.
      DISABLE_BACKGROUND_JOBS: 'vuln-scan,vuln-rescan,deprecation-refresh,threat-feed,license-backfill,sbom-scan',
      // Request-time egress, same posture as .gitlab-ci.yml's .app_boot: the throwaway DB
      // would otherwise seed the public registries as the org's upstreams, and any proxy
      // route a spec reaches for a name it has not pushed fans out to them. Every spec
      // reads back what it pushed, so nothing here needs a real pull-through; seed the
      // upstreams with a reserved-TLD host the request-time DNS check fails closed on
      // instead. OCI's upstream pair is hard-coded in UpstreamRegistrySeeder and has no
      // key to override.
      PyPI__Upstream: 'http://upstream.invalid',
      Npm__Upstream: 'http://upstream.invalid',
      NuGet__Upstream: 'http://upstream.invalid',
      Maven__Upstream: 'http://upstream.invalid',
      Go__Upstream: 'http://upstream.invalid',
      Go__SumDb: 'http://upstream.invalid',
      Cargo__Upstream: 'http://upstream.invalid',
      Apk__Upstream: 'http://upstream.invalid',
      Terraform__Upstream: 'http://upstream.invalid',
      Hex__Upstream: 'http://upstream.invalid',
    },
  } : undefined,
  globalSetup: './global-setup.ts',
})
