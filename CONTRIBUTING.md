# Contributing to Dependably

---

## Building from source

```bash
# Install Node deps and build the frontend
cd web && npm install && npm run build && cd ..

# Run locally (defaults to SQLite + local blob store at /data)
dotnet run --project src/Dependably

# Release binary — x64
dotnet publish src/Dependably -c Release -r linux-musl-x64 --self-contained true

# Release binary — ARM64 (e.g. Raspberry Pi)
dotnet publish src/Dependably -c Release -r linux-musl-arm64 --self-contained true
```

`web/.npmrc` sets `ignore-scripts=true`, so `npm ci` does not run lifecycle scripts (including `prepare`). On a fresh clone, run `npm run prepare` once from `web/` after `npm ci` to install the husky pre-commit hooks:

```bash
cd web && npm ci && npm run prepare
```

### Dependency checks (pre-commit)

When dependency manifests change, the pre-commit hook audits them with the dependably
checkers: `@dependably/npm-check` runs on `web/package.json` / `web/package-lock.json`, and
`Dependably.NuGetCheck` (the `nuget-check` local dotnet tool) runs on the backend
`packages.lock.json` files. Both flag known vulnerabilities and any package source/registry
host that isn't public or allowlisted in the repo-root **`.dependably-check`** config.

Both tools live on the private dogfood feed, so the checks require a `DEPENDABLY_TOKEN`
environment variable with access to `dependably.northwardlabs.ca`:

```bash
export DEPENDABLY_TOKEN=…   # a dogfood-registry token; read from env, never committed
```

Without `DEPENDABLY_TOKEN` the checks are skipped with a warning (so contributors without
feed access can still commit); CI enforces them regardless. To trust an additional private
registry host, add it to `.dependably-check`:

```json
{ "common": { "allowedRegistryHosts": ["dependably.northwardlabs.ca"] } }
```

### Docker

```bash
# Build for the current machine's architecture (default: x64)
docker build -t dependably .

# Build for ARM64
docker build --build-arg RID=linux-musl-arm64 -t dependably .

# Build and start via compose
docker compose up -d --build
```

---

## Running tests

### Unit, integration, and security tests

```bash
# Unit, compliance, and security tests (no external dependencies)
dotnet test --filter "Category!=Integration"

# All tests including integration (requires LocalStack + Azurite)
dotnet test

# Single test class
dotnet test --filter "ClassName=PurlNormalizerTests"
```

### End-to-end tests (Playwright)

E2e tests run against a live instance. Locally that means the Docker container; in CI the test runner starts the published binary itself.

**Local — start the app first, then run tests:**

```bash
# 1. Start the app (port 8080)
docker compose up -d --build

# 2. Run all e2e tests headless (default)
cd web && npm run e2e -- --project=chromium

# Run headed (opens a real browser — useful for debugging)
npm run e2e -- --project=chromium --headed

# Interactive UI mode (step through tests with a GUI)
npm run e2e:ui

# Debug mode (pauses at each step in a headed browser)
npm run e2e:debug

# Run a single spec file
npm run e2e -- e2e/specs/auth.spec.ts

# Show the HTML report from the last run
npm run e2e:report
```

The tests connect to `http://localhost:8080`. If the container isn't running they will fail immediately on the health check.

**CI** — the pipeline publishes the backend, installs the ASP.NET Core runtime into the Playwright image, and starts the app on port 5221. Tests run headless (Playwright's default). No Docker is used in CI.

---

## Generating SBOMs

CycloneDX SBOMs are generated separately for the backend (.NET) and frontend (npm). Both are produced as CI artifacts on every pipeline run; to generate them locally:

```bash
# backend (from repo root)
dotnet tool restore && dotnet CycloneDX src/Dependably/Dependably.csproj -o . -fn sbom-backend.json -F json -spv 1.6

# frontend (from web/)
npm run sbom
```

Output: `sbom-backend.json` (repo root) and `web/sbom-frontend.json`. Both files are gitignored.

---

## AI code review (CI)

On every merge request, the `ai-review` stage runs four advisory reviews of the MR diff against a local LLM (Ollama), each from a different lens:

| Job | Lens | Report |
|---|---|---|
| `ai-review-security` | auth, injection, secrets, crypto, OWASP, input validation, privilege escalation | `ai-security-review.md` |
| `ai-review-code` | bugs, error handling, races, maintainability, complexity, performance | `ai-code-review.md` |
| `ai-review-architecture` | design patterns, service boundaries, coupling, scalability, reliability, DevOps | `ai-architecture-review.md` |
| `ai-review-docs` | missing README / API docs / migration notes / deployment instructions | `ai-docs-review.md` |

Each lens runs in **two passes**: a review pass produces candidate findings, then a **self-verify pass** re-checks them against the diff and keeps only those grounded in a quoted added/removed line — this filters the false positives a small model over-produces. Each job posts its (verified) findings as a **merge-request comment** (one per lens, updated in place on re-runs via a hidden marker), echoes them in the **job log** (collapsible section), and uploads a **Markdown artifact**. All logic lives in `ci/ai-review.sh`; the per-lens system prompts live in `ci/prompts/` (the shared verify prompt is `ci/prompts/verify.md`).

Output that degenerates (a repetition loop, or a runaway that hits the token cap without stopping) is **detected and suppressed** rather than posted as if it were a review — the artifact records that it was suppressed. Sampling is tuned to avoid both degeneration modes (small temperature against greedy loops; `min_p` tail-cutting and a modest `repeat_penalty` against word-salad).

A single weak model cannot reliably filter its own output — the verify pass tends to rubber-stamp its own family's speculation. So a **deterministic guard** runs in code after both passes: it drops *ungrounded* speculation (a hedged block — *may / might / could / suggests / can lead to* — that cites no `> ` diff line), caps the number of findings, and caps total report length. A hedged block that **does** quote a diff line is kept: the high-value findings (cross-tenant access, missing session revocation) are reasoning-heavy and naturally cautious in wording but still grounded, and the older "drop anything hedged" rule suppressed them along with the noise. A lens whose findings are all filtered out posts a single "no material findings" line, same as a clean review.

The reviews are **advisory** — `allow_failure: true` and not part of the release gate — so non-deterministic model output never blocks a merge. They run after the `sbom` stage (so the model only reviews an MR that already built and passed tests), are serialized by a shared `resource_group` so a single local model isn't hit concurrently, and run on merge-request pipelines only.

### Configuration

The endpoint and tuning knobs are job variables on the `.ai-review` template in `.gitlab-ci.yml`; override any of them as project CI/CD variables without editing YAML:

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_URL` | `http://192.168.2.25:11434` | Ollama base URL (`/api/chat` is appended) |
| `OLLAMA_MODEL` | `gemma4:26b-a4b-it-qat` | Model name — must be pulled on the Ollama host |
| `AI_REVIEW_MAX_DIFF_BYTES` | `120000` | Diff is truncated to this many bytes before review |
| `AI_REVIEW_DIFF_CONTEXT` | `10` | `git diff -U` context lines — more lets the model verify a hunk instead of speculating, but grows the diff toward the byte/context caps |
| `AI_REVIEW_NUM_CTX` | `49152` | Model context window — must hold the persona + capped diff (~3.45 bytes/token, so a 120000-byte diff ≈ 35K tokens) **and** leave room to generate; too small and the prompt fills the window, leaving no room for output (empty/near-empty review) |
| `AI_REVIEW_NUM_PREDICT` | `1500` | Hard cap on response length (backstops runaway generation) |
| `AI_REVIEW_THINK` | `false` | Model "thinking". Reasoning models split output into `thinking` + `content`, and thinking burns the `NUM_PREDICT` budget — on a real diff it exhausts the budget before writing any `content`, which we read as "no content". Kept off; set `true` only with a much larger `NUM_PREDICT` |
| `AI_REVIEW_TEMPERATURE` | `0.3` | Sampling temperature — a small non-zero value avoids greedy repetition loops |
| `AI_REVIEW_REPEAT_PENALTY` | `1.1` | Repetition penalty — kept modest; values ≳1.2 cause incoherent word-salad |
| `AI_REVIEW_MIN_P` | `0.05` | Min-p tail cut — drops improbable tokens; the robust guard against word-salad |
| `AI_REVIEW_SELF_VERIFY` | `1` | Run the second self-verify pass (`0` disables it) |
| `AI_REVIEW_VERIFY_PERSONA_FILE` | `ci/prompts/verify.md` | System prompt for the verify pass |
| `AI_REVIEW_MAX_FINDINGS` | `8` | Deterministic cap on findings kept per lens |
| `AI_REVIEW_MAX_REPORT_CHARS` | `2200` | Hard cap on posted report length |
| `AI_REVIEW_CURL_MAX_TIME` | `1000` | Per-request timeout, seconds |
| `AI_REVIEW_API_URL` | `$CI_API_V4_URL` | GitLab API base for posting comments (override if the API isn't at the default) |

**MR comments require a secret.** Set `AI_REVIEW_GITLAB_TOKEN` — a **masked, unprotected** CI/CD variable — to a project or group access token with **`api`** scope and at least the **Reporter** role. Without it the jobs still run and produce artifacts and job-log output; they just skip commenting. (`CI_JOB_TOKEN` can't create MR notes, hence the dedicated token.)

The runner must be able to reach `OLLAMA_URL`. Comment posting goes over the GitLab API and automatically falls back from `http` to `https` if the configured `CI_API_V4_URL` route-misses — some instances serve the v4 API only over https.

---

## Static analysis (Snyk Code)

Snyk Code (SAST) runs against the source. Most of its findings on this repo are **already-triaged false positives** — each carries an inline `// deepcode ignore <Rule>: <reason>` at the site (e.g. parameterized-Dapper "SQLi" in `OciController`, protocol-mandated SHA1/MD5 checksum hashes in `MavenController`, structured-logging "log forging" across the controllers).

The catch: inline `deepcode ignore` markers are honoured by Snyk's **IDE plugin and merge-request integration**, but **not** by the `snyk code test` CLI — and therefore not by the MCP `snyk_code_scan` or any CI invocation. Snyk Code also has **no per-finding `.snyk` ignore** (`.snyk` only excludes whole files via `exclude.code`, which would blind production controllers to real future bugs). So the CLI re-reports every false positive, drowning genuinely new findings.

To keep the CLI/CI signal clean **without weakening detection**, [`ci/snyk-code-scan.sh`](ci/snyk-code-scan.sh) runs the scan and diffs it against [`ci/snyk-code-baseline.json`](ci/snyk-code-baseline.json) — a committed set of **identities** for the known false positives, each keyed on `rule | file | <Snyk path-based identity fingerprint>`. That identity (Snyk's `fingerprints["1"]`) is **line-independent**, so editing a file that hosts a baselined FP no longer drifts the baseline — unlike the primary content fingerprint, which folds in surrounding lines and shifts on any cosmetic move. It fails only on findings **not** on the baseline; a new finding in any file (including a real bug in a file that also hosts a baselined FP) still surfaces. The one accepted trade-off: a second finding of the same rule in the same file with an identical data-flow shape shares one identity, so an extra instance of an already-baselined benign FP class can be absorbed silently.

```bash
ci/snyk-code-scan.sh            # exit 1 if any finding is not on the baseline
ci/snyk-code-scan.sh --update   # re-triage: regenerate the baseline (review the diff)
```

When a new finding appears: if it's **real**, fix it; if it's a **false positive**, add an inline `// deepcode ignore <Rule>: <reason>` at the site (keeps the IDE/MR view quiet) and run `--update`, committing the baseline change in the same MR. Whole-file, test-only noise stays in `.snyk` `exclude.code` instead.

> The raw `snyk code test` / MCP `snyk_code_scan` output still lists all findings — the CLI cannot suppress them. `ci/snyk-code-baseline.json` is the source of truth for which are known false positives; `ci/snyk-code-scan.sh` is the pass/fail check.

**CI job.** The `snyk-code` job (stage `test` in `.gitlab-ci.yml`) runs `ci/snyk-code-scan.sh` on every merge request. It is **gating** (`allow_failure: false`): a finding not on the baseline fails the pipeline and blocks the merge. (If a Snyk outage or result drift ever causes a spurious failure, drop it back to `allow_failure: true` to make it advisory again.)

`SNYK_TOKEN` **must be an unprotected, masked** CI/CD variable — merge-request pipelines run on unprotected branches, so a protected token would be absent there and the scan would error on every MR. (`snyk code test` reads `SNYK_TOKEN` from the environment; no `snyk auth` step is needed.)

**Upgrade path.** Snyk's first-party way to make per-finding ignores CLI-honoured is platform **consistent ignores**: monitor the project, run `snyk code test --report --remote-repo-url=…`, and approve ignores in the Snyk UI/API with a service account that has *View Project Ignores*. That makes the baseline file redundant; it is deferred here because it requires Snyk-platform setup and a service account rather than a repo file.

---

## SonarQube (CI)

The `sonarqube-check` job (stage `test`, post-merge on `main` and tags) runs `dotnet sonarscanner` and uploads coverage. It authenticates via the **`SONAR_TOKEN` environment variable** — SonarScanner for .NET (6+) picks it up directly, so the token is never interpolated onto the scanner command line and never appears in the job trace.

`SONAR_TOKEN` **must be a masked** CI/CD variable regardless: any future script change that echoes the environment (or passes the token as an argument) would otherwise print it verbatim into the job log. `SONAR_HOST_URL` and `SONAR_PROJECT_KEY` are not secrets and are passed as normal variables.

---

## Versioning

Dependably follows [Semantic Versioning](https://semver.org/). The version is stamped into the .NET assembly, the frontend SBOM, the Docker image label, and the `/version` runtime endpoint — all from two source-of-truth files.

### Sources of truth

| File | Property | Consumed by |
|---|---|---|
| `Directory.Build.props` | `<Version>` | All `.csproj` projects → assembly attributes (`AssemblyVersion`, `FileVersion`, `AssemblyInformationalVersion`) → backend SBOM `metadata.component.version` → `/version` endpoint |
| `web/package.json` | `"version"` | Frontend SBOM `metadata.component.version` |

The .NET SDK auto-appends the git commit SHA to `AssemblyInformationalVersion` (e.g. `0.1.0+cfab946...`), so `/version` returns both the release version and the exact commit it was built from.

### Build-time flow

```
Directory.Build.props  ──┐
                         ├─►  dotnet publish -p:Version=${VERSION}  ──►  Dependably.dll  ──►  /version endpoint
Dockerfile ARG VERSION ──┘                                                             └─►  backend SBOM

web/package.json ──►  cyclonedx-npm  ──►  frontend SBOM

Dockerfile ARG VERSION  ──►  LABEL org.opencontainers.image.version
```

The `Dockerfile` accepts a `VERSION` build arg (defaulting to the value in `Directory.Build.props`), passes it to `dotnet publish` via `-p:Version=`, and writes it to the OCI image label. CI overrides this arg with the value extracted from the git tag on tagged builds — see `.github/workflows/ci.yml` (`publish` job).

### Bumping the version

For a release `0.x.y`:

1. Edit `Directory.Build.props` — set `<Version>0.x.y</Version>`.
2. Edit `web/package.json` — set `"version": "0.x.y"`.
3. Commit:
   ```bash
   git commit -am "chore: bump version to 0.x.y"
   ```
4. Tag and push:
   ```bash
   git tag v0.x.y
   git push && git push --tags
   ```

CI's `publish` job triggers on `v*.*.*` tags, extracts `0.x.y` from the tag, passes it as the Docker `VERSION` build arg, and pushes both `:latest` and `:0.x.y` images to GHCR. The two source files and the git tag must agree — keep them in lockstep.

### Verifying the stamp

```bash
# Local build — confirm the stamped version
dotnet build -c Release
curl -s http://localhost:8080/version    # → {"version":"0.x.y+<sha>"}

# Docker image label
docker build -t dependably:test .
docker inspect dependably:test \
  --format '{{index .Config.Labels "org.opencontainers.image.version"}}'

# Override at build time (e.g. for an RC)
docker build --build-arg VERSION=0.x.y-rc1 -t dependably:rc .
```

### Build provenance (SLSA L2)

The `publish` job signs SLSA build provenance over the released GHCR image (keyless
OIDC/sigstore — no stored key) and attaches it to the registry alongside the image. The
provenance covers the exact image by digest, so consumers can confirm it was built by this
repo's CI and not swapped after the fact:

```bash
# Requires `docker login ghcr.io` — the attestation lives in the registry.
gh attestation verify oci://ghcr.io/<owner>/dependably:0.x.y \
  -R <owner>/dependably \
  --signer-workflow <owner>/dependably/.github/workflows/ci.yml
```

Binding `--signer-workflow` (rather than only "signed by someone in the org") is the
meaningful check — it ties the image to the `publish` job that produced it.

---

## Environment variables

This table is the canonical reference — other docs (including `CLAUDE.md`) link here rather than duplicating it.

> **Naming:** variables written `Section__Key` (double underscore) are the environment-variable form of the `Section:Key` configuration keys used in `appsettings.json` and code. Both spellings refer to the same setting.

### Core

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | Public base URL. The host portion (scheme and port stripped) is the apex hostname for multi-tenant subdomain routing and host-header filtering. When the host is non-localhost, the `AllowedHosts` allowlist is derived at startup — unknown `Host` headers are rejected before tenant resolution. In `DEPLOYMENT_MODE=single`, only the apex host and localhost are permitted. In `DEPLOYMENT_MODE=multi`, the apex host, `*.apex` (all tenant subdomains), and localhost are permitted. When `BASE_URL` is unset or localhost (local/dev), filtering is permissive (`AllowedHosts=*`) and a startup warning is logged. |
| `DB_PATH` | `/data/dependably.db` | SQLite database file path |
| `DB_PROVIDER` | `sqlite` | Database backend: `sqlite` (default, uses `DB_PATH`) or `postgres` (requires `DB_CONNECTION_STRING`). |
| `DB_CONNECTION_STRING` | — | Postgres connection string. Required when `DB_PROVIDER=postgres`; ignored for SQLite. |
| `DEFAULT_ORG_SLUG` | `default` | Slug of the org created on first boot |
| `DEPLOYMENT_MODE` | `single` | Tenancy mode: `single` or `multi`. `multi` requires a non-localhost `BASE_URL` (the host portion is the apex domain). `bound` pins every request to `BOUND_TENANT_SLUG` regardless of host (single-tenant intercept mode). |
| `BOUND_TENANT_SLUG` | — | Required when `DEPLOYMENT_MODE=bound`. Every request resolves to this tenant slug; the request host is ignored. |
| `RESERVED_SUBDOMAINS` | — | Comma-separated slugs to add to the built-in reserved list (e.g. `api,status,docs`). Prevents those subdomains from being claimed as tenant slugs in multi-tenant mode. |
| `DEPENDABLY_DEPLOYMENT_MODE` | `standalone` | Set to `ha` to require Redis and enable distributed locking |
| `DEPENDABLY_INSTANCE_ROLE` | `single` | Attached to OTel resource attributes as `dependably.instance.role`. Use to distinguish control-plane vs data-plane replicas in distributed traces. |
| `DEPLOYMENT_ENVIRONMENT` | `unknown` | Attached to OTel resource attributes as `deployment.environment` (e.g. `production`, `staging`). |
| `REDIS_CONNECTION_STRING` | — | Required when `DEPENDABLY_DEPLOYMENT_MODE=ha` |
| `REDIS_PASSWORD` | — | Password for the Redis connection. Applied on top of `REDIS_CONNECTION_STRING` when set. |
| `REDIS_SSL` | `false` | Set `true` to require TLS for the Redis connection. |
| `REDIS_DATABASE` | `0` | Redis logical database index. |
| `REDIS_KEY_PREFIX` | `dependably:` | Prefix for all Redis keys written by Dependably. Change when sharing a Redis instance with other applications. |
| `TRUSTED_PROXIES` | — (fail-closed: forwarded headers ignored) | Comma-separated IPs/CIDRs whose `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` headers are trusted (e.g. `10.0.0.0/8,172.18.0.1`). **When unset, all three forwarded headers are ignored** (fail-closed): `Connection.RemoteIpAddress`, `Request.Host`, and `Request.Scheme` reflect the real socket peer. A startup warning is logged. Set this to your reverse proxy's address(es) in any deployment that sits behind a TLS-terminating or IP-forwarding proxy — without it, `X-Forwarded-*` from the proxy are discarded, so `/metrics`/`/version` see the proxy's socket address, HSTS is not emitted, and scheme-dependent redirects may break. |
| `HOST_ROUTING` | — | Comma-separated `host=ecosystem` pairs that map incoming `Host` headers to an ecosystem prefix (e.g. `registry.npmjs.org=npm,pypi.org=pypi`). When set, requests whose `Host` matches an entry are treated as if the ecosystem path prefix were present, enabling clients that hardcode ecosystem registry hostnames to work without path rewriting. |
| `TENANT_HEADER_NAME` | `X-Dependably-Tenant` | Header name used by `HeaderTenantResolver` to identify the tenant in reverse-proxy deployments that inject a trusted tenant slug. |
| `CLAIM_ENFORCEMENT` | `off` | Set `on` to require packages to carry an upstream-provenance claim before publish is accepted. `off` (default) disables the gate; `on` enforces it on every push handler. |
| `AIR_GAPPED` | `false` | Set `true` (or `1`) to declare the instance air-gapped. Skips all outbound network calls (OSV queries, deprecation refresh, threat-feed, healthcheck pings) and logs a warning if any network-dependent setting is configured. Also see `OSV_MODE=local`. |
| `DISABLE_BACKGROUND_JOBS` | — | Comma-separated list of background job names to disable without fully air-gapping the instance (e.g. `vuln-scan,deprecation-refresh`). Known names are logged on startup. `AIR_GAPPED=true` disables all background jobs and takes precedence. |
| `REQUIRE_MFA` | — | Set `true` (or `1`) to enforce MFA enrollment instance-wide. When set, every authenticated user (tenant and system_admin) must complete TOTP enrollment before accessing any API endpoint. Composes with the per-tenant `require_mfa` setting in org_settings: either signal triggers enforcement. |
| `SHUTDOWN_GRACE_PERIOD` | `30` | Seconds the host waits for in-flight requests to drain after SIGTERM before forcefully exiting. Passed to ASP.NET Core's `ShutdownTimeout`. |
| `SHUTDOWN_PRESTOP_DELAY` | `10` | Seconds to sleep after SIGTERM and before draining. Gives load balancers time to remove this replica from rotation before the server stops accepting new connections. |

### First boot

These variables are consumed once, on the very first startup (when the `orgs` table is empty), to seed the initial admin account. They have no effect on subsequent starts.

| Variable | Default | Description |
|---|---|---|
| `FIRST_BOOT_ADMIN_EMAIL` | `admin@dependably.local` | Email address for the initial admin user created on first boot. |
| `FIRST_BOOT_ADMIN_PASSWORD` | random (logged) | Password for the initial admin user. When unset a random password is generated and printed to the startup log. Set this to skip the log-scrape step in automated deployments. |
| `FIRST_BOOT_SYSTEM_ADMIN_EMAIL` | `system@dependably.local` | Email for the `system_admin` operator account created on first boot (multi-tenant mode). Falls back to `FIRST_BOOT_ADMIN_EMAIL` when unset. |
| `FIRST_BOOT_SYSTEM_ADMIN_PASSWORD` | — | Password for the `system_admin` account. Falls back to `FIRST_BOOT_ADMIN_PASSWORD` when unset. |

### Blob storage

Storage has two tiers: **cache** (proxy artefacts, eviction-friendly) and **registry** (published artefacts, durable, never auto-evicted). Every storage variable below also accepts `_CACHE` / `_REGISTRY` suffixed variants for per-tier overrides; the unsuffixed value applies to both tiers.

| Variable | Default | Description |
|---|---|---|
| `STORAGE_BACKEND` | `local` | Blob storage backend: `local`, `s3`, or `azure` |
| `LOCAL_STORAGE_PATH` | `/data/blobs` | Root directory for local blob storage |
| `S3_BUCKET` | — | S3 bucket name (required when `STORAGE_BACKEND=s3`) |
| `S3_REGION` | — | AWS region (required when `STORAGE_BACKEND=s3`) |
| `AZURE_CONNECTION_STRING` | — | Azure Storage connection string (required when `STORAGE_BACKEND=azure`) |
| `AZURE_CONTAINER` | — | Azure blob container name (required when `STORAGE_BACKEND=azure`) |
| `PROXY_STAGING_PATH` | OS temp dir | Hash-and-stage directory for the proxy-fetch MISS path. Container deployments expecting large artefacts should set this to a disk-backed volume (e.g. `/data/staging`) — `/tmp` is often tmpfs (RAM-backed), which defeats the memory-bounding goal. |
| `STAGING_DISK_WARN_THRESHOLD_PERCENT` | `10` | Serilog `Warning` is emitted when available space on the staging volume falls below this percentage of total volume size. Set `0` to disable the warning. |
| `STAGING_DISK_FLOOR_BYTES` | `536870912` (512 MiB) | Hard floor: proxy fetches are rejected with 507 Insufficient Storage when available staging disk space falls below this value. When `Content-Length` is present the effective floor is `max(STAGING_DISK_FLOOR_BYTES, 2 × Content-Length)`. An explicit `0` is a deliberate opt-out that disables the guardrail entirely — both the absolute floor and the dynamic `2 × Content-Length` floor are skipped, and a startup `Warning` is logged (not recommended). A negative or unparseable value falls back to the default rather than disabling. |
| `DOTNET_GCHeapHardLimit` | — | Hex byte count; caps the .NET GC heap to protect the host from OOM-kill on memory-constrained hosts (Raspberry Pi, small ARM64 containers). Set to ~75 % of the container `mem_limit`; for a 1 GiB host use `0x30000000` (768 MiB), for 2 GiB use `0x60000000` (1.5 GiB), for 4 GiB use `0xC0000000` (3 GiB). See the `docker-compose.yml` environment block for a ready-to-uncomment example. This is a runtime hint — no code reads it; it is consumed by the .NET runtime before the process starts. |
| `CACHE_EVICT_SCHEDULE` | `0 * * * *` | Cron schedule (standard 5-field) for the cache eviction pass. Defaults to hourly. The job is a no-op when none of `CACHE_MAX_AGE_DAYS`, `CACHE_MAX_SIZE_BYTES`, or `CACHE_MAX_ARTIFACTS` are set. |
| `CACHE_MAX_AGE_DAYS` | — (no limit) | Evict proxy-cache artefacts not accessed within this many days. Unset means no age-based eviction. |
| `CACHE_MAX_SIZE_BYTES` | — (no limit) | Evict oldest-accessed proxy-cache artefacts until total cache size is at or below this byte count. |
| `CACHE_MAX_ARTIFACTS` | — (no limit) | Evict oldest-accessed proxy-cache artefacts until the row count is at or below this value. |
| `BLOB_STORE_SIZE_POLL_INTERVAL_SECONDS` | `300` | How often the blob-store size metric is refreshed. Set `0` to disable the background poller. |

### Uploads

| Variable | Default | Description |
|---|---|---|
| `MAX_UPLOAD_BYTES` | unlimited | Instance-wide upload size limit (bytes) |
| `MAX_UPLOAD_BYTES_PYPI` | — | PyPI-specific upload size limit (bytes) |
| `MAX_UPLOAD_BYTES_NPM` | — | npm-specific upload size limit (bytes) |
| `MAX_UPLOAD_BYTES_NUGET` | — | NuGet-specific upload size limit (bytes) |

### Upstream proxies

| Variable | Default | Description |
|---|---|---|
| `PyPI__Upstream` | `https://pypi.org` | Upstream PyPI registry for proxy cache |
| `Npm__Upstream` | `https://registry.npmjs.org` | Upstream npm registry for proxy cache |
| `NuGet__Upstream` | `https://api.nuget.org/v3` | Upstream NuGet registry for proxy cache |
| `Maven__Upstream` | `https://repo1.maven.org/maven2` | Upstream Maven registry (Maven Central) for proxy cache |
| `Maven__NegativeCacheTtl` | `01:00:00` | TTL (`TimeSpan` format) for negative (not-found) cache entries in the Maven proxy |
| `Maven__VerifyWithUpstreamSha256` | `true` | Verify Maven artifacts against the upstream-published `.sha256` sidecar |
| `Go__Upstream` | `https://proxy.golang.org` | Upstream Go module proxy (GOPROXY) seeded for new orgs. Override to point at a corporate mirror or GOPROXY-compatible proxy (e.g. `https://goproxy.cn`). Per-org registries are managed from the web UI; this value seeds the initial row. |
| `Go__SumDb` | `sum.golang.org` | The single Go checksum database (sumdb) proxied at `/go/sumdb/{name}/…` per the GOPROXY spec. A request naming any other sumdb returns 404 so the go client falls back to verifying directly; only this configured host is fetched (never a client-chosen host). Accepts a bare host or a full URL. To consume private modules whose checksums are not in the public sumdb, clients still set `GOPRIVATE` (or `GONOSUMDB`/`GONOSUMCHECK`) for those module prefixes so the go toolchain skips checksum-database verification for them. |
| `Cargo__Upstream` | `https://index.crates.io` | Upstream Cargo sparse registry index seeded for new orgs. Override to point at a mirror (the value must be a sparse index base URL, not the crates.io git index). Per-org registries are managed from the web UI; this value seeds the initial row. |
| `Rpm__Upstream` | — (no default URL) | Upstream RPM repo base URL. Proxy passthrough is enabled by default per-org (`ProxyPassthroughEnabled`), like every ecosystem — RPM is not disabled by default. It just has **no built-in default upstream** (RPM repos are distro/release-specific), so set this to give RPM a fetch target. |
| `Rpm__UpstreamMode` | `passthrough` | `passthrough` forwards upstream repodata verbatim and refuses hosted publish (a local package would shadow upstream); `merged` serves a combined `repomd.xml`/`primary.xml.gz` (local ∪ upstream, local shadows on NEVRA collision) and allows hosted publish alongside proxying. **Group (comps) and module (modulemd) metadata limitation**: Dependably does not generate comps or modulemd documents for locally published RPMs — group definitions and module streams are authored independently of packages. In merged mode, upstream group/module entries with content-addressed (hash-prefixed) hrefs are forwarded verbatim; plain-named entries (e.g. `comps.xml.gz` from classic createrepo) are dropped from the merged repomd so no unreachable href is advertised. In local/hosted-only mode, `comps.xml.gz`, `modules.yaml`, and similar requests return 404. `dnf install` works for all published RPMs; `dnf group install` and modular stream installs work only for packages that have definitions in the upstream repo. |
| `Rpm__GpgKey` | — (verification off) | Operator-pinned trust anchor for the RPM proxy: an inline ASCII-armored OpenPGP public key block, or a file path / `file:` URL the operator trusts out of band. When set, the proxy verifies `repomd.xml`'s detached signature (`repomd.xml.asc`) before trusting upstream metadata; on failure it refuses to resolve (fail closed). When unset, verification is skipped and a startup warning is logged. The anchor must be operator-provided — the upstream-fetched GPG key is not used as the trust root (circular against a MITM). |
| `Rpm__VerifyRepomdSignature` | derived | Force RPM signature verification on/off. When unset, verification is enabled iff `Rpm__GpgKey` is set. Setting `true` with no parseable key fails every resolution closed. |
| `Oci__ManifestTagTtl` / `Oci__TokenCacheDuration` / `Oci__UpstreamHttpTimeout` / `Oci__CatalogEnabled` | 5m / 55m / 30m / off | Instance-level OCI proxy tunings. **Upstream OCI registries are no longer configured here** — they are per-org and managed in Settings → Proxy → Upstream registries (host + repository-prefix routing + auth type), like every other ecosystem. Every org is seeded with Docker Hub and `mcr.microsoft.com` defaults. |

### Observability

| Variable | Default | Description |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP collector endpoint for logs, traces, and metrics push (e.g. `http://otel-collector:4317`). Logs ship via the Serilog OTLP sink (in addition to the always-on stdout JSON sink); traces and metrics ship via the OpenTelemetry SDK. When unset, logs go to stdout only and only the Prometheus scrape endpoint is active — no OTLP is exported. |
| `OTEL_SERVICE_NAME` | `dependably` | OTel `service.name` resource attribute. Override when running multiple Dependably instances in the same trace backend. |
| `OTEL_TRACES_SAMPLER_ARG` | `0.1` | Head-sampling ratio passed to `TraceIdRatioBasedSampler` (0.0–1.0). `1.0` records every trace; `0.0` disables tracing. |
| `TENANT_COUNT_POLL_INTERVAL_SECONDS` | `60` | How often the tenant-count metric is refreshed. Set `0` to disable the background poller. |

**Local collector quickstart.** The base `docker-compose.yml` ships no telemetry plumbing. To bring up a local OpenTelemetry Collector and route the app's logs/traces/metrics to it, add the opt-in overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.observability.yml logs -f otel-collector
```

The overlay sets `OTEL_EXPORTER_OTLP_ENDPOINT` for you and runs a collector whose `debug` exporter prints every received signal to its own stdout. Swap that exporter (in `otel-collector-config.yaml`) for a real backend to retain or query the telemetry.

### Vulnerability scanning and stats

| Variable | Default | Description |
|---|---|---|
| `OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV API base URL |
| `OSV_MODE` | — (online) | Set `local` to query a sideloaded offline OSV database instead of the live API. Requires `OSV_LOCAL_PATH`. Recommended when `AIR_GAPPED=true`. |
| `OSV_LOCAL_PATH` | — | Directory containing the sideloaded OSV database files. Required when `OSV_MODE=local`. |
| `OSV_LOCAL_REFRESH_MINUTES` | `60` | How often (minutes) the local OSV database is re-read from `OSV_LOCAL_PATH`. |
| `VULN_SCAN_SCHEDULE` | `0 4 * * *` | Cron for the vulnerability scan + rescan passes |
| `VULN_SCAN_JITTER_SECONDS` | `3600` | Random offset (0..N seconds) added to each scheduled scan to avoid a thundering herd against OSV. Set `0` to disable. |
| `VULN_RESCAN_AGE_HOURS` | `24` | Re-query OSV for previously-scanned versions older than this |
| `VULN_SCAN_BATCH_DELAY_MS` | `500` | Delay between OSV `/querybatch` calls |
| `THREAT_FEED_SCHEDULE` | `0 5 * * *` | Cron for the threat-feed refresh pass (CISA KEV membership + FIRST.org EPSS scores onto `vulnerabilities.is_kev` / `epss_score`, joined via CVE aliases) |
| `THREAT_FEED_JITTER_SECONDS` | `3600` | Random offset (0..N seconds) added to each scheduled threat-feed pass. Set `0` to disable. |
| `KEV_FEED_URL` | CISA catalog URL | Override the KEV catalog JSON endpoint (mirrors, tests) |
| `EPSS_API_URL` | `https://api.first.org/data/v1/epss` | Override the EPSS API endpoint (mirrors, tests) |
| `STATS_REFRESH_INTERVAL_SECONDS` | `60` | How often `StatsRefreshService` recomputes the per-org dashboard snapshot (`org_stats_snapshot`). The `/api/v1/stats` endpoint reads this snapshot instead of running live aggregate queries on every page load. Raise it on large multi-tenant instances where the aggregate pass is expensive. |

### Retention and GC

| Variable | Default | Description |
|---|---|---|
| `GC_SCHEDULE` | `0 3 * * *` | Cron schedule for the retention GC pass (per-org version limits, proxy eviction, activity pruning). |
| `AUDIT_EVENT_RETENTION_DAYS` | `365` | Delete `audit_event` rows older than this many days. The GC pass enforces this on each run. |
| `TENANT_HARD_DELETE_GRACE_DAYS` | `30` | Days after a tenant is marked for deletion before its data is permanently removed. During the grace period the deletion can be cancelled. |
| `TENANT_HARD_DELETE_SCHEDULE` | `0 4 * * *` | Cron schedule for the tenant hard-delete sweep. |
| `ORPHAN_RECONCILE_SCHEDULE` | `0 4 * * *` | Cron schedule for the orphan-blob reconciliation pass. Lists the `hosted/` prefix in the registry tier and deletes blobs with no matching `package_versions` row. Set to a non-parseable value to disable. |
| `ORPHAN_RECONCILE_GRACE_MINUTES` | `30` | Blobs modified more recently than this many minutes are skipped by the orphan reconciler, protecting in-flight publish operations that have written the blob but not yet committed the metadata row. |

### Deprecation refresh

| Variable | Default | Description |
|---|---|---|
| `DEPRECATION_REFRESH_SCHEDULE` | `0 5 * * *` | Cron schedule for the upstream deprecation refresh pass (npm and PyPI; NuGet/Maven/RPM/OCI are skipped). |
| `DEPRECATION_REFRESH_JITTER_SECONDS` | `3600` | Random offset (0..N seconds) added to each scheduled deprecation refresh to spread load. Set `0` to disable. |
| `DEPRECATION_REFRESH_AGE_HOURS` | `24` | Re-fetch upstream deprecation metadata for versions not checked within this many hours. |
| `DEPRECATION_REFRESH_BATCH_SIZE` | `500` | Maximum number of packages to refresh per pass. |
| `DEPRECATION_REFRESH_BATCH_DELAY_MS` | `500` | Delay (ms) between batches within one pass. |

### SIEM forwarding

Dependably can forward audit events to an external SIEM collector in real time. Configure either the webhook or the syslog forwarder (not both). When neither is configured the SIEM queue is not started and `SIEM_QUEUE_CAPACITY` has no effect.

| Variable | Default | Description |
|---|---|---|
| `SIEM_MAX_LOOKBACK_DAYS` | `90` | Maximum look-back window (days) for the `/api/v1/siem` pull endpoint. Requests beyond this window are rejected. Also seeds `instance_settings.siem_max_lookback_days` on first boot. |
| `SIEM_WEBHOOK_URL` | — | HTTPS endpoint to POST audit events to as NDJSON. Activates the webhook forwarder. |
| `SIEM_WEBHOOK_BEARER` | — | Bearer token added to the `Authorization` header of each webhook POST. |
| `SIEM_WEBHOOK_ALLOW_PRIVATE` | `true` | When `true`, RFC 1918 addresses (10/8, 172.16/12, 192.168/16) are allowed in `SIEM_WEBHOOK_URL` so self-hosted collectors on private networks are reachable. Loopback, link-local (169.254/16), and cloud-metadata addresses remain blocked regardless. Set to `false` to require a public IP or hostname. |
| `SIEM_SYSLOG_HOST` | — | Hostname of the syslog receiver. Required to activate the syslog forwarder. |
| `SIEM_SYSLOG_PORT` | `514` | Port of the syslog receiver. |
| `SIEM_SYSLOG_PROTO` | `udp` | Transport: `udp`, `tcp`, or `tls`. |
| `SIEM_SYSLOG_FORMAT` | `cef` | Message format: `cef` (ArcSight Common Event Format) or `rfc5424`. |
| `SIEM_QUEUE_CAPACITY` | `1024` | In-memory queue depth for outbound SIEM events. Events are dropped (with a metric) when the queue is full. Increase for high-audit-volume deployments or a slow collector. |

### Healthcheck pinging

Silent unless `HEALTHCHECK_PING_URL` is set. When configured, the instance sends periodic pings to an external dead-man's-switch monitor (Healthchecks.io, Better Uptime, Cronitor, etc.).

| Variable | Default | Description |
|---|---|---|
| `HEALTHCHECK_PING_URL` | — | URL to GET (or POST) on every interval. Required to enable pinging. |
| `HEALTHCHECK_PING_INTERVAL_SECONDS` | `60` | How often (seconds) to ping. |
| `HEALTHCHECK_PING_TIMEOUT_SECONDS` | `10` | HTTP request timeout (seconds) for each ping. |
| `HEALTHCHECK_PING_METHOD` | `GET` | HTTP method: `GET` or `POST`. |
| `HEALTHCHECK_PING_PAYLOAD` | — | Set `status` to include a JSON readiness payload in POST pings. Has no effect with `GET`. |
| `HEALTHCHECK_PING_INSTANCE_ID` | hostname | Instance identifier included in `status` payloads. Defaults to `Environment.MachineName`. |
| `HEALTHCHECK_PING_FAIL_URL` | — | Optional URL to call when the local readiness check fails. |
| `HEALTHCHECK_PING_SCOPE` | `replica` | `replica` pings on every replica; `leader` restricts pings to the leader node (requires Redis distributed lock). |

### Invite email delivery (SMTP)

Org invite emails are sent when `SMTP_HOST` is set. When absent, the invite link is returned in the API response body for manual delivery. On send failure the endpoint falls back to returning the link and logs a Warning.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | — (email delivery disabled) | SMTP relay hostname. When unset, invite links are returned in the API response instead of emailed. |
| `SMTP_PORT` | `587` | SMTP relay port |
| `SMTP_USERNAME` | — | SMTP auth username (optional) |
| `SMTP_PASSWORD` | — | SMTP auth password (optional, never logged) |
| `SMTP_FROM` | — (required when `SMTP_HOST` set) | Envelope From address for invite emails (e.g. `invites@example.com`) |
| `SMTP_STARTTLS` | `true` | Enable STARTTLS. Set `false` to disable (e.g. for port 465 implicit TLS via a relay wrapper) |

### Metrics endpoint access

| Variable | Default | Description |
|---|---|---|
| `METRICS_ENABLED` | `true` | Whether the `/metrics` Prometheus endpoint is enabled. Env var overrides the DB `instance_settings.metrics_enabled` value. Setting this locks out the API from changing the value — the system controller returns `409 Conflict` when this env var is set. Accepted values: `true`/`1`/`yes` or `false`/`0`/`no`. |
| `METRICS_ALLOWED_IPS` | `127.0.0.1,::1` | Comma-separated IPs/CIDRs allowed to scrape `/metrics`. Env var overrides the DB allowlist and locks out the API from changing the value. When empty the endpoint is unreachable from any address. |

### Network limits

| Variable | Default | Description |
|---|---|---|
| `KESTREL_MAX_CONNECTIONS` | `10000` | Maximum number of concurrent open TCP connections Kestrel accepts. Prevents connection-table exhaustion under a slow-client (slowloris) flood. Set `0` to remove the limit (not recommended on constrained hosts). Increase for high-traffic deployments with many simultaneous clients. |

### Background write queues

The activity and download-count writers buffer DB inserts off the hot path via bounded in-process channels. Watch `dependably.activity_writer.dropped` and `dependably.download_count_writer.dropped` (OTel counters) to detect sustained writer backpressure; a rising value means the drainer is falling behind the ingest rate and rows are being shed.

| Variable | Default | Description |
|---|---|---|
| `ACTIVITY_WRITER_QUEUE_CAPACITY` | `50000` | Bounded-channel capacity for the async activity-row writer. At 200 RPS the default gives ~250 s of runway before the channel saturates and rows are shed. Raise for sustained high-burst environments; each slot holds ~600 bytes. |
| `DOWNLOAD_COUNT_WRITER_QUEUE_CAPACITY` | `50000` | Bounded-channel capacity for the async download-count increment writer. Same sizing guidance as `ACTIVITY_WRITER_QUEUE_CAPACITY`. |

### Rate limiting

All limiters are per-token (download/push) or per-source-IP (login/anonymous/metadata). Defaults are sized for a single developer's worst burst; increase for larger fleets or stricter abuse budgets.

| Variable | Default | Description |
|---|---|---|
| `DOWNLOAD_RATE_LIMIT_PERMITS` | `1000` | Sliding-window permits per second per token/IP for package downloads. |
| `DOWNLOAD_RATE_LIMIT_QUEUE` | `500` | Queue depth for the download limiter. Requests that exceed the window are queued up to this depth before returning `429`. |
| `PUSH_RATE_LIMIT_PERMITS` | `20` | Sliding-window permits per second per token for package publish. Queue depth is `0` (no queuing — burst is rejected immediately). |
| `LOGIN_RATE_LIMIT_PERMITS` | `10` | Fixed-window permits per minute per IP for the login endpoint. |
| `TOKEN_CREATE_RATE_LIMIT_PERMITS` | `60` | Fixed-window permits per hour per IP for token-creation endpoints. |
| `ANON_RATE_LIMIT_PERMITS` | `120` | Fixed-window permits per minute per IP for unauthenticated probe endpoints (`/health`, `/ready`, `/version`, `/api/v1/bootstrap`, `/api/v1/auth/methods`, `/api/v1/licenses`). |
| `IMPORT_RATE_LIMIT_PERMITS` | `5` | Sliding-window permits per minute per token for bulk import requests. Queue depth is `0` (burst is rejected immediately). |
| `MANAGEMENT_RATE_LIMIT_PERMITS` | `300` | Sliding-window permits per minute per principal for authenticated management endpoints (`/api/v1/*`) not covered by a more specific policy. `/api/v1/docs/` is exempt. |
| `METADATA_RATE_LIMIT_PERMITS` | `500` | Sliding-window permits per second per source IP for metadata GET endpoints (npm packument, PyPI simple index, NuGet registration). |
| `METADATA_RATE_LIMIT_QUEUE` | `100` | Queue depth for the metadata rate limiter. Short bursts are absorbed; sustained floods return `429` once the queue fills. |
| `METADATA_REBUILD_CONCURRENCY` | `8` | Maximum number of simultaneous cache-MISS metadata rebuilds (upstream fetches that buffer a full response). Limits peak in-flight memory allocation. Cache HITs are unaffected. |

---

## Blob storage backends

**Local (default)**

```bash
STORAGE_BACKEND=local
LOCAL_STORAGE_PATH=/data/blobs
```

**S3**

```bash
STORAGE_BACKEND=s3
S3_BUCKET=my-dependably-bucket
S3_REGION=us-east-1
# AWS credentials via standard SDK chain (env vars, instance role, etc.)
```

**Azure Blob Storage**

```bash
STORAGE_BACKEND=azure
AZURE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=..."
AZURE_CONTAINER=dependably-blobs
```

---

## Tokens

Two token types are available per org:

- **User tokens** — tied to a user account, appear in audit logs with the user's identity
- **Service tokens** — named machine tokens with no user association, ideal for pipelines

Both support `pull` and `push` scopes. `push` implies `pull`. Tokens are stored as SHA-256 hashes; the raw value is shown only once on creation.

---

## Multitenancy

Each org has independent package namespaces, its own member list with roles (`admin`, `member`), per-ecosystem upload size limits, optional anonymous pull, and an optional PURL allowlist to restrict proxied packages.

Registry URLs are ecosystem-path-only: `/simple/`, `/npm/`, `/nuget/v3/index.json`, `/maven/`, `/rpm/`. Tenancy is host-resolved — in `DEPLOYMENT_MODE=single` (default) the bare host serves the one org; in `DEPLOYMENT_MODE=multi` each org is a subdomain of the apex host (`my-org.apex/simple/` etc.). OCI is at `/v2/` per the Distribution Spec.

---

## Proxy cache

On a cache miss, Dependably fetches from the configured upstream, verifies the SHA-256 checksum, stores the blob, and records the package as a proxy entry. Subsequent requests are served from the local blob store. Packages with a checksum mismatch are rejected and never stored.

Upstreams can be configured per org from the web UI, or globally via environment variables.

---

## High-availability deployment

Multi-replica deployments require Redis (`DEPENDABLY_DEPLOYMENT_MODE=ha`, `REDIS_CONNECTION_STRING`). Redis backs distributed locking, rate-limit state (login / invite / token-create limiters), and ASP.NET Core Data Protection key sharing.

The sections below call out constraints that are silent data-loss or security risks when violated. Read these before running more than one instance.

### SQLite metadata store — do not share over NFS

`SqliteMetadataStore` opens a single SQLite file (configured via `DB_PATH`). SQLite uses file-system locking for its write-serialization guarantee. **Network file systems (NFS, CIFS/SMB, most distributed POSIX mounts) do not implement POSIX advisory locks correctly**, and SQLite's documentation explicitly states that its locking is unsupported over NFS. Running two or more Dependably instances pointed at the same SQLite file over NFS risks write-lock corruption, WAL file divergence, and silent data loss.

**Do not:**
- Point multiple instances at a shared `DB_PATH` on an NFS/CIFS mount.
- Use SQLite (`DB_PROVIDER=sqlite`) in any multi-instance deployment.

**Do:**
- Use `DB_PROVIDER=postgres` with a shared Postgres connection string (`DB_CONNECTION_STRING`) for multi-instance deployments. Each instance connects to the same Postgres database; Postgres handles concurrent writers correctly.

### Local blob store — do not share LOCAL_STORAGE_PATH over NFS

`LocalBlobStore` reads and writes files under `LOCAL_STORAGE_PATH`. Atomic publish operations rely on `File.Move` for the final rename (which is atomic on a local POSIX filesystem). NFS does not guarantee atomic cross-directory renames, and cross-instance visibility of partial writes is undefined.

**Do not:**
- Mount the same `LOCAL_STORAGE_PATH` on an NFS volume and run more than one instance against it.

**Do:**
- Use `STORAGE_BACKEND=s3` (S3-compatible object store) or `STORAGE_BACKEND=azure` (Azure Blob Storage) for multi-instance deployments. Both backends are designed for concurrent multi-writer access. Refer to the [Blob storage backends](#blob-storage-backends) section for configuration.

### OCI chunked uploads — session affinity required

OCI clients push image layers via a two-step chunked upload: a `POST /v2/{name}/blobs/uploads/` creates a session UUID, then one or more `PATCH` requests append data to a local staging file on the replica that owns the session. **If a subsequent PATCH is routed to a different replica, that replica has no staging file and returns 404.**

Configure your load balancer to pin `/v2/*/blobs/uploads/*` requests to the replica that issued the session UUID:

- **nginx**: use the `sticky` module with `hash $uri consistent;` or sticky-route on the UUID path segment.
- **Traefik**: use a sticky session with `rule: PathPrefix(`/v2/`) && PathRegexp(`/blobs/uploads/`)` and `sticky.cookie`.
- **HAProxy**: `balance uri depth 6` or `stick on path_sub(/blobs/uploads/) table …`

The affinity key is the upload UUID, which is the last path segment of the `Location` header returned by the initial `POST`. Manifest pushes (`PUT /v2/{name}/manifests/{tag}`) and blob pulls (`GET /v2/{name}/blobs/{digest}`) are stateless and need no affinity.

Set `REPLICA_HINT=true` (or `INSTANCE_ROLE=replica`) on each replica instance; Dependably logs a startup warning reminding operators that session affinity is required.

### In-process rate limiters — per-tenant limits are per-replica without Redis

The download, push, import, management-API, and anonymous-probe rate limiters maintain their sliding-window counters in process memory on each replica. Without a shared backing store, each replica enforces the configured limit independently. A client that distributes requests across N replicas can exceed the nominal per-tenant limit by up to a factor of N before any single replica returns `429`.

The login, invite, and token-create limiters are Redis-backed when `REDIS_CONNECTION_STRING` is set (`DEPENDABLY_DEPLOYMENT_MODE=ha`), so those abuse-prevention limits hold across replicas in HA mode.

**The download and push limiters remain in-process even when Redis is configured.** These are per-second sliding-window limiters on the very hot path; adding Redis round-trips to every artefact download and every package push would increase latency on the path most sensitive to it. The practical risk in a typical multi-instance deployment is proportional to the number of replicas and the configured permit ceiling — two replicas at the default 1000 permits/sec per token gives an effective ceiling of ~2000 before both replicas 429 simultaneously.

Remediation options, in order of preference:

1. **Redis + sticky sessions (recommended for HA):** Set `REDIS_CONNECTION_STRING` and configure your load balancer to route each token/IP to a consistent replica (hash on the `Authorization` header or source IP). Sticky routing keeps the per-second sliding window accurate on the hot path without Redis round-trips; Redis covers the slower abuse paths (login, token-create, invite).
2. **Sticky sessions only:** If Redis is unavailable, sticky-route all traffic for a given token to a single replica. The in-process limiter on that replica then enforces the full configured limit.
3. **Reduce the per-replica permit ceiling:** If sticky routing is not possible, set `DOWNLOAD_RATE_LIMIT_PERMITS` and `PUSH_RATE_LIMIT_PERMITS` to `ceiling / N` (where N is your replica count) so the aggregate effective limit across replicas matches the intended value. This is a coarse approximation — uneven load distribution means individual replicas may still diverge — but it bounds the worst case.

See [`DOWNLOAD_RATE_LIMIT_PERMITS`](#rate-limiting), [`PUSH_RATE_LIMIT_PERMITS`](#rate-limiting), and [`REDIS_CONNECTION_STRING`](#core) for the relevant environment variables.

### Metadata caches are per-instance

Ecosystem metadata responses (the npm/PyPI/NuGet/Maven index and registration documents) are cached in an in-process `MemoryCache` on each instance. The cache is not shared across replicas and there is no cross-instance invalidation. After a push that lands on one instance, other instances continue serving their own cached metadata until that entry's TTL expires, so a client routed to a different replica can briefly see a stale index. Convergence relies on the short cache TTLs rather than active invalidation. Out-of-process cache invalidation (for example, a Redis pub/sub fan-out on push) is future work; until then, keep metadata TTLs short in multi-instance deployments where post-push staleness matters.

---

## Security model

- **OWASP API Security Top 10** alignment: BOLA/IDOR protection, SSRF protection with DNS rebinding re-validation, path traversal rejection, CRLF injection prevention
- **Authentication**: JWT HS256 sessions (8h, HttpOnly SameSite=Strict cookie); BCrypt-12 passwords; CSPRNG token generation; constant-time comparison
- **Scope enforcement**: `pull` and `push` scopes enforced at the HTTP handler level; scope mismatch returns 403, not 401
- **Account lockout**: 10 failed login attempts → 15-minute lockout with `Retry-After` header
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Content-Security-Policy` (management API), `Strict-Transport-Security` (when behind HTTPS proxy)
- **Trusted proxy / host hardening**: Forwarded-header processing is fail-closed — when `TRUSTED_PROXIES` is unset, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` are ignored entirely so caller-supplied values cannot spoof `RemoteIpAddress`, scheme, or host. When `TRUSTED_PROXIES` is set, those headers are processed only from the listed IPs/CIDRs. Host-header filtering is derived at startup from the host portion of `BASE_URL`: when that host is non-localhost, only that host (plus `*.apex` in multi mode) and localhost are accepted; unknown `Host` headers are rejected before tenant resolution, preventing Host injection into SAML SP URLs, absolute links, and CSRF Origin comparisons. When `BASE_URL` is unset or localhost (dev/local), filtering is permissive and a startup warning is logged.
- **Schema**: idempotent `CREATE TABLE IF NOT EXISTS` applied on startup; one-shot data migrations are recorded in the `_applied_migrations` ledger (see [src/Dependably/Infrastructure/schema/schema-migrations.md](src/Dependably/Infrastructure/schema/schema-migrations.md))

---

## Internationalization

The UI and API error messages are localized. English (`en`) is the source language; French (`fr`) ships out of the box.

| File | Purpose |
|------|---------|
| `web/src/locales/en.json` | Frontend strings — English source |
| `web/src/locales/fr.json` | Frontend strings — French translation |
| `src/Dependably/Resources/SharedResource.resx` | Backend error strings — English source |
| `src/Dependably/Resources/SharedResource.fr.resx` | Backend error strings — French translation |

Adding a string: add the key to `en.json` / `SharedResource.resx`, add the translation to each locale file, then run `node i18n/scripts/i18n-validate.js` to catch missing keys.

Adding a locale: see [i18n/adding-a-locale.md](i18n/adding-a-locale.md).

Full i18n architecture: see [i18n/README.md](i18n/README.md).

---

## Architecture notes

See [CLAUDE.md](CLAUDE.md) for a full breakdown of the project structure, key architectural rules, and tech stack decisions.

Architecture decision records live in [docs/adr/](docs/adr/). Key ADRs:

- [0001 — Auth stack: Identity Core hybrid](docs/adr/0001-auth-identity-hybrid.md) — why the auth layer uses Identity Core for MFA/credential primitives but keeps bespoke first-factor login, lockout, JWT sessions, and per-request session invalidation.
