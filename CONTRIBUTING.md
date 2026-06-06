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

A single weak model cannot reliably filter its own output — the verify pass tends to rubber-stamp its own family's speculation. So a **deterministic guard** runs in code after both passes: it drops findings phrased as speculation (hedge words like *may / might / could / suggests / can lead to*), caps the number of findings, and caps total report length. These are heuristics — they can drop a genuinely tentative finding — but for an advisory check, suppressing confident-sounding noise is the right trade. A lens whose findings are all filtered out posts a single "no material findings" line, same as a clean review.

The reviews are **advisory** — `allow_failure: true` and not part of the release gate — so non-deterministic model output never blocks a merge. They run after the `sbom` stage (so the model only reviews an MR that already built and passed tests), are serialized by a shared `resource_group` so a single local model isn't hit concurrently, and run on merge-request pipelines only.

### Configuration

The endpoint and tuning knobs are job variables on the `.ai-review` template in `.gitlab-ci.yml`; override any of them as project CI/CD variables without editing YAML:

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_URL` | `http://192.168.2.25:11434` | Ollama base URL (`/api/chat` is appended) |
| `OLLAMA_MODEL` | `qwen3-coder-30b` | Model name — must be pulled on the Ollama host |
| `AI_REVIEW_MAX_DIFF_BYTES` | `120000` | Diff is truncated to this many bytes before review |
| `AI_REVIEW_DIFF_CONTEXT` | `10` | `git diff -U` context lines — more lets the model verify a hunk instead of speculating, but grows the diff toward the byte/context caps |
| `AI_REVIEW_NUM_CTX` | `16384` | Model context window |
| `AI_REVIEW_NUM_PREDICT` | `1500` | Hard cap on response length (backstops runaway generation) |
| `AI_REVIEW_TEMPERATURE` | `0.3` | Sampling temperature — a small non-zero value avoids greedy repetition loops |
| `AI_REVIEW_REPEAT_PENALTY` | `1.1` | Repetition penalty — kept modest; values ≳1.2 cause incoherent word-salad |
| `AI_REVIEW_MIN_P` | `0.05` | Min-p tail cut — drops improbable tokens; the robust guard against word-salad |
| `AI_REVIEW_SELF_VERIFY` | `1` | Run the second self-verify pass (`0` disables it) |
| `AI_REVIEW_VERIFY_PERSONA_FILE` | `ci/prompts/verify.md` | System prompt for the verify pass |
| `AI_REVIEW_MAX_FINDINGS` | `5` | Deterministic cap on findings kept per lens |
| `AI_REVIEW_MAX_REPORT_CHARS` | `2200` | Hard cap on posted report length |
| `AI_REVIEW_CURL_MAX_TIME` | `1000` | Per-request timeout, seconds |
| `AI_REVIEW_API_URL` | `$CI_API_V4_URL` | GitLab API base for posting comments (override if the API isn't at the default) |

**MR comments require a secret.** Set `AI_REVIEW_GITLAB_TOKEN` — a **masked, unprotected** CI/CD variable — to a project or group access token with **`api`** scope and at least the **Reporter** role. Without it the jobs still run and produce artifacts and job-log output; they just skip commenting. (`CI_JOB_TOKEN` can't create MR notes, hence the dedicated token.)

The runner must be able to reach `OLLAMA_URL`. Comment posting goes over the GitLab API and automatically falls back from `http` to `https` if the configured `CI_API_V4_URL` route-misses — some instances serve the v4 API only over https.

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

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | Public base URL — used in NuGet service index and npm tarball URLs |
| `DB_PATH` | `/data/dependably.db` | SQLite database file path |
| `DEFAULT_ORG_SLUG` | `default` | Slug of the org created on first boot |
| `STORAGE_BACKEND` | `local` | Blob storage backend: `local`, `s3`, or `azure` |
| `LOCAL_STORAGE_PATH` | `/data/blobs` | Root directory for local blob storage |
| `S3_BUCKET` | — | S3 bucket name (required when `STORAGE_BACKEND=s3`) |
| `S3_REGION` | — | AWS region (required when `STORAGE_BACKEND=s3`) |
| `AZURE_CONNECTION_STRING` | — | Azure Storage connection string (required when `STORAGE_BACKEND=azure`) |
| `AZURE_CONTAINER` | — | Azure blob container name (required when `STORAGE_BACKEND=azure`) |
| `MAX_UPLOAD_BYTES` | unlimited | Instance-wide upload size limit (bytes) |
| `MAX_UPLOAD_BYTES_PYPI` | — | PyPI-specific upload size limit (bytes) |
| `MAX_UPLOAD_BYTES_NPM` | — | npm-specific upload size limit (bytes) |
| `MAX_UPLOAD_BYTES_NUGET` | — | NuGet-specific upload size limit (bytes) |
| `PyPI__Upstream` | `https://pypi.org` | Upstream PyPI registry for proxy cache |
| `Npm__Upstream` | `https://registry.npmjs.org` | Upstream npm registry for proxy cache |
| `NuGet__Upstream` | `https://api.nuget.org/v3` | Upstream NuGet registry for proxy cache |
| `Maven__Upstream` | `https://repo1.maven.org/maven2` | Upstream Maven registry (Maven Central) for proxy cache |
| `Rpm__Upstream` | — (no default URL) | Upstream RPM repo base URL. Proxy passthrough is enabled by default per-org (`ProxyPassthroughEnabled`), like every ecosystem — RPM is not disabled by default. It just has **no built-in default upstream** (RPM repos are distro/release-specific), so set this to give RPM a fetch target. Pair with `Rpm__UpstreamMode=passthrough`. |
| `Oci__Upstreams` | Docker Hub | Upstream OCI registries (prefix-routed). Set via `appsettings.json` `Oci:Upstreams`, not a flat env var. |
| `DEPENDABLY_DEPLOYMENT_MODE` | `standalone` | Set to `ha` to require Redis and enable distributed locking |
| `REDIS_CONNECTION_STRING` | — | Required when `DEPENDABLY_DEPLOYMENT_MODE=ha` |
| `VULN_SCAN_SCHEDULE` | `0 4 * * *` | Cron for the vulnerability scan + rescan passes |
| `VULN_RESCAN_AGE_HOURS` | `24` | Re-query OSV for previously-scanned versions older than this |
| `VULN_SCAN_BATCH_DELAY_MS` | `500` | Delay between OSV `/querybatch` calls |

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

Org routes: `/o/{slug}/simple/`, `/o/{slug}/npm/`, `/o/{slug}/nuget/`

---

## Proxy cache

On a cache miss, Dependably fetches from the configured upstream, verifies the SHA-256 checksum, stores the blob, and records the package as a proxy entry. Subsequent requests are served from the local blob store. Packages with a checksum mismatch are rejected and never stored.

Upstreams can be configured per org from the web UI, or globally via environment variables.

---

## Security model

- **OWASP API Security Top 10** alignment: BOLA/IDOR protection, SSRF protection with DNS rebinding re-validation, path traversal rejection, CRLF injection prevention
- **Authentication**: JWT HS256 sessions (8h, HttpOnly SameSite=Strict cookie); BCrypt-12 passwords; CSPRNG token generation; constant-time comparison
- **Scope enforcement**: `pull` and `push` scopes enforced at the HTTP handler level; scope mismatch returns 403, not 401
- **Account lockout**: 10 failed login attempts → 15-minute lockout with `Retry-After` header
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Content-Security-Policy` (management API), `Strict-Transport-Security` (when behind HTTPS proxy)
- **Schema**: idempotent `CREATE TABLE IF NOT EXISTS` applied on startup — no migration history table

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
