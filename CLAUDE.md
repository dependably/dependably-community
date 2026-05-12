# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**dependably** is a self-hosted private artifact repository for npm, PyPI, and NuGet. Core design priorities: supply chain awareness (first-fetch tracking, checksum verification, SBOM generation) and multitenancy (org isolation, scoped tokens, BOLA protection).

Tech stack: **ASP.NET Core 9 / C#**, **Dapper** (parameterized SQL only — no string interpolation), **SQLite** (`IMetadataStore` / `SqliteMetadataStore`), **Serilog** structured JSON logging, **JWT** sessions, **BCrypt** passwords, **NuGet.Versioning** for NuGet version normalization.

## Deploy

```bash
# Build and start (ARM64 / Raspberry Pi)
docker compose up -d --build

# Rebuild after code changes
docker compose up -d --build

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Commands

```bash
# Build
dotnet build

# Run all unit/compliance/security tests
dotnet test --filter "Category!=Integration"

# Run a single test class
dotnet test --filter "ClassName=PurlNormalizerTests"

# Run all tests including integration (requires LocalStack + Azurite)
dotnet test

# Run the server locally (defaults to local blob store at /data)
dotnet run --project src/Dependably

# Build release binary
dotnet publish src/Dependably -c Release -r linux-musl-x64 --self-contained true /p:PublishSingleFile=true
```

## Project structure

```
src/Dependably/
  Program.cs              — app bootstrap, DI wiring, graceful shutdown (30s SIGTERM drain)
  Infrastructure/
    IMetadataStore.cs     — returns SqliteConnection; all queries via Dapper
    SqliteMetadataStore.cs
    SchemaInitializer.cs  — applies embedded Schema.sql on startup (idempotent)
    FirstBootService.cs   — creates default org, JWT secret, admin password on first run
    Schema.sql            — embedded resource; full DB schema (CREATE TABLE IF NOT EXISTS)
  Storage/
    IBlobStore.cs         — PutAsync/GetAsync/ExistsAsync/DeleteAsync/GetTotalSizeAsync
    BlobKeys.cs           — single source of truth for key construction
    LocalBlobStore.cs     — STORAGE_BACKEND=local (default, path from LOCAL_STORAGE_PATH)
    S3BlobStore.cs        — STORAGE_BACKEND=s3 (S3_BUCKET, S3_REGION)
    AzureBlobStore.cs     — STORAGE_BACKEND=azure (AZURE_CONNECTION_STRING, AZURE_CONTAINER)
    InMemoryBlobStore.cs  — for tests only
    BlobStoreFactory.cs   — reads STORAGE_BACKEND env var, instantiates correct impl
  Protocol/
    PurlNormalizer.cs     — PyPi/Npm/NuGet canonical PURL construction
    PurlParser.cs         — parses PURL strings back to (ecosystem, name, version)
    UpstreamClient.cs     — fetches from upstream, verifies SHA-256, caches in blob store
  Security/
    PathSafeValidator.cs  — rejects path traversal, control chars, oversized inputs
    TokenAuthExtensions.cs — resolves Bearer/Basic token from HttpRequest
  Infrastructure/
    Models.cs             — Org, OrgSettings, Package, PackageVersion, TokenRecord records
    OrgRepository.cs      — org + settings + instance_settings queries
    PackageRepository.cs  — package/version CRUD; GetOrCreate pattern
    TokenRepository.cs    — resolves user + CI/CD tokens by SHA-256 hash
    AuditRepository.cs    — append-only audit_log + activity inserts
  Api/
    PyPiController.cs     — GET /o/{org}/simple/, GET /o/{org}/packages/{file}, POST /o/{org}/pypi/legacy/
    NpmController.cs      — GET+PUT /o/{org}/npm/{pkg}, GET /o/{org}/npm/tarballs/{pkg}/{file}
    NuGetController.cs    — full NuGet v3: service index, registration, flatcontainer, push, unlist, symbols
    ProblemResults.cs     — RFC 7807 helpers (ValidationError, Conflict, PayloadTooLarge, etc.)

tests/Dependably.Tests/
  Unit/                   — fast unit tests, no I/O
  Integration/            — WebApplicationFactory-based; use DependablyFactory (to be built in #29)
  Fixtures/packages/      — real package files (pypi/, npm/, nuget/)
```

## Key architectural rules

- **BlobKeys is the only place blob keys are constructed.** Callers never build key strings inline.
- **All Dapper queries must use parameterized form.** No string interpolation inside SQL calls — enforced by CI Roslyn analyzer.
- **`IBlobStore` never makes naming decisions** — keys always come from `BlobKeys`.
- **`IMetadataStore` returns raw connections.** Callers use Dapper extension methods and are responsible for `await using`.
- **PURLs are the canonical package identity.** `PurlNormalizer` is the single source of truth — used by push handlers, proxy handlers, simple index generator, and npm metadata rewriter.
- Org routes: `/o/{org}/simple/`, `/o/{org}/npm/`, `/o/{org}/nuget/`. Short aliases `/simple/`, `/npm/`, `/nuget/` redirect to the default org.
- **Token auth**: npm uses `Authorization: Bearer <token>`; PyPI and NuGet use `Authorization: Basic base64(user:<token>)`. Resolution in `TokenAuthExtensions.ResolveTokenAsync`. Token stored as SHA-256 hash in DB.
- **NuGet push** uses `X-NuGet-ApiKey` header, not Authorization.
- **Proxy cache miss** path: check `BlobKeys.Proxy(sha256)` in blob store → if absent, fetch from upstream, verify checksum, store, serve. Configured via `PyPI:Upstream`, `Npm:Upstream`, `NuGet:Upstream` settings.
- **Upload size limits**: checked in order — org ecosystem limit → org global limit → instance ecosystem limit. Returned as 413 before any blob is written.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DB_PATH` | `/data/dependably.db` | SQLite database file path |
| `STORAGE_BACKEND` | `local` | `local`, `s3`, or `azure` — default for both storage tiers |
| `STORAGE_BACKEND_CACHE` / `STORAGE_BACKEND_REGISTRY` | inherits | #57 per-tier override. Cache holds proxy artefacts (eviction-friendly); registry holds published artefacts (durable, never auto-evicted). |
| `LOCAL_STORAGE_PATH` | `/data/blobs` | Root for local blob store |
| `LOCAL_STORAGE_PATH_CACHE` / `LOCAL_STORAGE_PATH_REGISTRY` | inherits | Per-tier path override (use to keep tiers on separate volumes) |
| `S3_BUCKET` / `S3_REGION` | — | Required for S3 backend; suffixed `_CACHE` / `_REGISTRY` for per-tier |
| `AZURE_CONNECTION_STRING` / `AZURE_CONTAINER` | — | Required for Azure backend; suffixed `_CACHE` / `_REGISTRY` for per-tier |
| `DEFAULT_ORG_SLUG` | `default` | Slug of the default org created on first boot |
| `MAX_UPLOAD_BYTES` | — | Instance-wide upload size limit |
| `MAX_UPLOAD_BYTES_PYPI/NPM/NUGET` | — | Per-ecosystem upload size limits |
| `BASE_URL` | derived from request | Public base URL for tarball rewriting and NuGet service index |
| `PyPI:Upstream` | `https://pypi.org` | Upstream PyPI registry |
| `Npm:Upstream` | `https://registry.npmjs.org` | Upstream npm registry |
| `NuGet:Upstream` | `https://api.nuget.org/v3` | Upstream NuGet registry |
| `VULN_SCAN_SCHEDULE` | `0 4 * * *` | Cron schedule for vulnerability scan + rescan passes |
| `VULN_SCAN_JITTER_SECONDS` | `3600` | Random offset (0..N seconds) added to each scheduled scan to avoid thundering-herd against OSV. Set `0` to disable. |
| `VULN_RESCAN_AGE_HOURS` | `24` | Re-check already-scanned proxy versions whose `vuln_checked_at` is older than this |
| `VULN_SCAN_BATCH_DELAY_MS` | `500` | Delay between OSV /querybatch calls during scan/rescan |
