# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**dependably** is a self-hosted private artifact repository for npm, PyPI, NuGet, Maven, RPM, and OCI images. Core design priorities: supply chain awareness (first-fetch tracking, checksum verification, SBOM generation) and multitenancy (org isolation, scoped tokens, BOLA protection).

Tech stack: **ASP.NET Core 10 / C#**, **Dapper** (parameterized SQL only — no string interpolation), **SQLite** (`IMetadataStore` / `SqliteMetadataStore`), **Serilog** structured JSON logging, **JWT** sessions, **BCrypt** passwords, **NuGet.Versioning** for NuGet version normalization. **ASP.NET Core Identity Core** (`AddIdentityCore` only, no SignInManager/cookie scheme) over custom Dapper `IUserStore` implementations supplies the MFA and credential primitives (TOTP, recovery codes, BCrypt hashing, security_stamp); the first-factor login, lockout, JWT session, and per-request session-invalidation layers are bespoke for security reasons documented in `docs/adr/0001-auth-identity-hybrid.md`.

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

# Run all tests including integration (self-contained — uses in-memory blob + SQLite stores)
dotnet test

# Run the server locally (defaults to local blob store at /data)
dotnet run --project src/Dependably

# Build release binary
dotnet publish src/Dependably -c Release -r linux-musl-x64 --self-contained true /p:PublishSingleFile=true

# Web frontend (Svelte, from web/)
cd web && npm install
npm run dev      # Vite dev server
npm run build    # production build into src/Dependably/wwwroot — wipes ALL of wwwroot,
                 # including the tracked wwwroot/swagger/ assets; restore them afterwards
                 # (git checkout -- src/Dependably/wwwroot/swagger)
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
    PurlNormalizer.cs     — canonical PURL construction for every ecosystem (pypi/npm/nuget/maven/rpm)
    PurlParser.cs         — parses PURL strings back to (ecosystem, name, version)
    UpstreamClient.cs     — fetches from upstream, verifies SHA-256, caches in blob store
  Security/
    PathSafeValidator.cs  — rejects path traversal, control chars, oversized inputs
    TokenAuthExtensions.cs — resolves Bearer/Basic token from HttpRequest
  Infrastructure/
    Models.cs             — Org, OrgSettings, Package, PackageVersion, TokenRecord records
    OrgRepository.cs      — org + settings + instance_settings queries
    PackageRepository.cs  — package/version CRUD; GetOrCreate pattern
    TokenRepository.cs    — resolves user + service tokens by SHA-256 hash
    AuditRepository.cs    — append-only audit_log + activity inserts
  Api/
    PyPiController.cs     — GET /simple/, GET /packages/{file}, POST /pypi/legacy/
    NpmController.cs      — GET+PUT /npm/{pkg}, GET /npm/tarballs/{pkg}/{file}
    NuGetController.cs    — full NuGet v3: service index, registration, flatcontainer, push, unlist, symbols
    MavenController.cs    — GET/HEAD/PUT /maven/{**path}: artifact + sidecar + metadata proxy and publish
    RpmController.cs      — GET /rpm/repodata/* + /rpm/packages/*, PUT /rpm/upload
    OciController.cs      — OCI Distribution Spec at /v2/{**path} (GET/HEAD/POST/PUT)
    ProblemResults.cs     — RFC 7807 helpers (ValidationError, Conflict, PayloadTooLarge, etc.)

tests/Dependably.Tests/
  Unit/                   — fast unit tests, no I/O
  Integration/            — WebApplicationFactory-based; use DependablyFactory
  Fixtures/packages/      — real package files (pypi/, npm/, nuget/)
```

## Key architectural rules

- **BlobKeys is the only place blob keys are constructed.** Callers never build key strings inline — enforced by the `BlobKeyConstructionComplianceTests` test (inline literal/interpolated keys passed to `IBlobStore` members fail; opt out a deliberate non-namespaced key with `// blobkey-ok: <reason>`).
- **All Dapper queries must use parameterized form.** No string interpolation inside SQL — enforced by the `NoInterpolatedSqlComplianceTests` test (the `SecurityCodeScan` analyzer also flags it as an advisory warning, but the test is the gate). A compile-time-constant interpolated fragment (e.g. a whitelisted `ORDER BY`) opts out with a `// rawsql: <reason>` comment in the 5 lines above the SQL literal.
- **SQL touching tenant-scoped tables must filter on `org_id`/`tenant_id`** — enforced by the `OrgIdFilteringComplianceTests` test. Legitimately cross-tenant queries (one-shot migrations, system-admin views, queries keyed by an FK-bound id that's already org-scoped) opt out with a `// xtenant: <reason>` comment in the 5 lines above the SQL literal.
- **Comments describe the current architecture, not its development history.** No issue/tracker numbers (`#123`), milestone tags (`M2.1`), or ephemeral branch/PR pointers (`this PR`, `see plan §2`, `pre-#91`, `used to…`) in code or config comments — that provenance belongs in git history and the issue tracker, not the source. Write present-tense descriptions of how the code behaves now. The unambiguous patterns (`#NNN`, `M<x>.<y>`, `this PR/MR`, `see plan`, `pre-#`) are enforced over `src/**/*.cs` comments by the `CommentProvenanceComplianceTests` test; the prose-history form (`used to…`) is a guideline a regex can't safely distinguish from present-tense purpose, so it stays reviewer-enforced. (Functional markers such as the `// xtenant:` / `// rawsql:` / `// blobkey-ok:` opt-outs and `// deepcode ignore` suppressions are not provenance and are fine.)
- **Project files (`*.csproj`, `*.props`) carry no XML comments.** Rationale for package pins and build config belongs in git history, the issue tracker, and project memory — not in inline `<!-- … -->` essays that drift from the truth and read as AI slop. Enforced by the `ProjectFileCommentComplianceTests` test (any `<!-- … -->` in a `.csproj`/`.props` outside `bin`/`obj`/`node_modules`/`.claude` fails). A deliberate, rare comment opts out with an inline `<!-- csproj-comment-ok: <reason> -->` marker.
- **Wall-clock reads go through the injected `TimeProvider`** (`TimeProvider.System` registered as a DI singleton; static helpers take the timestamp as a parameter, like `MavenMetadataBuilder.Build`). No `DateTime.Now/UtcNow/Today` or `DateTimeOffset.Now/UtcNow` in src or tests — enforced by the `TimeDeterminismComplianceTests` test. Tests freeze time with `FakeTimeProvider` (`TestTime.Frozen()` / `ControllerScenario.Clock` / `DependablyFactory.FrozenClock`) and assert exact instants instead of tolerances; seed offsets must stay far from window boundaries (no `.AddDays(-365)` against 1-year cutoffs — leap years shift it). A deliberate wall-clock read (e.g., a test polling deadline awaiting real async completion) opts out with `// now-ok: <reason>` in the 5 lines above.
- **`IBlobStore` never makes naming decisions** — keys always come from `BlobKeys`.
- **Architectural invariants are enforced by `Category=Compliance` static-scan tests, not just docs.** The family (`OrgIdFilteringComplianceTests`, `NoInterpolatedSqlComplianceTests`, `BlobKeyConstructionComplianceTests`, `CommentProvenanceComplianceTests`, `ProjectFileCommentComplianceTests`, `NoDebugOutputComplianceTests`, `NoFocusedOrSkippedTestComplianceTests`, plus the `Schema*ComplianceTests`) reads source, regexes for a banned pattern, and fails with the full list — so violations surface locally and on every MR. Production code uses Serilog (no `Console`/`Debug` output outside the allowlisted first-boot banner) and ships no `NotImplementedException` stubs; no committed test is focused (`.only`/`fit`/`fdescribe`) or skipped (`.skip`/`[Fact(Skip=…)]`, opt out a deliberate skip with `// skip-ok: <reason>`). Prefer adding a compliance test over a CI grep when codifying a new rule.
- **`IMetadataStore` returns raw connections.** Callers use Dapper extension methods and are responsible for `await using`.
- **PURLs are the canonical package identity.** `PurlNormalizer` is the single source of truth — used by push handlers, proxy handlers, simple index generator, and npm metadata rewriter.
- Registry routes: `/simple/`, `/npm/`, `/nuget/v3/index.json`, `/maven/`, `/rpm/`. Tenancy is host-resolved: `DEPLOYMENT_MODE=single` (default) serves the one org from the bare host; `DEPLOYMENT_MODE=multi` routes each org by subdomain (`my-org.apex/simple/` etc.). OCI has no org prefix — the Distribution Spec mandates `/v2/`.
- **Token auth**: npm uses `Authorization: Bearer <token>`; PyPI and NuGet use `Authorization: Basic base64(user:<token>)`. Resolution in `TokenAuthExtensions.ResolveTokenAsync`. Token stored as SHA-256 hash in DB.
- **NuGet push** uses `X-NuGet-ApiKey` header, not Authorization.
- **Proxy cache miss** path: check `BlobKeys.Proxy(sha256)` in blob store → if absent, fetch from upstream, verify checksum, store, serve. Configured via `PyPI:Upstream`, `Npm:Upstream`, `NuGet:Upstream` settings.
- **Upload size limits**: checked in order — org ecosystem limit → org global limit → instance ecosystem limit. Returned as 413 before any blob is written.
- **OpenAPI is split into two named documents.** Management endpoints (`/api/v1/…`) are documented at `/api/v1/docs/` (spec: `/openapi/management.json`); protocol surfaces (`/v2/`, `/simple/`, `/npm/`, `/nuget/v3/`, …) are documented at `/docs/` (spec: `/openapi/protocol.json`). The split is route-prefix-driven (via `OpenApiOptions.ShouldInclude` against `ApiDescription.RelativePath`), not attribute-driven — new controllers land in the right document automatically based on where they route.
- **Protocol surfaces follow upstream ecosystem specifications, not Dependably API versioning.** OCI is at `/v2/` because the Distribution Spec mandates it; PyPI is at `/simple/` because PEP 503 mandates it; npm and NuGet are at the paths their clients hardcode. Do not add internal version segments to these routes.
- **AI code review runs in CI as an advisory `ai-review` stage.** Four MR-only jobs (`ai-review-security`, `-code`, `-architecture`, `-docs`) send the MR diff to a local Ollama model and post per-lens findings as merge-request comments (plus a job-log section and a Markdown artifact). Logic lives in `ci/ai-review.sh`, per-lens prompts in `ci/prompts/`; jobs are `allow_failure: true` and never gate a release. Configuration and the `AI_REVIEW_GITLAB_TOKEN` secret are documented in `CONTRIBUTING.md` → "AI code review (CI)".
- **The auth stack is an intentional Identity Core hybrid.** Identity Core (`AddIdentityCore`, no SignInManager/cookie scheme) over custom Dapper stores supplies MFA/credential primitives (TOTP, recovery codes, BCrypt, security_stamp). The first-factor login (constant-time + timing sentinel = email-enumeration defense), lockout (`ILockoutStore` keyed on `(realm,tenantId,email)` so unknown accounts are boundable), JWT sessions (HS256 with scope/tid/tver claims that `RouteScopeFilter` and the `ApiToken` scheme depend on), and per-request session invalidation (`tver` claim checked in `OnJwtTokenValidatedAsync` — immediate on password change vs SecurityStampValidator's ~30-min poll) are bespoke for security reasons. `token_version`/`tver` is the canonical session-invalidation signal; `security_stamp` is Identity-internal and rotated alongside it at credential-change sites. Do not migrate the first-factor, lockout, session-issuance, or invalidation layers to `SignInManager`/`Identity.Application`/`SecurityStampValidator` without first revisiting `docs/adr/0001-auth-identity-hybrid.md`.

## Git workflow

- **Every code change gets its own git worktree + branch** (`feat|fix|chore/<slug>`) and ships through an MR — never edit the primary `main` checkout directly. `main` is a **protected** branch; a direct push to it is server-rejected.
- **Sync before you branch or tag.** `git fetch origin && git rebase origin/main` (or branch from a freshly pulled `main`). Never branch from, or tag, stale `main` — a branch cut from an out-of-date `main` re-introduces already-merged conflicts and turns green pre-merge into red post-merge.
- **A release tag is created only after the merge lands.** Pull the merged `main` first, then tag — do not tag a branch tip before its MR merges. `validate-release-tag` requires the **annotated** tag to be an ancestor of `main`, point at the current commit, and match `Directory.Build.props` `<Version>`. Release versioning steps live in `CONTRIBUTING.md` → "Versioning".

## Backend/Frontend JSON contract

- **Anything the browser/Svelte frontend consumes serializes camelCase** via `JsonSerializerDefaults.Web` — see `StatsRefreshService.SnapshotJson`, `OrgController`, `OrgSettingsController`. The C# default `JsonSerializer.Serialize(obj)` with no options emits **PascalCase**, which the frontend does not read and which surfaces as a runtime crash, not a compile error. Always pass Web options for frontend-facing payloads.
- **External wire formats deliberately differ.** OSV, SIEM, and audit-event payloads use `JsonNamingPolicy.SnakeCaseLower` (`OsvClient`, `WebhookSiemForwarder`, `PackageEvents`) because their consumers expect snake_case. **Match the consumer, never rely on the C# default.**
- New snapshot/serialization endpoints: verify the emitted casing against the frontend's expectations, and handle `JsonException` on the deserialize side rather than letting it bubble.

## Definition of done

- **A task is done only when the gate is green by exit code, not by tailed output.** Run `dotnet test --filter "Category!=Integration"` and build with `-p:TreatWarningsAsErrors=true` (CI treats warnings as errors when `CI=true`); read the real exit status, not the last scrolled lines of a long log.
- **Before claiming an MR pipeline is green, fetch the actual per-job pass/fail status** — do not infer success from a single "posted note" or a truncated tail. A masked failure read as success is the most common cause of a follow-up fix pass.
- UI changes ship no emoji codepoints in Svelte (the `chrome-emoji-guard` CI gate blocks them) — use the `icons.svg` sprite; conventions are in `DESIGN.md` §11.

## Environment variables

The complete reference table lives in [CONTRIBUTING.md → Environment variables](CONTRIBUTING.md#environment-variables) — keep that table as the single source of truth; do not duplicate it here. Behavioral notes that matter when changing code:

- Config keys are written `Section:Key` in `appsettings.json` and code; their environment-variable form uses double underscores (`Rpm__VerifyRepomdSignature` sets `Rpm:VerifyRepomdSignature`). Both spellings refer to the same setting.
- **Storage is two tiers**: *cache* holds proxy artefacts (eviction-friendly); *registry* holds published artefacts (durable, never auto-evicted). `STORAGE_BACKEND`, `LOCAL_STORAGE_PATH`, and the S3/Azure variable pairs all accept `_CACHE` / `_REGISTRY` suffixes for per-tier overrides; unsuffixed values apply to both tiers.
- **`TRUSTED_PROXIES` unset = forwarded headers ignored (fail-closed)**. When unset, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` are discarded; `Connection.RemoteIpAddress`, `Request.Host`, and `Request.Scheme` reflect the real socket peer. Set to your proxy's IP(s)/CIDR(s) to enable forwarding. A startup warning is logged when unset and a proxy-dependent feature (e.g. HSTS, scheme-relative redirects) may not work as expected.
- **RPM** follows the same per-org `ProxyPassthroughEnabled` gate (default **on**) as every ecosystem — it is not disabled by default; it just ships with no default upstream URL (repos are distro/release-specific). `Rpm:UpstreamMode`: `passthrough` (default) forwards upstream repodata verbatim and refuses hosted publish; `merged` serves local ∪ upstream (local shadows on NEVRA collision) and allows hosted publish. RPM signature trust anchors are per-org and DB-backed (Settings → Trust Anchors); `Rpm:VerifyRepomdSignature=true` is an instance-level override that forces repomd.xml signature verification on regardless of per-org anchor state — with no per-org anchor this fails every resolution closed. The upstream-fetched GPG key is never the trust root.
- **`PROXY_STAGING_PATH`** (proxy-fetch MISS hash-and-stage dir) defaults to the OS temp dir; in containers `/tmp` is often RAM-backed tmpfs, which defeats memory bounding — large-artefact deployments should point it at a disk-backed volume.
- **OCI upstream registries are per-org and DB-backed**, configured in Settings → Proxy → Upstream registries like every other ecosystem (the `upstream_registry` table, `ecosystem='oci'`, with host + repository-prefix routing + auth type). The legacy static `Oci:Upstreams` config array is no longer read. `OciOptions` retains only the instance-level scalars (`Oci:ManifestTagTtl`, `Oci:TokenCacheDuration`, `Oci:UpstreamHttpTimeout`, `Oci:CatalogEnabled`).
