# Operating Dependably

Reference for people running a Dependably instance: every environment variable, storage
backends, tokens and capabilities, multitenancy, proxy caching, high-availability
deployment, the security model, internationalization, and architecture notes.

Building, testing, and shipping a code change to this repository is covered in
[CONTRIBUTING.md](CONTRIBUTING.md) instead.

## Environment variables

This table is the canonical reference — other docs (including `CLAUDE.md`) link here rather than duplicating it.

> **Naming:** variables written `Section__Key` (double underscore) are the environment-variable form of the `Section:Key` configuration keys used in `appsettings.json` and code. Both spellings refer to the same setting.

### Core

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | Public base URL. The host portion (scheme and port stripped) is the apex hostname for multi-tenant subdomain routing and host-header filtering. When the host is non-localhost, the `AllowedHosts` allowlist is derived at startup — unknown `Host` headers are rejected before tenant resolution. In `DEPLOYMENT_MODE=single`, only the apex host and localhost are permitted. In `DEPLOYMENT_MODE=multi`, the apex host, `*.apex` (all tenant subdomains), and localhost are permitted. When `BASE_URL` is unset or localhost (local/dev), filtering fails closed to loopback hosts only (`localhost`/`127.0.0.1`/`[::1]`, plus `*.localhost` in `DEPLOYMENT_MODE=multi`) — never `AllowedHosts=*` — and a startup warning is logged; a reverse-proxied deployment that never sets `BASE_URL` has every non-loopback `Host` header rejected. |
| `DB_PATH` | `/data/dependably.db` | SQLite database file path |
| `DB_PROVIDER` | `sqlite` | Database backend: `sqlite` (default, uses `DB_PATH`) or `postgres` (requires `DB_CONNECTION_STRING`). |
| `DB_CONNECTION_STRING` | — | Postgres connection string. Required when `DB_PROVIDER=postgres`; ignored for SQLite. |
| `DEFAULT_ORG_SLUG` | `default` | Slug of the org created on first boot |
| `DEFAULT_TENANT_SLUG` | — | Preferred spelling of `DEFAULT_ORG_SLUG`; when both are set, `DEFAULT_TENANT_SLUG` takes precedence. |
| `DEPLOYMENT_MODE` | `single` | Tenancy mode: `single` or `multi`. `multi` requires a non-localhost `BASE_URL` (the host portion is the apex domain). `header` routes each request to the tenant named by `TENANT_HEADER_NAME` (default `X-Dependably-Tenant`), for transparent-intercept deployments where the host belongs to an impersonated public registry and cannot carry the slug; it **requires `TRUSTED_PROXIES`**, because the header is accepted only from a listed socket peer (an unlisted caller resolves to no tenant, so an unset `TRUSTED_PROXIES` serves nothing). `bound` pins every request to `BOUND_TENANT_SLUG` regardless of host (single-tenant intercept mode). `edge` runs a headless cache-only node whose sole upstream for every ecosystem is one central master (requires `EDGE_MASTER_URL` + `EDGE_MASTER_TOKEN`; collapses to one implicit realm; no admin user is created). |
| `BOUND_TENANT_SLUG` | — | Required when `DEPLOYMENT_MODE=bound`. Every request resolves to this tenant slug; the request host is ignored. |
| `TENANT_HEADER_NAME` | `X-Dependably-Tenant` | Header carrying the tenant slug when `DEPLOYMENT_MODE=header`. Honoured only on requests whose socket peer is in `TRUSTED_PROXIES` — the header decides which org's artifacts are served, including on anonymous protocol routes, so an unauthenticated caller reaching the app port directly must not be able to name one. |
| `EDGE_MASTER_URL` | — | Required when `DEPLOYMENT_MODE=edge`. Base URL of the central master dependably instance the edge pulls through to for every ecosystem. First boot seeds one upstream registry row per ecosystem pointing at this URL; a changed value is re-applied on the next restart. The host is admitted through the SSRF guard so an internal/private master over a LAN link is reachable (only this exact host is exempted). Missing in edge mode is a hard startup error. |
| `EDGE_MASTER_TOKEN` | — | Required when `DEPLOYMENT_MODE=edge`. A reader-scoped service token minted on the master (in the org whose packages this edge serves), presented on every upstream fetch. Stored encrypted at rest in the seeded upstream rows when `DEPENDABLY_MASTER_KEY` is set. Revoking it on the master takes the edge cold-only immediately. Missing in edge mode is a hard startup error. |
| `EDGE_ACCESS_TOKEN` | — | Optional, `DEPLOYMENT_MODE=edge` only. Pre-shared token that inbound edge clients present to the edge node. When set, it is seeded as a reader-scoped service token in the edge's own DB and anonymous pull is turned off, so clients must authenticate (`Authorization: Bearer <token>`, or Basic for PyPI/NuGet); rotating the value replaces the row on the next restart. When **unset**, the edge accepts anonymous reads (anonymous pull on) and logs a startup warning — intended for trusted networks only. Never logged. |
| `Proxy__MetadataCacheTtlSeconds` | `0` (disabled), `120` in edge mode | Positive TTL for the upstream-metadata cache (packuments, PyPI simple-index/JSON, NuGet registration, maven-metadata). `0` disables it — the default on a standard instance, where every metadata request forwards upstream as before. Edge mode defaults to `120` so a headless pull-through node absorbs metadata load and keeps resolving versions during a brief master outage; an explicit value (including `0`) overrides the edge default. |
| `Proxy__MetadataCacheMaxStaleSeconds` | `86400` | Serve-stale window: how long past its TTL an expired cached metadata document may still be served when the refresh fetch fails with a *transient* upstream failure (network error, timeout, 5xx). Only meaningful when the cache is enabled. A 404 is not transient and is never served stale. |
| `Proxy__MetadataCacheNegativeTtlSeconds` | `60` | TTL for cached upstream 404s, so repeated misses for a missing package don't stampede the master. `0` disables negative caching. Only meaningful when the cache is enabled. |
| `Proxy__MetadataCacheMaxBytes` | `134217728` (128 MB) | Total memory bound for cached metadata bodies. Entry size is the buffered body length plus a small overhead constant; the byte-bounded cache evicts least-recently-used entries under pressure. A single document larger than the 32 MB metadata cap passes through uncached rather than evicting the cache. |
| `METADATA_LOCAL_CACHE_TTL_SECONDS` | `600` | TTL for the rendered-response cache of **locally-owned** metadata (npm packument, NuGet registration, PyPI simple index, Maven metadata, RPM repodata) — distinct from the `Proxy__MetadataCache*` family above, which caches the *upstream-fetch* result. Invalidated on publish/unpublish, and (when `REDIS_CONNECTION_STRING` is set) fanned out to every other replica, so this TTL is a backstop for a dropped broadcast rather than the primary convergence mechanism — see [Metadata caches are per-instance, invalidated across replicas over Redis](#metadata-caches-are-per-instance-invalidated-across-replicas-over-redis). The default is the recommended value in multi-instance deployments too. |
| `METADATA_PROXY_CACHE_TTL_SECONDS` | `300` | TTL for the rendered-response cache of **proxy-merged** metadata (same four ecosystems), shorter than the local TTL because the upstream can change independently of any local publish. |
| `RESERVED_SUBDOMAINS` | — | Comma-separated slugs to add to the built-in reserved list (e.g. `api,status,docs`). Prevents those subdomains from being claimed as tenant slugs in multi-tenant mode. |
| `DEPENDABLY_DEPLOYMENT_MODE` | `standalone` | Set to `ha` to require Redis and enable distributed locking |
| `DEPENDABLY_INSTANCE_ROLE` | `single` | Attached to OTel resource attributes as `dependably.instance.role`. Use to distinguish control-plane vs data-plane replicas in distributed traces. |
| `DEPLOYMENT_ENVIRONMENT` | `unknown` | Attached to OTel resource attributes as `deployment.environment` (e.g. `production`, `staging`). |
| `REDIS_CONNECTION_STRING` | — | Required when `DEPENDABLY_DEPLOYMENT_MODE=ha` |
| `REDIS_PASSWORD` | — | Password for the Redis connection. Applied on top of `REDIS_CONNECTION_STRING` when set. |
| `REDIS_SSL` | `false` | Set `true` to require TLS for the Redis connection. |
| `REDIS_DATABASE` | `0` | Redis logical database index. |
| `REDIS_KEY_PREFIX` | `dependably:` | Prefix for all Redis keys written by Dependably. Change when sharing a Redis instance with other applications. |
| `TRUSTED_PROXIES` | — (fail-closed: forwarded headers ignored) | Comma-separated IPs/CIDRs whose `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` headers are trusted (e.g. `10.0.1.0/24,172.18.0.1`). **When unset, all three forwarded headers are ignored** (fail-closed): `Connection.RemoteIpAddress`, `Request.Host`, and `Request.Scheme` reflect the real socket peer. A startup warning is logged. Set this to your reverse proxy's address(es) in any deployment that sits behind a TLS-terminating or IP-forwarding proxy — without it, `X-Forwarded-*` from the proxy are discarded, so `/metrics`/`/version` see the proxy's socket address, HSTS is not emitted, and scheme-dependent redirects may break. **A co-located proxy (same host/docker network, forwarding to Kestrel over loopback) additionally defeats the `/metrics`, `/version`, and management docs/OpenAPI loopback-default IP allowlists** — every caller it forwards appears as `127.0.0.1`, an allowlisted operator; see [Security model](#security-model). Forwarded-header processing walks the whole `X-Forwarded-For` chain to the first untrusted hop, so **every host inside a trusted CIDR is itself a trusted forwarding hop and can present its own forged address as the client-facing source IP** — this matters most for a broad range like a whole VPC CIDR, where every in-VPC client (not just the reverse proxy) gains that power. **`DEPLOYMENT_MODE=header` depends on this setting for its tenant routing**: the tenant header (`TENANT_HEADER_NAME`, default `X-Dependably-Tenant`) is honoured only from a socket peer listed here, on the same fail-closed footing as `X-Forwarded-*` — unset means no peer qualifies, every request resolves to no tenant, and a startup warning names it. A `/0` entry is rejected outright at startup; a narrower-but-still-broad entry (wider than `/22` for IPv4, wider than `/64` for IPv6) is not rejected — a large proxy subnet can be a legitimate deployment — but logs a startup warning naming the entry, and the full resolved trusted-network set is logged at `Information` on every boot so the effective configuration is auditable. |
| `DEPENDABLY_MASTER_KEY` | — (opt-in; secrets stored unencrypted, startup warning) | Operator master key (KEK) that envelope-encrypts the DB-resident secrets — `jwt_secret`, `mfa_encryption_key`, the instance SMTP password (`smtp_password`), the operator Slack webhook URL (`system_slack_webhook_url`), per-org Slack webhook URLs, webhook signing secrets, and the DataProtection key ring — at rest. Value is an inline base64-encoded **32-byte** key (AES-256) **or** a path to a file containing one. When set, those secrets are transparently encrypted (`enc:v1:` envelope) and migrated in place on startup; **when unset, they are stored unencrypted** and a startup warning is logged — place the SQLite file / Postgres data directory on an OS-encrypted volume (LUKS/dm-crypt, encrypted EBS) instead. The key lives **outside** the database and must be injected identically into every replica. **Fail-closed:** if encrypted secrets exist but the key is absent (or invalid), the server refuses to start rather than mint new ones. Losing the key is unrecoverable for the encrypted data (`jwt_secret`/DataProtection regenerate at the cost of forced re-login; losing `mfa_encryption_key` forces MFA re-enrollment). Rotation is a manual offline re-wrap. See `ADR-envelope-encryption-db-secrets`. |
| `Auth__JwtSigningKeyRefreshSeconds` | `1` | How often each replica re-reads `instance_settings.jwt_secret` to pick up a rotation performed elsewhere (`POST /api/v1/system/jwt-secret/rotate`, apex + `scope=system`). The rotating replica reloads synchronously, so this bounds only how long *other* replicas keep honouring the superseded secret — the single trust window rotation leaves open. `0` re-reads on every validation, closing the window at the cost of a DB round trip per authenticated request. There is no old-key grace period: rotation invalidates every session, including the caller's. |
| `HOST_ROUTING` | — | Comma-separated `host=ecosystem` pairs that map incoming `Host` headers to an ecosystem prefix (e.g. `registry.npmjs.org=npm,pypi.org=pypi`), so clients that hardcode ecosystem registry hostnames reach the right controller without needing the prefix in the request they send. For every ecosystem but PyPI the mapping is a fixed per-host prefix (`/npm`, `/nuget`, `/maven`, `/rpm`, `/v2`) prepended to the path unless it's already there. `pypi` is path-dependent: a request already under `/simple/` or `/packages/` (PyPI's PEP 503 index and download routes, already unprefixed) passes through unchanged, while everything else routed to a `pypi`-mapped host (the legacy JSON API, and twine's bare-host `/legacy/` upload endpoint) gets `/pypi` prepended so it reaches the route that actually exists. |
| `CLAIM_ENFORCEMENT` | `off` | Set `on` to require packages to carry an upstream-provenance claim before publish is accepted. `off` (default) disables the gate; `on` enforces it on every push handler. |
| `PUBLISH_NAME_BINDING` | `off` | Set `on` to enforce name-level publish authorization: the first principal to hosted-publish a `(ecosystem, name)` owns it, and a later publish by a different principal (a token bound to a different identity) is refused with 403 unless it holds a grant. Applies to every hosted push path (npm, PyPI, NuGet, Maven, RPM, OCI, Cargo). Ownership is recorded on first publish **regardless** of this flag (so enabling it later has authoritative first-publisher data, and so a deleted internal name never silently reverts to upstream resolution — the dependency-confusion resurrection guard). Default `off` because binding a name to its first post-upgrade publisher would otherwise break orgs that publish one name from several principals (rotated CI tokens, shared packages); enable it once grants are in place. A user token's principal is its owning user; a service token's is the token itself. Grants are managed through the management API (caller needs `tenant:configure`): `GET /api/v1/name-bindings` lists the org's bound names, `GET`/`POST /api/v1/name-grants` list and create co-publish grants against a bound name, and `DELETE /api/v1/name-grants/{grantId}` revokes one. The surface is API-only — there is no Settings page for grants; use the management docs at `/api/v1/docs/` or direct calls. |
| `AIR_GAPPED` | `false` | Set `true` (or `1`) to declare the instance air-gapped. Skips all outbound network calls (OSV queries, deprecation refresh, threat-feed, healthcheck pings) and logs a warning if any network-dependent setting is configured. Does not stop SBOM policy re-evaluation, which makes no outbound call — see the note below the table. Also see `OSV_MODE=local`. |
| `DISABLE_BACKGROUND_JOBS` | — | Comma-separated list of background job names to disable without fully air-gapping the instance (e.g. `vuln-scan,deprecation-refresh`). Known names are logged on startup. `AIR_GAPPED=true` disables all background jobs and takes precedence. **`sbom-scan` disables scanning only, not SBOM policy re-evaluation** — see the note below the table. |
| `REQUIRE_MFA` | — | Set `true` (or `1`) to enforce MFA enrollment instance-wide. When set, every authenticated user (tenant and system_admin) must complete TOTP enrollment before accessing any API endpoint. Composes with the per-tenant `require_mfa` setting in org_settings: either signal triggers enforcement. |
| `REQUIRE_SECURE_COOKIES` | — | Set `true` to force the `Secure` flag on the session/MFA/trusted-device cookies unconditionally, regardless of the inbound request's scheme or `BASE_URL`. Without it, `Secure` is set only when the live request is HTTPS, the request carries `X-Forwarded-Proto: https` (read even when `TRUSTED_PROXIES` left the header untrusted — for this decision a forged value only restricts the forger's own cookie), or `BASE_URL` declares an https scheme — a plain-HTTP deployment ships the session cookie without `Secure`, letting a MITM capture the session JWT. A startup warning is logged whenever cookies may be issued without `Secure` on a non-HTTPS-declared deployment. Do not set this on local plain-HTTP dev — the browser will refuse to store a `Secure` cookie over `http://`, and login will silently fail to persist a session. |
| `TRUSTED_DEVICE_TTL_DAYS` | `30` | Days a "remember this device" MFA cookie remains valid before re-prompting for a TOTP code. |
| `Mfa__AcceptLegacyRecoveryCodes` | `false` | Set `true` to keep accepting MFA recovery codes stored in the legacy unsalted SHA-256 format. Codes issued before recovery-code hashes became keyed and salted (releases before v0.2.1) are stored as a bare SHA-256 digest over a ~47-bit code space — brute-forceable offline from a database dump, and usable as a second factor against a known password. A legacy digest cannot be rewritten into the keyed form (the code's plaintext is known only while it is being redeemed, at which point it is consumed), so the fallback is **off by default** and affected users regenerate their recovery codes from Settings → Security instead. New installs have no legacy codes and need no opt-in. Set this only to open a temporary migration window on an instance upgraded from a pre-v0.2.1 release; a warning is logged the first time a legacy code is rejected. Users whose codes stop verifying still hold their TOTP authenticator. |
| `SHUTDOWN_GRACE_PERIOD` | `30` | Seconds the host waits for in-flight requests to drain after SIGTERM before forcefully exiting. Passed to ASP.NET Core's `ShutdownTimeout`. |
| `SHUTDOWN_PRESTOP_DELAY` | `0` | Seconds to sleep after SIGTERM and before draining, so a load balancer can remove this replica from rotation before the server stops accepting new connections. The sleep runs *before* any background service shuts down, so a value that exceeds the container's stop timeout (Docker's default is 10s) means SIGKILL lands before the queues flush and the instance lock is released. Set it only with a matching stop grace period — `docker-compose.yml` reserves 45s; on Kubernetes, pair a 10s delay with a `terminationGracePeriodSeconds` of 45s so the pre-stop sleep and the in-flight drain both fit inside it. |
| `INSTANCE_LOCK_STALE_SECONDS` | `90` | SQLite-only. Staleness window for the shared-database single-writer guard. On startup a file-backed SQLite deployment claims a heartbeat lock. A holder whose heartbeat is already older than this window (a crashed predecessor) is taken over at once; a holder whose heartbeat is still fresh is watched — startup waits up to this window and takes the lock over if the heartbeat stays frozen (an orphaned row), or fails as soon as it advances (a live peer). The heartbeat refreshes every third of this window. The lock is released on graceful shutdown. No effect on Postgres (legitimately multi-writer) or in-memory stores. |
| `REPLICA_HINT` / `INSTANCE_ROLE` | — | Set `REPLICA_HINT=true` (or `INSTANCE_ROLE=replica`) on each multi-replica instance so Dependably logs a startup warning reminding operators that OCI chunked-upload session affinity is required — see "OCI chunked uploads — session affinity required" under [High-availability deployment](#high-availability-deployment). |

#### `sbom-scan` disables scanning, not SBOM policy re-evaluation

The nightly SBOM pass has two halves and only one of them reaches the network. **Scanning** queries
OSV to refresh the advisory links on `sbom_components`; **policy re-evaluation** reads stored
components, stored advisory rows and the tenant's own settings, and makes no outbound call.

`AIR_GAPPED=true`, `DISABLE_BACKGROUND_JOBS=sbom-scan`, and edge mode's forced disable all stop the
scanning half. They deliberately do **not** stop re-evaluation, and there is no switch that does.
Re-evaluation is what turns already-stored facts into a verdict — a withdrawn `not_affected`
statement, a CVE joining KEV, an EPSS score crossing a tenant's tolerance. Disabling it does not
reduce egress (there is none to reduce); it silently freezes `policy_status` and
`sbom_policy_findings` at whatever the last evaluation produced, with no next-pass floor to recover
them. An operator would be turning off a security verdict, not a network call, so the switch is not
offered.

The cost on a node with no projects — an edge node, or a fresh instance — is one indexed query that
returns no rows per pass.

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
| `STORAGE_PRESIGNED_READS` | `false` (off) | When on, a **full, digest-addressed OCI blob `GET`** that hits the local cache is answered with a `307` to a short-lived presigned URL on the object store, so the layer bytes never transit the application tier. Applies only to object-store backends that can sign (`s3`, and `azure` when the container client holds an account key); the `local` backend and any store that cannot sign stream as before. The redirect is issued **after** the same pull authorization, tenant-scoped lookup, and block gate the streaming path runs, and only for immutable digest-addressed content — manifests, tag lists, ranged reads, and the upstream cache-miss path are never redirected. Off by default: the URL is a replayable bearer credential for that one blob until it expires, and a redirected read is not observable by this instance beyond the moment it is granted. |
| `STORAGE_PRESIGNED_READ_TTL_SECONDS` | `60` | Lifetime of a minted presigned read URL. Clamped to `5`–`900`; an unparseable value falls back to the default. Keep it just long enough for a client to follow the redirect — it bounds the window in which a leaked URL is useful. |
| `PROXY_STAGING_PATH` | OS temp dir | Hash-and-stage directory for the proxy-fetch MISS path. Container deployments expecting large artefacts should set this to a disk-backed volume (e.g. `/data/staging`) — `/tmp` is often tmpfs (RAM-backed), which defeats the memory-bounding goal. |
| `PROXY_SOURCE_PINNING` (`Proxy__SourcePinning`) | `false` (off) | Dependency-confusion guard for non-OCI proxying. When on, the **first** upstream host to successfully serve a proxied `(org, ecosystem, package-name)` binds that name to that host; a later proxy fetch resolving the same name from a **different** upstream host is refused (before any version row is written). Off by default so it never surprises an existing multi-mirror deployment or blocks proxying after an operator legitimately re-points an upstream. **Set this to `true` on any deployment that mixes a private/internal registry with a public one** (the confusion window a public squatter would exploit); OCI already gets equivalent protection from per-upstream repository-prefix routing. Note the two fail-open skips: when pinning is off, or when an upstream row has no parseable URL, the pin check is bypassed. |
| `STAGING_DISK_WARN_THRESHOLD_PERCENT` | `10` | Serilog `Warning` is emitted when available space on the staging volume falls below this percentage of total volume size. Set `0` to disable the warning. |
| `STAGING_DISK_FLOOR_BYTES` | `536870912` (512 MiB) | Hard floor: proxy fetches are rejected with 507 Insufficient Storage when available staging disk space falls below this value. When `Content-Length` is present the effective floor is `max(STAGING_DISK_FLOOR_BYTES, 2 × Content-Length)`. An explicit `0` is a deliberate opt-out that disables the guardrail entirely — both the absolute floor and the dynamic `2 × Content-Length` floor are skipped, and a startup `Warning` is logged (not recommended). A negative or unparseable value falls back to the default rather than disabling. |
| `STAGING_DISK_POLL_INTERVAL_SECONDS` | `60` | How often the background staging-disk monitor samples free/used space on the staging volume and evaluates `STAGING_DISK_WARN_THRESHOLD_PERCENT`. Independent of the per-request `STAGING_DISK_FLOOR_BYTES` check, which is evaluated live on each proxy fetch. |
| `DOTNET_GCHeapHardLimit` | — | Hex byte count; caps the .NET GC heap to protect the host from OOM-kill on memory-constrained hosts (Raspberry Pi, small ARM64 containers). Set to ~75 % of the container `mem_limit`; for a 1 GiB host use `0x30000000` (768 MiB), for 2 GiB use `0x60000000` (1.5 GiB), for 4 GiB use `0xC0000000` (3 GiB). See the `docker-compose.yml` environment block for a ready-to-uncomment example. This is a runtime hint — no code reads it; it is consumed by the .NET runtime before the process starts. |
| `CACHE_EVICT_SCHEDULE` | `0 * * * *` | Cron schedule (standard 5-field) for the cache eviction pass. Defaults to hourly. The pass evicts nothing unless at least one of the three cap variables below is set. |
| `CACHE_MAX_AGE_DAYS` | — (no limit) | Evict proxy-cache artefacts not accessed within this many days. Opt-in: with this and the two caps below all unset, the eviction pass evicts nothing. A proxied version's only catalogue row lives on the cache plane, so a cap here expires packages that per-org `keep_versions` retention — the intended control, and unlimited by default — would have retained. |
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

### Tenant limits

Instance-wide defaults for per-tenant caps.

| Variable | Default | Description |
|---|---|---|
| `DEFAULT_STORAGE_QUOTA_BYTES` | — (unlimited) | Default aggregate hosted-storage quota (bytes) applied to every tenant that has no explicit per-tenant override. Seeded into `instance_settings` at first boot, and only when set — upgrading an existing install does not suddenly impose a ceiling. Editable afterward from the system_admin Settings page. |
| `MAX_ACTIVE_TOKENS_PER_TENANT` | `1000` | Maximum number of active (non-revoked) tokens a single tenant may hold at once. Seeded into `instance_settings` at first boot; editable afterward from the system_admin Settings page. |
| `MAX_CONCURRENT_OCI_UPLOADS_PER_TENANT` | `32` | Maximum number of concurrent OCI chunked-upload sessions a single tenant may have open. Bounds staging-volume exposure from abandoned `docker push` sessions. Seeded into `instance_settings` at first boot; editable afterward from the system_admin Settings page. |
| `OCI_UPLOAD_TTL_MINUTES` | `60` | Age (minutes) after which an OCI upload session's `created_at` makes it eligible for cleanup by the staging janitor. Read directly from configuration on every janitor pass — not an `instance_settings` value, so it can be changed by restarting with a new value. |

### Upstream proxies

| Variable | Default | Description |
|---|---|---|
| `PyPI__Upstream` | `https://pypi.org` | Upstream PyPI registry for proxy cache, seeded for new orgs. Per-org registries are managed from Settings → Proxy; this value seeds the initial row. |
| `Npm__Upstream` | `https://registry.npmjs.org` | Upstream npm registry for proxy cache, seeded for new orgs. Per-org registries are managed from Settings → Proxy; this value seeds the initial row. |
| `Npm__AcceptSha1Shasum` | `false` | Set `true` to let a hex SHA-1 `dist.shasum` count as the integrity check that admits an npm tarball to the proxy cache. npm publishes a `sha512` SRI in `dist.integrity` for anything published this decade; only older packuments carry `dist.shasum` alone. SHA-1 is chosen-prefix-collision-broken, so **off by default** a shasum-only packument is treated as **unverified** rather than verified: the tarball still serves — exactly like an upstream that publishes no digest at all — but the registry does not record a broken digest as an integrity guarantee. Cache placement is unaffected either way (the blob is stored under its own SHA-256, so a SHA-1 collision cannot displace an existing entry). Packages carrying a `sha512` SRI are unaffected by this setting, and every other algorithm (SHA-256, SHA-512) still decides admission normally. A warning is logged once per process the first time a shasum-only packument is admitted. |
| `NuGet__Upstream` | `https://api.nuget.org/v3` | Upstream NuGet registry for proxy cache, seeded for new orgs. Per-org registries are managed from Settings → Proxy; this value seeds the initial row. |
| `Maven__Upstream` | `https://repo1.maven.org/maven2` | Upstream Maven registry (Maven Central) for proxy cache, seeded for new orgs. Per-org registries are managed from Settings → Proxy; this value seeds the initial row. |
| `Maven__NegativeCacheTtl` | `01:00:00` | TTL (`TimeSpan` format) for negative (not-found) cache entries in the Maven proxy |
| `Maven__VerifyWithUpstreamSha256` | `true` | Verify Maven artifacts against the upstream-published `.sha256` sidecar |
| `Go__Upstream` | `https://proxy.golang.org` | Upstream Go module proxy (GOPROXY) seeded for new orgs. Override to point at a corporate mirror or GOPROXY-compatible proxy (e.g. `https://goproxy.cn`). Per-org registries are managed from the web UI; this value seeds the initial row. |
| `Go__SumDb` | `sum.golang.org` | The single Go checksum database (sumdb) proxied at `/go/sumdb/{name}/…` per the GOPROXY spec. A request naming any other sumdb returns 404 so the go client falls back to verifying directly; only this configured host is fetched (never a client-chosen host). Accepts a bare host or a full URL. To consume private modules whose checksums are not in the public sumdb, clients still set `GOPRIVATE` (or `GONOSUMDB`/`GONOSUMCHECK`) for those module prefixes so the go toolchain skips checksum-database verification for them. |
| `Cargo__Upstream` | `https://index.crates.io` | Upstream Cargo sparse registry index seeded for new orgs. Override to point at a mirror (the value must be a sparse index base URL, not the crates.io git index). Per-org registries are managed from the web UI; this value seeds the initial row. |
| `Rpm__Upstream` | — (no default URL) | Upstream RPM repo base URL. Proxy passthrough is enabled by default per-org (`ProxyPassthroughEnabled`), like every ecosystem — RPM is not disabled by default. It just has **no built-in default upstream** (RPM repos are distro/release-specific), so set this to give RPM a fetch target. |
| `Rpm__UpstreamMode` | `passthrough` | `passthrough` forwards upstream repodata verbatim and refuses hosted publish (a local package would shadow upstream); `merged` serves a combined `repomd.xml`/`primary.xml.gz` (local ∪ upstream, local shadows on NEVRA collision) and allows hosted publish alongside proxying. **Group (comps) and module (modulemd) metadata limitation**: Dependably does not generate comps or modulemd documents for locally published RPMs — group definitions and module streams are authored independently of packages. In merged mode, upstream group/module entries with content-addressed (hash-prefixed) hrefs are forwarded verbatim; plain-named entries (e.g. `comps.xml.gz` from classic createrepo) are dropped from the merged repomd so no unreachable href is advertised. In local/hosted-only mode, `comps.xml.gz`, `modules.yaml`, and similar requests return 404. `dnf install` works for all published RPMs; `dnf group install` and modular stream installs work only for packages that have definitions in the upstream repo. |
| `Rpm__VerifyRepomdSignature` | derived | Instance-level override for RPM `repomd.xml` signature verification. When unset, verification is enabled iff the org has at least one RPM trust anchor in `signature_trust_anchor`. Setting `true` with no per-org anchor configured fails every resolution closed. Trust anchors are per-org and managed via Settings → Trust Anchors (or `POST /api/v1/trust-anchors`), not via an env key. |
| `Rpm__PrimaryMapCacheSizeLimitBytes` | `314572800` (300 MiB) | Size bound, in bytes, for the dedicated in-memory cache of parsed `primary.xml.gz` package maps. Kept separate from the shared metadata cache because a Fedora/EPEL-scale primary map (tens to 100+ MB) would otherwise evict the rest of that cache, or silently fail to insert if it exceeds the shared budget. Size up for a deployment mirroring several large distro repos at once. |
| `Oci__ManifestTagTtl` / `Oci__TokenCacheDuration` / `Oci__UpstreamHttpTimeout` | 1h / 55m / 30m | Instance-level OCI proxy tunings. **Upstream OCI registries are no longer configured here** — they are per-org and managed in Settings → Proxy → Upstream registries (host + repository-prefix routing + auth type), like every other ecosystem. Every org is seeded with Docker Hub and `mcr.microsoft.com` defaults. `ManifestTagTtl` bounds how long a cached tag → digest mapping is served before upstream is *asked* again (moving tags rebuild on the order of days/weeks, so hourly is ample and cuts Docker Hub 429 exposure ~12× vs the old 5m; lower it for faster tag pickup). A 1h TTL does **not** delay acceptance by an hour — it only spaces out the asking; whether a newly observed digest is *promoted* is governed independently by the org's `min_release_age_hours` (Settings → Proxy), measured from the digest's first local observation. The two compose; they do not stack. |
| `Oci__ManifestTagStaleGrace` | `1.00:00:00` (24h) | How long past its TTL a tag's last accepted digest may still be served while the upstream is unavailable (429/5xx/timeout/transport failure). Within the window the pull succeeds with `X-Cache: STALE` and the serve is audited; past it the pull fails 502. Measured from the moment the entry became stale (`last_revalidated + ManifestTagTtl`) and never extended by further failed attempts, so an outage cannot become serve-stale-forever. A genuine upstream 404 is a miss, never a stale serve. |
| `Oci__MaxBlobProxyBytes` | `10737418240` (10 GiB) | Largest single blob this registry will proxy from an OCI upstream. The OCI plane needs its own bound because its unit of transfer is an image layer: a CUDA/ML base image routinely ships one layer several GB wide, where a metadata document or an npm tarball does not — so this is sized here rather than by raising the shared upstream-fetch constant, which would widen every other ecosystem's bound at the same time. **This is a disk bound, not a memory one:** blobs stream straight into the cache-tier blob store and are never buffered whole, so raising it commits cache-tier storage (`LOCAL_STORAGE_PATH_CACHE` and the eviction settings governing it), not process memory. Size the cache tier before raising it. A blob over the cap is refused with **502 `UNAVAILABLE`**, never 404 — a refusal is not an absence, and reporting it as one sends operators looking for a corrupt cache. Minimum accepted value is 1 MiB; the instance refuses to start below it. |
| `Sbom__MaxUploadBytes` | `52428800` (50 MiB) | Instance-level ceiling, in bytes, on one uploaded SBOM/VEX/SARIF document. Checked before any byte is written to the blob store, so an oversized document is refused with `413` rather than staged and discarded. Instance-level on purpose: these are analysis documents about a team's own build, not registry artefacts, so they do not walk the per-org ecosystem/global upload-limit ladder. |
| `Apk__Upstream` | `https://dl-cdn.alpinelinux.org/alpine` | Upstream Alpine apk mirror seeded for new orgs. The route is 1:1 with dl-cdn's `{release}/{repo}/{arch}/{file}` layout, so a sed rewrite of `/etc/apk/repositories` is the only client-side change. Per-org registries are managed from Settings → Proxy; this value seeds the initial row. apk is proxy-only (no hosted push, like Go). |
| `Terraform__Upstream` | `https://registry.terraform.io` | Upstream Terraform provider registry seeded for new orgs. Its **host** is also what admits a provider to the mirror: a provider is addressed by its own source address (`{hostname}/{namespace}/{type}`), and only providers whose hostname matches a configured upstream are served — the request path never becomes the fetch host. Note this registry serves metadata only; archives come from whatever host it names in `download_url` (`releases.hashicorp.com` for HashiCorp's own providers), discovered per version rather than configured. Terraform is proxy-only (no hosted push, like Go and apk), and the client must reach the mirror over **https** — terraform rejects an `http:` mirror while parsing its CLI config. |
| `Hex__Upstream` | `https://repo.hex.pm` | Upstream Hex repository (the read plane, not the `hex.pm/api` API) seeded for new orgs. Every Hex registry resource is RSA-signed, so an upstream is consulted only when its signing public key is known: the seeded hex.pm row uses the well-known hex.pm key, and any other upstream needs its PEM public key stored on the row (`public_key_pem`, set from Settings → Proxy → Upstream registries). Verified upstream resources are rebuilt and re-signed under the org's own key, which needs `DEPENDABLY_MASTER_KEY` to be set — without it the Hex read plane answers 503. Publishing needs a token with `publish:hex` and points Mix at `HEX_API_URL=<base>/hex/api`; retiring needs `yank:hex`. |
| `Apk__IndexTtl` | `00:01:00` (60s) | TTL (`TimeSpan` format) for the memory-cached passthrough of `APKINDEX.tar.gz` and other index-adjacent files (`.SIGN.RSA.*`, etc). `.apk` package blobs stay TOFU-only (see `Apk__NegativeCacheTtl` note); `APKINDEX.tar.gz` itself is signature-verified server-side — see `Apk__VerifyIndexSignature`. |
| `Apk__VerifyIndexSignature` | derived | Instance-level override for `APKINDEX.tar.gz` embedded RSA signature verification. When unset, verification is enabled iff the org has at least one apk `rsa` trust anchor in `signature_trust_anchor`. Setting `true` with no per-org anchor configured fails every resolution closed. `APKINDEX.tar.gz` is two concatenated gzip members — the first decompresses to a tiny tar of `.SIGN.RSA[256\|512].<keyname>` entries (raw PKCS#1v1.5 signatures over the raw compressed bytes of the second member); a failed check refuses to cache or serve the index (502). `.apk` package fetches remain TOFU regardless of this setting — only the index is verified. SHA-1 (`.SIGN.RSA.<keyname>`) signatures verify only under `Apk__AcceptSha1IndexSignatures`. Trust anchors are per-org and managed via Settings → Trust Anchors (or `POST /api/v1/trust-anchors`), not via an env key; anchor keys must clear the minimum-strength floor (RSA ≥ 2048 bits, elliptic curves ≥ 255-bit field) at import. |
| `Apk__AcceptSha1IndexSignatures` | `false` | Set `true` to let a SHA-1 `.SIGN.RSA.<keyname>` entry satisfy `APKINDEX.tar.gz` signature verification. The digest algorithm is named by the `.SIGN.*` entry inside the **upstream-supplied index**, so leaving SHA-1 acceptable lets the artefact under verification choose the broken arm — the reason it is **off by default**. With it off, only `.SIGN.RSA256.*` / `.SIGN.RSA512.*` entries can verify; an index that carries nothing else fails the check (reason `weak_signature_algorithm`, `dependably.apk.index_signature_failures`), and a failed check refuses to cache or serve the index. **Alpine's own mirrors still sign with SHA-1**, so an org that has pinned an apk trust anchor (or set `Apk__VerifyIndexSignature=true`) needs this opt-in to verify a stock Alpine index. Orgs with no apk trust anchor are unaffected — verification does not run at all. A warning is logged once per process the first time a SHA-1 index signature is accepted, and once the first time one is refused. |
| `Apk__NegativeCacheTtl` | `00:05:00` (5m) | TTL (`TimeSpan` format) for cached upstream 404s on `.apk` package fetches, so repeated misses for a missing package/arch combination don't repeat the upstream round-trip on every request. |

### Egress proxies

`HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are **deliberately not honoured.** Every outbound HTTP
handler this codebase constructs sets `UseProxy = false`, so an ambient proxy variable in the
container or host environment has no effect on upstream registry fetches, webhook and Slack
delivery, SIEM forwarding, OSV and threat-feed lookups, or healthcheck pings.

This is a security posture, not an oversight. Those clients carry an SSRF `ConnectCallback` that
resolves the target host, refuses the connection if any resolved address is in a blocked range, and
then dials one of those already-vetted addresses — closing the DNS-rebinding window a URL-level
check alone leaves open. **The callback vets the address the handler is about to dial, and under a
proxy that address is the proxy's.** The guard would pass, and the proxy would then resolve and
fetch the real target on the app's behalf — returning "allowed" about a host that is not the one
being reached. For most of these clients the connect gate is the *only* request-time check, since
write-time URL validation is IP-literal-only and a hostname resolving to a private address passes
it.

.NET makes this reachable by environment alone: `SocketsHttpHandler.UseProxy` defaults to `true`
and a null `Proxy` falls back to `HttpClient.DefaultProxy`, which on Unix is built from
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`. No code or configuration file has to name a proxy for the
whole gate to stop applying — which is why the pairing is enforced by
`OutboundHttpHandlerComplianceTests` rather than left to review.

`NO_PROXY` is therefore not consulted either; there is nothing to exclude from.

**If you need an egress proxy**, the supported route is to add it deliberately rather than
ambiently: validate `request.RequestUri` on every hop in a `DelegatingHandler` (DNS-resolve plus the
same `SsrfGuard` predicate the connect callback uses), pin the proxy authority to an operator
allowlist, and take the gate's `// egress-ok: <reason>` marker on the handlers involved. Setting the
environment variable alone will not work, and is not made to work on purpose.

### Observability

| Variable | Default | Description |
|---|---|---|
| `LOG_FORMAT` | `json` | Console log output format. `json` (default) emits ECS (Elastic Common Schema) structured JSON to stdout via `EcsTextFormatter` — one object per line, `log.level` always present, suitable for Elastic Stack, AWS CloudWatch, Datadog, and Loki ingestion; `text` emits human-readable Serilog console output for interactive tailing. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP collector endpoint for logs, traces, and metrics push (e.g. `http://otel-collector:4317`). Logs ship via the Serilog OTLP sink (in addition to the always-on stdout JSON sink); traces and metrics ship via the OpenTelemetry SDK. When unset, logs go to stdout only and only the Prometheus scrape endpoint is active — no OTLP is exported. |
| `OTEL_SERVICE_NAME` | `dependably` | OTel `service.name` resource attribute. Override when running multiple Dependably instances in the same trace backend. |
| `OTEL_TRACES_SAMPLER_ARG` | `0.1` | Head-sampling ratio passed to `TraceIdRatioBasedSampler` (0.0–1.0). `1.0` records every trace; `0.0` disables tracing. |
| `TENANT_COUNT_POLL_INTERVAL_SECONDS` | `60` | How often the tenant-count metric is refreshed. Set `0` to disable the background poller. |
| `ADVISORY_INVENTORY_POLL_INTERVAL_SECONDS` | `300` | How often the advisory-inventory metric (`dependably.advisories.tracked`, grouped by ecosystem/severity) is refreshed. Set `0` to disable the background poller. |

**Local collector quickstart.** The base `docker-compose.yml` ships no telemetry plumbing. To bring up a local OpenTelemetry Collector and route the app's logs/traces/metrics to it, add the opt-in overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.observability.yml logs -f otel-collector
```

The overlay sets `OTEL_EXPORTER_OTLP_ENDPOINT` for you and runs a collector whose `debug` exporter prints every received signal to its own stdout. Swap that exporter (in `otel-collector-config.yaml`) for a real backend to retain or query the telemetry.

The collector image resolves through `${DEP_IMAGE_REGISTRY}` like everything else, defaulting to
`dependably.northwardlabs.ca`. Without mirror credentials, name the public registry explicitly:

```bash
DEP_IMAGE_REGISTRY=docker.io docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
```

Emptying the variable does **not** fall back the way it does in `.gitlab-ci.yml` — compose's
`${VAR:-default}` treats an empty value as absent and re-selects the mirror. The pinned digest is
the same on either host, since a pull-through proxy serves the upstream manifest unchanged.

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
| `AUDIT_EVENT_PII_DAYS` | `90` | Pseudonymization horizon for `audit_event`: the GC pass clears `source_ip` and `user_agent` on rows older than this while keeping the forensic skeleton (`actor_id`, `event_type`, `payload`, timestamp). Mirrors `AUDIT_LOG_PII_DAYS`. |
| `AUDIT_EVENT_RETENTION_DAYS` | `365` | Delete `audit_event` rows older than this many days. The GC pass enforces this on each run. Must be ≥ `AUDIT_EVENT_PII_DAYS` to get a pseudonymized window before deletion. |
| `ACTIVITY_RETENTION_DAYS` | `90` | Instance default for pruning `activity` rows (per-download IP/actor events) when an org's `activity_retention_days` is NULL. A per-org value overrides it; NULL means "use this default", not "retain forever". |
| `AUDIT_LOG_PII_DAYS` | `90` | Pseudonymization horizon for `audit_log`: the GC pass clears `source_ip` and `detail` (which carry IPs and email/SAML-NameID data) on rows older than this while keeping the forensic skeleton (actor, action, scope, timestamp). |
| `AUDIT_LOG_RETENTION_DAYS` | `365` | Deletion horizon for `audit_log`: the GC pass deletes rows older than this many days across every scope. Must be ≥ `AUDIT_LOG_PII_DAYS` to get a pseudonymized window before deletion. |
| `AUDIT_TRUNCATE_IP` | `false` | When true, audit events record the source **network** rather than the host: `/24` for IPv4, `/48` for IPv6 (e.g. `192.0.2.0/24`). Off by default because attribution is what an audit trail is for; turning it on trades that for a smaller personal-data footprint at write time. Applies only to the audit write path — rate-limit partition keys aggregate independently and are unaffected. |
| `AUDIT_DISABLE_USER_AGENT` | `false` | When true, audit events record no `user_agent` at all. A UA string is a browser/device fingerprint with little forensic value beyond "which client", so a deployment that does not want to hold one need not. |
| `LOGIN_ATTEMPTS_RETENTION_DAYS` | `30` | Delete idle, unlocked `login_attempts` rows older than this many days. The window is far beyond any lockout duration, so an active throttle is never dropped; it bounds the email-hash membership set. |
| `ACCOUNT_SEND_THROTTLE_RETENTION_DAYS` | `7` | Delete `account_send_throttle` rows whose window started more than this many days ago. A row that old is inert — the next request for that account restarts its window regardless — so the sweep changes no decision; it bounds the pseudonym set the same way `LOGIN_ATTEMPTS_RETENTION_DAYS` does. |
| `JOB_RUN_RETENTION_DAYS` | `14` | Delete successful `background_job_runs` rows older than this many days. Nothing else deletes from that table and its loudest writer is a 60-second timer, so this is the only bound on it. A non-positive or unparseable value falls back to the default — there is no value that disables the sweep. The latest run per job, and the latest success per job, are kept regardless of age so `/health` can always report a job’s last outcome. |
| `JOB_RUN_FAILURE_RETENTION_DAYS` | `90` | Delete `background_job_runs` rows whose outcome is not `success` older than this many days. Longer than `JOB_RUN_RETENTION_DAYS` on purpose: a failed or cancelled run is the forensic record an operator goes looking for, and there are few of them, so the short window is the one that removes almost all the volume. |
| `TENANT_HARD_DELETE_GRACE_DAYS` | `30` | Days after a tenant is marked for deletion before its data is permanently removed. During the grace period the deletion can be cancelled. On permanent removal the tenant's `scope='tenant'` `audit_log` rows are erased (no FK cascade covers them), and its `audit_event` rows are pseudonymized (`source_ip`/`user_agent` cleared) rather than deleted, since `audit_event.org_id`'s `ON DELETE SET NULL` foreign key means the schema already intends those rows to outlive the tenant. |
| `TENANT_HARD_DELETE_SCHEDULE` | `0 4 * * *` | Cron schedule for the tenant hard-delete sweep. |
| `ORPHAN_RECONCILE_SCHEDULE` | `0 4 * * *` | Cron schedule for the orphan-blob reconciliation pass. Lists the `hosted/` prefix in the registry tier and deletes blobs that no metadata row references. The referenced set is the union of every table that can hold a hosted blob key — `package_versions`, the secondary-file tables (`package_version_files`, `maven_version_files`, `nuget_symbol_index`), whose rows are the sole reference to artefacts such as a Maven `.pom`/sources jar, a PyPI sdist published alongside a wheel, or a NuGet symbols package, and `project_documents`, the sole reference to an uploaded SBOM/VEX/SARIF original. Registry tier only: the cache tier is `CacheEvictionService`'s concern, and the `proxy/`, `oci/`, `go/`, `cargo/`, and `apk/` key namespaces fall outside the `hosted/` prefix this sweep walks. Set to a non-parseable value to disable. **Disabling has a cost beyond deferred cleanup for uploaded SBOM/VEX/SARIF documents**: this sweep is their only reclamation path — a re-upload rewrites the `(project version, kind)` row and the document it replaced simply stops being referenced, with nothing deleting it inline — so with the sweep off, every superseded document's bytes stay on the registry tier for good. The same applies when `AIR_GAPPED` or `DISABLE_BACKGROUND_JOBS` disables the job. Superseded documents are outside the per-org storage quota (`org_storage_bytes` does not count `project_documents`), so the leak shows up as registry-tier disk, not as a tenant hitting its ceiling. |
| `ORPHAN_RECONCILE_GRACE_MINUTES` | `30` | Blobs modified more recently than this many minutes are skipped by the orphan reconciler, protecting in-flight publish operations that have written the blob but not yet committed the metadata row. |

### Deprecation refresh

| Variable | Default | Description |
|---|---|---|
| `DEPRECATION_REFRESH_SCHEDULE` | `0 5 * * *` | Cron schedule for the upstream deprecation refresh pass (npm and PyPI; NuGet/Maven/RPM/OCI are skipped). |
| `DEPRECATION_REFRESH_JITTER_SECONDS` | `3600` | Random offset (0..N seconds) added to each scheduled deprecation refresh to spread load. Set `0` to disable. |
| `DEPRECATION_REFRESH_AGE_HOURS` | `24` | Re-fetch upstream deprecation metadata for versions not checked within this many hours. |
| `DEPRECATION_REFRESH_BATCH_SIZE` | `500` | Maximum number of packages to refresh per pass. |
| `DEPRECATION_REFRESH_BATCH_DELAY_MS` | `500` | Delay (ms) between batches within one pass. |

### License backfill

| Variable | Default | Description |
|---|---|---|
| `LICENSE_BACKFILL_SCHEDULE` | `0 6 * * *` | Cron schedule for the license backfill pass. Reads the cached bytes of npm/PyPI/NuGet proxy artifacts that have never had a license-extraction pass (ingested before ingest-time license capture existed), writes any SPDX identifiers to the cache plane, and stamps them so each is scanned exactly once. Cache-only; never fetches upstream. |

### License enforcement — serve vs. publish

License policy is a per-org DB setting (`org_settings`), managed from Settings → License policy
(`PUT /api/v1/license-policy/mode`) rather than an environment variable — there is no seeding
env var because the allow/block lists and mode are meaningless until an operator populates them.
Two independent tri-state (`off` / `warn` / `block`) modes govern it:

- **`license_enforcement_mode`** (the `mode` field) gates the **serve** path: `BlockGateService`
  evaluates it on every download and index render. Under `block`, an artifact with zero recorded
  SPDX entries is treated as an unknown license (`NOASSERTION`) and denied — for the ecosystems
  whose manifests declare a license (npm/pypi/nuget/maven/cargo/rpm); go/apk/oci keep the
  empty-set pass-through because they routinely record no license at all.
- **`license_publish_enforcement_mode`** (the `publishMode` field) gates the **publish** path
  for the same license-less case, independently: `off` (the default) reproduces the original
  behavior — a license-less hosted publish is accepted, occupies storage, and is judged only at
  serve time by `license_enforcement_mode`; `warn` accepts the publish but records a
  `license_publish_warn` activity row noting it will not be servable under the current serve
  policy; `block` rejects the publish outright (`license_publish_blocked`, HTTP 403), before any
  version row is written.

The two modes are deliberately independent, not linked: an operator who turns on the serve-path
gate did not necessarily ask for publishes to start failing too, so `license_publish_enforcement_mode`
defaults `off` and no currently-succeeding publish workflow starts rejecting on upgrade. Mirroring
the same leave-unchanged-on-absent contract the five `verify_*` fields on `PUT /api/v1/proxy-settings`
use, a `PUT /api/v1/license-policy/mode` call that omits `publishMode` leaves the stored
publish-side value untouched rather than resetting it to `off`.

### SAML certificate expiry

Daily background sweep that checks the effective IdP signing certificate expiry for every tenant with SAML configured and emits `audit_log` events at configurable day-to-expiry thresholds.

| Variable | Default | Description |
|---|---|---|
| `SAML_CERT_EXPIRY_SCHEDULE` | `0 6 * * *` | Cron schedule for the SAML certificate expiry sweep (06:00 UTC daily). |
| `SAML_CERT_EXPIRY_JITTER_SECONDS` | `1800` | Random offset (0..N seconds) added to each scheduled sweep to spread load. |
| `SAML_CERT_EXPIRY_WARN_DAYS` | `30,14,7,1` | Comma-separated days-to-expiry thresholds at which an alert event is emitted. Progression is forward-only per certificate — a tenant that received a "30d" alert only gets "14d" once the window shrinks past 14. |

### SIEM forwarding

Dependably can forward audit events to an external SIEM collector in real time. Configure either the webhook or the syslog forwarder (not both). When neither is configured the SIEM queue is not started and `SIEM_QUEUE_CAPACITY` has no effect.

> **Both SIEM sinks are personal-data egress points, as is the SMTP relay.** A forwarded event carries `actor_id` and the typed `detail` payload; the SMTP relay carries recipient addresses and security-notification content. Configuring any of them sends personal data to a system outside this instance — if that system is in another jurisdiction, that is a Chapter V transfer and needs its own Art. 46 mechanism. Both SIEM transports therefore default to encrypted, and a plaintext one has to be chosen explicitly. (`SiemEvent` deliberately omits `source_ip`, so the address never leaves the instance through this path at all.)

| Variable | Default | Description |
|---|---|---|
| `SIEM_MAX_LOOKBACK_DAYS` | `90` | Maximum look-back window (days) for the `/api/v1/siem` pull endpoint. Requests beyond this window are rejected. Also seeds `instance_settings.siem_max_lookback_days` on first boot. |
| `SIEM_WEBHOOK_URL` | — | HTTPS endpoint to POST audit events to as NDJSON. Activates the webhook forwarder. **Must be `https://`** — a cleartext URL is refused at startup, because the POST carries actor ids, event payloads, and the `SIEM_WEBHOOK_BEARER` credential. Override with `SIEM_WEBHOOK_ALLOW_INSECURE`. |
| `SIEM_WEBHOOK_BEARER` | — | Bearer token added to the `Authorization` header of each webhook POST. |
| `SIEM_WEBHOOK_ALLOW_INSECURE` | `false` | When `true`, permits a plaintext `http://` `SIEM_WEBHOOK_URL` (e.g. a collector on a trusted loopback interface). Off by default: the request carries personal data and the bearer credential. Distinct from `SIEM_WEBHOOK_ALLOW_PRIVATE`, which governs the address *range*, not the transport. |
| `SIEM_WEBHOOK_ALLOW_PRIVATE` | `true` | When `true`, RFC 1918 addresses (10/8, 172.16/12, 192.168/16) are allowed in `SIEM_WEBHOOK_URL` so self-hosted collectors on private networks are reachable. Loopback, link-local (169.254/16), and cloud-metadata addresses remain blocked regardless. Set to `false` to require a public IP or hostname. |
| `SIEM_SYSLOG_HOST` | — | Hostname of the syslog receiver. Required to activate the syslog forwarder. |
| `SIEM_SYSLOG_PORT` | `514` | Port of the syslog receiver. |
| `SIEM_SYSLOG_PROTO` | `tls` | Transport: `udp`, `tcp`, or `tls`. Defaults to `tls` because the stream carries personal data; `udp`/`tcp` stay selectable and log a startup warning naming the exposure. Over UDP the events can also be forged, not merely read. |
| `SIEM_SYSLOG_FORMAT` | `cef` | Message format: `cef` (ArcSight Common Event Format) or `rfc5424`. |
| `SIEM_QUEUE_CAPACITY` | `1024` | In-memory queue depth for outbound SIEM events. Events are dropped (with a metric) when the queue is full. Increase for high-audit-volume deployments or a slow collector. |
| `SIEM_ACTIVITY_DOWNLOAD_EVENTS` | `false` | Adds `download` to the event types `/api/v1/siem/events/activity` will serve. Off by default: a download row per artefact pull is the highest-volume event the registry emits, and an authorized pull is not something a SOC can triage. While it is off, a collector that asks for `event=download` gets a 400 naming this variable — never a silently short response. |
| `SIEM_ACTIVITY_LAG_SECONDS` | `30` | Write-lag cap on `/api/v1/siem/events/activity`: the feed never serves past `now − N`, and reports the window it served. Activity rows are timestamped when they are enqueued and inserted up to a flush interval later, so a collector that read up to "now" and advanced its watermark there would permanently miss every row whose timestamp precedes the watermark but whose INSERT landed after the read. Raise it on an instance whose activity writer runs backlogged (watch `dependably.activity_writer.dropped`); under a saturated queue the true lag is unbounded, so the cap bounds the common case rather than guaranteeing the worst one. |

#### Auth pull feed (`/api/v1/siem/events/auth`)

Serves the audit plane (`audit_log`). Block-gate refusals are not on it — those are the activity
feed below.

- **`action=` matches an exact name or a dotted family.** `action=checksum_failure` selects that
  one action; `action=login.` (or `action=login`) selects the whole `login.*` family; a trailing
  separator is optional and ignored. Repeatable, OR'd, deduplicated, and a row matched by several
  values is returned once. An unrecognized value is not an error — it matches nothing, so a
  collector written against a newer instance keeps working against an older one. An unrecognized
  value does count against `max_family_filters` (the instance cannot know whether the newer release
  writes it as a leaf or a family root, so it is treated as a family), and that is **one shared
  budget** with the dotted families you name deliberately — eleven family prefixes plus fifteen
  names an older instance does not recognize is twenty-six, and is refused.
- **The default set is the security vocabulary.** With no `action=` parameter the feed serves every
  action marked `security_relevant` by the catalogue endpoint below: authentication and MFA, credential
  lifecycle, privilege and membership change, identity-provider trust, refusals (credential,
  capability, rate limit, scope, allowlist), supply-chain integrity failures, tenant lifecycle, and
  bulk personal-data export. Configuration changes — allowlists, licence policy, retention, proxy
  and webhook settings, user preferences — are *not* in it; they are compliance-audit material
  rather than something a SOC alerts on, and they are one `action=` value away.
- **Naming declared actions is free; naming families is what is bounded.** A filter that names a
  declared action becomes one entry in an `IN` list, and — because no declared action sits under
  another — carries no family `LIKE` term at all. A filter that names a dotted family, or an action
  this release does not declare, adds one unindexable `LIKE` evaluated against every candidate row
  of the window. So there are two limits rather than one: `max_action_filters` (every action the
  instance declares *plus* a full complement of families — the two sets are disjoint and a
  collector can legitimately want both) and `max_family_filters` (the number of families the
  vocabulary implies). Exceeding either is a `400` naming which one; in practice the family limit
  is the one that answers, because only declared actions are free and there are only so many of
  those. **Pinning the exact action set your collector understands, instead
  of inheriting `default_actions` and letting it widen under you on an upgrade, is both the safer
  subscription and the cheaper query.**
- **Discovery: `GET /api/v1/siem/actions`.** Returns `actions` (`[{action, security_relevant}]`
  for the whole declared vocabulary), `default_actions` (what the no-filter feed serves),
  `family_prefixes` (the dotted families the vocabulary implies — the values that count against
  the family limit, along with undeclared names), and `max_action_filters` / `max_family_filters`
  (the two limits above). Same auth as the feeds. It is the *declared* vocabulary, not a `SELECT DISTINCT` over the tenant's rows, because
  the question worth answering is "what am I **not** receiving?" — and a distinct-values query can
  only ever report what has already happened. Diff it against your subscription list when you
  upgrade; an action family added in a release is otherwise invisible until the day it fires.
- **Formats.** `application/json` (default), `application/x-ndjson`, `application/x-cef` — the
  `Accept` header negotiates. CEF carries the tenant slug as `cs4Label=OrgSlug`.
- **`orgSlug` is served beside `orgId`.** A platform-admin caller reads every tenant, and a
  read:audit credential has no tenant-lookup route, so an alert carrying only the 32-hex id cannot
  be resolved to a customer at all.
- **`actorEmail` is intentionally always null, for every user actor.** It is not a bug and it will
  not be populated. `audit_log.actor_label` denormalizes a display name for **service** actors
  only: a user's display name *is* their email, and the member-removal and retention scrubs cover a
  fixed column list, so a denormalized copy would be personal data outside the reach of both
  sweeps — an Art. 17 erasure that leaves the address behind in the audit trail. The consequence is
  a real asymmetry: a service-token action is attributable from the feed alone, a human action is
  not. Resolve an `actorId` through the management API (`GET /api/v1/users`, which is
  tenant-scoped and needs a management credential, not a read:audit one) and keep that mapping on
  the collector's side.
- **`sourceIp` is the immediate TCP peer, not necessarily the client.** With `TRUSTED_PROXIES`
  unset (the fail-closed default), forwarded headers are ignored and every row records the
  socket peer — a reverse proxy's or container bridge's address, identical across every request
  it forwards. A live instance behind an unconfigured proxy has shown every auth event over 90
  days carrying the Docker bridge gateway address. Per-source brute-force/password-spray
  correlation, geo-IP/ASN enrichment, IP blocklisting, and `same_source_ip`-style correlation
  rules all silently stop working — a frequency rule still fires on request volume, so the
  detection looks intact. Set `TRUSTED_PROXIES` to the proxy's address(es) to restore client
  attribution.
- **Action names are a declared vocabulary** (`AuditActions`), pinned by
  `AuditActionVocabularyComplianceTests`: a name a writer emits but does not declare fails the
  build, as does a declared name nothing writes and a CEF mapping for a name nothing writes.
  Rows written before this change carry `project.create` for what is now uniformly
  `project.created`; query the old spelling explicitly to read that history.

#### Auth pull feed response envelope

The JSON response from `/api/v1/siem/events/auth` carries three fields beyond `items` and
`next_cursor`. **NDJSON and CEF do not carry them** — those formats are one record per line and
their shape is fixed for existing collectors.

| Field | Meaning |
|---|---|
| `latest_event_at` | Millisecond-precision timestamp of the most recent `audit_log` row visible to this caller **ignoring the action filter**. This is what separates "my filter matched nothing" from "the registry is quiet" from "the audit writer is broken" — all three otherwise look identical: HTTP 200 with an empty `items`. |
| `matched` | Rows matching the filter across the whole `since`/`until` window, independent of page size. |
| `matched_capped` | `true` when `matched` was probed against a cap rather than counted to completion, in which case `matched` is a floor rather than an exact count. The cap exists because the action predicate is unindexable and an unscoped count over a wide window would scan the table. |

A collector should alert when `latest_event_at` keeps advancing while `matched` stays zero: that is
the registry being busy while this collector's filter selects nothing, which is a configuration
fault on the collector's side and is otherwise silent.

#### Activity pull feed (`/api/v1/siem/events/activity`)

`/api/v1/siem/events/auth` serves the audit plane (`audit_log`). Block-gate refusals are not on
that plane: they are `activity` rows, and the two planes are disjoint and never dual-written — so
this second pull endpoint is how a refusal reaches a collector at all.

- **Allowlist, not a filter.** `event=blocked` (the default) selects the whole block-gate family —
  `blocked` plus every `blocked_<gate>` arm, matched as a range so an arm added in a later release
  is carried without a config change. `event=blocked_<gate>` selects one arm. `event=download`
  needs `SIEM_ACTIVITY_DOWNLOAD_EVENTS=true`. Any other value is refused with a 400.
- **Tenant scope.** A token or tenant-session caller is pinned to its own tenant and `?org=` is
  inert for it. A platform admin (`platform:*`) reads any tenant, but must name one: the underlying
  query takes a non-nullable org id, so "every tenant at once" is not expressible on this feed.
- **Paging and the watermark.** Keyset-paged on `(created_at, id)`, newest first, via `cursor`;
  `limit` is 1–500. `until` — the instant a collector advances its watermark to, never its own
  clock — is served **only on the last page** (`next_cursor` null) and is `null` on a truncated
  one. Rows come newest-first, so a truncated page has served only the newest slice of the window
  and every older row is still behind the cursor; advancing there would step over them
  permanently. Page to the end, then advance. NDJSON carries `since`/`until`/`lag_seconds`/
  `next_cursor` in a trailer object on every page; CEF emits `# window_until=` only on the last
  one. Both window bounds are inclusive, so an event on exactly the served `until` millisecond is
  delivered again on the next poll — dedupe on event id.
- **Formats.** `application/json` (default), `application/x-ndjson`, `application/x-cef` — the same
  `Accept` negotiation as the auth feed.
- **Edge posture.** An edge replica writes activity rows to its local store but ships no management
  plane, so this endpoint exists only on the origin; edge-written rows are local forensics until
  edge→origin forwarding lands.
- **Index.** `idx_activity_org_event` serves this feed on Postgres while blocked events are a
  small fraction of `activity` (the normal shape). Above that fraction Postgres prefers
  `idx_activity_org` with a filter, and SQLite's planner takes `idx_activity_org` for this query
  regardless — a SQLite deployment carries the index's write cost without a read benefit. Adding
  it is a non-`CONCURRENTLY` build at boot under the migration lock on the HA Postgres topology.
- **Retention.** The rows behind this feed are *deleted* at the tenant's `activity_retention_days`
  (instance default `ACTIVITY_RETENTION_DAYS`, 90 days) — unlike `audit_log`, there is no
  pseudonymized tail left behind. A collector that stops polling for longer than that window loses
  those events outright.


#### Protocol-plane denial events

All three families below are in the auth feed's default set, so a collector that sends no
`action=` parameter receives them without configuring anything.

| Action | Fires when | `detail` fields |
|---|---|---|
| `auth.token.rejected` | A credential was presented and did not resolve to a usable token for the tenant it was aimed at. `reason=invalid` covers an unknown, revoked, expired or malformed secret and a disabled owner — the token lookup folds all of them into one predicate, so they are genuinely indistinguishable and no `expired` reason is emitted. `reason=tenant_mismatch` is a live credential from another tenant. | `reason`, `partition`, `route`, `ecosystem`, `count`, `window_start`, `window_end`, `replica` |
| `auth.capability.denied` | A resolved credential lacked the capability the route demanded. **Not every plane gates** — see the coverage note below. OCI additionally keeps writing its per-credential `oci.scope_denied` row. | the same fields plus `required` and `granted` |
| `ratelimit.rejected` | A request was refused by the rate limiter (`429`), on any plane. `partition` is the limiter's own subject, and it uses **more namespaces than the `auth.*` events do** (see the coverage note below) — and `policy` names the `[EnableRateLimiting("…")]` policy that refused it. | the same fields plus `policy` |

#### Coverage note: what `auth.capability.denied` does and does not see

Only the planes with an inline capability gate emit it. As of the current tree those are
**npm, PyPI, Maven, Cargo, Hex and OCI**. **NuGet, RPM, Go, APK and Terraform have no inline
capability check**, so a credential lacking the capability is never refused there and no denial is
recorded — the absence of rows for those planes means "not gated", not "nothing was attempted".

Two further limits worth stating rather than leaving to be discovered:

- **The gates are `token is not null && !token.HasCapability(…)`.** An anonymous request is not
  gated at all, by design, so with `AnonymousPull` on a read proceeds without a capability check and
  produces no denial. The event is about credentials that fall short, not about unauthenticated
  access.
- **Proxy and cache-serve branches are largely ungated** even on the six planes that do gate; the
  checks sit on the hosted-artifact branches. A denied *proxied* read is therefore rare to
  non-existent today.

Do not write a detection that treats "no `auth.capability.denied` for plane X" as evidence that
nothing was refused there.

#### Coverage note: `partition` namespaces

`partition` identifies who was refused, and **it is not one namespace — branch on the prefix,
never parse it as an address**:

| Form | Written by |
|---|---|
| `ip:<address-or-/64>` | `auth.*` events with no resolved credential, and limiter partitions that use the IP form |
| `user:<subject>` | limiter partitions for an authenticated caller |
| `token:<reference>` | `auth.*` inline capability gates (a truncated token **id**) and `ratelimit.rejected` (a hash prefix of the **presented secret**) — the same prefix, two different meanings |
| `proto:<address>` | the protocol-plane default limiter |
| `<address>:<policy>` | Redis-backed per-IP limiters |
| `overflow` | an accumulator fold — the denial is counted, but its partition is no longer resolvable |

Where each reason can originate:

| Reason | Protocol planes (`/npm/`, `/simple/`, `/v2/`, `/maven/`, `/cargo/`, `/hex/`, `/nuget/`, …) | Management plane (`/api/v1/…`) |
|---|---|---|
| `invalid` | Yes — every inline credential resolution, read and write. | Yes — this is the only plane whose routes are gated by the `ApiToken` `[Authorize]` scheme, and the record is written on challenge, not on scheme failure (see below). |
| `tenant_mismatch` | Yes — read paths, the hosted-write plane (npm publish and dist-tags, PyPI publish, NuGet push/symbols/unlist), and the whole Hex plane. | No — a management route has one tenant by construction. |
| `insufficient_capability` (`auth.capability.denied`) | Yes. | Yes. |

Five properties an operator writing rules on these needs to know:

- **A rejection is not a 401.** With anonymous pull enabled, an unresolved credential is served
  `200` as an anonymous caller; the event still fires. That is the leaked-token case — a revoked
  credential still being retried by somebody's CI job produces no error status at all.
- **They are coalesced, and the count is the signal.** Each key accumulates over a one-minute
  window and writes one row carrying `count`, so an unauthenticated caller cannot choose the audit
  write rate. Counts are **per replica**: the true total for a key is the SUM of the rows sharing
  `(org, partition, reason, window_start)`, and `replica` names which one wrote each. That SUM is
  computable because the window is **aligned to the wall clock**, not to a replica's uptime:
  `window_start`/`window_end` are the start and end of the UTC minute the counted denials fell in,
  so replicas started at unrelated instants label the same denial identically and the grouping
  joins across them. A burst spanning a minute boundary is therefore two rows per replica, one per
  minute, rather than one row straddling both. An open window is held in memory, so a `SIGKILL`
  loses up to one window; `SIGTERM` drains it.
- **`route` is the endpoint route template, never the request path.** Under sustained key spray
  the partition and route fold to the literal `overflow` while the count is preserved — a row
  reading `partition=overflow` has a real count and no attribution.
- **`partition` carries two namespaces; branch on the prefix, never parse it as an address.**
  `ip:<address>` is the rate-limit form of the source (IPv4 in full, IPv6 collapsed to its `/64`,
  so one routed allocation is one subject) and is what every `auth.token.rejected` row and every
  denial from the `[Authorize]`-gated management routes carries. `token:<8 hex>` is a truncated
  credential id and comes from the inline capability gates, which hold the resolved token. The
  management path cannot emit the `token:` form: its principal carries `sub`, which for a personal
  access token is the token *owner's* user id, so using it would name a person rather than a
  credential and would fold two of one user's tokens into a single key.
- **Tenant scope.** A cross-tenant presentation is recorded under the **target** tenant and is
  actor-less: the presenting tenant's token id and token name never appear in the target tenant's
  audit trail or SIEM feed. A denial with no resolvable tenant is written system-scope. The edge
  runs the same seams and writes the same rows, but ships no pull endpoint, so on an edge node they
  are local forensics only until edge→origin forwarding exists.
- **A failed `ApiToken` scheme is not a rejection.** Management routes accept either a JWT session
  or an API token, and ASP.NET runs both schemes against the same `Authorization: Bearer` header —
  so the token scheme fails on every ordinary dashboard request while the request itself succeeds
  on the JWT. The record is written when the request actually ends unauthorized, never at the
  scheme failure, and a dashboard session therefore produces none of these events.

### Webhook subscriptions (package events)

Per-org outbound webhooks deliver signed JSON payloads to subscriber URLs when package events occur (publish, yank, vulnerability, etc.). Subscriptions are managed in Settings → Webhooks.

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_ALLOW_PRIVATE` | — | When `true`, RFC 1918 addresses (10/8, 172.16/12, 192.168/16) are allowed as webhook endpoint targets — for example, self-hosted receivers on a private network. Loopback, link-local (169.254/16), and cloud-metadata addresses remain blocked regardless. Unset or `false` requires a public IP or hostname. |
| `WEBHOOK_QUEUE_CAPACITY` | `1024` | In-memory queue depth **per org**. Queuing is partitioned by org, so a backlog sheds only the events of the org that created it (dropped with a log warning); one org filling its queue never costs another org an event. Worst-case in-memory depth is therefore this value times the number of orgs with a simultaneous backlog — lower it on instances with a large tenant count and a small memory budget. |
| `WEBHOOK_DISPATCH_WORKERS` | `4` | How many orgs' events are delivered concurrently. Each org is served by at most one worker at a time and yields after one event, so service rotates across orgs rather than draining one org's backlog first. |
| `WEBHOOK_FANOUT_CONCURRENCY` | `8` | Upper bound on how many subscriptions within one event's fan-out are delivered to concurrently. Bounds one org's own fan-out latency without letting it open an unbounded number of outbound connections. |
| `WEBHOOK_ENVELOPE_BUDGET_SECONDS` | `120` | Hard deadline on one event's whole fan-out, applied on the shutdown drain as well as in normal service. A worker returns to serving other orgs within this bound however the subscriber endpoints behave; a delivery cut off by it is logged as a warning. One subscription's full retry budget is ~96s (4 attempts at the 15s per-attempt HTTP timeout plus 36s of backoff), so the default leaves a legitimately slow subscriber room to finish. Accepted range is 1-3600 seconds; anything else is refused with a startup warning and the default is used. |
| `BLOCK_WEBHOOK_THROTTLE_WINDOW_MINUTES` | `15` | Coalescing window for the `package.blocked` webhook event, keyed on (org, purl, refusing arm). Repeated refusals of the same coordinate inside the window dispatch once; the window resets from the most recent dispatch. Does not affect the underlying audit/activity/quarantine rows, which are written on every refusal regardless. State is process-local and in-memory (see `BlockRefusalWebhookThrottle`). A non-positive or unparseable value falls back to the default of `15` silently — there is no startup warning, unlike `WEBHOOK_ENVELOPE_BUDGET_SECONDS` above. |

Subscriptions are capped at **50 per org** (not configurable): every subscription multiplies the delivery work one event creates, and the per-event budget above bounds how much of it can be attempted. The delivery HTTP client carries a fixed **15-second** per-attempt timeout, also not configurable — it is a safety bound the budget depends on, not a tuning knob.

### Alert Slack delivery

Per-org Slack notifications for freshly-raised alerts (Settings → Integrations). Same partitioned-queue shape as the webhook dispatcher above, for the same reason: the webhook URL is tenant-supplied, so one org's unreachable endpoint must not delay another org's security alerts. The Slack HTTP client carries a fixed **10-second** per-attempt timeout.

| Variable | Default | Description |
|---|---|---|
| `ALERT_SLACK_QUEUE_CAPACITY` | `1024` | In-memory queue depth **per org** for outbound Slack alerts. Overflow drops (with a log warning) only that org's own alerts. Worst-case in-memory depth is this value times the number of orgs with a simultaneous backlog. |
| `ALERT_SLACK_WORKERS` | `4` | How many orgs' alerts are delivered concurrently, served round-robin one alert per org per turn. |
| `ALERT_SLACK_BUDGET_SECONDS` | `90` | Hard deadline on one alert's delivery including retries, applied on the shutdown drain as well as in normal service, so a worker returns to serving other orgs within this bound. Accepted range is 1-3600 seconds; anything else is refused with a startup warning and the default is used. |

### Health probes (`/health`, `/ready`)

`GET /health` is a flat liveness OK — the process is running. `GET /ready` is the readiness probe: it fans out to the metadata store, the blob store, and (when configured) Redis, and short-circuits to `503 {"status":"draining"}` from the moment `SIGTERM` starts graceful shutdown, so it carries the drain signal `/health` does not.

**Required vs reported dependencies.** Every dependency `/ready` probes is shared by the whole replica fleet, so a failure is perfectly correlated across it: an RDS failover, an S3 5xx window, or an ElastiCache failover makes all N replicas answer identically. A load balancer that deregisters on those signals removes the entire fleet for a condition it cannot route around — partial degradation becomes total outage, and it gets worse as the replica count grows. So `/ready` answers 503 only when a **required** dependency is down; the rest are reported in the body as degradation and left to alerting. That makes `/ready` safe to point an ALB/NLB target group or a Kubernetes readiness probe at.

Defaults differ per plane. On a full host the metadata store is the only required dependency — nothing resolves without it, while blob-store and Redis failures leave metadata reads, index generation, and cached-manifest serving working. On an edge node (`DEPLOYMENT_MODE=edge`) the blob store joins the required set: serving artefact bytes out of its own, usually node-local, store is the node's entire purpose, and a node-local failure is exactly the uncorrelated condition a load balancer *can* route around.

| Plane | Required (503 on failure) | Reported only (200, shown in body) |
|---|---|---|
| Full host (`DEPLOYMENT_MODE=single` / `multi`) | `db` | `blob_store`, `redis` |
| Edge node (`DEPLOYMENT_MODE=edge`) | `db`, `blob_store` | `redis` |

**Strict view.** `GET /ready?strict=true` demands every dependency green and answers 503 if any is down, required or not. Point deployment gating and alerting at the strict view; point the load balancer at the plain `/ready`. The outbound healthcheck pinger (below) always uses the strict view, since it is an alerting signal.

The body names both sets so the distinction is legible without knowing the configuration:

```json
{
  "status": "degraded",
  "strict": false,
  "checks": { "db": "ok", "blob_store": "error", "redis": "ok" },
  "required": ["db"],
  "degraded": ["blob_store"]
}
```

`status` is `ready` (all green), `degraded` (something is down but nothing load-bearing), `unready` (a required dependency is down), or `draining` (graceful shutdown). Intersect `degraded` with `required` to see whether a current failure is load-bearing. Per-check values are `ok`/`error` only — raw failure text (file paths, Redis endpoints, driver errors) is logged server-side and never returned to the anonymous caller.

| Variable | Default | Description |
|---|---|---|
| `READINESS_HARD_DEPENDENCIES` | `db` (full host), `db,blob_store` (edge) | Comma-separated readiness check names whose failure makes `/ready` answer 503. Known names: `db`, `blob_store`, `redis`. Overrides the per-plane default wholesale — set `db,blob_store,redis` to restore strict-on-every-probe behaviour, or narrow it further if your deployment genuinely serves without one of them. Unknown names are simply never matched by a check. |
| `READINESS_BLOB_PROBE_TTL_SECONDS` | `15` | How long a blob-store probe result (success *or* failure) is reused before the store is probed again. Readiness is polled by every load-balancer node against every replica; without a TTL that is one object-store metadata request per poll, a permanent unbudgeted load floor. The probe itself is already the cheapest call the backend offers (a path stat locally, a `HEAD`-equivalent metadata request on S3/Azure — never an object read). `0` disables caching and probes on every call; values above 300 are clamped. The metadata-store probe is never cached — it is the required dependency and must reflect live state. |

### Healthcheck pinging

Silent unless `HEALTHCHECK_PING_URL` is set. When configured, the instance sends periodic pings to an external dead-man's-switch monitor (Healthchecks.io, Better Uptime, Cronitor, etc.).

| Variable | Default | Description |
|---|---|---|
| `HEALTHCHECK_PING_URL` | — | URL to GET (or POST) on every interval. Required to enable pinging. |
| `HEALTHCHECK_PING_INTERVAL_SECONDS` | `60` | How often (seconds) to ping. Values below `1` are raised to `1` with a startup warning; omit `HEALTHCHECK_PING_URL` to disable pinging. |
| `HEALTHCHECK_PING_TIMEOUT_SECONDS` | `10` | HTTP request timeout (seconds) for each ping. Values below `1` are raised to `1` with a startup warning. |
| `HEALTHCHECK_PING_METHOD` | `GET` | HTTP method: `GET` or `POST`. |
| `HEALTHCHECK_PING_PAYLOAD` | — | Set `status` to include a JSON readiness payload in POST pings. Has no effect with `GET`. |
| `HEALTHCHECK_PING_INSTANCE_ID` | hostname | Instance identifier included in `status` payloads. Defaults to `Environment.MachineName`. |
| `HEALTHCHECK_PING_FAIL_URL` | — | Optional URL to call when the local readiness check fails. |
| `HEALTHCHECK_PING_SCOPE` | `replica` | `replica` pings on every replica; `leader` restricts pings to the leader node (requires Redis distributed lock). |

### Email delivery (SMTP)

**SMTP is an instance-level transport. Tenants configure how Dependably *uses* that transport, not
how mail is transported.** There is one relay per deployment, owned by the operator; a tenant owns
only whether alert mail is sent and to whom. There is no per-org SMTP configuration.

SMTP is configured entirely in the database — there is no env-var form. Configure the relay (host,
port, security mode, username/password, from address) from **Settings → Instance settings →
Instance email (SMTP)** in single mode, or the operator apex **System Settings → Email (SMTP)** in
multi-tenant mode. A master key (`DEPENDABLY_MASTER_KEY`, see above) must be configured before the
password field can be set.

Every outgoing message uses that one transport:

| Message | Trigger | When the relay is unconfigured |
| --- | --- | --- |
| Org invite | `POST /api/v1/invites` | 200 with the invite link in the response body for manual delivery. A send failure falls back to the same and logs a Warning. |
| Password reset link | `POST /api/v1/auth/forgot-password` | 202, nothing sent. Deliberately no link-in-response — the reset token must never reach the response body. |
| Password-changed notice | password reset, self-service change, operator-forced reset | Nothing sent; the request still succeeds. |
| MFA enabled / disabled notice | MFA setup verify, MFA disable | Nothing sent. |
| Email-change verification link | `PATCH /api/v1/users/{id}/email` | 202, nothing sent; the pending change expires unredeemed. |
| Email-changed notice (to the former address) | `POST /api/v1/auth/confirm-email-change` | Nothing sent. |
| Alert email | quarantine / vulnerability alerts | Queued durably in `email_outbox` and delivered when the relay appears, or retired by a ceiling below. |

**The org invite, password reset, and email-change verification links are live credentials — possessing
one grants what a stolen password or session cookie would (account control, and for an invite,
account creation) — so all three are refused over an unencrypted instance transport
(`security=none`, or any value that is not `starttls`/`ssl`) unless the operator opts in via
`SMTP_ALLOW_INSECURE_CREDENTIAL_MAIL`.** A refusal is treated exactly like "relay unconfigured" in
the table above (202/nothing-sent for reset and email-change; the invite link-in-response fallback
for invites) and logs a Warning naming the security mode. `starttls` counts as encrypted because
Dependably requests MailKit's mandatory-upgrade mode — the connection fails rather than falling
back to cleartext if the server does not complete STARTTLS — never the opportunistic mode that
would downgrade silently. Loopback and other private-range relay hosts are **not** exempted: an
operator relaying to `127.0.0.1` in cleartext still needs the override. Password-changed, MFA
enabled/disabled, email-changed, and alert-email notices carry no bearer secret (a plain "this
happened" notice, not a link) and are unaffected either way.

| Variable | Default | Description |
| --- | --- | --- |
| `SMTP_ALLOW_INSECURE_CREDENTIAL_MAIL` | `false` | When `true`, permits sending the org-invite, password-reset, and email-change-verification links over an unencrypted (`security=none` or unrecognized) instance SMTP transport. Off by default: those messages carry a bearer credential. Mirrors `SIEM_WEBHOOK_ALLOW_INSECURE`'s naming, accepted spellings (`true`/`1`/`yes`), and posture — an instance-level opt-in, not a per-org setting. |
| `EMAIL_TRANSPORT_BREAKER_FAILURE_THRESHOLD` | `3` | Consecutive instance-SMTP delivery failures before the transport breaker opens and stops attempting sends. The breaker guards the shared relay, so it is instance-level: it suspends attempts for every org rather than disabling any org's email channel, which stays tenant-owned configuration. |
| `EMAIL_TRANSPORT_BREAKER_INITIAL_COOLDOWN_SECONDS` | `30` | How long the breaker waits before its first probe after opening. Each further failed probe doubles the wait, up to `EMAIL_TRANSPORT_BREAKER_MAX_COOLDOWN_MINUTES`. |
| `EMAIL_TRANSPORT_BREAKER_MAX_COOLDOWN_MINUTES` | `10` | Ceiling on the breaker's exponential cooldown, so a long relay outage still retries on a bounded interval rather than backing off indefinitely. |

A tenant enables alert email and sets its recipients on **Settings → Integrations → Email**, which
also shows delivery health and a test-send button. Delivery failure records health but never disables
the channel: the relay is operator infrastructure shared by every org, so one outage must not become
a per-tenant configuration failure. (Slack delivery, whose webhook URL *is* tenant-owned, still
auto-disables after sustained failure.)

#### The alert-email outbox

Alert mail is the one message class that is **persisted before any delivery attempt**. It carries no
credential and nobody can re-request it, so losing it to a relay outage loses information outright.
The guarantee is deliberately narrow:

> Alert email is durably persisted until it is delivered, or until an explicit terminal
> retry/retention policy expires it.

That is not "every message is eventually sent". Every other message class in the table above stays on
the in-memory path and keeps its fail-silent semantics — a reset link and a verification link are
live bearer tokens, and persisting a rendered body would put them at rest in the database, where the
recovery (request another one) is already cheaper than the exposure.

A message ends in exactly one of five states. `pending` and `sending` are the only non-terminal ones;
`delivered`, `dead_letter` (the message or the configuration is wrong — a permanent SMTP 5xx, an
invalid recipient, a relay host the SSRF guard refuses) and `expired` (it ran out of attempts, retry
time, or retention) are terminal, and nothing in the delivery path deletes them. Keeping
`dead_letter` and `expired` apart is what makes a backlog readable: the first needs the message
fixed, the second needs the relay fixed sooner.

Failures are classified off MailKit. An SMTP **4xx**, a socket error, a protocol error, or a timeout
is transient and retries on an exponential backoff (30 s doubling to a 30-minute ceiling). An SMTP
**5xx**, an unparseable recipient, a refused credential, or an SSRF-blocked relay host is permanent
and dead-letters without retrying. Anything **unrecognised** is retried like a transient failure but
bounded by the retry ceiling — so a novel failure degrades into "gives up eventually" rather than
"dropped immediately".

An unconfigured or disabled relay is not a failed attempt: the worker claims nothing, so no message
burns retries against a relay nothing dialed. Those rows wait durably until the operator configures
the transport, or until the retention ceiling retires them.

| Variable | Default | Description |
|---|---|---|
| `EMAIL_OUTBOX_MAX_RETRY_HOURS` | `6` | Maximum retry duration. A message that has been retrying this long is retired to `expired` rather than attempted again — an alert delivered three days late can be worse than one never sent. |
| `EMAIL_OUTBOX_RETENTION_HOURS` | `72` | Maximum queue retention: how long a row may sit in a non-terminal state **at all**, independent of the retry budget. This is the bound that retires mail queued while the relay was never configured, which consumes no attempts and so would never hit the retry ceiling. |
| `EMAIL_OUTBOX_MAX_ATTEMPTS` | `12` | Retry ceiling in attempts, the third of the three conditions that retire a message to `expired`. |
| `EMAIL_OUTBOX_MAX_DEPTH` | `10000` | Maximum queue size, counted over non-terminal rows. **Shed policy: refuse the newest.** At the cap an enqueue fails and the refusal is recorded on the alert row's `email_status` and the org's delivery-health columns, so the drop is visible rather than log-only. Evicting the oldest instead is rejected: those rows are nearest their retention ceiling and already survived a restart, so dropping them discards the start of the outage and makes the durability guarantee unstateable. |
| `EMAIL_OUTBOX_BACKLOG_WARN_DEPTH` | `100` | Backlog depth at which the worker logs a warning naming the depth, the oldest queued message, and the dead-letter/expired counts. Edge-triggered — logged on the crossing and on recovery, not on every poll. |
| `EMAIL_OUTBOX_TERMINAL_RETENTION_DAYS` | `30` | How long terminal rows are kept for inspection before the retention GC pass deletes them. The only delete path on the table, and the storage limit on the recipient addresses it holds. |
| `STATS_HISTORY_RETENTION_DAYS` | `365` | Delete `org_stats_history` rows (the dashboard's append-only daily trend history) older than this many days. A non-positive or unparseable value falls back to the 365-day default — there is no value that disables the sweep. Observational only — the sweep is a plain storage limit, and nothing else reads a deleted row. |

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
| `PUSH_RATE_LIMIT_PERMITS` | `20` | Sliding-window permits per second per token for package publish. |
| `PUSH_RATE_LIMIT_QUEUE` | `100` | Queue depth for the push limiter. Requests that exceed the window are queued up to this depth before returning `429`. A publish client bursts structurally — an OCI push spends three requests per layer and runs several layers concurrently — and OCI clients do not honour `Retry-After` on a write, so a rejected request aborts the whole push. Set to `0` only to restore hard rejection. |
| `LOGIN_RATE_LIMIT_PERMITS` | `10` | Fixed-window permits per minute per IP for the login endpoint. Honoured by both the in-process limiter (standalone) and the Redis-backed limiter (`DEPENDABLY_DEPLOYMENT_MODE=ha`); the window itself (one minute) is not configurable in either mode. |
| `TOKEN_CREATE_RATE_LIMIT_PERMITS` | `60` | Fixed-window permits per hour per IP for token-creation endpoints. Honoured by both the in-process limiter (standalone) and the Redis-backed limiter (`DEPENDABLY_DEPLOYMENT_MODE=ha`); the window itself (one hour) is not configurable in either mode. |
| `INVITE_RATE_LIMIT_PERMITS` | `20` | Fixed-window permits per hour per IP for invite and sensitive-config write endpoints (member invites, instance email/Slack config, alert settings). Honoured by both the in-process limiter (standalone) and the Redis-backed limiter (`DEPENDABLY_DEPLOYMENT_MODE=ha`); the window itself (one hour) is not configurable in either mode. |
| `ANON_RATE_LIMIT_PERMITS` | `120` | Fixed-window permits per minute per IP for unauthenticated probe endpoints (`/health`, `/ready`, `/version`, `/api/v1/bootstrap`, `/api/v1/auth/methods`, `/api/v1/licenses`). |
| `IMPORT_RATE_LIMIT_PERMITS` | `5` | Sliding-window permits per minute per token for bulk import requests. Queue depth is `0` (burst is rejected immediately). |
| `SBOM_UPLOAD_RATE_LIMIT_PERMITS` | `30` | Sliding-window permits per minute per token for the SBOM/VEX/SARIF upload endpoints. Deliberately above `IMPORT_RATE_LIMIT_PERMITS`: a CI run for a mono-repo pushes one document per module per kind and would `429` partway through at the import budget. Queue depth is `0` (burst is rejected immediately, with `Retry-After`). |
| `RESCAN_RATE_LIMIT_PERMITS` | `20` | Sliding-window permits per minute per caller (token hash → user sub → IP, same precedence as the management default) for the on-demand vulnerability rescan endpoint. The endpoint's own cooldown is per-package, so this bounds a caller fanning out across many distinct packages instead. Queue depth is `0` (burst is rejected immediately). |
| `MANAGEMENT_RATE_LIMIT_PERMITS` | `300` | Sliding-window permits per minute per principal for authenticated management endpoints (`/api/v1/*`) not covered by a more specific policy. `/api/v1/docs/` is exempt. |
| `METADATA_RATE_LIMIT_PERMITS` | `500` | Sliding-window permits per second per source IP for metadata GET endpoints (npm packument, PyPI simple index, NuGet registration). |
| `METADATA_RATE_LIMIT_QUEUE` | `100` | Queue depth for the metadata rate limiter. Short bursts are absorbed; sustained floods return `429` once the queue fills. |
| `PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS` | `300` | Sliding-window permits per minute per source IP for the default-deny backstop applied by the global limiter to any protocol route that declares no explicit rate-limit policy. A route needing more throughput carries an explicit `download`/`metadata` policy; this only bounds otherwise-unmetered routes so a forgotten policy is never entirely unlimited. |
| `RATE_LIMIT_REDIS_FAILURE_MODE` | `open` | What the Redis-backed abuse-prevention limiters (`login`, `invite`, `token-create`) do when Redis cannot be reached, or replies with something the limiter cannot parse, and there is no counter to decide with. `open` grants the request — a Redis outage does not lock every user out, at the cost of running with no login rate limiting for its duration. `closed` denies with `429` instead (`Retry-After` = the policy's window length), keeping the abuse budget enforced through the outage at the cost of refusing legitimate logins. Either way every such decision is logged at `Warning` and counted on `dependably.rate_limit.backend_unavailable` (attributes `policy`, `decision`, and `cause` — `connection` when Redis could not be reached, `malformed_reply` when it replied but not in the shape the limiter's script expects) — alert on that counter: under `open` it is the only signal that login rate limiting is currently switched off. Applies only to the Redis-backed limiters; the in-process limiters have no such failure mode. Any value other than `open` or `closed` fails startup rather than silently resolving to the permissive default. |
| `RATE_LIMIT_IPV6_PREFIX` | `64` | IPv6 network prefix (bits, `1`–`128`) that per-IP rate-limit partition keys collapse to. A routed `/64` is the smallest per-subscriber allocation, so keying below it lets one attacker mint a fresh budget per source address. IPv4 always partitions at the full `/32`; audit `source_ip` fields always record the full address regardless of this setting. |
| `ACCOUNT_SEND_MAX_PER_WINDOW` | `5` | Account-targeted transactional emails (today: the self-serve password-reset link) permitted per **target account** per window, independent of source IP. Every per-IP limiter is blind to who the mail is addressed to, so a distributed attacker can mail-bomb one mailbox from many prefixes without ever tripping one; this budget is what stops that. Raising it weakens the mail-bomb defense; lowering it lets an attacker deny a specific user their reset link for longer. |
| `ACCOUNT_SEND_WINDOW_MINUTES` | `60` | Window length for `ACCOUNT_SEND_MAX_PER_WINDOW`. The budget restarts once a window elapses, so an account can be held down for at most one window past the attacker's last request. |
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

Both carry an explicit **capability** subset chosen at creation — fine-grained permission strings like `read:artifact`, `publish:npm`, or the family wildcard `publish:*` — rather than a coarse scope. A token can only be minted with capabilities the caller's own role already grants (no privilege escalation); a mint request asking for more returns 400. At request time, a token used against a route requiring a capability it wasn't minted with returns 403, not 401. Capabilities are the single source of truth for permission checks. Tokens are stored as SHA-256 hashes; the raw value is shown only once on creation.

Which capabilities a role can grant to a token it mints follows the role→capability mapping below (see [Multitenancy](#multitenancy) for the full role list): `member` gets read-only capabilities, `admin` adds publish/import/yank and tenant:configure, `owner` adds tenant:admin, and `auditor` is limited to audit-read.

---

## Multitenancy

Each org has independent package namespaces, its own member list with roles (`owner`, `admin`, `member`, `auditor`), per-ecosystem upload size limits, optional anonymous pull, and an optional PURL allowlist to restrict proxied packages. `owner` is the only role that holds `tenant:admin`, which gates owner-role assignment — inviting an owner, and changing or removing another member's role. `auditor` is a read-only role limited to audit-log access.

In **single mode** the org is the deployment, so instance-wide configuration (`/api/v1/instance/*` — settings, the SMTP transport, `/metrics` access, background-job status) is gated on `tenant:configure` and is therefore available to `admin` as well as `owner`. Those routes do not exist in multi-tenant mode, where instance configuration is a control-plane concern reached through the `system_admin` realm at `/api/v1/system/*`.

Registry URLs are ecosystem-path-only: `/simple/`, `/npm/`, `/nuget/v3/index.json`, `/maven/`, `/rpm/`. Tenancy is host-resolved — in `DEPLOYMENT_MODE=single` (default) the bare host serves the one org; in `DEPLOYMENT_MODE=multi` each org is a subdomain of the apex host (`my-org.apex/simple/` etc.). OCI is at `/v2/` per the Distribution Spec.

---

## Proxy cache

On a cache miss, Dependably fetches from the configured upstream, verifies the SHA-256 checksum, stores the blob, and records the package as a proxy entry. Subsequent requests are served from the local blob store. Packages with a checksum mismatch are rejected and never stored.

Upstreams are per-org and DB-backed (the `upstream_registry` table) — the resolver is deliberately DB-only, with no `IConfiguration` fallback. They are managed per org from Settings → Proxy. The `<Eco>__Upstream` environment variables (below) only **seed the initial row** for newly created orgs; changing one on an existing install has no effect on that org's already-seeded upstream — update the row from Settings → Proxy instead.

### Large OCI layers behind a reverse proxy

The OCI blob proxy streams through: on a cache miss it mirrors upstream bytes to the pulling
client by the same pass that hashes and caches them, so the client starts receiving data at the
upstream's own time-to-first-byte rather than after the whole layer has landed. A reverse proxy in
front of Dependably therefore needs a read timeout that covers the **gap between bytes**, not the
duration of the whole transfer — `proxy_read_timeout`'s 60 s default is fine for a multi-gigabyte
layer that takes twenty minutes, because bytes keep arriving throughout.

Two bounds still apply to the transfer as a whole. `Oci__UpstreamHttpTimeout` (default 30 min)
caps the upstream fetch end to end — raise it if your link cannot pull your largest layer inside
it. And the cache tier needs transient room for roughly **twice** the layer, because the verified
staging entry is copied to its content-addressed key before being deleted.

A client that hangs up mid-layer does not cancel the fetch; the caching pass finishes, so its
retry is a cache hit. Such a request is logged at `Information` and answered `504`, not `500` —
if you see `500`s on `/v2/…/blobs/…`, they are not disconnects.

### NuGet symbol servers

A NuGet upstream can carry a **symbol-server base URL** (`upstream_registry.symbol_server_url`), which is what an SSQP miss falls through to. It is a separate field because a symbol server is a different host from the v3 index and cannot be derived from it: nuget.org's index is `https://api.nuget.org/v3/index.json`, its symbol server `https://symbols.nuget.org/download/symbols`.

- A nuget.org upstream is **seeded with that endpoint automatically**, both at creation and via a one-shot migration for pre-existing rows. Only the canonical nuget.org API hosts match — a private feed that mirrors nuget.org is not nuget.org, and guessing its symbol host would send debug-id lookups, which carry the PDB names of private code, to a third party.
- Every other upstream starts **empty, which disables symbol proxying for it**. Set it with `PUT /api/v1/upstream-registries/{id}/symbol-server` (requires `tenant:configure`); sending an empty value clears it again. The URL is validated exactly like an upstream base URL, including the plaintext-`http` opt-in.
- nuget.org publishes **no `.snupkg` download endpoint** — its service index carries `SymbolPackagePublish`, which is push-only. Symbol resolution against it is therefore SSQP-by-debug-id only, which is what the fall-through implements.

---

## High-availability deployment

Multi-replica deployments require Redis (`DEPENDABLY_DEPLOYMENT_MODE=ha`, `REDIS_CONNECTION_STRING`). Redis backs distributed locking, rate-limit state (login / invite / token-create limiters), ASP.NET Core Data Protection key sharing, and the cross-replica rendered-metadata invalidation channel.

The sections below call out constraints that are silent data-loss or security risks when violated. Read these before running more than one instance.

### Load-balancer health checks — use `/ready`, gate on `/ready?strict=true`

Point the target group / readiness probe at `GET /ready`. It fails only on a **required** dependency (the metadata store by default) and reports shared-dependency failures as degradation instead, so an object-store or cache incident cannot deregister every replica at once — see [Health probes](#health-probes-health-ready) for the classification and how to override it with `READINESS_HARD_DEPENDENCIES`. `/ready` is also shutdown-aware: it turns 503 the moment `SIGTERM` lands, which is what lets `SHUTDOWN_PRESTOP_DELAY` drain a replica out of rotation before it stops accepting connections. `/health` carries no drain signal and should not be used for rotation.

Point deployment gating and alerting at `GET /ready?strict=true`, which still demands every dependency green.

### SQLite metadata store — do not share over NFS

`SqliteMetadataStore` opens a single SQLite file (configured via `DB_PATH`). SQLite uses file-system locking for its write-serialization guarantee. **Network file systems (NFS, CIFS/SMB, most distributed POSIX mounts) do not implement POSIX advisory locks correctly**, and SQLite's documentation explicitly states that its locking is unsupported over NFS. Running two or more Dependably instances pointed at the same SQLite file over NFS risks write-lock corruption, WAL file divergence, and silent data loss.

A startup guard enforces single-writer semantics on file-backed SQLite: each process claims a heartbeat lock (the `instance_lock` table), and a second process started against the same file **refuses to start** while the first is alive, naming the holder.

A fresh heartbeat on the row does not by itself prove the holder is alive — a predecessor that died ungracefully (SIGKILL, OOM, power loss) leaves the same evidence behind. So a fresh foreign holder is *watched* rather than rejected outright: startup polls the heartbeat and fails the moment it advances (a live peer), or takes the lock over once it has stayed frozen long enough to go stale (an orphaned row). The cost of an ungraceful predecessor is therefore a bounded startup delay — at most `INSTANCE_LOCK_STALE_SECONDS` — instead of a crash loop. The lock is released on graceful shutdown, so a clean restart waits for nothing. `DELETE FROM instance_lock` still short-circuits the wait when the holder is definitively gone. The guard does not run on Postgres (legitimately multi-writer).

**Do not:**
- Point multiple instances at a shared `DB_PATH` on an NFS/CIFS mount.
- Use SQLite (`DB_PROVIDER=sqlite`) in any multi-instance deployment.

**Do:**
- Use `DB_PROVIDER=postgres` with a shared Postgres connection string (`DB_CONNECTION_STRING`) for multi-instance deployments. Each instance connects to the same Postgres database; Postgres handles concurrent writers correctly.

An **existing standalone install already on SQLite** moves to Postgres in place with the `migrate-to-postgres` / `verify-postgres-migration` subcommands of the product image. The full procedure — quiescing writes via the instance lock, the per-type conversion rules, the verification pass to run before cutting over, and the rollback — is the SQLite-to-Postgres migration runbook in `dependably-enterprise`. The migration moves metadata only; the blob store is untouched, so point the new deployment at the same one.

### Local blob store — do not share LOCAL_STORAGE_PATH over NFS

`LocalBlobStore` reads and writes files under `LOCAL_STORAGE_PATH`. Atomic publish operations rely on `File.Move` for the final rename (which is atomic on a local POSIX filesystem). NFS does not guarantee atomic cross-directory renames, and cross-instance visibility of partial writes is undefined.

**Do not:**
- Mount the same `LOCAL_STORAGE_PATH` on an NFS volume and run more than one instance against it.

**Do:**
- Use `STORAGE_BACKEND=s3` (S3-compatible object store) or `STORAGE_BACKEND=azure` (Azure Blob Storage) for multi-instance deployments. Both backends are designed for concurrent multi-writer access. Refer to the [Blob storage backends](#blob-storage-backends) section for configuration.

### OCI chunked uploads — session affinity required

OCI clients push image layers via a two-step chunked upload: a `POST /v2/{name}/blobs/uploads/` creates a session UUID, then one or more `PATCH` requests append data to a local staging file on the replica that owns the session. The session row itself lives in the shared database, so a mis-routed `PATCH` still *resolves* the session — it is the staging file that is replica-local. **A `PATCH` routed to a replica that does not own the session is refused with `416 Requested Range Not Satisfiable`**, carrying a `Range` header with the offset the session is actually at. The upload is not destroyed: it stays resumable from that offset on the replica that owns it.

Configure your load balancer to pin `/v2/*/blobs/uploads/*` requests to the replica that issued the session UUID:

- **nginx**: use the `sticky` module with `hash $uri consistent;` or sticky-route on the UUID path segment.
- **Traefik**: use a sticky session with `rule: PathPrefix(`/v2/`) && PathRegexp(`/blobs/uploads/`)` and `sticky.cookie`.
- **HAProxy**: `balance uri depth 6` or `stick on path_sub(/blobs/uploads/) table …`

The affinity key is the upload UUID, which is the last path segment of the `Location` header returned by the initial `POST`. Manifest pushes (`PUT /v2/{name}/manifests/{tag}`) and blob pulls (`GET /v2/{name}/blobs/{digest}`) are stateless and need no affinity.

Set `REPLICA_HINT=true` (or `INSTANCE_ROLE=replica`) on each replica instance; Dependably logs a startup warning reminding operators that session affinity is required.

### In-process rate limiters — per-tenant limits are per-replica without Redis

The download, push, import, management-API, and anonymous-probe rate limiters maintain their sliding-window counters in process memory on each replica. Without a shared backing store, each replica enforces the configured limit independently. A client that distributes requests across N replicas can exceed the nominal per-tenant limit by up to a factor of N before any single replica returns `429`.

The login, invite, and token-create limiters are Redis-backed when `REDIS_CONNECTION_STRING` is set (`DEPENDABLY_DEPLOYMENT_MODE=ha`), so those abuse-prevention limits hold across replicas in HA mode. When Redis cannot be reached these limiters have no counter to decide with; the request is resolved by [`RATE_LIMIT_REDIS_FAILURE_MODE`](#rate-limiting) (`open` by default — the request is granted, so login rate limiting is off for the duration of the outage) and the decision is logged at `Warning` and counted on `dependably.rate_limit.backend_unavailable`. Alert on that counter.

### Account lockout state in HA is Redis-resident

In standalone deployments the failed-login counters and lockout expiries live in the SQLite `login_attempts` table. In HA mode they live in Redis under TTL keys (`lockout:attempts:*`, `lockout:locked:*`) with no database mirror, so **anything that loses recent Redis writes — a flush, an eviction under `maxmemory`, or a failover to a replica behind on replication — resets the failed-attempt counters for every account and releases any active lockout.** Two operational consequences:

- Treat Redis availability and persistence as a security-relevant signal, not just an availability one. Run Redis with `maxmemory-policy noeviction` (or a policy that cannot evict these keys) so lockout state is never dropped to make room, and alert on failover and on `dependably.rate_limit.backend_unavailable`.
- A Redis outage does *not* silently bypass lockout. The lockout store lets its errors propagate and the login path does not catch them, so an attempt that cannot read or write lockout state aborts with a `500` before any session is issued — login fails closed even though the rate limiter defaults to failing open.

**The download and push limiters remain in-process even when Redis is configured.** These are per-second sliding-window limiters on the very hot path; adding Redis round-trips to every artefact download and every package push would increase latency on the path most sensitive to it. The practical risk in a typical multi-instance deployment is proportional to the number of replicas and the configured permit ceiling — two replicas at the default 1000 permits/sec per token gives an effective ceiling of ~2000 before both replicas 429 simultaneously.

Remediation options, in order of preference:

1. **Redis + sticky sessions (recommended for HA):** Set `REDIS_CONNECTION_STRING` and configure your load balancer to route each token/IP to a consistent replica (hash on the `Authorization` header or source IP). Sticky routing keeps the per-second sliding window accurate on the hot path without Redis round-trips; Redis covers the slower abuse paths (login, token-create, invite).
2. **Sticky sessions only:** If Redis is unavailable, sticky-route all traffic for a given token to a single replica. The in-process limiter on that replica then enforces the full configured limit.
3. **Reduce the per-replica permit ceiling:** If sticky routing is not possible, set `DOWNLOAD_RATE_LIMIT_PERMITS` and `PUSH_RATE_LIMIT_PERMITS` to `ceiling / N` (where N is your replica count) so the aggregate effective limit across replicas matches the intended value. This is a coarse approximation — uneven load distribution means individual replicas may still diverge — but it bounds the worst case.

See [`DOWNLOAD_RATE_LIMIT_PERMITS`](#rate-limiting), [`PUSH_RATE_LIMIT_PERMITS`](#rate-limiting), and [`REDIS_CONNECTION_STRING`](#core) for the relevant environment variables.

### Metadata caches are per-instance, invalidated across replicas over Redis

Ecosystem metadata responses (the npm packument, PyPI simple index, NuGet registration, Maven `maven-metadata.xml`, and RPM repodata documents) are cached in an in-process `MemoryCache` on each instance. The cache itself is not shared across replicas — but the *invalidation* is.

When `REDIS_CONNECTION_STRING` is set, a mutation that changes a package's rendered metadata (publish, unpublish, dist-tag change, deprecate, unlist, admin upload, admin delete) publishes the package coordinates — org, ecosystem, and package identity — to the `<REDIS_KEY_PREFIX>metadata-invalidation` pub/sub channel. Every replica subscribes and evicts the matching entries locally, expanding the coordinates into that ecosystem's full cache-key variant set (npm local + proxy; PyPI HTML + JSON; NuGet SemVer1/2 × local/proxy; Maven artifact-level + SNAPSHOT version-level; every RPM repodata document plus the merged tuple). Both the publish path and the receive path run the same expansion, so an invalidation can never be complete on the pushing replica and partial on its peers.

**Because this is a freshness optimisation, it degrades rather than fails.** If Redis is unreachable the broadcast is dropped, logged at warning, and counted on `dependably.metadata.invalidations_published{outcome="server_error"}`; the push still succeeds and peer replicas converge on TTL expiry exactly as they did before the channel existed. `dependably.metadata.invalidations_received` counts messages applied from peers, so a working channel is visible in metrics. A replica that cannot subscribe at startup logs a warning and keeps serving.

**Standalone deployments need no Redis.** With `REDIS_CONNECTION_STRING` unset the in-process eviction on the single replica is the whole invalidation, and no broker dependency is introduced.

The TTLs ([`METADATA_LOCAL_CACHE_TTL_SECONDS`](#core), default `600`, and [`METADATA_PROXY_CACHE_TTL_SECONDS`](#core), default `300`) are therefore a backstop for a dropped broadcast, not the primary convergence mechanism — **leave them at their defaults**, including in multi-instance deployments. Shortening them does not reduce upstream network fetches (that is the separate `Proxy__MetadataCache*` family); it only multiplies re-render and re-merge work on every replica.

### Scheduled background jobs — leader-coordinated per job

Scheduled background jobs that mutate shared state (the database or the shared cache tier) acquire a per-job distributed lock before each tick, so a multi-replica deployment runs each of these exactly once per scheduled occurrence rather than once per replica: `CacheEvictionService`, `RetentionService`, `DeprecationRefreshService`, `ThreatFeedRefreshService`, `VulnerabilityScanService`, `OrphanBlobReconcilerService`, `TenantHardDeleteService`, and `StatsRefreshService`. In standalone mode the in-process lock always grants, so a single instance still runs every job on every tick.

`OciStagingJanitorService` is deliberately **not** leader-coordinated — it sweeps this replica's own local staging directory, and its shared-row cleanup is an idempotent no-op on a losing race, so every replica must run its own pass.

The lock is held for the whole pass through a renewal lease, not just for a fixed TTL: a running job heartbeats its lock three times per TTL window, so a pass that takes longer than the TTL (a large orphan-blob reconcile, a big tenant hard-delete sweep, a wide retention pass) keeps the lock instead of letting it lapse under itself and handing a second replica a concurrent run. The TTL therefore bounds how long a lock survives a *crashed* leader, not how long a pass may take.

If renewal stops being confirmable — the backend answers that this instance no longer holds the lock, or a whole TTL window passes with the lock backend unreachable — the lease is treated as lost and the in-flight pass is **cancelled**: an instance that has lost its lease is no longer the leader and stops rather than finishing unleased. The aborted pass is logged at warning level and the next scheduled tick on any instance retries. A single transient renewal failure inside the window does not abort the pass; the lease retries within the time it has left.

A distributed-lock backend failure (a Redis connection blip or failover, not a clean "lock held by another instance" response) on the *acquire* path is treated as a skipped tick rather than a fatal error, so a transient Redis hiccup does not stop a replica.

---

## Security model

- **OWASP API Security Top 10** alignment: BOLA/IDOR protection, SSRF protection with DNS rebinding re-validation, path traversal rejection, CRLF injection prevention
- **Egress**: outbound HTTP clients bypass any ambient `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (`UseProxy = false`), because a proxy would make the SSRF connect gate vet the proxy's address rather than the target's — see [Egress proxies](#egress-proxies)
- **Authentication**: JWT HS256 sessions (8h, HttpOnly SameSite=Strict cookie); BCrypt-12 passwords; CSPRNG token generation; constant-time comparison. Each JWT is bound to its purpose by a fixed `iss` and a per-purpose `aud` (session vs MFA challenge), and each validator pins the audience it accepts — so a token minted for one purpose is refused for another during token validation, not by a downstream claim check. Both values are fixed constants, not configuration.
- **Capability enforcement**: tokens carry an explicit capability subset (e.g. `read:artifact`, `publish:npm`), checked at the HTTP handler level; capability mismatch returns 403, not 401 — see [Tokens](#tokens)
- **Account lockout**: 10 failed login attempts → 15-minute lockout with `Retry-After` header
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Content-Security-Policy` (management API), `Strict-Transport-Security` (when behind HTTPS proxy)
- **Trusted proxy / host hardening**: Forwarded-header processing is fail-closed — when `TRUSTED_PROXIES` is unset, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` are ignored entirely so caller-supplied values cannot spoof `RemoteIpAddress`, scheme, or host. When `TRUSTED_PROXIES` is set, those headers are processed only from the listed IPs/CIDRs. Host-header filtering is derived at startup from the host portion of `BASE_URL`: when that host is non-localhost, only that host (plus `*.apex` in multi mode) and localhost are accepted; unknown `Host` headers are rejected before tenant resolution, preventing Host injection into SAML SP URLs, absolute links, and CSRF Origin comparisons. When `BASE_URL` is unset or localhost (dev/local), filtering is permissive and a startup warning is logged. **A co-located reverse proxy defeats the `/metrics`, `/version`, and management docs/OpenAPI IP allowlists when `TRUSTED_PROXIES` is unset**: those allowlists default to loopback (`127.0.0.1`, `::1`), and any proxy forwarding to Kestrel over loopback makes every caller it forwards appear as an allowlisted operator — the allowlist fails open, not closed, in that specific topology. A startup warning names this exposure when it applies; the fix is `TRUSTED_PROXIES` set to the proxy's address(es), not a code change to the allowlist itself.
- **Schema**: idempotent `CREATE TABLE IF NOT EXISTS` applied on startup; one-shot data migrations are recorded in the `_applied_migrations` ledger (see [src/Dependably.Core/Infrastructure/schema/schema-migrations.md](src/Dependably.Core/Infrastructure/schema/schema-migrations.md))

---

## Internationalization

The UI and API error messages are localized. English (`en`) is the source language; French (`fr`) ships out of the box.

| File | Purpose |
|------|---------|
| `web/src/locales/en.json` | Frontend strings — English source |
| `web/src/locales/fr.json` | Frontend strings — French translation |
| `src/Dependably.Core/Resources/SharedResource.resx` | Backend error strings — English source |
| `src/Dependably.Core/Resources/SharedResource.fr.resx` | Backend error strings — French translation |

Adding a string: add the key to `en.json` / `SharedResource.resx` (backend entries include a translator `<comment>`), add the translation to each locale file, run `bash i18n/scripts/i18n-export.sh` to refresh the translator handoff package (`i18n/handoff/*.xlf`), then `node i18n/scripts/i18n-validate.js` — it fails on missing keys **and** on a handoff that was not regenerated.

Adding a locale: see [i18n/adding-a-locale.md](i18n/adding-a-locale.md).

Full i18n architecture: see [i18n/README.md](i18n/README.md).

---

## Architecture notes

See [CLAUDE.md](CLAUDE.md) for a full breakdown of the project structure, key architectural rules, and tech stack decisions.

Architecture decision records live in the spec repo,
[dependably-community.spec](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec),
under `specs/adr/`, alongside the standing architecture specs. Design intent is
deliberately kept out of this repo: it changes on a different clock from the
code, and it is indexed for retrieval as one corpus. Key ADRs:

- [ADR-auth-identity-hybrid](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec/-/blob/main/specs/adr/ADR-auth-identity-hybrid.md) — why the auth layer uses Identity Core for MFA/credential primitives but keeps bespoke first-factor login, lockout, JWT sessions, and per-request session invalidation.
- [ADR-envelope-encryption-db-secrets](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec/-/blob/main/specs/adr/ADR-envelope-encryption-db-secrets.md) — envelope-encrypting DB-resident secrets under an operator-held master key.
- [ADR-terraform-provider-network-mirror](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec/-/blob/main/specs/adr/ADR-terraform-provider-network-mirror.md) — why Terraform providers are served as a network mirror, not a provider registry.
- [ARCH-personal-data-inventory](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec/-/blob/main/specs/architecture/ARCH-personal-data-inventory.md) — what an instance holds about identifiable people, the retention horizons that bound it, and the gates that keep the inventory from rotting.
- [ADR-sqlite-to-postgres-migration](https://gitlab.northwardlabs.ca/moonlitlabs/dependably-community.spec/-/blob/main/specs/adr/ADR-sqlite-to-postgres-migration.md) — why the migrator derives its plan from the database rather than a list in code, and aborts rather than coercing.
