# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.3] - 2026-07-29

A patch release carrying the 0.4.1 and 0.4.2 cycles, which shipped without their own
sections here. **Read "Changed — action required" before upgrading**: existing browser
sessions are signed out, API tokens minted before the `capabilities` column are deleted,
and two weak-hash acceptances become default-off opt-ins.

### Added

- **Unexpected server errors now return a problem document with a correlation id.** A request
  that fails in a way no typed handler covers previously produced a bare `500` with an empty
  body; it now returns localized `application/problem+json` (en/fr) carrying a `correlationId`
  — the request's W3C trace id, the same value the logs and traces are stamped with — so an
  operator can find the failure from what the caller quotes. The body still carries no
  exception type, message, or stack trace. Applies to both the community and edge images.
- **`RATE_LIMIT_REDIS_FAILURE_MODE` — fail-open vs fail-closed for the Redis-backed
  abuse-prevention limiters** (`login`, `invite`, `token-create`). `open` (the default, and the
  behaviour every existing deployment already has) grants the request when Redis cannot be
  reached; `closed` denies it with `429`. **Only `open` and `closed` are accepted — any other
  value fails startup** rather than resolving to the permissive default, so a misspelled `closed`
  can never read as configured fail-closed while behaving fail-open. Ignored by edge nodes, which
  run only in-process limiters.
- **`dependably.rate_limit.backend_unavailable` counter** (attributes: `policy`, `decision`),
  incremented alongside a `Warning` log every time one of those limiters resolves a request
  without Redis. Under the default fail-open posture this is the only signal that login rate
  limiting is currently switched off — alert on it.

### Deprecated

- **`org_settings.storage_used_bytes` is dormant and will be dropped in the release after this
  one.** Every quota check now derives a tenant's stored bytes from the live `org_storage_bytes`
  view, so there is one definition of "bytes this org holds" and nothing to drift; nothing in this
  release reads or writes the counter. The column itself is deliberately retained — 0.4.2 still
  *increments* it, and dropping it now would fail that slot's quota `UPDATE` for the whole
  blue-green cutover window. No operator action is needed for this release, in either direction: a
  0.4.2 slot keeps working alongside it, and rolling back to 0.4.2 keeps the counter's stored value.

### Changed — action required

- **Weak-hash acceptance is now an explicit, default-off operator opt-in, in the two places a
  broken digest still carried weight in a security decision.**
  - `Npm__AcceptSha1Shasum` (default `false`) — an npm packument carrying only a hex SHA-1
    `dist.shasum` and no `sha512` SRI is now treated as **unverified** for proxy cache admission
    rather than checksum-verified. The tarball still serves, on the same footing as an upstream
    that publishes no digest at all; the registry simply no longer records a
    chosen-prefix-collision-broken digest as an integrity guarantee. Packages carrying a `sha512`
    SRI — everything published this decade — are unaffected, as is every SHA-256/SHA-512 spec.
  - `Apk__AcceptSha1IndexSignatures` (default `false`) — a SHA-1 `.SIGN.RSA.<keyname>` entry in an
    `APKINDEX.tar.gz` no longer satisfies index signature verification. The digest algorithm there
    is named by the upstream-supplied index itself, so an attacker who can produce a chosen-prefix
    SHA-1 collision was choosing the weak arm. Refusal is a verification failure (new reason
    `weak_signature_algorithm` on `dependably.apk.index_signature_failures`); the index is neither
    cached nor served. **Alpine's own mirrors still sign with SHA-1**, so an org that has pinned an
    apk trust anchor (or set `Apk__VerifyIndexSignature=true`) must set this opt-in to keep
    verifying a stock Alpine index. Orgs with no apk anchor never ran verification and are
    unaffected. `.SIGN.RSA256.*` / `.SIGN.RSA512.*` signatures verify in either posture.

  Each acceptance and each refusal logs once per process, mirroring
  `Mfa__AcceptLegacyRecoveryCodes`.

- **Signature trust anchors must clear a minimum-strength floor at import.** `POST
  /api/v1/trust-anchors` (Settings → Trust Anchors) now rejects material whose key is below
  RSA/DSA/ElGamal 2048 bits or a 255-bit elliptic-curve field, across every `anchor_kind` that
  carries a key — `rsa` (apk), `pgp` (RPM, Maven), `spki` (npm), `x509` (NuGet), `sigstore_root`
  and `rekor_key` (PyPI). An anchor bounds the strength of every signature verdict derived from
  it, and RSA below 2048 has been under the NIST SP 800-57 / BSI TR-02102 floor since 2010. This
  is a hard floor rather than an opt-in because the anchor key is the operator's own choice, not
  something an upstream ecosystem forces. **Anchors already stored are not re-checked** and keep
  verifying — the floor applies only when adding one, so no upgrade breaks a running deployment;
  rotate a legacy key at your own pace.

- **Existing browser sessions are signed out on upgrade.** Session JWTs now carry a bound
  `iss`/`aud` pair, and validation requires both, so a session cookie minted by an earlier
  version no longer authenticates. Users log in again once; nothing else is affected — API
  tokens, service tokens, and `token_version` invalidation are unchanged. There is no new
  configuration: the issuer and audience are fixed values, since tokens are already signed with
  the instance's own `jwt_secret`.

- **API tokens that carry no capability set are deleted on upgrade and must be re-minted.**
  The `capabilities` column was added to `user_tokens` / `service_tokens` by an `ALTER TABLE
  ADD COLUMN` with no default, so every token minted before it exists with `capabilities =
  NULL`. Such a token authenticates but grants nothing — an API token's capability set is its
  ceiling and never falls back to its owner's role — so it now fails every capability-gated
  route and management action. Rather than leave those rows listed as live while denying them
  at each request, the `purge_legacy_null_capability_tokens` migration deletes them at startup.
  **Any automation still using a pre-capabilities token stops working and the token disappears
  from Settings → Tokens; mint a replacement with an explicit capability set.** Tokens created
  with capabilities are untouched, and fresh installs have nothing to purge.

- **RPM signature verification now checks the payload digest, so an RPM signed only with
  `RPMSIGTAG_RSA` and carrying no `RPMTAG_PAYLOADDIGEST` records `failed` instead of `verified`.**
  That tag signs the main header, not the payload; the payload is bound to it by the digest inside
  the signed header, which is now recomputed over the streamed payload rather than assumed. With
  no digest present nothing binds the payload, so the verdict is fail-closed. rpm has written the
  digest since 4.14 and older packages carry a header+payload signature that is verified directly,
  so this affects only packages that have neither. Under `verify_rpm_signatures=block` such a
  package is refused; under `warn`/`off` behaviour is unchanged.

### Security

- **Deleting a hosted version no longer frees its coordinates for reuse under a blocking
  version-overwrite policy.** Each hard delete records a version tombstone, and a republish of
  a tombstoned `(org, ecosystem, name, version)` is refused with `409 version_tombstoned` under
  exactly the policy that would refuse overwriting the live version. This closes
  delete-then-republish as a way around `version_overwrite_policy=block` (the default) using
  only publish + delete rights. Orgs on `allow`, or on `exception` with a package-level
  `allow` override, are unaffected. Only deletions from this release forward are remembered,
  and retention/cache-eviction deletes never tombstone. To republish a deleted coordinate,
  an administrator relaxes the org's version-overwrite policy (Settings → Gates).
- **A JWT's type is now bound into the token, not inferred from its `scope` claim.** Every JWT
  the instance mints is signed with the same `jwt_secret`, so a pre-second-factor MFA challenge
  and a full session token were distinguishable only by an application-layer scope check that had
  to name each non-session scope explicitly. Session tokens now carry the session audience and
  challenge tokens the challenge audience, and each validator pins the one it accepts — so a
  token minted for another purpose is refused during token validation, before any claim check
  runs, and a new token type added later inherits the refusal without an allow-list update. The
  scope check is retained as a second, independent barrier.

### Fixed

- **A Redis outage no longer disables login, invite, and token-create rate limiting silently.**
  The Redis fixed-window limiter caught every exception and granted the request from a bare
  `catch` with no log and no metric, so there was no way to know it was happening, alert on it, or
  size the exposure afterwards. Grants (and, under the new fail-closed posture, denials) are now
  logged at `Warning` with the policy name and counted. Account lockout is unaffected and was
  never bypassed by this: the lockout store's errors propagate and the login path does not catch
  them, so an attempt that cannot read or write lockout state fails closed before any session is
  issued.

  **This does not mean lockout state is durable in HA.** With `DEPENDABLY_DEPLOYMENT_MODE=ha`
  the lockout store is Redis-resident with no database fallback, so a flush, an eviction under
  `maxmemory`, or a failover to a lagging replica resets every account's failed-attempt counter
  — and unlike an outage, that path returns *successfully*, reading as a clean account rather
  than an error. Run Redis with `maxmemory-policy noeviction` so lockout keys are never evicted
  to make room, and treat a failover as a security-relevant event. See CONTRIBUTING.md →
  "Account lockout state in HA is Redis-resident".

## [0.4.0] - 2026-07-17

A minor release: new protocol and operator surfaces, a large correction to how proxied
artefacts are catalogued, and several fail-closed security changes. **Read "Changed —
action required" before upgrading**; three items change how an existing deployment
behaves, and one (legacy `SMTP_*`) fails silently if ignored.

### Changed — action required

- **Legacy `SMTP_*` environment variables are ignored.** Email configuration is now
  database-backed and there is no environment-to-database seed, so `SMTP_HOST`,
  `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, and `SMTP_STARTTLS` have no
  effect. **An upgraded deployment that still sets them stops sending org invite emails
  with no error** — the invite endpoint falls back to returning the invite link in the API
  response body. Reconfigure the relay at **Settings → Instance settings → Instance email
  (SMTP)**, then remove the variables. Alert email delivery is configured separately at
  **Settings → Integrations → Email**, and which alerts fire on the **Alerts** tab. A
  startup warning now names any legacy variable it finds present-but-ignored.
- **A `/0` CIDR in `TRUSTED_PROXIES` now fails startup.** `0.0.0.0/0` or `::/0` told the
  forwarded-headers middleware to trust every peer, letting any client forge
  `X-Forwarded-For` and impersonate an allowlisted caller against the `/metrics`,
  `/version`, and management OpenAPI IP gates. This is refused at boot, consistent with the
  existing fail-fast on malformed entries. Narrower-but-still-broad ranges (a proxy fleet
  subnet, a VPC CIDR) remain an operator judgment call. **A deployment carrying `/0` will
  not start until the entry is narrowed.**
- **MFA recovery codes issued before the keyed-hash scheme are rejected by default.** The
  legacy form is a bare unsalted SHA-256 over Identity's ~47-bit code space —
  brute-forceable offline from a database dump and then usable as a second factor. A legacy
  digest cannot be upgraded in place (the plaintext exists only during redemption), so
  unredeemed codes kept the weak form indefinitely. Affected users must regenerate their
  recovery codes. To open a temporary migration window, set
  `Mfa:AcceptLegacyRecoveryCodes=true`; the first rejection logs a warning naming the
  setting. New installs have no legacy rows and are unaffected.
- **The management OpenAPI surface now requires an authenticated session.**
  `/openapi/management.json` and `/api/v1/docs/*` were gated by the metrics IP allowlist
  alone, so any caller inside it could enumerate the whole control-plane API contract
  unauthenticated. Both now also require a validated JWT carrying `scope=tenant` or
  `scope=system`. **Anything that scraped the management spec anonymously must now
  authenticate.** The protocol document (`/openapi/protocol.json`, `/docs/`) stays public —
  package-manager clients discover it by spec.

### Changed — behavior

- **A proxy fetch that cannot be recorded on the cache plane is now refused with 503**
  rather than served. An artefact the registry cannot catalogue cannot be scanned or gated,
  and one it cannot vouch for is not served. The cache-plane record is retried before the
  fetch gives up; the staged bytes make the client's retry cheap. This is a 503 and never a
  404 — the artefact exists upstream, it just could not be admitted. Under sustained
  metadata-store trouble, proxy installs now fail loudly instead of silently minting
  uncatalogued rows.
- **`maven-metadata.xml` now lists cached proxy versions.** The document built its local
  version set from `package_versions` only, so whenever the upstream merge contributed
  nothing (proxying off for the coordinate, or upstream unreachable) it omitted versions the
  org had cached and could serve by exact coordinate — breaking version discovery and
  SNAPSHOT/`latest` resolution. It now unions the org's cache-plane versions. **Expect
  one-time ETag churn**: wherever an org had cached proxy versions the document content
  changes on first serve after upgrade, and changes again as new versions are cached, so
  clients revalidate and refetch. The body stays byte-stable for a given version set.
  `<latest>`/`<release>` are now resolved by version order rather than row position: the
  union was ordered by `MAX(created_at)` alone, but the cache-plane backfill stamps one
  shared timestamp into every row it writes, so on an upgraded deployment every proxied
  version of a coordinate tied — leaving `<latest>` free to land on an arbitrary older
  version and to move between cache rebuilds, an unstable ETag against the byte-stability
  the generated `.sha1`/`.md5` sidecars depend on.
- **A `local_only` claim now purges the cache plane too.** The purge only deleted
  `origin='proxy'` rows from `package_versions`, but every current proxy fetch lands on the
  shared cache plane — so flipping a name to `local_only` left cached upstream copies
  catalogued, still advertised, still served, and their bytes never reclaimed.
  `purged_count` (in the API response, the claim history row, and the audit detail) now
  counts versions removed from **both** planes, so the number an operator sees may be
  larger than in 0.3.1 for the same action.
- **`GET /api/v1/lookup` answers a definitively-absent package with `200` and
  `found=false`**, not `404` — an absent package is an answer to the query, not a failed
  request. An unreachable upstream is still `503`. Clients that treated `404` as
  "not found" must read the `found` field.
- **NuGet proxy fetches no longer mask metadata-store failures as `404`.** The rethrow
  predicate was SQLite-only, so under `DB_PROVIDER=postgres` a transient DB error (pool
  exhaustion, failover) fell through to a blanket 404: the client reported a real package as
  nonexistent (NU1102) and, because 404 is not retried, the restore failed outright. These
  now surface as a retryable 5xx, matching npm/PyPI. PyPI's equivalent 404-masking was fixed
  alongside it.
- **SAML login fails closed on an expired pinned IdP signing certificate.** Production
  SP-initiated login returns a 503 Problem instead of redirecting into a doomed round-trip,
  and the ACS path returns a closed 401, where both previously logged a warning and
  proceeded. The admin **Test SSO** path stays warn-only so an expired cert is still
  diagnosable.
- **Host filtering fails closed when `BASE_URL` is unset or localhost** — requests arriving
  through a reverse proxy under a real domain are rejected with 400 until `BASE_URL` names
  that domain. The CORS policy warns rather than silently trusting a localhost origin.

### Added

- **npm audit works.** `POST /npm/-/npm/v1/security/advisories/bulk` previously refused with
  a deliberate 501; it now answers from the registry's OSV-backed advisory data, projected
  into npm's bulk-advisory wire format. Version ranges are evaluated under npm's native
  semver ordering (`fixed` exclusive, `last_affected` inclusive). Queries go through the
  existing `IOsvSource` batch path, so remote and air-gapped (local dump) hosts behave
  alike. The audit is refused rather than answered when the advisory source cannot be
  vouched for — a clean report from an unavailable source would be a false all-clear.
- **Operator-facing JWT signing-secret rotation** — `POST /api/v1/system/jwt-secret/rotate`.
  The secret is generated server-side, never accepted, echoed, or logged, and becomes
  effective on the serving replica before the response is written; other replicas converge
  within `Auth:JwtSigningKeyRefreshSeconds` (default 1 s), and the response reports that
  window. **Rotation signs everybody out, including the caller** — there is no old-key grace
  period, because a leaked `jwt_secret` forges any session on the instance and honouring the
  old key would keep an attacker's forged tokens alive just as long. Expect the next request
  to 401. Previously an operator's only remedy for a suspected key compromise was a manual DB
  edit plus a restart — and doing that on a live instance broke it, since the validation key
  was captured once at process start.
- **PEP 691 JSON Simple API** for modern pip/uv — `GET /simple/` and `/simple/{package}/`
  now negotiate the response representation from the `Accept` header
  (`application/vnd.pypi.simple.v1+json` vs. `text/html`, quality-value aware), defaulting to
  HTML so existing installs are unaffected. The JSON projection shares the HTML renderer's
  block-gate filtering, so a client negotiating JSON cannot discover an artifact the download
  gate would deny.
- **Instance and per-org email delivery, and operator Slack.** An instance SMTP transport
  (Settings → Instance settings) delivers org invites; per-org alert email settings with a
  delivery gate and recipients live on the **Alerts** tab, with the transport itself on
  **Settings → Integrations → Email**. Operator-realm Slack notifications cover tenant
  lifecycle and admin events.
- **Risk drill-down API and UI** — the rows behind the Overview dashboard's risk tiles.
  `GET /api/v1/risk/operational` lists the versions at or over the versions-behind threshold
  (and returns the tile's own distinct-package count alongside the row total);
  `GET /api/v1/risk/license` lists versions carrying a blocklisted SPDX identifier or no
  license at all, labelling each row `blocklisted` or `unknown`. Both union the uploaded and
  proxied storage planes exactly as the tiles do, so a list agrees with the count it came
  from, and both gate on `read:packages` — the capability that already serves the tiles — so
  they are not admin-only. The dashboard tiles drill down into them.
- **Activity time window** — `GET /api/v1/activity` accepts `since=24h|7d|30d|90d`, honoured
  by the paged list and the `format=csv` export alike, so the blocked-pull drill-down scopes
  to the same 30-day window the dashboard tile counts.
- **PAT auth on license-policy and lookup reads** — `GET /api/v1/license-policy` (plus its
  `/allowlist` and `/blocklist` views) and `GET /api/v1/lookup` now accept a PAT or service
  token carrying `read:packages`, joining the rest of the read-only management surface.
  Policy mutations stay JWT-session-only.
- **`artifact_inventory` read model** — one canonical place that merges a package's two
  catalogues (uploaded and proxied). The storage baseline, license-risk tile, and version
  lists read from it rather than each re-deriving the union.
- **Copy remediation brief** action on the Vulnerabilities page, with CWE-to-skill coverage
  across nine curated skills.
- **OCI cross-repository blob mount**, with the sub-operation pinned in the inventory.
- **Maven version-level SNAPSHOT metadata** with `snapshot`/`snapshotVersions`.

### Fixed

#### Tenant isolation and security

- **Cross-tenant OCI blob read (critical) and existence oracle (high).** The `oci_blobs`
  store is content-addressed with no org segment, so in the default single-store deployment
  (cache == registry) one tenant's bytes resolve under the identical key any other tenant
  would compute — a bare store hit was never proof of authorization. Blob `GET` now confirms
  entitlement before serving a shared-store hit, and `HEAD` answers a cache hit only from an
  `oci_blobs` row scoped to the caller's own org.
- **`local_only` was bypassed on the proxy cache-hit serve path** — a dependency-confusion
  bypass: the claim was enforced on the fetch path but not when serving an already-cached
  artefact.
- **Per-tenant storage quota is enforced on the cache-fill path.** The proxy cache-MISS
  write paths streamed verified upstream bytes into the cache tier with no quota check,
  letting a tenant with proxy passthrough enabled grow the shared cache plane without bound.
  The quota gate also now accounts for in-flight fills: deriving the ceiling from a live
  `SUM` was racy, since a fill is invisible to it until recorded after the fetch returns, so
  K concurrent pulls of K distinct artefacts all admitted themselves against the same
  pre-fill sum. Upstream registries are per-org and tenant-admin configured, so a tenant
  could point its org at a server it controls and burst far past its ceiling onto shared disk.
- **Percent-encoded path traversal** rejected in Go proxy module/version, Maven proxy path
  segments, and lookup `ValidateName`.
- **OCI `aws_ecr` auth fails closed** rather than falling back to anonymous.
- **`/edge/status`** is gated behind the metrics IP allowlist.
- **npm scoped-name allow/blocklist gate**, and rate limiting extended to the dist-tag and
  unpublish mutation routes.
- **Raw exception text** (SMTP and other test-send paths) no longer leaks to API responses.
- **Upstream metadata TTL cache is isolated per credential**, so one tenant's authenticated
  upstream response cannot be served to another.
- **A session-invalidation race in `UserTokenVersionStore`** (invalidate-then-fill) is closed,
  and logout revocation failures are no longer swallowed.

#### Proxy cataloguing and the storage planes

This release completes the move of proxied artefacts onto the shared cache plane
(`cache_artifact` + `tenant_artifact_access`). Several read surfaces still joined
`package_versions` and so were blind to proxied artefacts:

- **Proxy zombie rows: a second sweep.** The one-shot migration ran on deployed databases
  while the fetch path could still mint an `origin='proxy'` row in `package_versions`
  (it fell back to the hosted plane whenever it could not record on the cache plane). Rows
  written after that first pass ledgered itself were left uncleaned — invisible to the
  vulnerability sweep and to retention, which both read `package_versions` as
  `origin='uploaded'`, so unscanned and unreclaimable. The fetch path now catalogues
  exclusively on the cache plane and refuses a fetch it cannot record there, so no new zombie
  is produced; this release re-runs the idempotent backfill-and-delete once more to catch the
  stragglers. On a database with none it is a no-op. **Back up your database before
  upgrading** — the sweep deletes `package_versions` rows after re-cataloguing them.
- **The storage baseline counts every plane**, and no longer drops orphan artifacts.
- **Proxied version counts counted files, not versions.** `cache_artifact` is keyed
  `UNIQUE (ecosystem, name, version, filename)`, so one proxied version owns one row per
  file — but the package tile's `VersionCount` and retention both read a row as a version.
  A proxied Maven version (jar + pom + sources + javadoc) reported 4, NuGet with its
  `.nuspec` 2, multi-file PyPI 2, and a version held on both planes counted twice, while the
  detail page showed one. Both now count distinct versions, so tile counts and retention
  agree with the detail page.
- **A release-age hold stays raised on the proxy plane**, and a proxy version can be manually
  blocked or approved (both previously only worked for uploaded versions).
- **The deprecation refresh revisits stale hosted-only packages** the cache pass cannot see.
- **PyPI gates a first fetch even when the blob is a global cache hit**, and gates a proxy
  first-fetch *before* adopting it rather than after.
- **The orphan-blob reconciler unions every table holding a hosted blob key** —
  `package_versions` plus `package_version_files`, `maven_version_files`, and
  `nuget_symbol_index`, whose rows are the sole reference to a Maven `.pom`/sources jar, a
  PyPI sdist published alongside a wheel, or a NuGet symbols package. Reconciling against
  `package_versions` alone deleted live artefacts.
- **Quarantine decisions match proxy artifacts by cache-plane coordinate.**
- **A plane-coverage compliance gate** now routes and marks every uploaded-catalogue read, so
  a new read surface cannot silently go plane-blind.

#### OCI

- **Every OCI image reported as having no license.** An image's SPDX expression was captured
  only on its `oci_blobs` manifest row, never in the shared `package_version_licenses` table
  every other ecosystem uses — so the package-detail page rendered no licenses for any image,
  and the license-risk tile and its drill-down counted correctly-licensed images as "no
  license" while never flagging one whose license was on the blocklist. An image's license is
  now projected onto whichever plane catalogued it as an ordinary license row, and existing
  images are backfilled. The OCI special-casing is gone from every license reader.
- **A crash-loop on multi-tenant upgrade** from the OCI licence backfill.
- **A shared manifest blob is no longer destroyed** by a management version delete; the
  physical blob delete is gated on a real cross-org refcount and serialised on the per-key
  lock, closing quota and dangling-row races.
- **Single-flight blob joiners get their own per-org `oci_blobs` row.**
- **Both catalogue planes are guarded** against scanning and evicting images.

#### Correctness and robustness

- **Hosted blob keys are content-addressed on every publish path**, so bytes and checksum
  cannot diverge; this closes a publish blob-checksum race and covers the RPM/Maven paths
  outside the publish service.
- **A transient DB failure in one stats refresh pass no longer stops the host**, and a cache
  blob delete that persistently fails no longer livelocks eviction.
- **Durable delivery bookkeeping survives shutdown**, and a quota double-decrement is fixed.
- **npm packument rebuilds are request-lifetime-safe and invalidation-safe**; NuGet
  proxy-merged registration rebuilds are `HttpContext`-independent; a lost-invalidation
  window in `RenderedResponseCache` rebuilds is closed.
- **Package search**: substring search restored, case folding aligned across providers, and
  the `LIKE` pattern anchored to the name prefix.
- **Maven advisories match in `OSV_MODE=local`** by converting the purl name to colon form.
- **Webhook dispatch and SIEM retry backoff are driven off `TimeProvider`.**
- **`RpmHeaderParser` bounds header-intro overflow and offset reads.**
- **PyPI advertises the local sha256** for filenames hosted both locally and upstream, and
  renders local files before upstream in the JSON merged index.
- **The operational-risk tile no longer undercounts cross-ecosystem name collisions** — it
  counts distinct `(ecosystem, name)` pairs, matching what the drill-down lists.
- **The unread `metadata_cache` table is dropped**, as is a Postgres-broken duplicate
  `ListInstanceSettingsAsync`.

### Known limitations

- **A proxied/cache-plane version cannot be deleted from the management UI or API** (#385).
  `DELETE /api/v1/packages/{ecosystem}/{name}/{version}` resolves through `package_versions`
  only, so it returns 404 for proxy versions across every proxy ecosystem, and their bytes
  keep counting toward the org storage total. For OCI this is permanent, since cache-plane
  manifests are also excluded from automated retention/eviction by design.
- **An OCI protocol manifest delete leaves a UI zombie** (#399).
  `DELETE /v2/{repo}/manifests/{digest}` cleans `oci_tags`, `oci_blobs`, and the refcounted
  blob, but not the tag-push `package_versions` shadow row — so the management package page
  and `artifact_inventory` keep listing the deleted digest as a version.

## [0.3.1] - 2026-07-12

This file was introduced during the 0.3.1 cycle; releases before it are not catalogued here.
The entries below describe surfaces that shipped in or before 0.3.1.

### Added

- **Go module proxy** — GOPROXY protocol surface at `/go/`. Implements `@v/list`, `.info`, `.mod`, `.zip`, and `@latest` routes with bang-encoding decode at the route boundary and re-encode on upstream URL construction. All requests go through the proxy cache-miss path; `.zip` fetches record a `package_versions` row in the catalogue. Proxy-only (no hosted push path).
- **Cargo sparse registry** — sparse index protocol at `/cargo/`. Serves `config.json`, sparse index files (per-name path layout), and crate downloads at `api/v1/crates/{name}/{version}/download`. Local versions shadow upstream on collision; crate downloads are cached in the blob store on first fetch. OSV vulnerability scanning and PURL normalization (`pkg:cargo/{name}@{version}`) are included.
- **Staging-disk guardrails** — `StagingDiskMonitor` samples staging volume free space every 60 s and emits OTel gauges and a Serilog `Warning` when free space falls below `STAGING_DISK_WARN_THRESHOLD_PERCENT` (default 10 %). Proxy fetches are rejected with 507 Insufficient Storage when available bytes fall below `STAGING_DISK_FLOOR_BYTES` (default 512 MiB); when `Content-Length` is present the effective floor is `max(STAGING_DISK_FLOOR_BYTES, 2 × Content-Length)`.
