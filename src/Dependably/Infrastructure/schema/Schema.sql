-- Dependably database schema
-- Applied on first boot via SchemaInitializer

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    -- Soft-delete: set on DELETE /api/v1/system/tenants/{slug}; cleared on restore.
    -- TenantHardDeleteService cascade-deletes rows where deleted_at < now() - 30 days.
    deleted_at  TEXT,
    -- Tenant lifecycle gate consulted by ITenantStorageResolver before every registry write.
    -- 'active' is the only state that admits writes; 'suspended'/'archived'/'deleting' raise
    -- TenantNotReadyException. Community has no UI to change this beyond 'active' today, but
    -- the resolver checks it defensively so hand-modified rows or future enterprise imports
    -- can't slip through.
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','suspended','archived','deleting')),
    -- Reserved for future multi-region routing. Fully dormant in community.
    region      TEXT,
    -- Per-tenant entitlement document (audit_retention, sso_enforced, sbom_signing,
    -- private_packages_enabled, …). One column rather than a per-feature flood. Canonical
    -- schema + strict binding (reject unknown/retired keys, log skipped) live in enterprise;
    -- community ignores the column.
    features    TEXT NOT NULL DEFAULT '{}',
    -- Reserved for future enterprise hierarchy; not interpreted by any query in community.
    -- Schema capacity only — no FK, no model field, no API surface. See community/enterprise boundary rule.
    parent_tenant_id TEXT,
    -- Aggregate storage quota for the tenant's hosted artefacts (sum of package_versions.size_bytes
    -- under this org's packages). NULL = unlimited; positive integer = byte cap. Checked in
    -- PackagePublishService before the blob put — exceeding the cap returns 413. Noisy-neighbour
    -- guard for multi-tenant pool deployments; trivially satisfied in single-tenant installs.
    storage_quota_bytes INTEGER,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS org_settings (
    org_id              TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    anonymous_pull      INTEGER NOT NULL DEFAULT 0,
    allowlist_mode      INTEGER NOT NULL DEFAULT 0,
    max_upload_bytes    INTEGER,
    max_upload_bytes_pypi   INTEGER,
    max_upload_bytes_npm    INTEGER,
    max_upload_bytes_nuget  INTEGER,
    keep_versions       INTEGER,            -- GC: max versions to retain per package per ecosystem
    keep_days           INTEGER,            -- GC: evict proxy blobs unused for this many days
    activity_retention_days INTEGER,        -- GC: delete activity rows older than this
    license_enforcement_mode  TEXT    NOT NULL DEFAULT 'off',
    proxy_passthrough_enabled INTEGER NOT NULL DEFAULT 1,
    max_osv_score_tolerance   REAL    NOT NULL DEFAULT 10.0,
    -- Minimum upstream-release age (hours) before a proxy-fetched version is allowed past the
    -- block gate. NULL = policy off. Supply-chain hold: lets community detection (npm/PyPI/NuGet
    -- removals, advisories) catch up before a fresh upstream version reaches tenant builds.
    -- First-fetch only; already-cached versions are unaffected, and unblock requires an operator
    -- action once the threshold passes (no automatic rescan).
    min_release_age_hours     INTEGER,
    default_language          TEXT    NOT NULL DEFAULT 'en',  -- new tenant users start with this locale
    allow_version_overwrite   INTEGER NOT NULL DEFAULT 0    -- #45 replacement policy; off by default
);

CREATE TABLE IF NOT EXISTS instance_settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

-- Tenant users. 1:1 with tenants — a user belongs to exactly one tenant. The same email may
-- exist as separate accounts in different tenants (UNIQUE(tenant_id, email)) — by design,
-- modeled on Slack/Auth0/Notion-style strict tenant isolation.
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner','auditor')),
    account_type TEXT NOT NULL DEFAULT 'forms' CHECK (account_type IN ('forms','saml')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    password_reset_issued_at TEXT,
    language    TEXT,  -- NULL = inherit org_settings.default_language
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (tenant_id, email)
);

-- Operator identity for multi-tenant deployments. Empty in single-mode installs. system_admins
-- see only the control plane (tenant CRUD, instance settings, minimal user lookup) and never
-- tenant business data. Strictly separate from `users` — different lifecycle, no tenant_id.
CREATE TABLE IF NOT EXISTS system_admins (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    -- Mirrors users.account_status: 'active' (can log in), 'locked' (auto-lockout from
    -- throttling), 'disabled' (operator-set). Required for /api/v1/system/admins CRUD so
    -- operators can disable peers without hard-deleting and losing the audit-trail identity.
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    password_reset_issued_at TEXT,
    language    TEXT,  -- NULL = fall back to 'en'
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS packages (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,   -- 'pypi' | 'npm' | 'nuget'
    name        TEXT NOT NULL,
    purl_name   TEXT NOT NULL,   -- normalized per ecosystem
    is_proxy    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (org_id, ecosystem, purl_name)
);

CREATE TABLE IF NOT EXISTS package_versions (
    id          TEXT PRIMARY KEY,
    package_id  TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version     TEXT NOT NULL,
    purl        TEXT NOT NULL UNIQUE,
    blob_key    TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    checksum_sha256 TEXT,
    yanked      INTEGER NOT NULL DEFAULT 0,
    yank_reason TEXT,
    first_fetch INTEGER NOT NULL DEFAULT 0,  -- 1 if this was a cache-miss proxy fetch
    last_used   TEXT,                         -- ISO 8601 UTC; updated on each download
    vuln_checked_at TEXT,        -- ISO 8601 UTC; set after OSV vulnerability scan
    manual_block_state TEXT,     -- NULL = follow auto policy, 'blocked' = manual block, 'allowed' = manual override of auto-block
    deprecated  TEXT,            -- NULL = not deprecated; otherwise upstream deprecation message (npm/NuGet)
    -- origin tracking: 'proxy' = upstream cache; 'uploaded' = user-pushed file (admin
    -- /admin/upload or protocol push). Existing databases that pre-date this column get it
    -- via an additive ALTER TABLE in SchemaInitializer, and legacy 'imported'/'private'
    -- rows are collapsed to 'uploaded' by the collapse_origin_to_uploaded one-shot migration.
    origin      TEXT NOT NULL DEFAULT 'proxy',
    -- ISO 8601 UTC; timestamp the version was first published to the public upstream registry
    -- (PyPI upload_time_iso_8601, npm time[version], NuGet catalogEntry.published). Captured on
    -- first proxy fetch, fail-soft (null if upstream metadata can't be parsed). Always NULL for
    -- origin='uploaded' rows — uploaded versions have no upstream publish date.
    published_at TEXT,
    -- Hex SHA-1 of the artefact bytes. Captured on every npm publish (the packument
    -- dist.shasum field uses SHA-1 by spec) and from upstream packuments on proxy first-fetch.
    -- NULL for PyPI / NuGet versions and for legacy rows pre-dating the column.
    checksum_sha1 TEXT,
    -- Upstream-published integrity hash, stored VERBATIM in upstream's native encoding so
    -- operators can copy-paste against the public registry's UI without re-encoding:
    --   npm   → 'sha512-{base64}' (the SRI form printed on npmjs.com)
    --   NuGet → '{base64}'        (packageHash as written in the registration leaf)
    --   PyPI  → '{hex}'           (sha256 from the #sha256= simple-index fragment)
    -- Algorithm column tags how to interpret the value. NULL for uploaded versions (no
    -- upstream claim to compare against) and for legacy rows pre-dating the column.
    upstream_integrity_value TEXT,
    upstream_integrity_algorithm TEXT,  -- 'sha256' | 'sha512-sri' | 'sha512-b64'
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (package_id, version)
);

CREATE TABLE IF NOT EXISTS user_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings, e.g. ["publish:npm"].
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT,
    last_used_at TEXT            -- updated (throttled ~60s) when the token authenticates a request.
);

CREATE TABLE IF NOT EXISTS service_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings.
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT,
    last_used_at TEXT            -- updated (throttled ~60s) when the token authenticates a request.
);

CREATE TABLE IF NOT EXISTS invites (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner','auditor')),
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT NOT NULL,
    accepted_at TEXT
);
-- Prevent duplicate pending invites: only one unaccepted invite per (org, email) at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_unique_pending
    ON invites (org_id, email) WHERE accepted_at IS NULL;

CREATE TABLE IF NOT EXISTS allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    purl_pattern TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (org_id, purl_pattern)
);

CREATE TABLE IF NOT EXISTS blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,  -- regex matched against the full package PURL
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (org_id, pattern)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    -- 'tenant' for per-tenant business events; 'system' for operator events (tenant.created,
    -- tenant.deleted, tenant.restored, tenant.hard_deleted, system_admin.password_reset, etc).
    -- /api/v1/system/audit filters by scope='system'; tenant audit endpoints filter by
    -- scope='tenant' AND org_id = caller's tid.
    scope       TEXT NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','system')),
    org_id      TEXT,
    actor_id    TEXT,
    action      TEXT NOT NULL,
    ecosystem   TEXT,
    purl        TEXT,
    detail      TEXT,           -- JSON
    source_ip   TEXT,           -- canonical remote IP (IPv4-mapped IPv6 collapsed); null for background paths
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_log_scope ON audit_log(scope, created_at DESC);

CREATE TABLE IF NOT EXISTS activity (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,  -- 'pypi' | 'npm' | 'nuget' for package events; 'auth' for login/lockout
    purl        TEXT,           -- null for non-package events (auth)
    event_type  TEXT NOT NULL,  -- 'push' | 'pull' | 'first_fetch' | 'delete' | 'vuln_scan' | 'login.success' | 'login.failure' | 'login.locked'
    actor_id    TEXT,
    detail      TEXT,
    source_ip   TEXT,           -- captured for HTTP-originated events (downloads, push, delete, blocked_*); null for background paths
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              TEXT PRIMARY KEY,
    osv_id          TEXT NOT NULL UNIQUE,
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    aliases         TEXT,           -- JSON array of alias IDs
    summary         TEXT,
    severity        TEXT,           -- 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | NULL
    cvss_score      REAL,
    affected_versions TEXT,         -- JSON array of version strings
    published_at    TEXT,
    modified_at     TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS package_version_vulns (
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (package_version_id, vuln_id)
);

-- Indexes for common query patterns
CREATE TABLE IF NOT EXISTS login_attempts (
    email_hash  TEXT PRIMARY KEY,   -- SHA-256 of lowercased email — avoids storing PII
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,              -- ISO 8601 UTC; NULL = not locked
    last_attempt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_packages_org_ecosystem ON packages(org_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_vulns_ecosystem_pkg ON vulnerabilities(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_pkg_version_vulns_version ON package_version_vulns(package_version_id);
CREATE INDEX IF NOT EXISTS idx_package_versions_package ON package_versions(package_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_org ON activity(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_tokens_hash ON user_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_service_tokens_hash ON service_tokens(token_hash);

-- License governance (#21)
CREATE TABLE IF NOT EXISTS package_version_licenses (
    id                  TEXT PRIMARY KEY,
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    license_spdx        TEXT NOT NULL,                  -- SPDX identifier e.g. MIT, Apache-2.0
    source              TEXT NOT NULL DEFAULT 'upstream',   -- 'upstream' | 'sbom' | 'manual'
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (package_version_id, license_spdx)
);

CREATE TABLE IF NOT EXISTS license_allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (org_id, license_spdx)
);

CREATE TABLE IF NOT EXISTS license_blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (org_id, license_spdx)
);

CREATE INDEX IF NOT EXISTS idx_pkg_version_licenses ON package_version_licenses(package_version_id);

-- SPDX license reference data. Seeded from an embedded JSON list (license-list-data) by
-- SpdxLicenseSeeder on every boot when instance_settings.spdx_list_version differs from the
-- embedded value. No FK from policy tables — admins must be able to allow/block identifiers
-- that aren't in the bundled list (custom or post-bundle SPDX additions).
CREATE TABLE IF NOT EXISTS spdx_license (
    identifier      TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    is_osi_approved INTEGER NOT NULL DEFAULT 0,
    is_fsf_libre    INTEGER NOT NULL DEFAULT 0,
    is_deprecated   INTEGER NOT NULL DEFAULT 0,
    reference_url   TEXT,
    -- Copyleft strength is NOT published by SPDX; sourced from a curated overlay
    -- (BlueOak/ChooseALicense/FSF). Identifiers absent from the overlay get 'unclassified'.
    copyleft        TEXT NOT NULL DEFAULT 'unclassified'
        CHECK (copyleft IN ('permissive','weak-copyleft','strong-copyleft','network-copyleft','public-domain','unclassified'))
);
CREATE INDEX IF NOT EXISTS idx_spdx_license_osi ON spdx_license(is_osi_approved);
CREATE INDEX IF NOT EXISTS idx_spdx_license_copyleft ON spdx_license(copyleft);

-- JWT revocations: stores revoked jti values until their expiry time.
-- Rows are cleaned up by the GC pass via RetentionService.
CREATE TABLE IF NOT EXISTS jwt_revocations (
    jti         TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL  -- ISO 8601 UTC; row can be deleted after this time
);
CREATE INDEX IF NOT EXISTS idx_jwt_revocations_expires ON jwt_revocations(expires_at);

-- Per-tenant SAML 2.0 SP configuration. Tenant admins upload IdP metadata XML and toggle
-- forms/SAML login independently. forms_login_enabled=0 (SAML-only) is gated by a recent
-- successful test (last_test_at) to prevent lockout from a misconfigured IdP.
CREATE TABLE IF NOT EXISTS tenant_saml_config (
    org_id              TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    enabled             INTEGER NOT NULL DEFAULT 0,
    forms_login_enabled INTEGER NOT NULL DEFAULT 1,
    idp_entity_id       TEXT,
    idp_sso_url         TEXT,
    idp_signing_cert    TEXT,                          -- base64 X.509 from metadata
    metadata_xml        TEXT,                          -- raw uploaded XML
    sp_entity_id        TEXT,
    name_id_format      TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    email_attribute     TEXT,                          -- attribute name; NULL = use NameID
    button_label        TEXT,
    last_test_at        TEXT,
    last_test_email     TEXT,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- One-shot correlation-id store for SAML admin-test runs. The signed test cookie carries a
-- cid (Guid) that maps back to a row here; ACS atomically stamps consumed_at on first use,
-- so a leaked or replayed cookie can't drive a second IdP round-trip. Rows expire after the
-- cookie TTL (15 minutes) and are GC'd by the retention pass.
CREATE TABLE IF NOT EXISTS saml_test_runs (
    cid          TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor_id     TEXT,
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_saml_test_runs_expires ON saml_test_runs(expires_at);

-- IdP-issued identities linked to local users. Identity is (idp_entity_id, nameid) — never
-- email. NameID is the IdP's stable subject identifier; email can change in the IdP without
-- breaking login. Multiple IdPs per user is supported by design (UNIQUE allows many rows
-- per user_id). email_snapshot is recorded for audit/UX only.
CREATE TABLE IF NOT EXISTS external_identities (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_entity_id   TEXT NOT NULL,
    nameid          TEXT NOT NULL,
    email_snapshot  TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_login_at   TEXT,
    UNIQUE (org_id, idp_entity_id, nameid)
);
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id);

-- ── Multitenant architecture (#43–#54) ─────────────────────────────────────────
-- New tables and columns introduced by the multitenant architecture roadmap. Each
-- table here keeps the org_id-first composite-index convention from older tables.

-- #47 per-tenant package name claims. Three states: unclaimed (default; reject local writes),
-- local_only (proxy disabled, local writes accepted), mixed (both, local wins on collision).
CREATE TABLE IF NOT EXISTS claim (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('unclaimed','local_only','mixed')),
    reason      TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    deleted_at  TEXT,
    UNIQUE (org_id, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_claim_org_state ON claim (org_id, state);

-- #47 append-only history of claim transitions. Forensic record + UI history view.
CREATE TABLE IF NOT EXISTS claim_history (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    claim_id        TEXT NOT NULL REFERENCES claim(id) ON DELETE CASCADE,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    prior_state     TEXT,                  -- NULL on creation event
    new_state       TEXT NOT NULL,
    reason          TEXT NOT NULL,
    purged_count    INTEGER NOT NULL DEFAULT 0,  -- proxy artifacts purged on transition
    actor_id        TEXT REFERENCES users(id),
    occurred_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_claim_history_org_time ON claim_history (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_claim_history_claim ON claim_history (claim_id, occurred_at DESC);

-- #48 global shared proxy-cache index. One row per (ecosystem, name, version, filename).
-- No tenant column: the artifact is content-addressed and shared across tenants.
-- last_accessed_at drives LRU eviction; per-tenant access lives in tenant_artifact_access.
CREATE TABLE IF NOT EXISTS cache_artifact (
    id                  TEXT PRIMARY KEY,
    ecosystem           TEXT NOT NULL,
    name                TEXT NOT NULL,
    version             TEXT NOT NULL,
    filename            TEXT NOT NULL,
    blob_key            TEXT NOT NULL,        -- BlobKeys.Proxy(sha256)
    content_hash        TEXT NOT NULL,        -- sha256 hex
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    upstream_url        TEXT,
    upstream_etag       TEXT,
    first_cached_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_accessed_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (ecosystem, name, version, filename)
);
CREATE INDEX IF NOT EXISTS idx_cache_artifact_lru ON cache_artifact (last_accessed_at);

-- #48 per-tenant access tracking on the shared cache. Answers "which tenants pulled X" for
-- vulnerability response. Upserted on every cache hit and lazy fetch.
CREATE TABLE IF NOT EXISTS tenant_artifact_access (
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cache_artifact_id   TEXT NOT NULL REFERENCES cache_artifact(id) ON DELETE CASCADE,
    first_accessed_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_accessed_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    access_count        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (org_id, cache_artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_artifact_access_artifact
    ON tenant_artifact_access (cache_artifact_id);

-- #48 cached upstream metadata documents (npm package JSON, PyPI simple HTML, NuGet registration).
-- Global; freshness via TTL revalidation. Per-tenant access is not tracked (low privacy value;
-- metadata changes too often for the tracking to be useful).
CREATE TABLE IF NOT EXISTS metadata_cache (
    id              TEXT PRIMARY KEY,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    document        TEXT NOT NULL,             -- JSON or HTML, ecosystem-dependent
    content_hash    TEXT NOT NULL,
    upstream_etag   TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at      TEXT NOT NULL,
    UNIQUE (ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_metadata_cache_expires ON metadata_cache (expires_at);

-- #52 typed audit events. Replaces the freeform audit_log gradually; both tables coexist
-- during M1.4. Envelope columns are required; payload is JSON. event_id is UUIDv7.
CREATE TABLE IF NOT EXISTS audit_event (
    event_id            TEXT PRIMARY KEY,                    -- UUIDv7
    schema_version      INTEGER NOT NULL DEFAULT 1,
    event_type          TEXT NOT NULL,                       -- e.g. 'package.publish'
    org_id              TEXT REFERENCES orgs(id) ON DELETE SET NULL,  -- NULL for cross-tenant platform events
    tenant_resolver     TEXT NOT NULL,                       -- single | multi | header | bound
    actor_type          TEXT NOT NULL CHECK (actor_type IN ('user','api_token','system')),
    actor_id            TEXT,
    request_id          TEXT,
    source_ip           TEXT,
    user_agent          TEXT,
    outcome             TEXT NOT NULL CHECK (outcome IN ('accepted','rejected','error')),
    payload             TEXT NOT NULL,                       -- JSON; per-event-type shape
    occurred_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_time ON audit_event (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_type ON audit_event (org_id, event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor ON audit_event (org_id, actor_id, occurred_at DESC);

-- Per-tenant registry bucket binding. Dormant in community: a NULL/absent row means "use
-- the global STORAGE_BACKEND_REGISTRY env vars" — which is how community's LocalBlobStore
-- and the small-tenant SaaS fallback path both work. Enterprise reads bucket/endpoint here
-- per request to route silo-registry writes to the tenant's own R2 bucket. See
-- ITenantStorageResolver for the resolution semantics.
CREATE TABLE IF NOT EXISTS tenant_storage (
    org_id                      TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    registry_bucket             TEXT,
    registry_region             TEXT,
    registry_endpoint           TEXT,
    registry_force_path_style   INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Async provisioning state machine for cloud-resource creation (R2 buckets, KMS keys,
-- SAML metadata exchanges, etc). HTTP create-tenant returns fast; a worker drains the row,
-- making the actual cloud-API call off the request path. Resolver gates registry calls on
-- state='ready' for kind='registry_bucket_create'. Absent rows are treated as ready in
-- community since LocalBlobStore needs no provisioning. UNIQUE(org_id, kind) forces retries
-- to UPDATE the existing row, never INSERT — workers must reset state, not duplicate.
-- idempotency_key is for HTTP-layer caller-supplied idempotency (Idempotency-Key header);
-- orthogonal to per-tenant uniqueness, not redundant with it.
CREATE TABLE IF NOT EXISTS tenant_provisioning_jobs (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'creating'
                    CHECK (state IN ('creating','ready','failed')),
    idempotency_key TEXT,
    last_error      TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    completed_at    TEXT,
    UNIQUE (org_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_tenant_provisioning_jobs_org ON tenant_provisioning_jobs(org_id, kind);

-- Per-run history for IHostedService background workers. Replaces the in-memory
-- last-success dictionary on DependablyMeter with a persistent record. Written by
-- BackgroundJobScope.Dispose() fire-and-forget; surfaced in the sysadmin Audit page
-- "Background Jobs" tab. id is a GUID-N; run_id matches the OTel trace correlation id
-- attached to the activity. outcome is the same vocabulary BackgroundJobScope already
-- emits to the histogram ('success' | 'server_error' | 'cancelled'). No GC yet — see
-- the follow-up tracked alongside this PR for the retention pass.
CREATE TABLE IF NOT EXISTS background_job_runs (
    id              TEXT PRIMARY KEY,
    job_name        TEXT NOT NULL,
    operation       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL,
    outcome         TEXT NOT NULL,
    error_message   TEXT
);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_started_at
    ON background_job_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_job_started
    ON background_job_runs(job_name, started_at DESC);

-- NOTE: SchemaInitializer also runs ALTER TABLE statements for the columns above.
-- Those are no-ops on fresh installs (duplicate column error is swallowed / IF NOT EXISTS).
-- They exist solely to add the columns to databases created before those columns were
-- included in the CREATE TABLE blocks. Schema.sql is the authoritative complete schema.
