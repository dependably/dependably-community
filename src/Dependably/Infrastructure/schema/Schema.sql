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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (package_id, version)
);

CREATE TABLE IF NOT EXISTS tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings, e.g. ["publish:npm"].
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT
);

CREATE TABLE IF NOT EXISTS cicd_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT
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
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_cicd_tokens_hash ON cicd_tokens(token_hash);

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

-- NOTE: SchemaInitializer also runs ALTER TABLE statements for the columns above.
-- Those are no-ops on fresh installs (duplicate column error is swallowed / IF NOT EXISTS).
-- They exist solely to add the columns to databases created before those columns were
-- included in the CREATE TABLE blocks. Schema.sql is the authoritative complete schema.
