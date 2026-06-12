-- Dependably database schema (PostgreSQL)
-- Applied on first boot via SchemaInitializer

CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    deleted_at  TEXT,
    -- Tenant lifecycle gate consulted by ITenantStorageResolver before every registry write.
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','suspended','archived','deleting')),
    -- Reserved for future multi-region routing. Fully dormant in community.
    region      TEXT,
    -- Per-tenant entitlement document; canonical schema + strict binding live in enterprise.
    features    TEXT NOT NULL DEFAULT '{}',
    -- Reserved for future enterprise hierarchy; not interpreted by any query in community.
    -- Schema capacity only — no FK, no model field, no API surface.
    parent_tenant_id TEXT,
    -- Aggregate storage quota for the tenant's hosted artefacts. NULL = unlimited.
    -- Checked in PackagePublishService before the blob put; exceeding returns 413.
    storage_quota_bytes BIGINT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE TABLE IF NOT EXISTS org_settings (
    org_id              TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    anonymous_pull      INTEGER NOT NULL DEFAULT 0,
    allowlist_mode      INTEGER NOT NULL DEFAULT 0,
    max_upload_bytes    INTEGER,
    max_upload_bytes_pypi   INTEGER,
    max_upload_bytes_npm    INTEGER,
    max_upload_bytes_nuget  INTEGER,
    max_upload_bytes_maven  INTEGER,        -- per-ecosystem Maven cap; falls back to max_upload_bytes
    max_upload_bytes_rpm    INTEGER,        -- per-ecosystem RPM cap; falls back to max_upload_bytes
    max_upload_bytes_oci    INTEGER,        -- per-ecosystem OCI (Docker) cap; falls back to max_upload_bytes
    keep_versions       INTEGER,            -- GC: max versions to retain per package per ecosystem
    keep_days           INTEGER,            -- GC: evict proxy blobs unused for this many days
    activity_retention_days INTEGER,        -- GC: delete activity rows older than this
    license_enforcement_mode  TEXT    NOT NULL DEFAULT 'off',
    proxy_passthrough_enabled INTEGER NOT NULL DEFAULT 1,
    max_osv_score_tolerance   REAL    NOT NULL DEFAULT 10.0,
    -- Supply-chain hold: minimum upstream-release age (hours) before a proxy-fetched version
    -- clears the block gate. NULL = policy off. See Schema.sql for the full rationale.
    min_release_age_hours     INTEGER,
    default_language          TEXT    NOT NULL DEFAULT 'en',
    allow_version_overwrite   INTEGER NOT NULL DEFAULT 0,
    maven_reserved_prefixes   TEXT    NOT NULL DEFAULT '[]', -- dep-confusion guard; JSON array of groupId prefixes
    -- Per-tenant air-gap posture; forces proxy passthrough off and skips the vuln/deprecation
    -- scan passes for this org. Composes with the instance AIR_GAPPED env var. See Schema.sql.
    air_gapped                INTEGER NOT NULL DEFAULT 0,
    -- Policy for upstream-deprecated/abandoned packages. See Schema.sql for the full rationale.
    block_deprecated          TEXT    NOT NULL DEFAULT 'off' CHECK (block_deprecated IN ('off', 'warn', 'block_new', 'block_all')),
    -- Policy for versions carrying a malicious-package advisory (OSV MAL- ids). See Schema.sql.
    block_malicious           TEXT    NOT NULL DEFAULT 'block' CHECK (block_malicious IN ('off', 'warn', 'block')),
    -- Policy for CISA-KEV-listed (exploited-in-the-wild) advisories. See Schema.sql.
    block_kev                 TEXT    NOT NULL DEFAULT 'off' CHECK (block_kev IN ('off', 'warn', 'block')),
    -- EPSS exploitation-probability ceiling (0.0–1.0); NULL = policy off. See Schema.sql.
    max_epss_tolerance        REAL,
    -- Running tally of hosted-artefact bytes for this tenant. See Schema.sql for the full
    -- rationale (atomic reserve-before-write, backfill, delete decrement).
    storage_used_bytes        BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS instance_settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

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
    language    TEXT,
    -- Monotonic session-invalidation counter. Embedded in tenant JWTs as the `tver` claim
    -- and bumped on password change so outstanding sessions go stale immediately.
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS system_admins (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    password_reset_issued_at TEXT,
    language    TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE TABLE IF NOT EXISTS packages (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,   -- 'pypi' | 'npm' | 'nuget'
    name        TEXT NOT NULL,
    purl_name   TEXT NOT NULL,   -- normalized per ecosystem
    is_proxy    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    -- Upstream's declared latest version (npm dist-tags.latest / PyPI info.version), refreshed by
    -- the background upstream-metadata pass. NULL when no upstream baseline is known.
    upstream_latest_version    TEXT,
    upstream_latest_checked_at TEXT,
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
    -- Cumulative count of served downloads (download + first_fetch events). See Schema.sql.
    download_count BIGINT NOT NULL DEFAULT 0,
    vuln_checked_at TEXT,        -- ISO 8601 UTC; set after OSV vulnerability scan
    manual_block_state TEXT,     -- NULL = follow auto policy, 'blocked' = manual block, 'allowed' = manual override of auto-block
    deprecated  TEXT,            -- NULL = not deprecated; otherwise upstream deprecation message (npm/NuGet)
    -- origin tracking: 'proxy' = upstream cache; 'uploaded' = user-pushed file (admin
    -- /admin/upload or protocol push). Existing databases that pre-date this column get it
    -- via an additive ALTER TABLE in SchemaInitializer, and legacy 'imported'/'private'
    -- rows are collapsed to 'uploaded' by the collapse_origin_to_uploaded one-shot migration.
    origin      TEXT NOT NULL DEFAULT 'proxy',
    -- ISO 8601 UTC; first-publish timestamp from the public upstream registry. See Schema.sql.
    published_at TEXT,
    -- Hex SHA-1 of the artefact bytes (npm packument shasum). See Schema.sql.
    checksum_sha1 TEXT,
    -- Upstream-published integrity hash + algorithm tag. See Schema.sql.
    upstream_integrity_value TEXT,
    upstream_integrity_algorithm TEXT,
    -- Trailing path segment of blob_key. See Schema.sql for rationale.
    filename    TEXT,
    -- ISO 8601 UTC; set after the last upstream deprecation metadata refresh. See Schema.sql.
    deprecation_checked_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (package_id, version)
);

CREATE TABLE IF NOT EXISTS user_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings.
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    expires_at  TEXT,
    last_used_at TEXT            -- updated (throttled ~60s) when the token authenticates a request.
);

CREATE TABLE IF NOT EXISTS service_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
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
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    expires_at  TEXT NOT NULL,
    accepted_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_unique_pending
    ON invites (org_id, email) WHERE accepted_at IS NULL;

CREATE TABLE IF NOT EXISTS allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    purl_pattern TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, purl_pattern)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','system')),
    org_id      TEXT,
    actor_id    TEXT,
    actor_kind  TEXT,
    action      TEXT NOT NULL,
    ecosystem   TEXT,
    purl        TEXT,
    detail      TEXT,
    source_ip   TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);
CREATE INDEX IF NOT EXISTS idx_audit_log_scope ON audit_log(scope, created_at DESC);

CREATE TABLE IF NOT EXISTS activity (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    purl        TEXT,
    event_type  TEXT NOT NULL,
    actor_id    TEXT,
    actor_kind  TEXT,
    detail      TEXT,
    source_ip   TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
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
    osv_json        TEXT,           -- full OSV advisory JSON; source of truth for the rich detail panel
    published_at    TEXT,
    modified_at     TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    -- Threat-feed enrichment (CISA KEV membership + FIRST.org EPSS score). See Schema.sql.
    is_kev          INTEGER NOT NULL DEFAULT 0,
    kev_checked_at  TEXT,
    epss_score      REAL,
    epss_checked_at TEXT
);

CREATE TABLE IF NOT EXISTS package_version_vulns (
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    checked_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    PRIMARY KEY (package_version_id, vuln_id)
);

-- Indexes for common query patterns
CREATE TABLE IF NOT EXISTS login_attempts (
    email_hash  TEXT PRIMARY KEY,   -- SHA-256 of lowercased email -- avoids storing PII
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,              -- ISO 8601 UTC; NULL = not locked
    last_attempt TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX IF NOT EXISTS idx_packages_org_ecosystem ON packages(org_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_vulns_ecosystem_pkg ON vulnerabilities(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_pkg_version_vulns_version ON package_version_vulns(package_version_id);
CREATE INDEX IF NOT EXISTS idx_package_versions_package ON package_versions(package_id);
CREATE INDEX IF NOT EXISTS idx_package_versions_filename ON package_versions(filename);
CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_org ON activity(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_tokens_hash ON user_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_service_tokens_hash ON service_tokens(token_hash);

CREATE TABLE IF NOT EXISTS blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,  -- regex matched against the full package PURL
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, pattern)
);

-- Operator-reserved namespaces (dependency-confusion guard). A name matching a pattern for
-- its ecosystem never consults upstream — no metadata merge, no proxy fetch. Patterns are
-- exact names or trailing-`*` globs ('@acme/*', 'acme-*', 'Acme.*'); maven patterns use
-- dot-boundary prefix semantics ('com.acme' also covers 'com.acme.*' groupIds).
CREATE TABLE IF NOT EXISTS reserved_namespace (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,  -- 'npm' | 'pypi' | 'nuget' | 'maven'
    pattern     TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, ecosystem, pattern)
);

-- Review queue for policy-gate blocks. See Schema.sql for the full rationale.
CREATE TABLE IF NOT EXISTS quarantine (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    ecosystem           TEXT NOT NULL,
    purl                TEXT NOT NULL,
    gate                TEXT NOT NULL,  -- 'deprecated' | 'release_age' | 'malicious' | 'kev' | 'epss' | 'vuln_score'
    detail              TEXT,           -- same JSON the blocked_* activity row carries
    state               TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied')),
    decided_by          TEXT REFERENCES users(id),
    decided_at          TEXT,
    note                TEXT,           -- optional reviewer note recorded with the decision
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    updated_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, purl)
);

CREATE INDEX IF NOT EXISTS idx_quarantine_org_state ON quarantine(org_id, state, updated_at DESC);

-- Per-org upstream proxy registries. One ordered list per ecosystem; `position` ascending is
-- priority (lowest tried first, falling through on miss/unreachable). An ecosystem with zero
-- rows has proxying effectively disabled for that org. auth_type/username/secret are reserved
-- for authenticated upstreams and are dormant in community (anonymous-only).
CREATE TABLE IF NOT EXISTS upstream_registry (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,              -- 'pypi' | 'npm' | 'nuget' | 'maven' | 'rpm'
    name        TEXT,                       -- optional display label
    url         TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0, -- ascending = priority; lowest tried first
    auth_type   TEXT NOT NULL DEFAULT 'anonymous',
    username    TEXT,
    secret      TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, ecosystem, url)
);
CREATE INDEX IF NOT EXISTS idx_upstream_registry_org_eco
    ON upstream_registry(org_id, ecosystem, position);

-- License governance
CREATE TABLE IF NOT EXISTS package_version_licenses (
    id                  TEXT PRIMARY KEY,
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    license_spdx        TEXT NOT NULL,                  -- SPDX identifier e.g. MIT, Apache-2.0
    source              TEXT NOT NULL DEFAULT 'upstream',   -- 'upstream' | 'sbom' | 'manual'
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (package_version_id, license_spdx)
);

CREATE TABLE IF NOT EXISTS license_allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, license_spdx)
);

CREATE TABLE IF NOT EXISTS license_blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (org_id, license_spdx)
);

CREATE INDEX IF NOT EXISTS idx_pkg_version_licenses ON package_version_licenses(package_version_id);

-- RPM metadata. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS rpm_metadata (
    package_version_id  TEXT PRIMARY KEY REFERENCES package_versions(id) ON DELETE CASCADE,
    rpm_name            TEXT NOT NULL,
    epoch               INTEGER NOT NULL DEFAULT 0,
    rpm_version         TEXT NOT NULL,
    rpm_release         TEXT NOT NULL,
    arch                TEXT NOT NULL,
    summary             TEXT,
    description         TEXT,
    build_host          TEXT,
    build_time          INTEGER,
    packager            TEXT,
    vendor              TEXT,
    rpm_group           TEXT,
    source_rpm          TEXT,
    url                 TEXT,
    installed_size      INTEGER NOT NULL DEFAULT 0,
    archive_size        INTEGER NOT NULL DEFAULT 0,
    header_start        INTEGER NOT NULL DEFAULT 0,
    header_end          INTEGER NOT NULL DEFAULT 0,
    requires_json       TEXT NOT NULL DEFAULT '[]',
    provides_json       TEXT NOT NULL DEFAULT '[]',
    conflicts_json      TEXT NOT NULL DEFAULT '[]',
    obsoletes_json      TEXT NOT NULL DEFAULT '[]',
    files_json          TEXT NOT NULL DEFAULT '[]',
    changelogs_json     TEXT NOT NULL DEFAULT '[]',
    rpm_license         TEXT,
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);
CREATE INDEX IF NOT EXISTS idx_rpm_metadata_arch ON rpm_metadata(arch);

CREATE TABLE IF NOT EXISTS rpm_repodata_state (
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    arch          TEXT NOT NULL,
    last_built_at TEXT,
    dirty         INTEGER NOT NULL DEFAULT 1,
    generation    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, arch)
);

-- Maven multi-file per-version tracker. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS maven_version_files (
    id                  TEXT PRIMARY KEY,
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    filename            TEXT NOT NULL,
    classifier          TEXT,
    extension           TEXT NOT NULL,
    blob_key            TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    checksum_sha256     TEXT,
    checksum_sha1       TEXT,
    checksum_md5        TEXT,
    origin              TEXT NOT NULL DEFAULT 'uploaded',
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (package_version_id, filename)
);
CREATE INDEX IF NOT EXISTS idx_maven_version_files_version ON maven_version_files(package_version_id);
CREATE INDEX IF NOT EXISTS idx_maven_version_files_filename ON maven_version_files(filename);

-- OCI / Docker registry storage. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS oci_blobs (
    digest        TEXT NOT NULL,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    media_type    TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    blob_key      TEXT NOT NULL,
    cached_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    upstream_checked_at TEXT,
    origin        TEXT NOT NULL DEFAULT 'uploaded',  -- 'uploaded' (local push) or 'proxy' (upstream cache)
    PRIMARY KEY (digest, org_id)
);
CREATE INDEX IF NOT EXISTS idx_oci_blobs_org ON oci_blobs(org_id);

CREATE TABLE IF NOT EXISTS oci_tags (
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    digest      TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    last_revalidated TEXT,  -- per-tag TTL revalidation timestamp; NULL forces a re-check on first access
    PRIMARY KEY (org_id, repository, tag)
);
CREATE INDEX IF NOT EXISTS idx_oci_tags_repository ON oci_tags(org_id, repository);

-- In-progress OCI blob upload sessions (push). See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS oci_uploads (
    upload_id      TEXT NOT NULL,
    org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository     TEXT NOT NULL,
    staging_path   TEXT NOT NULL,
    received_bytes INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    PRIMARY KEY (upload_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_oci_uploads_org ON oci_uploads(org_id);

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

-- Per-tenant SAML 2.0 SP configuration.
CREATE TABLE IF NOT EXISTS tenant_saml_config (
    org_id              TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    enabled             INTEGER NOT NULL DEFAULT 0,
    forms_login_enabled INTEGER NOT NULL DEFAULT 1,
    idp_entity_id       TEXT,
    idp_sso_url         TEXT,
    idp_signing_cert    TEXT,
    metadata_xml        TEXT,
    sp_entity_id        TEXT,
    name_id_format      TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    email_attribute     TEXT,
    button_label        TEXT,
    last_test_at        TEXT,
    last_test_email     TEXT,
    last_test_claims    TEXT,
    idp_signing_cert_override TEXT,
    role_attribute      TEXT,
    role_mapping        TEXT,
    default_role        TEXT NOT NULL DEFAULT 'member',
    -- Opt-in ceiling raise for IdP-driven role assignment: 0 = the IdP may auto-assign
    -- member/auditor only; 1 = the IdP may also assign admin. 'owner' is never IdP-assignable.
    idp_can_assign_admin INTEGER NOT NULL DEFAULT 0,
    -- Stage of the last emitted cert-expiry alert for this tenant's effective IdP signing cert.
    -- NULL = no alert emitted yet (or cert changed/cleared since the last alert). Tracks whether
    -- the daily sweep needs to emit a new event for the current expiry window ('30','14','7','1',
    -- 'expired'). Reset to NULL whenever the metadata cert or the override cert is replaced.
    cert_expiry_alert_stage TEXT,
    updated_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- One-shot correlation-id store for SAML admin-test runs.
CREATE TABLE IF NOT EXISTS saml_test_runs (
    cid          TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor_id     TEXT,
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_saml_test_runs_expires ON saml_test_runs(expires_at);

-- One-time-use store binding SP-initiated AuthnRequests to their responses. /saml/login inserts
-- the AuthnRequest id; ACS consumes it by matching the response's InResponseTo. An unsolicited
-- (IdP-initiated) or replayed response has no consumable pending row and is rejected.
CREATE TABLE IF NOT EXISTS saml_pending_requests (
    request_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_saml_pending_requests_expires ON saml_pending_requests(expires_at);

-- Replay guard for production SAML logins. ACS records each accepted assertion's signed ID
-- (per tenant) on first sight; a repeat presentation within its validity window is rejected.
-- The key is (tenant_id, assertion_id): each tenant has exactly one IdP (tenant_saml_config is
-- keyed by org_id), so idp_entity_id is recorded for audit but is intentionally not part of the key.
CREATE TABLE IF NOT EXISTS saml_consumed_assertions (
    tenant_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    assertion_id  TEXT NOT NULL,
    idp_entity_id TEXT,
    consumed_at   TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    PRIMARY KEY (tenant_id, assertion_id)
);
CREATE INDEX IF NOT EXISTS idx_saml_consumed_assertions_expires ON saml_consumed_assertions(expires_at);

-- IdP-issued identities linked to local users. Identity is (idp_entity_id, nameid) -- not
-- email. Email can change in the IdP without breaking login; cross-IdP collisions on the
-- same email are impossible.
CREATE TABLE IF NOT EXISTS external_identities (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_entity_id   TEXT NOT NULL,
    nameid          TEXT NOT NULL,
    email_snapshot  TEXT,
    created_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    last_login_at   TEXT,
    UNIQUE (org_id, idp_entity_id, nameid)
);
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id);

-- ── Multitenant architecture ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS claim (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('unclaimed','local_only','mixed')),
    reason      TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    updated_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    deleted_at  TEXT,
    UNIQUE (org_id, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_claim_org_state ON claim (org_id, state);

CREATE TABLE IF NOT EXISTS claim_history (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    claim_id        TEXT NOT NULL REFERENCES claim(id) ON DELETE CASCADE,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    prior_state     TEXT,
    new_state       TEXT NOT NULL,
    reason          TEXT NOT NULL,
    purged_count    INTEGER NOT NULL DEFAULT 0,
    actor_id        TEXT REFERENCES users(id),
    occurred_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);
CREATE INDEX IF NOT EXISTS idx_claim_history_org_time ON claim_history (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_claim_history_claim ON claim_history (claim_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS cache_artifact (
    id                  TEXT PRIMARY KEY,
    ecosystem           TEXT NOT NULL,
    name                TEXT NOT NULL,
    version             TEXT NOT NULL,
    filename            TEXT NOT NULL,
    blob_key            TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    size_bytes          BIGINT NOT NULL DEFAULT 0,
    upstream_url        TEXT,
    upstream_etag       TEXT,
    first_cached_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    last_accessed_at    TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (ecosystem, name, version, filename)
);
CREATE INDEX IF NOT EXISTS idx_cache_artifact_lru ON cache_artifact (last_accessed_at);

CREATE TABLE IF NOT EXISTS tenant_artifact_access (
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cache_artifact_id   TEXT NOT NULL REFERENCES cache_artifact(id) ON DELETE CASCADE,
    first_accessed_at   TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    last_accessed_at    TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    access_count        BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (org_id, cache_artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_artifact_access_artifact
    ON tenant_artifact_access (cache_artifact_id);

CREATE TABLE IF NOT EXISTS metadata_cache (
    id              TEXT PRIMARY KEY,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    document        TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    upstream_etag   TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    expires_at      TEXT NOT NULL,
    UNIQUE (ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_metadata_cache_expires ON metadata_cache (expires_at);

CREATE TABLE IF NOT EXISTS audit_event (
    event_id            TEXT PRIMARY KEY,
    schema_version      INTEGER NOT NULL DEFAULT 1,
    event_type          TEXT NOT NULL,
    org_id              TEXT REFERENCES orgs(id) ON DELETE SET NULL,
    tenant_resolver     TEXT NOT NULL,
    actor_type          TEXT NOT NULL CHECK (actor_type IN ('user','api_token','system')),
    actor_id            TEXT,
    request_id          TEXT,
    source_ip           TEXT,
    user_agent          TEXT,
    outcome             TEXT NOT NULL CHECK (outcome IN ('accepted','rejected','error')),
    payload             TEXT NOT NULL,
    occurred_at         TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_time ON audit_event (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_type ON audit_event (org_id, event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor ON audit_event (org_id, actor_id, occurred_at DESC);

-- Per-tenant registry bucket binding. See Schema.sql for the full semantics.
CREATE TABLE IF NOT EXISTS tenant_storage (
    org_id                      TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    registry_bucket             TEXT,
    registry_region             TEXT,
    registry_endpoint           TEXT,
    registry_force_path_style   INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-- Async provisioning state machine. See Schema.sql for the full semantics.
CREATE TABLE IF NOT EXISTS tenant_provisioning_jobs (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'creating'
                    CHECK (state IN ('creating','ready','failed')),
    idempotency_key TEXT,
    last_error      TEXT,
    started_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    completed_at    TEXT,
    UNIQUE (org_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_tenant_provisioning_jobs_org ON tenant_provisioning_jobs(org_id, kind);

-- Per-run history for IHostedService background workers. See Schema.sql for full semantics.
CREATE TABLE IF NOT EXISTS background_job_runs (
    id              TEXT PRIMARY KEY,
    job_name        TEXT NOT NULL,
    operation       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    duration_ms     BIGINT NOT NULL,
    outcome         TEXT NOT NULL,
    error_message   TEXT
);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_started_at
    ON background_job_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_job_started
    ON background_job_runs(job_name, started_at DESC);

-- Content-addressed negative cache for upstream 404 responses.
-- Shared across tenants — the key is SHA-256(url)[..32] which is content-addressed.
-- TTL enforced at query time.
CREATE TABLE IF NOT EXISTS upstream_negative_cache (
    url_key     TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (url_key, ecosystem)
);

-- Pre-computed dashboard aggregates, one row per org. The /api/v1/stats endpoint
-- reads this snapshot instead of running the eight live aggregate queries in
-- PackageAnalyticsRepository.GetOrgStatsAsync on every page load; StatsRefreshService
-- recomputes it per org on a fixed interval. stats_json holds a serialized OrgStats.
CREATE TABLE IF NOT EXISTS org_stats_snapshot (
    org_id      TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    stats_json  TEXT NOT NULL,
    computed_at TEXT NOT NULL,
    duration_ms BIGINT NOT NULL DEFAULT 0
);

-- npm dist-tag registry. One row per (package, tag); tag names are freeform strings
-- npm sends on `npm publish --tag <tag>`. UNIQUE(package_id, tag) enforces one version
-- per tag per package. org_id is denormalized from packages so org_id-scoped queries
-- satisfy the OrgIdFiltering compliance gate without joining through packages.
CREATE TABLE IF NOT EXISTS npm_dist_tags (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    package_id  TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    version     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (package_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_npm_dist_tags_org ON npm_dist_tags(org_id, package_id);

-- Cargo sparse index metadata. One row per package_versions row carrying the full
-- newline-delimited JSON index line for that version. Tenant-scoped via JOIN to packages.org_id.
CREATE TABLE IF NOT EXISTS cargo_metadata (
    id          BIGSERIAL PRIMARY KEY,
    version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    index_line  TEXT NOT NULL,
    UNIQUE(version_id)
);
CREATE INDEX IF NOT EXISTS idx_cargo_metadata_version ON cargo_metadata(version_id);

-- NOTE: SchemaInitializer also runs ALTER TABLE statements for the columns above.
-- Those are no-ops on fresh installs (IF NOT EXISTS). They exist solely to add the
-- columns to databases created before those columns were included in the CREATE TABLE
-- blocks. Schema.pg.sql is the authoritative complete schema.
