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
    max_upload_bytes_maven  INTEGER,        -- #99 per-ecosystem Maven cap; falls back to max_upload_bytes
    max_upload_bytes_rpm    INTEGER,        -- #100 per-ecosystem RPM cap; falls back to max_upload_bytes
    max_upload_bytes_oci    INTEGER,        -- #101 per-ecosystem OCI (Docker) cap; falls back to max_upload_bytes
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
    maven_reserved_prefixes   TEXT    NOT NULL DEFAULT '[]' -- #101 dep-confusion guard; JSON array of groupId prefixes
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
    -- ISO 8601 UTC; first-publish timestamp from the public upstream registry. See Schema.sql.
    published_at TEXT,
    -- Hex SHA-1 of the artefact bytes (npm packument shasum). See Schema.sql.
    checksum_sha1 TEXT,
    -- Upstream-published integrity hash + algorithm tag. See Schema.sql.
    upstream_integrity_value TEXT,
    upstream_integrity_algorithm TEXT,
    -- Trailing path segment of blob_key. See Schema.sql for rationale (#91).
    filename    TEXT,
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
    published_at    TEXT,
    modified_at     TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
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

-- #100 RPM metadata. See Schema.sql for full rationale.
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

-- #99 Maven multi-file per-version tracker. See Schema.sql for full rationale.
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

-- #98 OCI / Docker registry storage. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS oci_blobs (
    digest        TEXT NOT NULL,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    media_type    TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    blob_key      TEXT NOT NULL,
    cached_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    upstream_checked_at TEXT,
    origin        TEXT NOT NULL DEFAULT 'uploaded',  -- #103 'uploaded' (local push) or 'proxy' (upstream cache)
    PRIMARY KEY (digest, org_id)
);
CREATE INDEX IF NOT EXISTS idx_oci_blobs_org ON oci_blobs(org_id);

CREATE TABLE IF NOT EXISTS oci_tags (
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    digest      TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    last_revalidated TEXT,  -- #103 per-tag TTL revalidation timestamp; NULL forces a re-check on first access
    PRIMARY KEY (org_id, repository, tag)
);
CREATE INDEX IF NOT EXISTS idx_oci_tags_repository ON oci_tags(org_id, repository);

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

-- ── Multitenant architecture (#43-#54) ─────────────────────────────────────────

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

-- Content-addressed negative cache for upstream 404 responses (#101, #102, #103).
-- Shared across tenants — the key is SHA-256(url)[..32] which is content-addressed.
-- TTL enforced at query time.
CREATE TABLE IF NOT EXISTS upstream_negative_cache (
    url_key     TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (url_key, ecosystem)
);

-- NOTE: SchemaInitializer also runs ALTER TABLE statements for the columns above.
-- Those are no-ops on fresh installs (IF NOT EXISTS). They exist solely to add the
-- columns to databases created before those columns were included in the CREATE TABLE
-- blocks. Schema.pg.sql is the authoritative complete schema.
