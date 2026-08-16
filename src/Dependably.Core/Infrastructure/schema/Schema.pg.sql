-- Dependably database schema (PostgreSQL)
-- Applied on first boot via SchemaInitializer
--
-- Every temporal TEXT column below carries a CHECK accepting exactly the three canonical
-- UtcTimestamp shapes (second/millisecond/microsecond precision, always UTC 'Z') and NULL —
-- see TemporalCheckPredicate.ForPostgres. Fresh installs get it here, from CREATE TABLE.
--
-- An existing Postgres database is brought up to the same constraint on every boot by
-- SchemaInitializer.TemporalCheckRetrofit.cs: per column, ADD CONSTRAINT ... NOT VALID under
-- the <table>_<column>_check name Postgres itself assigns the inline CHECK below, then
-- VALIDATE CONSTRAINT, each validation caught on its own so one unfixable legacy row leaves
-- that single column NOT VALID rather than wedging the boot or costing the other columns
-- their constraints. The retrofit derives its column set from the CHECK text in this file, so
-- a temporal column added to a CREATE TABLE block below is retrofitted with no new migration
-- code. SQLite is never retrofitted at all (see Schema.sql).
--
-- That retrofit carries a release-sequencing precondition nothing in the code can enforce: a
-- NOT VALID constraint still rejects NEW writes, including those the OLD binary makes while
-- both slots serve one database during a blue-green cutover. It is only safe in a release
-- whose immediate predecessor already writes canonical shapes on every path — notably
-- package_versions.published_at, packages.upstream_latest_published_at, and
-- cache_artifact.published_at, all written on hosted publish or proxy first-fetch.
--
-- Every temporal column that participates in a CREATE INDEX below — as an indexed key column,
-- or referenced in a partial index's WHERE predicate — additionally declares COLLATE "C" on
-- fresh installs: byte-exact ordering (SQLite's default TEXT collation is already byte order,
-- so it needs no equivalent — see Schema.sql), and immunity to glibc collation-version drift,
-- which has previously invalidated every btree index on a text column under the affected
-- collation and required a REINDEX. This is NOT applied in place to an existing database:
-- ALTER COLUMN ... TYPE text COLLATE "C" rewrites the table and every index on it under
-- ACCESS EXCLUSIVE — the same boot-stall hazard removed from the timestamp normalization
-- sweep — so it is an operator-run, maintenance-window change instead; see
-- docs/postgres-collate-migration.md for the copy-pasteable SQL.

CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    deleted_at  TEXT
        CHECK (deleted_at IS NULL OR deleted_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
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
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
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
    max_upload_bytes_cargo  INTEGER,        -- per-ecosystem Cargo cap; falls back to max_upload_bytes
    keep_versions       INTEGER,            -- GC: max versions to retain per package per ecosystem
    keep_days           INTEGER,            -- GC: evict proxy blobs unused for this many days
    activity_retention_days INTEGER DEFAULT 90,  -- GC: delete activity rows older than this; NULL resolves to the ACTIVITY_RETENTION_DAYS instance default (90) so activity is bounded by default
    purge_unlisted_after_days INTEGER,      -- GC: hard-delete uploaded versions unlisted longer than this (opt-in; NULL = off)
    license_enforcement_mode  TEXT    NOT NULL DEFAULT 'off',
    -- Publish-side licence gate, independent of license_enforcement_mode. See Schema.sql for
    -- the full rationale.
    license_publish_enforcement_mode TEXT NOT NULL DEFAULT 'off'
                              CHECK (license_publish_enforcement_mode IN ('off','warn','block')),
    proxy_passthrough_enabled INTEGER NOT NULL DEFAULT 1,
    max_osv_score_tolerance   REAL    NOT NULL DEFAULT 10.0,
    -- Supply-chain hold: minimum upstream-release age (hours) before a proxy-fetched version
    -- clears the block gate. NULL = policy off. The gate is re-evaluated on every serve and
    -- index render; held versions serve again automatically once they age past the threshold.
    -- See Schema.sql for the full rationale.
    min_release_age_hours     INTEGER,
    default_language          TEXT    NOT NULL DEFAULT 'en',
    -- IANA zone name used to render stored instants for users who have not chosen one.
    -- Display only: every instant is stored in UTC regardless of this setting.
    default_timezone          TEXT    NOT NULL DEFAULT 'UTC',
    allow_version_overwrite   INTEGER NOT NULL DEFAULT 0,   -- legacy boolean; kept for blue-green safety; see version_overwrite_policy
    -- Tri-state same-version-push policy. See Schema.sql for the full rationale.
    version_overwrite_policy  TEXT    NOT NULL DEFAULT 'block'
                              CHECK (version_overwrite_policy IN ('block','exception','allow')),
    maven_reserved_prefixes   TEXT    NOT NULL DEFAULT '[]', -- dep-confusion guard; JSON array of groupId prefixes
    -- Per-tenant air-gap posture; forces proxy passthrough off and skips the vuln/deprecation
    -- scan passes for this org. Composes with the instance AIR_GAPPED env var. See Schema.sql.
    air_gapped                INTEGER NOT NULL DEFAULT 0,
    -- Per-tenant MFA enrollment requirement. When 1, all authenticated users in this
    -- org must complete MFA enrollment before accessing any API endpoints. Composes with
    -- the instance REQUIRE_MFA env var: effective requirement = instance OR tenant. See Schema.sql.
    require_mfa               INTEGER NOT NULL DEFAULT 0,
    -- Policy for upstream-deprecated/abandoned packages. See Schema.sql for the full rationale.
    block_deprecated          TEXT    NOT NULL DEFAULT 'off' CHECK (block_deprecated IN ('off', 'warn', 'block_new', 'block_all')),
    -- Upstream-removal (revocation) gate. Three values; defaults to 'warn'. See Schema.sql.
    block_revoked             TEXT    NOT NULL DEFAULT 'warn' CHECK (block_revoked IN ('off', 'warn', 'block')),
    -- Policy for versions carrying a malicious-package advisory (OSV MAL- ids). See Schema.sql.
    block_malicious           TEXT    NOT NULL DEFAULT 'block' CHECK (block_malicious IN ('off', 'warn', 'block')),
    -- Policy for CISA-KEV-listed (exploited-in-the-wild) advisories. See Schema.sql.
    block_kev                 TEXT    NOT NULL DEFAULT 'off' CHECK (block_kev IN ('off', 'warn', 'block')),
    -- EPSS exploitation-probability ceiling (0.0–1.0); NULL = policy off. See Schema.sql.
    max_epss_tolerance        REAL,
    -- Install/lifecycle-script proxy gate: 'off' (default) / 'warn' / 'block'. See Schema.sql.
    block_install_scripts     TEXT    NOT NULL DEFAULT 'off' CHECK (block_install_scripts IN ('off', 'warn', 'block')),
    -- npm proxy-origin signature-verification gate: 'off' (default) / 'warn' / 'block'. See Schema.sql.
    verify_npm_signatures     TEXT    NOT NULL DEFAULT 'off' CHECK (verify_npm_signatures IN ('off', 'warn', 'block')),
    -- NuGet proxy-origin .nupkg signature-verification gate: 'off' (default) / 'warn' / 'block'. See Schema.sql.
    verify_nuget_signatures   TEXT    NOT NULL DEFAULT 'off' CHECK (verify_nuget_signatures IN ('off', 'warn', 'block')),
    -- PyPI proxy-origin PEP 740 attestation-verification gate: 'off' (default) / 'warn' / 'block'. See Schema.sql.
    verify_pypi_attestations  TEXT    NOT NULL DEFAULT 'off' CHECK (verify_pypi_attestations IN ('off', 'warn', 'block')),
    -- RPM proxy-origin per-package GPG header signature-verification gate: 'off' (default) / 'warn' / 'block'. See Schema.sql.
    verify_rpm_signatures     TEXT    NOT NULL DEFAULT 'off' CHECK (verify_rpm_signatures IN ('off', 'warn', 'block')),
    -- Maven proxy-origin detached .asc OpenPGP signature-verification gate: 'off' (default) / 'warn' / 'block'. See Schema.sql.
    verify_maven_signatures   TEXT    NOT NULL DEFAULT 'off' CHECK (verify_maven_signatures IN ('off', 'warn', 'block')),
    -- Terraform proxy-origin publisher-signed SHASUMS chain verification gate: 'off' (default) /
    -- 'warn' / 'block'. See Schema.sql.
    verify_terraform_signatures TEXT  NOT NULL DEFAULT 'off' CHECK (verify_terraform_signatures IN ('off', 'warn', 'block')),
    -- Dormant hosted-bytes counter, retained for one release of blue-green compatibility with the
    -- preceding release, which still increments it. Nothing in this release reads or writes it.
    -- See Schema.sql.
    storage_used_bytes        BIGINT  NOT NULL DEFAULT 0,
    -- Per-tenant RPM hosted-publishing posture override. NULL (default) inherits the instance
    -- Rpm:UpstreamMode env value; an explicit value overrides the env value in EITHER direction.
    -- See Schema.sql.
    rpm_upstream_mode         TEXT    CHECK (rpm_upstream_mode IS NULL OR rpm_upstream_mode IN ('passthrough','merged'))
);

CREATE TABLE IF NOT EXISTS instance_settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

-- DataProtection key ring, persisted for durable encryption across restarts.
-- Instance-global: not tenant-scoped (mirrors instance_settings). One row per
-- key element; the ring is cached in-memory by KeyRingProvider and written here
-- only when a new key is generated or an existing key is refreshed.
CREATE TABLE IF NOT EXISTS data_protection_keys (
    friendly_name TEXT PRIMARY KEY,
    xml           TEXT NOT NULL
);

-- Emails are stored canonically (trimmed, lowercased) by every writer, which is what makes the
-- byte-exact UNIQUE below agree with the case-folded lookups (lower(email) = lower(@email)) that
-- every account resolution uses. The matching case-insensitive unique index
-- (idx_users_tenant_email_ci) is created by SchemaInitializer rather than declared here: a
-- database that already holds two rows differing only in case cannot take it, and that has to be
-- reported and retried on a later boot rather than abort the schema apply.
-- personal-data: included — the subject's own account row (email, role, login history)
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner','auditor')),
    account_type TEXT NOT NULL DEFAULT 'forms' CHECK (account_type IN ('forms','saml')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT
        CHECK (last_login_at IS NULL OR last_login_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    password_reset_issued_at TEXT
        CHECK (password_reset_issued_at IS NULL OR password_reset_issued_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    language    TEXT,
    timezone    TEXT,  -- IANA zone name; NULL = inherit the org/instance default
    -- Monotonic session-invalidation counter. Embedded in tenant JWTs as the `tver` claim
    -- and bumped on password change so outstanding sessions go stale immediately.
    token_version INTEGER NOT NULL DEFAULT 1,
    -- MFA fields used by the ASP.NET Core Identity UserStore. mfa_authenticator_key holds
    -- the AES-GCM-encrypted TOTP key; mfa_recovery_codes holds a JSON array of SHA-256
    -- hashes of the one-time recovery codes; security_stamp is a random value rotated on
    -- every credential change so UserManager can detect concurrent mutations.
    mfa_authenticator_key TEXT,
    mfa_recovery_codes TEXT,
    security_stamp TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (tenant_id, email)
);

-- personal-data: excluded — operator-plane identity with no tenant_id; the tenant self-service export serves tenant data subjects only
CREATE TABLE IF NOT EXISTS system_admins (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT
        CHECK (last_login_at IS NULL OR last_login_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    password_reset_issued_at TEXT
        CHECK (password_reset_issued_at IS NULL OR password_reset_issued_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    language    TEXT,
    timezone    TEXT,  -- IANA zone name; NULL = inherit the org/instance default
    -- MFA fields used by the ASP.NET Core Identity UserStore. Mirrors the same set on users.
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_authenticator_key TEXT,
    mfa_recovery_codes TEXT,
    security_stamp TEXT,
    -- Monotonic session-invalidation counter. Mirrors users.token_version; system JWTs
    -- embed this as the `tver` claim and are rejected when the stored version advances.
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

CREATE TABLE IF NOT EXISTS packages (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,   -- 'pypi' | 'npm' | 'nuget' | 'maven' | 'rpm' | 'oci' | 'cargo' | 'golang' | 'apk'
    name        TEXT NOT NULL,
    purl_name   TEXT NOT NULL,   -- normalized per ecosystem
    is_proxy    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Upstream's declared latest version (npm dist-tags.latest / PyPI info.version), refreshed by
    -- the background upstream-metadata pass. NULL when no upstream baseline is known.
    upstream_latest_version    TEXT,
    upstream_latest_checked_at TEXT
        CHECK (upstream_latest_checked_at IS NULL OR upstream_latest_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Publish timestamp of upstream_latest_version. See Schema.sql for the full rationale.
    upstream_latest_published_at TEXT
        CHECK (upstream_latest_published_at IS NULL OR upstream_latest_published_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Per-package same-version-push override. NULL = inherit. See Schema.sql for the full rationale.
    same_version_push_override TEXT
                               CHECK (same_version_push_override IN ('allow','block')),
    -- Package-level metadata surfaced in the UI. See Schema.sql for the full rationale.
    homepage       TEXT,
    repository_url TEXT,
    description    TEXT,
    UNIQUE (org_id, ecosystem, purl_name)
);

CREATE TABLE IF NOT EXISTS package_versions (
    id          TEXT PRIMARY KEY,
    package_id  TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    version     TEXT NOT NULL,
    purl        TEXT NOT NULL,
    blob_key    TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    checksum_sha256 TEXT,
    yanked      INTEGER NOT NULL DEFAULT 0,
    yank_reason TEXT,
    -- ISO 8601 UTC; stamped when yanked is set to 1, cleared to NULL on un-yank. NULL for
    -- never-yanked rows and for legacy rows pre-dating the column. Drives the org
    -- purge_unlisted_after_days retention gate — a NULL yanked_at is never age-purgeable.
    yanked_at   TEXT
        CHECK (yanked_at IS NULL OR yanked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    first_fetch INTEGER NOT NULL DEFAULT 0,  -- 1 if this was a cache-miss proxy fetch
    last_used   TEXT    -- ISO 8601 UTC; updated on each download
        CHECK (last_used IS NULL OR last_used ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Cumulative count of served downloads (download + first_fetch events). See Schema.sql.
    download_count BIGINT NOT NULL DEFAULT 0,
    vuln_checked_at TEXT    -- ISO 8601 UTC; set after OSV vulnerability scan
        CHECK (vuln_checked_at IS NULL OR vuln_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    manual_block_state TEXT,     -- NULL = follow auto policy, 'blocked' = manual block, 'allowed' = manual override of auto-block
    deprecated  TEXT,            -- NULL = not deprecated; otherwise upstream deprecation message (npm/NuGet)
    -- origin tracking: 'proxy' = upstream cache; 'uploaded' = user-pushed file (admin
    -- /admin/upload or protocol push). Existing databases that pre-date this column get it
    -- via an additive ALTER TABLE in SchemaInitializer, and legacy 'imported'/'private'
    -- rows are collapsed to 'uploaded' by the collapse_origin_to_uploaded one-shot migration.
    origin      TEXT NOT NULL DEFAULT 'proxy',
    -- ISO 8601 UTC; first-publish timestamp from the public upstream registry. See Schema.sql.
    published_at TEXT
        CHECK (published_at IS NULL OR published_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Hex SHA-1 of the artefact bytes (npm packument shasum). See Schema.sql.
    checksum_sha1 TEXT,
    -- Upstream-published integrity hash + algorithm tag. See Schema.sql.
    upstream_integrity_value TEXT,
    upstream_integrity_algorithm TEXT,
    -- Trailing path segment of blob_key. See Schema.sql for rationale.
    filename    TEXT,
    -- ISO 8601 UTC; set after the last upstream deprecation metadata refresh. See Schema.sql.
    deprecation_checked_at TEXT
        CHECK (deprecation_checked_at IS NULL OR deprecation_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- ISO 8601 UTC; first time this version was observed removed from upstream. See Schema.sql.
    revoked_at TEXT
        CHECK (revoked_at IS NULL OR revoked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Operational-risk signal: count of upstream STABLE versions strictly newer than this one.
    -- NULL = unknown, never 0. See Schema.sql for the full rationale.
    versions_behind INTEGER,
    -- Install/lifecycle-script supply-chain signal + kind discriminator. See Schema.sql.
    has_install_script INTEGER NOT NULL DEFAULT 0,
    install_script_kind TEXT,
    -- Provenance/signature-verification outcome + verifying signer keyid. See Schema.sql.
    provenance_status TEXT,
    provenance_signer TEXT,
    -- Install-relevant manifest subset captured at hosted npm publish. See Schema.sql.
    manifest_json TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- ISO 8601 UTC; stamped when a same-version re-push overwrites this row's bytes.
    -- NULL means never overwritten, in which case the effective pushed date is created_at.
    updated_at  TEXT
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (package_id, version)
);

-- personal-data: included — the subject's personal access tokens
CREATE TABLE IF NOT EXISTS user_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings.
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at  TEXT
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_used_at TEXT    -- updated (throttled ~60s) when the token authenticates a request.
        CHECK (last_used_at IS NULL OR last_used_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

CREATE TABLE IF NOT EXISTS service_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at  TEXT
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_used_at TEXT    -- updated (throttled ~60s) when the token authenticates a request.
        CHECK (last_used_at IS NULL OR last_used_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

-- personal-data: included — invites the subject created, and invites addressed to their email
CREATE TABLE IF NOT EXISTS invites (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner','auditor')),
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    accepted_at TEXT COLLATE "C"
        CHECK (accepted_at IS NULL OR accepted_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_unique_pending
    ON invites (org_id, email) WHERE accepted_at IS NULL;

-- Self-serve "forgot password" reset links. Distinct from users.password_reset_issued_at, which
-- backs the operator-issued temporary-password support flow (SystemAdminRepository) and carries
-- no token of its own.
-- personal-data: included — the subject's self-serve reset links
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    consumed_at TEXT COLLATE "C"
        CHECK (consumed_at IS NULL OR consumed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_prt_user_pending ON password_reset_tokens(user_id) WHERE consumed_at IS NULL;

-- Self-service email rectification (GDPR Art. 16). Structurally a sibling of
-- password_reset_tokens, with one deliberate difference: the pending NEW address lives on the
-- token row rather than on users, so the account keeps its current, already-verified address
-- until the link mailed to the new one is redeemed. An unredeemed or expired request therefore
-- changes nothing — a mistyped address cannot lock a user out of their own account, and someone
-- who gets a session cannot silently repoint the account's recovery mailbox.
-- personal-data: included — the subject's pending email rectifications, including the new address
CREATE TABLE IF NOT EXISTS email_change_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- The address being moved to, lowercased. Verified only when the token is consumed; the
    -- UNIQUE (tenant_id, email) constraint on users is what finally arbitrates a collision.
    new_email   TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    consumed_at TEXT COLLATE "C"
        CHECK (consumed_at IS NULL OR consumed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_ect_user_pending ON email_change_tokens(user_id) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    purl_pattern TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, purl_pattern)
);

-- personal-data: included — security/config rows attributed to the subject (source_ip history)
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','system')),
    -- No FK to orgs: rows are retained for forensic purposes after an org is deleted.
    org_id      TEXT,
    actor_id    TEXT,
    actor_kind  TEXT,
    -- Actor display name, denormalized at write time so a forensic row stays readable after the
    -- row it would otherwise join to is gone. Written for service actors only: service_tokens is
    -- hard-deleted on revocation, so the join that resolves 'service:<name>' stops matching and
    -- the row would read as anonymous. A user actor deliberately gets none -- the erasure and
    -- retention sweeps null a fixed column list, so an email here would be personal data at rest
    -- that neither sweep reaches. Nullable: rows predating it, and rows written by a preceding
    -- release during a blue-green cutover, resolve through the existing joins instead.
    actor_label TEXT,
    action      TEXT NOT NULL,
    ecosystem   TEXT,
    purl        TEXT,
    detail      TEXT,
    source_ip   TEXT,
    -- Millisecond precision, matching AuditRepository's NowMs() writer: SIEM's since/until window
    -- and pagination cursor (ListAuthEventsAsync) compare this column at millisecond precision,
    -- so a second-precision DEFAULT-written row would silently fall outside every future window.
    created_at  TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_audit_log_scope ON audit_log(scope, created_at DESC);
-- Retention sweep index: RetentionService pseudonymizes then deletes rows by created_at age
-- across every scope, so the sweep needs a scope-independent index on the age column.
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- personal-data: included — activity-feed rows attributed to the subject (source_ip history)
CREATE TABLE IF NOT EXISTS activity (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    purl        TEXT,
    event_type  TEXT NOT NULL,
    actor_id    TEXT,
    actor_kind  TEXT,
    -- see audit_log.actor_label; service actors only, NULL for users
    actor_label TEXT,
    detail      TEXT,
    source_ip   TEXT,
    -- Millisecond precision, matching AuditRepository.LogActivityAsync's NowMs() writer: the
    -- activity feed's since window (OrgAuditController) compares this column at millisecond
    -- precision.
    created_at  TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              TEXT PRIMARY KEY,
    osv_id          TEXT NOT NULL UNIQUE,
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    aliases         TEXT,           -- JSON array of alias IDs
    summary         TEXT,
    severity        TEXT            -- NULL when the advisory carries no CVSS severity classification
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    cvss_score      REAL,
    affected_versions TEXT,         -- JSON array of version strings
    osv_json        TEXT,           -- full OSV advisory JSON; source of truth for the rich detail panel
    published_at    TEXT
        CHECK (published_at IS NULL OR published_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    modified_at     TEXT
        CHECK (modified_at IS NULL OR modified_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    fetched_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (fetched_at IS NULL OR fetched_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Threat-feed enrichment (CISA KEV membership + FIRST.org EPSS score). See Schema.sql.
    is_kev          INTEGER NOT NULL DEFAULT 0,
    kev_checked_at  TEXT
        CHECK (kev_checked_at IS NULL OR kev_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    epss_score      REAL,
    epss_checked_at TEXT
        CHECK (epss_checked_at IS NULL OR epss_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

-- Global shared proxy-cache index. See Schema.sql for the full rationale.
-- purl is the canonical package identity for cross-ecosystem lookups; no UNIQUE constraint
-- because Maven maps one purl to many filenames (jar + pom + sources + javadoc sidecars).
-- Supply-chain columns are reserved capacity in community. See community/enterprise boundary rule.
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
    first_cached_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (first_cached_at IS NULL OR first_cached_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_accessed_at    TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (last_accessed_at IS NULL OR last_accessed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Canonical PURL for this artifact. No UNIQUE: Maven maps one purl to many filenames.
    purl                TEXT,
    -- Hex SHA-1 of the artifact bytes (npm packument shasum field uses SHA-1 by spec).
    checksum_sha1       TEXT,
    -- ISO 8601 UTC; upstream first-publish timestamp captured at ingest. NULL when unavailable.
    published_at        TEXT
        CHECK (published_at IS NULL OR published_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Upstream deprecation message when set; NULL when not deprecated.
    deprecated          TEXT,
    -- ISO 8601 UTC; last time the deprecation state was refreshed from upstream.
    deprecation_checked_at TEXT
        CHECK (deprecation_checked_at IS NULL OR deprecation_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- ISO 8601 UTC; first time this version was observed removed from upstream. See Schema.sql.
    revoked_at          TEXT
        CHECK (revoked_at IS NULL OR revoked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Operational-risk signal: count of upstream STABLE versions strictly newer than this one.
    -- NULL = unknown, never 0. See Schema.sql for the full rationale.
    versions_behind     INTEGER,
    -- Supply-chain signal: 1 when the artifact ships an install/lifecycle script.
    has_install_script  INTEGER NOT NULL DEFAULT 0,
    -- Discriminator for which kind of install script fired (e.g. 'npm:postinstall').
    install_script_kind TEXT,
    -- Provenance/signature-verification outcome at ingest: 'verified', 'failed', 'unsigned', or NULL.
    provenance_status   TEXT,
    -- Trust-anchor keyid when provenance_status is 'verified'. NULL otherwise.
    provenance_signer   TEXT,
    -- Upstream-published integrity hash in native encoding (see package_versions for encoding notes).
    upstream_integrity_value TEXT,
    -- Algorithm tag for upstream_integrity_value: 'sha256' | 'sha512-sri' | 'sha512-b64'.
    upstream_integrity_algorithm TEXT,
    -- ISO 8601 UTC; set after the last OSV vulnerability scan against this artifact.
    vuln_checked_at     TEXT
        CHECK (vuln_checked_at IS NULL OR vuln_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- ISO 8601 UTC; set after the last license-extraction pass against this artifact. NULL =
    -- never scanned for licenses. Stamped by LicenseBackfillService. See Schema.sql.
    license_checked_at  TEXT
        CHECK (license_checked_at IS NULL OR license_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- JSON install-manifest subset (dependencies/optionalDependencies/bin/engines). See Schema.sql.
    manifest_json       TEXT,
    UNIQUE (ecosystem, name, version, filename)
);
CREATE INDEX IF NOT EXISTS idx_cache_artifact_lru ON cache_artifact (last_accessed_at);
CREATE INDEX IF NOT EXISTS idx_cache_artifact_purl ON cache_artifact (purl);

-- Per-tenant access tracking on the shared cache. See Schema.sql for the full rationale.
-- Per-tenant policy state columns are reserved capacity in community.
CREATE TABLE IF NOT EXISTS tenant_artifact_access (
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cache_artifact_id   TEXT NOT NULL REFERENCES cache_artifact(id) ON DELETE CASCADE,
    first_accessed_at   TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (first_accessed_at IS NULL OR first_accessed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_accessed_at    TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (last_accessed_at IS NULL OR last_accessed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    access_count        BIGINT NOT NULL DEFAULT 1,
    -- Per-tenant manual policy override: NULL = follow auto policy, 'blocked' = manual block,
    -- 'allowed' = manual override of auto-block. Mirrors package_versions.manual_block_state.
    manual_block_state  TEXT,
    -- Per-tenant yank: 1 when an operator has yanked this artifact for this tenant.
    yanked              INTEGER NOT NULL DEFAULT 0,
    -- Optional reason recorded when yanked = 1.
    yank_reason         TEXT,
    -- ISO 8601 UTC; most recent time any user in this tenant downloaded this artifact.
    last_used           TEXT
        CHECK (last_used IS NULL OR last_used ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Cumulative download count for this tenant. Monotonic; survives activity-log pruning.
    download_count      BIGINT NOT NULL DEFAULT 0,
    -- Tenant content binding: the artifact bytes THIS tenant fetched for the coordinate. See
    -- Schema.sql for the full rationale. The three are bound independently and a NULL falls back
    -- to the shared cache_artifact value for that field alone.
    content_hash        TEXT,
    blob_key            TEXT,
    size_bytes          BIGINT,
    PRIMARY KEY (org_id, cache_artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_artifact_access_artifact
    ON tenant_artifact_access (cache_artifact_id);
-- idx_tenant_artifact_access_blob_key covers the tenant half of the shared-blob refcount
-- CacheOrphanBlobDeleter takes before every physical delete; without it each eviction scans the
-- whole table, and evictions run in a loop. It is NOT declared here. blob_key reaches an existing
-- database through RunAdditiveMigrationsAsync, which runs AFTER this whole file, so a CREATE INDEX
-- naming it here resolves against the old table shape on every upgrade boot: Postgres raises
-- 42703 and crash-loops, and SQLite silently truncates the rest of this file, never creating the
-- tables declared below. The index is created next to that ALTER instead, in
-- SchemaInitializer.RunAdditiveMigrationsAsync, which covers fresh installs too because that pass
-- runs unconditionally. Declaring it here becomes safe only once a shipped release has the column
-- in this CREATE TABLE block, which is what SchemaSyncComplianceTests checks.

CREATE TABLE IF NOT EXISTS package_version_vulns (
    -- Surrogate PK so cache_artifact-owned rows can exist without a package_versions FK.
    id                  TEXT PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    checked_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (checked_at IS NULL OR checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Polymorphic metadata owner: NULL for the package_version arm; set to the
    -- cache_artifact row for proxy-origin metadata. owner_kind discriminates which FK
    -- is authoritative.
    cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
    owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                        CHECK (owner_kind IN ('package_version','cache_artifact')),
    -- Owner invariant: exactly one FK arm is active and matches owner_kind.
    CHECK (
        (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
        OR
        (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
    )
);
-- Partial unique indexes enforce per-arm dedup without a composite PK.
CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_pv_vuln
    ON package_version_vulns (package_version_id, vuln_id)
    WHERE owner_kind = 'package_version';
CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_ca_vuln
    ON package_version_vulns (cache_artifact_id, vuln_id)
    WHERE owner_kind = 'cache_artifact';
CREATE INDEX IF NOT EXISTS idx_package_version_vulns_cache_artifact
    ON package_version_vulns (cache_artifact_id);

-- Indexes for common query patterns
-- Tenant-scoped lockout throttle: keyed by LoginService.HashLockoutKey(realm, tenantId, email), a
-- SHA-256 pseudonym that folds the realm and tenant into the hash, so a tenant login and a
-- system-admin login for the same address track independent failure counters, and one tenant's
-- lockout state is never observable from another tenant.
-- personal-data: included — the subject's failed-login / lockout throttle row (pseudonymized key)
CREATE TABLE IF NOT EXISTS login_attempts (
    email_hash  TEXT PRIMARY KEY,   -- LoginService.HashLockoutKey(realm, tenantId, email): pseudonymized, not anonymous (a candidate address is confirmable). RetentionService prunes idle rows.
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT    -- ISO 8601 UTC; NULL = not locked
        CHECK (locked_until IS NULL OR locked_until ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_attempt TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (last_attempt IS NULL OR last_attempt ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

-- Per-account send throttle for account-targeted transactional mail (password reset today).
-- Keyed on the same (realm, tenant, email) pseudonym as login_attempts.email_hash, so the bucket
-- follows the TARGET account rather than the source IP: a distributed attacker spread over many
-- /64s still shares one bucket per account. Complements — never replaces — the per-IP limiter.
-- The row exists for every requested address, matched or not, so the write path is uniform and
-- introduces no timing divergence an attacker could read as an account-existence oracle.
-- personal-data: included — the subject's per-account transactional-mail send budget (same pseudonymized key as login_attempts)
CREATE TABLE IF NOT EXISTS account_send_throttle (
    email_hash   TEXT NOT NULL,    -- LoginService.HashLockoutKey("tenant", orgId, email): pseudonymized, not anonymous. RetentionService prunes idle rows.
    purpose      TEXT NOT NULL,    -- which account-targeted send this bucket bounds, e.g. 'password_reset'
    window_start TEXT NOT NULL    -- ISO 8601 UTC; start of the current fixed window
        CHECK (window_start IS NULL OR window_start ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    send_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email_hash, purpose)
);

CREATE INDEX IF NOT EXISTS idx_packages_org_ecosystem ON packages(org_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_vulns_ecosystem_pkg ON vulnerabilities(ecosystem, package_name);
-- vuln_id FK index: cascade deletes on vulnerabilities scan the child table without this.
-- package_version_id and cache_artifact_id are covered by the partial unique indexes above.
CREATE INDEX IF NOT EXISTS idx_pkg_version_vulns_vuln ON package_version_vulns(vuln_id);
CREATE INDEX IF NOT EXISTS idx_package_versions_package ON package_versions(package_id);
CREATE INDEX IF NOT EXISTS idx_package_versions_filename ON package_versions(filename);
CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_org ON activity(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_tokens_hash ON user_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_service_tokens_hash ON service_tokens(token_hash);
-- FK-column indexes: Postgres does not auto-index foreign key columns; without these,
-- cascade deletes on the parent table cause full child-table scans. Indexes for tables
-- defined later in this file are placed adjacent to those tables below.
CREATE INDEX IF NOT EXISTS idx_user_tokens_org ON user_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_user_tokens_user ON user_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_service_tokens_org ON service_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by);

CREATE TABLE IF NOT EXISTS blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,  -- regex matched against the full package PURL
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, pattern)
);

-- Operator-reserved namespaces (dependency-confusion guard). A name matching a pattern for
-- its ecosystem never consults upstream — no metadata merge, no proxy fetch. Patterns are
-- exact names or trailing-`*` globs ('@acme/*', 'acme-*', 'Acme.*'); maven patterns use
-- dot-boundary prefix semantics ('com.acme' also covers 'com.acme.*' groupIds).
-- personal-data: excluded — created_by is an authorship stamp on org-owned namespace governance, not the subject's data
CREATE TABLE IF NOT EXISTS reserved_namespace (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,  -- 'npm' | 'pypi' | 'nuget' | 'maven' | 'cargo' | 'golang' | 'apk'
    pattern     TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, pattern)
);
CREATE INDEX IF NOT EXISTS idx_reserved_namespace_created_by ON reserved_namespace(created_by);

-- Review queue for policy-gate blocks. See Schema.sql for the full rationale.
-- personal-data: excluded — decided_by is a provenance stamp on an org-owned supply-chain decision
CREATE TABLE IF NOT EXISTS quarantine (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    ecosystem           TEXT NOT NULL,
    purl                TEXT NOT NULL,
    gate                TEXT NOT NULL,  -- 'deprecated' | 'revoked' | 'release_age' | 'malicious' | 'kev' | 'epss' | 'vuln_score'
    detail              TEXT,           -- same JSON the blocked_* activity row carries
    state               TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied')),
    decided_by          TEXT REFERENCES users(id),
    decided_at          TEXT
        CHECK (decided_at IS NULL OR decided_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    note                TEXT,           -- optional reviewer note recorded with the decision
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    updated_at          TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, purl)
);

CREATE INDEX IF NOT EXISTS idx_quarantine_org_state ON quarantine(org_id, state, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_version ON quarantine(package_version_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_decided_by ON quarantine(decided_by);

-- Per-tenant alert center. See Schema.sql for the full rationale.
CREATE TABLE IF NOT EXISTS alert (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    type         TEXT NOT NULL CHECK (type IN ('quarantine_new', 'vuln_severity')),
    severity     TEXT,
    source_ref   TEXT NOT NULL,
    ecosystem    TEXT,
    purl         TEXT,
    title        TEXT NOT NULL,
    detail       TEXT,
    state        TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'dismissed')),
    dismissed_by TEXT REFERENCES users(id),
    dismissed_at TEXT
        CHECK (dismissed_at IS NULL OR dismissed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    slack_status TEXT,
    slack_error  TEXT,
    email_status TEXT,
    email_error  TEXT,
    created_at   TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    updated_at   TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, type, source_ref)
);
CREATE INDEX IF NOT EXISTS idx_alert_org_state ON alert(org_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_dismissed_by ON alert(dismissed_by);

-- Per-org alert toggles, vuln severity floor, and optional Slack/email delivery channels. Slack
-- auto-disables on sustained failure; email does not, because it rides the instance-level SMTP
-- transport and its failures belong to the operator, not the tenant. email_inherit_instance and
-- email_smtp_* are retired and unread; they stay declared because releases still in the field read
-- all seven during a blue-green cutover, their stored values are scrubbed to the inherit-the-
-- instance-transport shape by the scrub_alert_settings_retired_smtp_transport migration, and they
-- are dropped once the minimum supported upgrade-from release no longer reads them. See Schema.sql
-- for the full rationale.
CREATE TABLE IF NOT EXISTS alert_settings (
    org_id                     TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    quarantine_alerts_enabled INTEGER NOT NULL DEFAULT 1,
    vuln_alerts_enabled       INTEGER NOT NULL DEFAULT 1,
    vuln_min_severity         TEXT NOT NULL DEFAULT 'HIGH' CHECK (vuln_min_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    slack_enabled              INTEGER NOT NULL DEFAULT 0,
    slack_webhook_url          TEXT,
    slack_last_delivery_at     TEXT
        CHECK (slack_last_delivery_at IS NULL OR slack_last_delivery_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    slack_last_status          TEXT,
    slack_consecutive_failures INTEGER NOT NULL DEFAULT 0,
    slack_failing_since        TEXT
        CHECK (slack_failing_since IS NULL OR slack_failing_since ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    slack_last_error           TEXT,
    email_enabled              INTEGER NOT NULL DEFAULT 0,
    email_inherit_instance     INTEGER NOT NULL DEFAULT 1,
    email_recipients           TEXT,
    email_smtp_host            TEXT,
    email_smtp_port            INTEGER,
    email_smtp_security        TEXT CHECK (email_smtp_security IS NULL OR email_smtp_security IN ('starttls', 'ssl', 'none')),
    email_smtp_username        TEXT,
    email_smtp_password        TEXT,
    email_smtp_from            TEXT,
    email_last_delivery_at     TEXT
        CHECK (email_last_delivery_at IS NULL OR email_last_delivery_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    email_last_status          TEXT,
    email_consecutive_failures INTEGER NOT NULL DEFAULT 0,
    email_failing_since        TEXT
        CHECK (email_failing_since IS NULL OR email_failing_since ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    email_last_error           TEXT,
    created_at                 TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    updated_at                 TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

-- Durable outbox for outbound alert mail. A row is persisted before any delivery attempt and
-- outlives the process, so an SMTP outage longer than one worker's retry budget — or than one
-- process lifetime — no longer loses the message. The guarantee the table exists to make is
-- narrow and exact: alert mail is durably persisted until it is delivered, or until an explicit
-- terminal retry/retention policy expires it. It is not "every message is eventually sent".
--
-- state is the lifecycle. 'pending' and 'sending' are the only non-terminal values; 'delivered',
-- 'dead_letter' and 'expired' are terminal and the delivery path never rewrites them.
-- 'dead_letter' means the message is bad (a permanent SMTP 5xx, an invalid recipient, a relay
-- host the SSRF guard refuses); 'expired' means it ran out of attempts or out of retention.
-- Keeping the two apart is what makes a backlog readable: a dead letter needs the message or the
-- configuration fixed, an expired row needs the relay fixed sooner.
--
-- org_id is NULLABLE on purpose. Alert mail is per-org, but operator-scope (system_admin) mail
-- has no tenant, so the column carries which plane a row belongs to instead of assuming one. A
-- NULL org_id row is operator mail and cascades with no tenant. Every row is written and read
-- through EmailOutboxRepository; the drain and sweep statements are cross-tenant by design and
-- carry their own xtenant markers.
--
-- coalesce_key is the natural burst-dedup key — the alert kind plus the package coordinate —
-- carried from the first release even though nothing groups on it yet. Backfilling it onto an
-- existing backlog would be a migration of every row, which is precisely what declaring it now
-- avoids. It is always grouped with org_id, never keyed on alone.
--
-- message_kind discriminates the terminal bookkeeping the delivery worker performs. 'alert'
-- writes the outcome back to alert.email_status and the org's alert_settings health columns via
-- correlation_id. 'invite' is declared capacity with no writer yet: invite mail still sends
-- synchronously, because its caller falls back to showing the link in the response when the
-- relay is unavailable and that fallback needs a synchronous outcome.
--
-- Security-token mail is deliberately absent. A password-reset link and an email-change
-- verification link are live credentials, and persisting a rendered body would put them at rest
-- in this table; both stay on the in-memory, fail-silent path, where the recovery is the user
-- requesting another one.
-- `recipients` is the org's configured alert-delivery list snapshotted at raise time, not the data
-- subject's own address, and one row is addressed to several recipients at once — so returning it to
-- one of them would disclose the others. Storage limitation is discharged instead: terminal rows are
-- pruned by the retention sweep, non-terminal rows retire at their own ceiling, and the org_id FK
-- cascades the whole backlog away with its tenant.
-- personal-data: excluded — queued outbound alert mail; recipients is the org's delivery list, not the subject's own data
CREATE TABLE IF NOT EXISTS email_outbox (
    id                TEXT PRIMARY KEY,
    org_id            TEXT REFERENCES orgs(id) ON DELETE CASCADE,  -- NULL = operator-scope mail
    message_kind      TEXT NOT NULL DEFAULT 'alert' CHECK (message_kind IN ('alert', 'invite')),
    coalesce_key      TEXT NOT NULL,   -- burst-dedup key, always read with org_id
    correlation_id    TEXT,            -- alert.id when message_kind = 'alert'
    recipients        TEXT NOT NULL,   -- comma-separated, same form as alert_settings.email_recipients
    subject           TEXT NOT NULL,
    body              TEXT NOT NULL,
    occurrence_count  INTEGER NOT NULL DEFAULT 1,  -- raw alerts folded into this row by coalescing
    state             TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sending', 'delivered', 'dead_letter', 'expired')),
    attempts          INTEGER NOT NULL DEFAULT 0,
    failure_class     TEXT
        CHECK (failure_class IS NULL OR failure_class IN ('transient', 'permanent', 'unknown')),
    last_error        TEXT,
    next_attempt_at   TEXT COLLATE "C" NOT NULL   -- earliest next delivery attempt (exponential backoff)
        CHECK (next_attempt_at IS NULL OR next_attempt_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    retry_deadline_at TEXT NOT NULL   -- maximum-retry-duration ceiling; past it the row expires
        CHECK (retry_deadline_at IS NULL OR retry_deadline_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at        TEXT NOT NULL   -- maximum-retention ceiling, independent of the retry budget
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    lease_expires_at  TEXT            -- 'sending' claim lease; a lapsed lease returns the row to the drain set
        CHECK (lease_expires_at IS NULL OR lease_expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    completed_at      TEXT COLLATE "C"   -- set once, when the row reaches a terminal state
        CHECK (completed_at IS NULL OR completed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    created_at        TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_email_outbox_state_next ON email_outbox(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_email_outbox_state_completed ON email_outbox(state, completed_at);
CREATE INDEX IF NOT EXISTS idx_email_outbox_org ON email_outbox(org_id);
-- Burst-coalescing lookup: "is there already a pending row for this (org, coalesce_key)". Carried
-- from the first release the column existed, since email_outbox has never shipped without it —
-- there is no backlog to migrate an index onto.
CREATE INDEX IF NOT EXISTS idx_email_outbox_coalesce ON email_outbox(coalesce_key, org_id);

-- Per-org upstream proxy registries. One ordered list per ecosystem; `position` ascending is
-- priority (lowest tried first, falling through on miss/unreachable). An ecosystem with zero
-- rows has proxying effectively disabled for that org. For non-OCI ecosystems auth_type is
-- 'anonymous' (default), 'bearer' (Authorization: Bearer <secret>), or 'basic'
-- (base64(username:secret)) — used to chain to a private upstream that refuses anonymous pull;
-- secret is encrypted at rest (enc:v1: prefix). For OCI rows: auth_type
-- drives the pull auth mechanism ('anonymous'|'basic'|'dockerhub_token_exchange'); url holds
-- the registry host (e.g. 'registry-1.docker.io'); token_endpoint is the operator-pinned
-- auth realm for DockerHubTokenExchange; prefixes is a JSON TEXT array (e.g. '["library/",""]')
-- — first-match-wins prefix routing, empty string is the catch-all fallback.
CREATE TABLE IF NOT EXISTS upstream_registry (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem      TEXT NOT NULL,              -- 'pypi' | 'npm' | 'nuget' | 'maven' | 'rpm' | 'oci' | 'apk'
    name           TEXT,                       -- optional display label
    url            TEXT NOT NULL,
    position       INTEGER NOT NULL DEFAULT 0, -- ascending = priority; lowest tried first
    auth_type      TEXT NOT NULL DEFAULT 'anonymous',
    username       TEXT,
    secret         TEXT,
    token_endpoint TEXT,                       -- OCI: operator-pinned token-exchange realm URL
    prefixes       TEXT,                       -- OCI: JSON array of repository-name prefix strings
    -- NuGet: base URL of this upstream's symbol server. A symbol server is a different host from
    -- the v3 index (nuget.org's lives at https://symbols.nuget.org/download/symbols), so it cannot
    -- be derived from url. NULL disables symbol proxying for this upstream — the fail-closed
    -- default for any feed whose symbol host is unknown.
    symbol_server_url TEXT,
    -- Terraform: which protocol this upstream speaks. NULL is the ecosystem's own default, which
    -- for Terraform is the provider *registry* protocol a public registry serves. 'mirror' marks an
    -- upstream speaking the *network mirror* protocol instead — the one Dependably itself serves,
    -- which is how an edge node chains its master. The two are not interchangeable: their endpoint
    -- shapes differ, so a wrong value fails every fetch rather than degrading. Ignored by every
    -- other ecosystem, whose serve and fetch protocols are the same.
    upstream_protocol TEXT CHECK (upstream_protocol IS NULL OR upstream_protocol IN ('mirror')),
    created_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, url)
);
CREATE INDEX IF NOT EXISTS idx_upstream_registry_org_eco
    ON upstream_registry(org_id, ecosystem, position);

-- Per-(org, ecosystem, package name) upstream source pin. The first upstream to successfully
-- serve a proxied name binds that name to that upstream host; a later proxy fetch resolving the
-- same name from a DIFFERENT upstream host is refused. This is the non-OCI analogue of OCI
-- repository-prefix routing and closes the dependency-confusion window where a private-upstream
-- miss silently falls through to a public upstream squatting the same name. upstream_host is the
-- scheme+authority (e.g. https://registry.npmjs.org) of the serving upstream.
CREATE TABLE IF NOT EXISTS upstream_source_pin (
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    upstream_host TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (org_id, ecosystem, name)
);

-- NuGet symbol-server (SSQP) index. Maps a Portable-PDB debug-id key to the exact PDB entry
-- inside a stored .snupkg so a debugger can fetch a single PDB by GUID+age via
-- GET /nuget/symbols/{pdb}/{key}/{pdb}. Populated on symbol push (one row per contained PDB).
-- ssqp_key and pdb_filename are stored lowercased and matched case-insensitively per the SSQP
-- protocol. Tenant-scoped on org_id. owner_kind discriminates which FK is authoritative, the
-- package_version_licenses / package_version_vulns shape: a hosted symbol package indexes against
-- its package_versions row, a proxied one against the cache_artifact row holding the fetched
-- .snupkg. Exactly one FK is set per row, enforced by the invariant CHECK.
-- backcompat-ok: nuget_symbol_index.package_version_id — the added invariant CHECK cannot reject
-- anything the previous release writes. That writer always supplies package_version_id and omits
-- both new columns, so owner_kind takes its 'package_version' DEFAULT and cache_artifact_id stays
-- NULL, which is exactly the first arm. Relaxing NOT NULL only widens what is accepted; the
-- previous release's reader inner-joins package_versions, so proxy-owned rows are invisible to it
-- rather than malformed.
CREATE TABLE IF NOT EXISTS nuget_symbol_index (
    id                 TEXT PRIMARY KEY,
    org_id             TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    package_version_id TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    pdb_filename       TEXT NOT NULL,
    ssqp_key           TEXT NOT NULL,
    snupkg_blob_key    TEXT NOT NULL,
    entry_path         TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    cache_artifact_id  TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
    owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                       CHECK (owner_kind IN ('package_version','cache_artifact')),
    CHECK (
        (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
        OR
        (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_lookup ON nuget_symbol_index(org_id, ssqp_key, pdb_filename);
CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv ON nuget_symbol_index(package_version_id);
CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_ca ON nuget_symbol_index(cache_artifact_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv_key
    ON nuget_symbol_index (org_id, ssqp_key, pdb_filename, package_version_id)
    WHERE owner_kind = 'package_version';
CREATE UNIQUE INDEX IF NOT EXISTS idx_nuget_symbol_index_ca_key
    ON nuget_symbol_index (org_id, ssqp_key, pdb_filename, cache_artifact_id)
    WHERE owner_kind = 'cache_artifact';

-- Per-org operator-pinned signature trust anchors. Each row is one trust anchor
-- (PGP public key, X.509 cert, npm SPKI key, Sigstore root, Rekor key, or publisher
-- identity) for one (org, ecosystem) combination. List semantics — multiple anchors
-- per ecosystem are supported (no UNIQUE on org_id + ecosystem). The verifier resolves
-- all rows for an (org, ecosystem) pair at request time and accepts a signature
-- verified by any of them. anchor_kind discriminates the material format:
-- 'pgp' | 'x509' | 'spki' | 'sigstore_root' | 'trusted_publisher' | 'rekor_key'.
-- material is PUBLIC key material stored plaintext (PGP public keys, X.509 certs,
-- SPKI DER base64, Sigstore bundle JSON, etc.) — no envelope encryption.
-- created_by holds the user id of the operator who added the anchor.
-- personal-data: excluded — created_by is a provenance stamp on org-owned trust-anchor config
CREATE TABLE IF NOT EXISTS signature_trust_anchor (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,   -- 'rpm' | 'npm' | 'nuget' | 'pypi' | 'maven' | 'apk' | 'terraform'
    anchor_kind TEXT NOT NULL,   -- 'pgp' | 'spki' | 'x509' | 'sigstore_root' | 'trusted_publisher' | 'rekor_key' | 'rsa'
    key_id      TEXT,            -- optional key fingerprint / subject for display
    material    TEXT NOT NULL,   -- public key material: armored PGP / base64 DER / PEM / JSON
    label       TEXT,            -- operator-supplied display label
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    created_by  TEXT             -- user id of the operator who added this anchor
);
-- FK-column index: cascade deletes on orgs scan this table without it.
-- Also the hot read path: resolve all anchors for (org, ecosystem) at verify time.
CREATE INDEX IF NOT EXISTS idx_signature_trust_anchor_org_eco
    ON signature_trust_anchor(org_id, ecosystem);

-- License governance
CREATE TABLE IF NOT EXISTS package_version_licenses (
    id                  TEXT PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    license_spdx        TEXT NOT NULL,                  -- SPDX identifier e.g. MIT, Apache-2.0
    source              TEXT NOT NULL DEFAULT 'upstream',   -- 'upstream' | 'sbom' | 'manual'
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Polymorphic metadata owner: NULL for hosted package_version rows; set to the
    -- cache_artifact row for proxy-origin metadata scanned before a version row exists.
    -- owner_kind discriminates which FK is authoritative. Reserved capacity in community.
    cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
    owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                        CHECK (owner_kind IN ('package_version','cache_artifact')),
    UNIQUE (package_version_id, license_spdx),
    UNIQUE (cache_artifact_id, license_spdx),
    -- Owner invariant: exactly one FK arm is active and matches owner_kind.
    CHECK (
        (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
        OR
        (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_package_version_licenses_cache_artifact
    ON package_version_licenses (cache_artifact_id);

CREATE TABLE IF NOT EXISTS license_allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, license_spdx)
);

CREATE TABLE IF NOT EXISTS license_blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, license_spdx)
);

CREATE INDEX IF NOT EXISTS idx_pkg_version_licenses ON package_version_licenses(package_version_id);

-- RPM metadata. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS rpm_metadata (
    -- Surrogate PK so cache_artifact-owned rows can exist without a package_versions FK.
    id                  TEXT PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
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
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Polymorphic metadata owner: NULL for hosted package_version rows; set to the
    -- cache_artifact row for proxy-origin metadata scanned before a version row exists.
    -- owner_kind discriminates which FK is authoritative. Reserved capacity in community.
    cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
    owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                        CHECK (owner_kind IN ('package_version','cache_artifact')),
    -- Owner invariant: exactly one FK arm is active and matches owner_kind.
    CHECK (
        (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
        OR
        (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_rpm_metadata_arch ON rpm_metadata(arch);
CREATE INDEX IF NOT EXISTS idx_rpm_metadata_cache_artifact ON rpm_metadata(cache_artifact_id);
-- Partial unique indexes enforce per-arm dedup (one row per artifact per owner arm).
CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_pv
    ON rpm_metadata (package_version_id)
    WHERE owner_kind = 'package_version';
CREATE UNIQUE INDEX IF NOT EXISTS idx_rpm_metadata_ca
    ON rpm_metadata (cache_artifact_id)
    WHERE owner_kind = 'cache_artifact';

CREATE TABLE IF NOT EXISTS rpm_repodata_state (
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    arch          TEXT NOT NULL,
    last_built_at TEXT
        CHECK (last_built_at IS NULL OR last_built_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    dirty         INTEGER NOT NULL DEFAULT 1,
    generation    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, arch)
);

-- Maven multi-file per-version tracker. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS maven_version_files (
    id                  TEXT PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    filename            TEXT NOT NULL,
    classifier          TEXT,
    extension           TEXT NOT NULL,
    blob_key            TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    checksum_sha256     TEXT,
    checksum_sha1       TEXT,
    checksum_md5        TEXT,
    origin              TEXT NOT NULL DEFAULT 'uploaded',
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- Polymorphic metadata owner: NULL for hosted package_version rows; set to the
    -- cache_artifact row for proxy-origin metadata scanned before a version row exists.
    -- owner_kind discriminates which FK is authoritative. Reserved capacity in community.
    cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
    owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                        CHECK (owner_kind IN ('package_version','cache_artifact')),
    -- Owner invariant: exactly one FK arm is active and matches owner_kind.
    CHECK (
        (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
        OR
        (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_maven_version_files_version ON maven_version_files(package_version_id);
CREATE INDEX IF NOT EXISTS idx_maven_version_files_filename ON maven_version_files(filename);
CREATE INDEX IF NOT EXISTS idx_maven_version_files_cache_artifact ON maven_version_files(cache_artifact_id);
-- Partial unique indexes replace the old UNIQUE(package_version_id, filename) constraint.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_pv_filename
    ON maven_version_files (package_version_id, filename)
    WHERE owner_kind = 'package_version';
CREATE UNIQUE INDEX IF NOT EXISTS idx_mvf_ca_filename
    ON maven_version_files (cache_artifact_id, filename)
    WHERE owner_kind = 'cache_artifact';

-- PyPI multi-file-per-version distribution files (wheel + sdist + per-platform wheels).
-- See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS package_version_files (
    id                  TEXT PRIMARY KEY,
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    filename            TEXT NOT NULL,
    blob_key            TEXT NOT NULL,
    size_bytes          BIGINT NOT NULL DEFAULT 0,
    checksum_sha256     TEXT,
    created_at          TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (package_version_id, filename)
);
-- The UNIQUE(package_version_id, filename) index covers the version FK (leftmost member);
-- this one covers the org FK cascade and the org-scoped filename resolution on download.
CREATE INDEX IF NOT EXISTS idx_package_version_files_org_filename
    ON package_version_files (org_id, filename);

-- OCI / Docker registry storage. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS oci_blobs (
    digest        TEXT NOT NULL,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    media_type    TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    blob_key      TEXT NOT NULL,
    cached_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (cached_at IS NULL OR cached_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    upstream_checked_at TEXT
        CHECK (upstream_checked_at IS NULL OR upstream_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    origin        TEXT NOT NULL DEFAULT 'uploaded',  -- 'uploaded' (local push) or 'proxy' (upstream cache)
    config_digest       TEXT,    -- image manifests only: the config blob digest parsed from the manifest body
    license_spdx        TEXT,    -- SPDX expression from the config's org.opencontainers.image.licenses label
    license_checked_at  TEXT    -- stamped when the config bytes were read (label present or not); NULL = config not yet seen
        CHECK (license_checked_at IS NULL OR license_checked_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (digest, org_id)
);
CREATE INDEX IF NOT EXISTS idx_oci_blobs_org ON oci_blobs(org_id);
CREATE INDEX IF NOT EXISTS idx_oci_blobs_org_config_digest ON oci_blobs(org_id, config_digest);

CREATE TABLE IF NOT EXISTS oci_tags (
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    -- No FK to oci_blobs: a tag may validly dangle to a GC'd or not-yet-stored manifest.
    -- Dangling tags are resolved lazily; the OCI pull path re-fetches the manifest on miss.
    digest      TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_revalidated TEXT    -- per-tag TTL revalidation timestamp; NULL forces a re-check on first access
        CHECK (last_revalidated IS NULL OR last_revalidated ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    -- A newer digest observed upstream but not yet promoted onto this tag: the org's
    -- min_release_age_hours gates PROMOTION (the tag keeps resolving to `digest` until the
    -- pending digest has been locally observed for that long), never availability. Replaced
    -- whenever upstream advertises a different digest; cleared on promotion or when upstream
    -- re-advertises the accepted digest.
    pending_digest TEXT,
    pending_first_seen_at TEXT    -- when pending_digest was FIRST observed locally; the promotion age is measured from this instant
        CHECK (pending_first_seen_at IS NULL OR pending_first_seen_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (org_id, repository, tag)
);
CREATE INDEX IF NOT EXISTS idx_oci_tags_repository ON oci_tags(org_id, repository);

-- manifest → referenced-blob edges. See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS oci_manifest_blobs (
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    manifest_digest TEXT NOT NULL,
    blob_digest     TEXT NOT NULL,
    recorded_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (recorded_at IS NULL OR recorded_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (org_id, manifest_digest, blob_digest)
);
CREATE INDEX IF NOT EXISTS idx_oci_manifest_blobs_org_blob
    ON oci_manifest_blobs(org_id, blob_digest);

-- In-progress OCI blob upload sessions (push). See Schema.sql for full rationale.
CREATE TABLE IF NOT EXISTS oci_uploads (
    upload_id      TEXT NOT NULL,
    org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository     TEXT NOT NULL,
    staging_path   TEXT NOT NULL,
    received_bytes INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
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
        CHECK (copyleft IN ('permissive','weak-copyleft','strong-copyleft','network-copyleft','public-domain','unclassified')),
    -- Full SPDX license text, bundled at build time from license-list-data (air-gapped
    -- runtime, no on-demand fetch). NULL for identifiers absent from the bundled texts
    -- (custom/post-bundle SPDX additions). Served on demand by the license-text endpoint;
    -- never joined into the list/detail SELECTs to keep those payloads small.
    license_text    TEXT
);
CREATE INDEX IF NOT EXISTS idx_spdx_license_osi ON spdx_license(is_osi_approved);
CREATE INDEX IF NOT EXISTS idx_spdx_license_copyleft ON spdx_license(copyleft);

-- JWT revocations: stores revoked jti values until their expiry time.
-- Rows are cleaned up by the GC pass via RetentionService.
CREATE TABLE IF NOT EXISTS jwt_revocations (
    jti         TEXT PRIMARY KEY,
    expires_at  TEXT COLLATE "C" NOT NULL    -- ISO 8601 UTC; row can be deleted after this time
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_jwt_revocations_expires ON jwt_revocations(expires_at);

-- Trusted-device tokens for MFA two-step login. A remembered device skips the TOTP step
-- for the configured TTL. token_hash is the SHA-256 of the raw cookie value (stored hashed
-- so the cookie bears the only copy of the preimage). user_id is not FK'd because system
-- realm rows reference system_admins, which is the MR-4 concern; tenant rows reference users.
-- Revoked on MFA disable and on password change.
-- personal-data: included — the subject's remembered MFA devices (user_agent history)
CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    realm       TEXT NOT NULL CHECK (realm IN ('tenant', 'system')),
    tenant_id   TEXT REFERENCES orgs(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    user_agent  TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_seen_at TEXT
        CHECK (last_seen_at IS NULL OR last_seen_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_token ON mfa_trusted_devices(token_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_user ON mfa_trusted_devices(user_id, realm);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_tenant ON mfa_trusted_devices(tenant_id);

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
    last_test_at        TEXT
        CHECK (last_test_at IS NULL OR last_test_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
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
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

-- One-shot correlation-id store for SAML admin-test runs.
-- personal-data: excluded — actor_id is a provenance stamp on org IdP-configuration diagnostics
CREATE TABLE IF NOT EXISTS saml_test_runs (
    cid          TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor_id     TEXT,
    issued_at    TEXT NOT NULL
        CHECK (issued_at IS NULL OR issued_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at   TEXT COLLATE "C" NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    consumed_at  TEXT
        CHECK (consumed_at IS NULL OR consumed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_saml_test_runs_expires ON saml_test_runs(expires_at);
-- FK-column index: tenant_id is not the PK; without this, cascade deletes on orgs scan the table.
CREATE INDEX IF NOT EXISTS idx_saml_test_runs_tenant ON saml_test_runs(tenant_id);

-- One-time-use store binding SP-initiated AuthnRequests to their responses. /saml/login inserts
-- the AuthnRequest id; ACS consumes it by matching the response's InResponseTo. An unsolicited
-- (IdP-initiated) or replayed response has no consumable pending row and is rejected.
CREATE TABLE IF NOT EXISTS saml_pending_requests (
    request_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    issued_at    TEXT NOT NULL
        CHECK (issued_at IS NULL OR issued_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at   TEXT COLLATE "C" NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    consumed_at  TEXT
        CHECK (consumed_at IS NULL OR consumed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_saml_pending_requests_expires ON saml_pending_requests(expires_at);
-- FK-column index: tenant_id is not the PK; without this, cascade deletes on orgs scan the table.
CREATE INDEX IF NOT EXISTS idx_saml_pending_requests_tenant ON saml_pending_requests(tenant_id);

-- Replay guard for production SAML logins. ACS records each accepted assertion's signed ID
-- (per tenant) on first sight; a repeat presentation within its validity window is rejected.
-- The key is (tenant_id, assertion_id): each tenant has exactly one IdP (tenant_saml_config is
-- keyed by org_id), so idp_entity_id is recorded for audit but is intentionally not part of the key.
CREATE TABLE IF NOT EXISTS saml_consumed_assertions (
    tenant_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    assertion_id  TEXT NOT NULL,
    idp_entity_id TEXT,
    consumed_at   TEXT NOT NULL
        CHECK (consumed_at IS NULL OR consumed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    expires_at    TEXT COLLATE "C" NOT NULL
        CHECK (expires_at IS NULL OR expires_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (tenant_id, assertion_id)
);
CREATE INDEX IF NOT EXISTS idx_saml_consumed_assertions_expires ON saml_consumed_assertions(expires_at);

-- IdP-issued identities linked to local users. Identity is (idp_entity_id, nameid) -- not
-- email. Email can change in the IdP without breaking login; cross-IdP collisions on the
-- same email are impossible.
-- personal-data: included — the subject's linked SAML identities (NameID, email snapshot)
CREATE TABLE IF NOT EXISTS external_identities (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_entity_id   TEXT NOT NULL,
    nameid          TEXT NOT NULL,
    email_snapshot  TEXT,
    created_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_login_at   TEXT
        CHECK (last_login_at IS NULL OR last_login_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, idp_entity_id, nameid)
);
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id);

-- ── Multitenant architecture ─────────────────────────────────────────

-- personal-data: excluded — created_by is a provenance stamp on org package-name claim governance
CREATE TABLE IF NOT EXISTS claim (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('unclaimed','local_only','mixed')),
    reason      TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    updated_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    deleted_at  TEXT
        CHECK (deleted_at IS NULL OR deleted_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_claim_org_state ON claim (org_id, state);
-- FK-column index: created_by references users(id) but is not covered by any other index.
CREATE INDEX IF NOT EXISTS idx_claim_created_by ON claim(created_by);

-- personal-data: excluded — actor_id is a provenance stamp on an org-owned claim-history row
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
    occurred_at     TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (occurred_at IS NULL OR occurred_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_claim_history_org_time ON claim_history (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_claim_history_claim ON claim_history (claim_id, occurred_at DESC);
-- FK-column index: actor_id references users(id) but is not covered by any other index.
CREATE INDEX IF NOT EXISTS idx_claim_history_actor ON claim_history(actor_id);

-- Name-ownership binding. See Schema.sql for the full rationale: the first hosted publisher of
-- a (org, ecosystem, purl_name) is recorded as its owner (trust-on-first-use); later hosted
-- publishes are authorized against it when PUBLISH_NAME_BINDING enforcement is on. Keyed to the
-- org (not the packages row) so it survives last-version deletion and acts as the resurrection
-- tombstone read by ClaimResolver.
CREATE TABLE IF NOT EXISTS package_name_binding (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    purl_name   TEXT NOT NULL,
    owner_kind  TEXT NOT NULL CHECK (owner_kind IN ('user','service')),
    owner_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, purl_name)
);

-- Additional principals explicitly permitted to publish to an already-bound name (see Schema.sql).
-- personal-data: excluded — created_by is a provenance stamp on an org-owned authorization row
CREATE TABLE IF NOT EXISTS package_name_grant (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    purl_name     TEXT NOT NULL,
    grantee_kind  TEXT NOT NULL CHECK (grantee_kind IN ('user','service')),
    grantee_id    TEXT NOT NULL,
    created_by    TEXT REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, purl_name, grantee_kind, grantee_id)
);
-- FK-column index: created_by references users(id) but is not covered by any other index.
CREATE INDEX IF NOT EXISTS idx_package_name_grant_created_by ON package_name_grant(created_by);

-- Version-granular delete tombstone for hard-deleted hosted versions; read by the publish
-- dedup gate to refuse a republish of a spent coordinate under a blocking version-overwrite
-- policy (see Schema.sql).
CREATE TABLE IF NOT EXISTS package_version_tombstone (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    purl_name     TEXT NOT NULL,
    version       TEXT NOT NULL,
    content_hash  TEXT,
    deleted_at    TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (deleted_at IS NULL OR deleted_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, purl_name, version)
);

-- personal-data: included — structured audit events attributed to the subject (source_ip/user_agent)
CREATE TABLE IF NOT EXISTS audit_event (
    event_id            TEXT PRIMARY KEY,
    schema_version      INTEGER NOT NULL DEFAULT 1,
    event_type          TEXT NOT NULL,
    -- ON DELETE SET NULL retains the event row after org deletion for forensic purposes.
    -- NULL also covers cross-tenant platform events that have no org scope.
    org_id              TEXT REFERENCES orgs(id) ON DELETE SET NULL,
    tenant_resolver     TEXT NOT NULL,
    actor_type          TEXT NOT NULL CHECK (actor_type IN ('user','api_token','system')),
    actor_id            TEXT,
    request_id          TEXT,
    source_ip           TEXT,
    user_agent          TEXT,
    outcome             TEXT NOT NULL CHECK (outcome IN ('accepted','rejected','error')),
    payload             TEXT NOT NULL,
    -- Millisecond precision (matches AuditEmitter's ToUtcIsoMillis() writer): this append-only
    -- forensic table needs a deterministic order for events sharing a wall-clock second, exactly
    -- like audit_log/activity.
    occurred_at         TEXT COLLATE "C" NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
        CHECK (occurred_at IS NULL OR occurred_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_time ON audit_event (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_type ON audit_event (org_id, event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor ON audit_event (org_id, actor_id, occurred_at DESC);
-- Retention-sweep index: the reaper's DELETE filters on a bare occurred_at range with no
-- org_id, so none of the org-scoped indexes above can serve it — this one exists purely to
-- keep that sweep an index range scan instead of a full-table scan.
CREATE INDEX IF NOT EXISTS idx_audit_event_occurred_at ON audit_event (occurred_at);

-- Per-tenant registry bucket binding. See Schema.sql for the full semantics.
CREATE TABLE IF NOT EXISTS tenant_storage (
    org_id                      TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    registry_bucket             TEXT,
    registry_region             TEXT,
    registry_endpoint           TEXT,
    registry_force_path_style   INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
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
    started_at      TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (started_at IS NULL OR started_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    completed_at    TEXT
        CHECK (completed_at IS NULL OR completed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_tenant_provisioning_jobs_org ON tenant_provisioning_jobs(org_id, kind);

-- Per-run history for IHostedService background workers. See Schema.sql for full semantics.
CREATE TABLE IF NOT EXISTS background_job_runs (
    id              TEXT PRIMARY KEY,
    job_name        TEXT NOT NULL,
    operation       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    started_at      TEXT COLLATE "C" NOT NULL
        CHECK (started_at IS NULL OR started_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    finished_at     TEXT NOT NULL
        CHECK (finished_at IS NULL OR finished_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    duration_ms     BIGINT NOT NULL,
    outcome         TEXT NOT NULL,
    error_message   TEXT
);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_started_at
    ON background_job_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_job_started
    ON background_job_runs(job_name, started_at DESC);

-- Content-addressed negative cache for upstream 404 responses.
-- The key is SHA-256(resolved-upstream-URL)[..32] including the org's upstream base host, not
-- just the artifact path/filename — shared across tenants on the same host, distinct across
-- tenants whose per-org upstreams point at different hosts, so one org's 404 never suppresses
-- another org's fetch against a host that does have the artifact.
-- TTL enforced at query time.
CREATE TABLE IF NOT EXISTS upstream_negative_cache (
    url_key     TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    fetched_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (fetched_at IS NULL OR fetched_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (url_key, ecosystem)
);

-- Pre-computed dashboard aggregates, one row per org. The /api/v1/stats endpoint
-- reads this snapshot instead of running the eight live aggregate queries in
-- PackageAnalyticsRepository.GetOrgStatsAsync on every page load; StatsRefreshService
-- recomputes it per org on a fixed interval. stats_json holds a serialized OrgStats.
CREATE TABLE IF NOT EXISTS org_stats_snapshot (
    org_id      TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    stats_json  TEXT NOT NULL,
    computed_at TEXT NOT NULL
        CHECK (computed_at IS NULL OR computed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
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
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    updated_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (package_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_npm_dist_tags_org ON npm_dist_tags(org_id, package_id);

-- Cargo sparse index metadata. One row per artifact carrying the full newline-delimited JSON
-- index line for that version. Tenant-scoped via JOIN to packages.org_id.
-- Each row is owned by exactly one package_versions row (owner_kind='package_version') or
-- one cache_artifact row (owner_kind='cache_artifact'); the respective FK is set and the
-- other is NULL. Partial unique indexes enforce per-arm dedup.
CREATE TABLE IF NOT EXISTS cargo_metadata (
    -- BIGSERIAL retained for compatibility with existing databases; mirrors the SQLite
    -- INTEGER AUTOINCREMENT PK used on the SQLite provider.
    id          BIGSERIAL PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    index_line  TEXT NOT NULL,
    -- Polymorphic metadata owner: NULL for hosted package_version rows; set to the
    -- cache_artifact row for proxy-origin metadata scanned before a version row exists.
    -- owner_kind discriminates which FK is authoritative. Reserved capacity in community.
    cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
    owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                        CHECK (owner_kind IN ('package_version','cache_artifact')),
    -- Owner invariant: exactly one FK arm is active and matches owner_kind.
    CHECK (
        (owner_kind = 'package_version' AND version_id IS NOT NULL AND cache_artifact_id IS NULL)
        OR
        (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND version_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_cargo_metadata_version ON cargo_metadata(version_id);
CREATE INDEX IF NOT EXISTS idx_cargo_metadata_cache_artifact ON cargo_metadata(cache_artifact_id);
-- Partial unique indexes replace the old UNIQUE(version_id) constraint.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_pv
    ON cargo_metadata (version_id)
    WHERE owner_kind = 'package_version';
CREATE UNIQUE INDEX IF NOT EXISTS idx_cargo_metadata_ca
    ON cargo_metadata (cache_artifact_id)
    WHERE owner_kind = 'cache_artifact';

-- Install-script allowlist: packages exempt from the install-script block-gate arm (arm 9).
-- See Schema.sql for the full rationale.
-- personal-data: excluded — created_by is a provenance stamp on org allowlist config
CREATE TABLE IF NOT EXISTS install_script_allowlist (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem        TEXT NOT NULL,
    name             TEXT NOT NULL,
    version_pattern  TEXT,
    created_by       TEXT REFERENCES users(id),
    created_at       TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    UNIQUE (org_id, ecosystem, name, version_pattern)
);
CREATE INDEX IF NOT EXISTS idx_install_script_allowlist_org ON install_script_allowlist(org_id);
CREATE INDEX IF NOT EXISTS idx_install_script_allowlist_created_by ON install_script_allowlist(created_by);

-- Admin-authored banners (tenant-scoped or system-wide). See Schema.sql for the full rationale.
-- personal-data: excluded — created_by is authorship provenance on an org/instance announcement; the subject's own dismissals ARE exported, via banner_dismissals
CREATE TABLE IF NOT EXISTS banners (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','system')),
    org_id      TEXT,
    severity    TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warn','alert')),
    body        TEXT NOT NULL,
    link_url    TEXT,
    link_label  TEXT,
    target_role TEXT NOT NULL DEFAULT 'all' CHECK (target_role IN ('all','member','admin','owner','auditor')),
    starts_at   TEXT NOT NULL
        CHECK (starts_at IS NULL OR starts_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    ends_at     TEXT COLLATE "C" NOT NULL
        CHECK (ends_at IS NULL OR ends_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_by  TEXT,
    created_at  TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_banners_resolution ON banners(scope, org_id, enabled, ends_at);

-- personal-data: included — banners the subject dismissed
CREATE TABLE IF NOT EXISTS banner_dismissals (
    banner_id   TEXT NOT NULL REFERENCES banners(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dismissed_at TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (dismissed_at IS NULL OR dismissed_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    PRIMARY KEY (banner_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_banner_dismissals_user ON banner_dismissals(user_id);

-- User-configured outbound webhooks for package events. See Schema.sql for the full rationale.
CREATE TABLE IF NOT EXISTS webhook_subscription (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    url                  TEXT NOT NULL,
    secret               TEXT,
    event_types          TEXT NOT NULL DEFAULT '[]',
    enabled              INTEGER NOT NULL DEFAULT 1,
    description          TEXT,
    last_delivery_at     TEXT
        CHECK (last_delivery_at IS NULL OR last_delivery_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_status          TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    failing_since        TEXT
        CHECK (failing_since IS NULL OR failing_since ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    last_error           TEXT,
    created_at           TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (created_at IS NULL OR created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    updated_at           TEXT NOT NULL DEFAULT (to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
        CHECK (updated_at IS NULL OR updated_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);
CREATE INDEX IF NOT EXISTS idx_webhook_sub_org_enabled ON webhook_subscription(org_id, enabled);

-- Single-writer mutual-exclusion lock over a shared SQLite database file. Carried here for schema
-- parity only: the guard that writes this table is SQLite-only (Postgres is a legitimately
-- multi-writer store, so a dependably fleet backed by Postgres never claims the lock). See
-- Schema.sql for the full rationale. Dormant in a Postgres deployment.
CREATE TABLE IF NOT EXISTS instance_lock (
    id           TEXT PRIMARY KEY,
    instance_id  TEXT NOT NULL,
    hostname     TEXT,
    heartbeat_at TEXT NOT NULL
        CHECK (heartbeat_at IS NULL OR heartbeat_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$'),
    acquired_at  TEXT NOT NULL
        CHECK (acquired_at IS NULL OR acquired_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?Z$')
);

-- NOTE: SchemaInitializer also runs ALTER TABLE statements for the columns above.
-- Those are no-ops on fresh installs (IF NOT EXISTS). They exist solely to add the
-- columns to databases created before those columns were included in the CREATE TABLE
-- blocks. Schema.pg.sql is the authoritative complete schema.
