-- Dependably database schema
-- Applied on first boot via SchemaInitializer
--
-- Every temporal TEXT column below carries a CHECK accepting exactly the three canonical
-- UtcTimestamp shapes (second/millisecond/microsecond precision, always UTC 'Z') and NULL —
-- see TemporalCheckPredicate.ForSqlite. Fresh installs get it here, from CREATE TABLE. An
-- existing SQLite database is deliberately NOT retrofitted with this CHECK: SQLite cannot
-- ALTER ADD CONSTRAINT, and the alternative (a recreate-table reshape across every temporal
-- table at boot) is a far larger hazard than the invariant is worth given every writer of
-- these columns is already canonical and the every-boot sweep in
-- SchemaInitializer.TimestampNormalization.cs repairs any legacy shape a stale binary still
-- produces. Existing Postgres databases are not retrofitted with this CHECK this release
-- either — see SchemaInitializer.TemporalColumnNaming.cs for the expand/migrate/contract
-- sequencing that defers the retrofit to a later release, once the released baseline writes
-- canonical shapes everywhere.
--
-- Schema.pg.sql additionally declares COLLATE "C" on its indexed temporal columns, for
-- byte-exact ordering and immunity to glibc collation-version drift. SQLite needs no
-- equivalent here: its default TEXT collation (BINARY) is already byte order, so there is
-- nothing to opt into — this is why the two files diverge on that one point.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    -- Soft-delete: set on DELETE /api/v1/system/tenants/{slug}; cleared on restore.
    -- TenantHardDeleteService cascade-deletes rows where deleted_at < now() - 30 days.
    deleted_at  TEXT
        CHECK (deleted_at IS NULL OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

CREATE TABLE IF NOT EXISTS org_settings (
    org_id              TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    anonymous_pull      INTEGER NOT NULL DEFAULT 0,
    allowlist_mode      INTEGER NOT NULL DEFAULT 0,
    max_upload_bytes    INTEGER,
    max_upload_bytes_pypi   INTEGER,
    max_upload_bytes_npm    INTEGER,
    max_upload_bytes_nuget  INTEGER,
    max_upload_bytes_maven  INTEGER,           -- per-ecosystem Maven cap; falls back to max_upload_bytes
    max_upload_bytes_rpm    INTEGER,           -- per-ecosystem RPM cap; falls back to max_upload_bytes
    max_upload_bytes_oci    INTEGER,           -- per-ecosystem OCI (Docker) cap; falls back to max_upload_bytes
    max_upload_bytes_cargo  INTEGER,           -- per-ecosystem Cargo cap; falls back to max_upload_bytes
    keep_versions       INTEGER,            -- GC: max versions to retain per package per ecosystem
    keep_days           INTEGER,            -- GC: evict proxy blobs unused for this many days
    activity_retention_days INTEGER DEFAULT 90,  -- GC: delete activity rows older than this; NULL resolves to the ACTIVITY_RETENTION_DAYS instance default (90) so activity is bounded by default
    purge_unlisted_after_days INTEGER,      -- GC: hard-delete uploaded versions unlisted longer than this (opt-in; NULL = off)
    license_enforcement_mode  TEXT    NOT NULL DEFAULT 'off',
    -- Publish-side licence gate, independent of license_enforcement_mode (the serve-path gate
    -- above): 'off' (default) accepts a licence-less hosted publish exactly as before; 'warn'
    -- accepts it but records an activity row noting it will not be servable under the current
    -- serve-path policy; 'block' rejects the publish outright with 'license_blocked'. Only
    -- engages for the ecosystems whose manifests declare a licence (npm/pypi/nuget/maven/cargo/
    -- rpm — see BlockGateService.DeclaredLicenseEcosystems); go/apk/oci keep the empty-set
    -- pass-through since they routinely record no licence at all.
    license_publish_enforcement_mode TEXT NOT NULL DEFAULT 'off'
                              CHECK (license_publish_enforcement_mode IN ('off','warn','block')),
    proxy_passthrough_enabled INTEGER NOT NULL DEFAULT 1,
    max_osv_score_tolerance   REAL    NOT NULL DEFAULT 10.0,
    -- Minimum upstream-release age (hours) before a proxy-fetched version is allowed past the
    -- block gate. NULL = policy off. Supply-chain hold: lets community detection (npm/PyPI/NuGet
    -- removals, advisories) catch up before a fresh upstream version reaches tenant builds.
    -- The gate is re-evaluated on every serve and index render against the current clock, so a
    -- held version serves again automatically once it ages past the threshold. The pending review
    -- row created when the hold first fired is cleared from the queue at that point.
    min_release_age_hours     INTEGER,
    default_language          TEXT    NOT NULL DEFAULT 'en',  -- new tenant users start with this locale
    -- IANA zone name used to render stored instants for users who have not chosen one.
    -- Display only: every instant is stored in UTC regardless of this setting.
    default_timezone          TEXT    NOT NULL DEFAULT 'UTC',
    allow_version_overwrite   INTEGER NOT NULL DEFAULT 0,   -- legacy boolean; kept for blue-green safety; see version_overwrite_policy
    -- Tri-state same-version-push policy: 'block' (default) = always reject duplicates;
    -- 'exception' = reject by default but individual packages can grant permission;
    -- 'allow' = allow by default but individual packages can deny. Supersedes the legacy
    -- allow_version_overwrite boolean; dual-write keeps the boolean in sync on every upsert.
    version_overwrite_policy  TEXT    NOT NULL DEFAULT 'block'
                              CHECK (version_overwrite_policy IN ('block','exception','allow')),
    maven_reserved_prefixes   TEXT    NOT NULL DEFAULT '[]', -- dep-confusion guard; JSON array of groupId prefixes
    -- Per-tenant air-gap posture. When 1, this org makes no outbound network requests:
    -- proxy passthrough is forced off (uncached upstream returns 404), and the vulnerability
    -- and deprecation-metadata scan passes skip this org. Composes with the instance AIR_GAPPED
    -- env var (effective air-gap = instance OR tenant).
    air_gapped                INTEGER NOT NULL DEFAULT 0,
    -- Per-tenant MFA enrollment requirement. When 1, all authenticated users in this
    -- org must complete MFA enrollment before accessing any API endpoints (enforced by
    -- MfaEnrollmentGuard). Composes with the instance REQUIRE_MFA env var: effective
    -- requirement = instance OR tenant.
    require_mfa               INTEGER NOT NULL DEFAULT 0,
    -- Policy for upstream-deprecated/abandoned packages: 'off' (allow), 'warn' (surface in UI),
    -- 'block_new' (refuse a deprecated version on cache miss — never fetch/cache/serve it — but
    -- keep serving already-cached versions), 'block_all' (block_new plus deny already-cached
    -- versions once deprecated). Both gates key on package_versions.deprecated being set.
    block_deprecated          TEXT    NOT NULL DEFAULT 'off' CHECK (block_deprecated IN ('off', 'warn', 'block_new', 'block_all')),
    -- Upstream-removal (revocation) gate. Three values (no block_new analog — revocation is always
    -- a full upstream removal). Defaults to 'warn' (observe-before-enforce): surface the badge but
    -- keep serving cached copies until an operator opts into 'block'.
    block_revoked             TEXT    NOT NULL DEFAULT 'warn' CHECK (block_revoked IN ('off', 'warn', 'block')),
    -- Policy for versions carrying a malicious-package advisory (OSV MAL- ids, sourced from the
    -- OpenSSF malicious-packages feed via the regular OSV scan). These advisories usually have
    -- no CVSS score, so the max_osv_score_tolerance gate never sees them — this gate keys on the
    -- advisory id prefix instead. 'block' (default) denies fetch and serve; 'warn' surfaces the
    -- advisory in the UI only; 'off' disables the gate. A manual per-version allow override
    -- still wins (false-positive escape hatch).
    block_malicious           TEXT    NOT NULL DEFAULT 'block' CHECK (block_malicious IN ('off', 'warn', 'block')),
    -- Policy for versions whose advisories alias a CVE in the CISA Known Exploited
    -- Vulnerabilities catalog: exploited-in-the-wild, independent of CVSS score. 'off'
    -- (default, back-compat) / 'warn' / 'block'. A manual per-version allow still wins.
    block_kev                 TEXT    NOT NULL DEFAULT 'off' CHECK (block_kev IN ('off', 'warn', 'block')),
    -- EPSS exploitation-probability ceiling (0.0–1.0). A version is blocked when the maximum
    -- epss_score across its advisories exceeds this value. NULL = policy off (default).
    max_epss_tolerance        REAL,
    -- Policy for artefacts that ship an install/lifecycle script (package_versions.has_install_script).
    -- 'off' (default) / 'warn' (surface in UI only) / 'block' (deny fetch and serve). Opt-in;
    -- a manual per-version allow override still wins.
    block_install_scripts     TEXT    NOT NULL DEFAULT 'off' CHECK (block_install_scripts IN ('off', 'warn', 'block')),
    -- Policy for npm proxy-origin signature verification (package_versions.provenance_status).
    -- 'off' (default) = do not verify; 'warn' = verify and surface in UI without blocking;
    -- 'block' = fail closed (a version that fails verification or is unsigned is refused, not
    -- cached or served). Enabling 'warn'/'block' requires at least one npm SPKI trust anchor in
    -- signature_trust_anchor; without one the verifier reports NULL and nothing blocks.
    verify_npm_signatures     TEXT    NOT NULL DEFAULT 'off' CHECK (verify_npm_signatures IN ('off', 'warn', 'block')),
    -- Policy for NuGet proxy-origin .nupkg signature verification (package_versions.provenance_status).
    -- 'off' (default) = do not verify; 'warn' = verify and surface in UI without blocking;
    -- 'block' = fail closed (a version whose .nupkg signature fails verification or is unsigned is
    -- refused, not cached or served). Enabling 'warn'/'block' requires at least one NuGet X.509
    -- trust anchor in signature_trust_anchor; without one the verifier reports NULL and nothing
    -- blocks. A manual per-version allow override still wins.
    verify_nuget_signatures   TEXT    NOT NULL DEFAULT 'off' CHECK (verify_nuget_signatures IN ('off', 'warn', 'block')),
    -- Policy for PyPI proxy-origin PEP 740 attestation verification (package_versions.provenance_status).
    -- 'off' (default) = do not verify; 'warn' = verify and surface in UI without blocking;
    -- 'block' = fail closed (a version whose attestation fails verification or that carries none is
    -- refused, not cached or served). Enabling 'warn'/'block' requires at least one sigstore_root
    -- and one trusted_publisher anchor in signature_trust_anchor; without both the verifier reports
    -- NULL and nothing blocks. Configure anchors via Settings → Security → Signature trust anchors.
    -- A manual per-version allow override still wins.
    verify_pypi_attestations  TEXT    NOT NULL DEFAULT 'off' CHECK (verify_pypi_attestations IN ('off', 'warn', 'block')),
    -- Policy for RPM proxy-origin per-package GPG header signature verification
    -- (cache_artifact.provenance_status). 'off' (default) = do not verify; 'warn' = verify and
    -- surface in UI without blocking; 'block' = fail closed. Enabling 'warn'/'block' requires
    -- at least one RPM PGP trust anchor in signature_trust_anchor; without it the verifier reports
    -- not-applicable and nothing blocks. A manual per-version allow override still wins.
    verify_rpm_signatures     TEXT    NOT NULL DEFAULT 'off' CHECK (verify_rpm_signatures IN ('off', 'warn', 'block')),
    -- Policy for Maven proxy-origin detached .asc OpenPGP signature verification
    -- (cache_artifact.provenance_status). 'off' (default) = do not verify; 'warn' = verify and
    -- surface in UI without blocking; 'block' = fail closed. Enabling 'warn'/'block' requires
    -- at least one per-org Maven PGP anchor in signature_trust_anchor; without one the verifier
    -- reports not-applicable and nothing blocks. A manual per-version allow override still wins.
    verify_maven_signatures   TEXT    NOT NULL DEFAULT 'off' CHECK (verify_maven_signatures IN ('off', 'warn', 'block')),
    -- Dormant running tally of a tenant's hosted-artefact bytes. Nothing in this release reads or
    -- writes it: every quota check derives stored bytes from the live org_storage_bytes view, which
    -- is the single definition and cannot drift. The column is retained for one release so a slot of
    -- the preceding release — which still increments the counter — keeps working against this schema
    -- for the whole blue-green cutover window; it is the expand step of expand/migrate/contract and
    -- is dropped in the release after this one. NOT NULL DEFAULT 0 keeps it omittable from every
    -- INSERT and gives the older slot's `storage_used_bytes + n` arithmetic a number rather than NULL.
    storage_used_bytes        INTEGER NOT NULL DEFAULT 0,
    -- Per-tenant RPM hosted-publishing posture override. NULL (default) inherits the instance
    -- Rpm:UpstreamMode env value; an explicit 'passthrough' or 'merged' overrides the env value
    -- in EITHER direction (an org can opt out of an instance-wide 'merged' just as it can opt
    -- into one). 'passthrough' refuses hosted RPM publish when the org has an rpm upstream
    -- registry configured (a local package would silently shadow upstream and break dnf
    -- resolution); 'merged' serves local ∪ upstream repodata (local shadows on NEVRA collision)
    -- and allows hosted publish. Resolved in RpmController.IsRpmPassthroughEffective, settable
    -- from Settings → Proxy without an instance restart.
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

-- Tenant users. 1:1 with tenants — a user belongs to exactly one tenant. The same email may
-- exist as separate accounts in different tenants (UNIQUE(tenant_id, email)) — by design,
-- modeled on Slack/Auth0/Notion-style strict tenant isolation.
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
        CHECK (last_login_at IS NULL OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    password_reset_issued_at TEXT
        CHECK (password_reset_issued_at IS NULL OR password_reset_issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR password_reset_issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR password_reset_issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    language    TEXT,  -- NULL = inherit org_settings.default_language
    timezone    TEXT,  -- IANA zone name; NULL = inherit org_settings.default_timezone
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (tenant_id, email)
);

-- Operator identity for multi-tenant deployments. Empty in single-mode installs. system_admins
-- see only the control plane (tenant CRUD, instance settings, minimal user lookup) and never
-- tenant business data. Strictly separate from `users` — different lifecycle, no tenant_id.
-- personal-data: excluded — operator-plane identity with no tenant_id; the tenant self-service export serves tenant data subjects only
CREATE TABLE IF NOT EXISTS system_admins (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT
        CHECK (last_login_at IS NULL OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Mirrors users.account_status: 'active' (can log in), 'locked' (auto-lockout from
    -- throttling), 'disabled' (operator-set). Required for /api/v1/system/admins CRUD so
    -- operators can disable peers without hard-deleting and losing the audit-trail identity.
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','locked','disabled')),
    password_reset_issued_at TEXT
        CHECK (password_reset_issued_at IS NULL OR password_reset_issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR password_reset_issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR password_reset_issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    language    TEXT,  -- NULL = fall back to 'en'
    timezone    TEXT,  -- IANA zone name; NULL = fall back to 'UTC'
    -- MFA fields used by the ASP.NET Core Identity UserStore. Mirrors the same set on users.
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_authenticator_key TEXT,
    mfa_recovery_codes TEXT,
    security_stamp TEXT,
    -- Monotonic session-invalidation counter. Mirrors users.token_version; system JWTs
    -- embed this as the `tver` claim and are rejected when the stored version advances.
    token_version INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

CREATE TABLE IF NOT EXISTS packages (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,   -- 'pypi' | 'npm' | 'nuget' | 'maven' | 'rpm' | 'oci' | 'cargo' | 'golang' | 'apk'
    name        TEXT NOT NULL,
    purl_name   TEXT NOT NULL,   -- normalized per ecosystem
    is_proxy    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Upstream's declared latest version (npm dist-tags.latest / PyPI info.version), refreshed by
    -- the background upstream-metadata pass. NULL when no upstream baseline is known.
    upstream_latest_version    TEXT,
    upstream_latest_checked_at TEXT
        CHECK (upstream_latest_checked_at IS NULL OR upstream_latest_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR upstream_latest_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR upstream_latest_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Publish timestamp of upstream_latest_version, when the ecosystem's metadata carries a
    -- per-release timestamp (npm packument time[], PyPI release upload_time_iso_8601, NuGet
    -- registration leaf published, Maven maven-metadata.xml lastUpdated). NULL when the baseline
    -- itself is unknown or the ecosystem's metadata doesn't expose a timestamp. Drives the
    -- packages-list/detail "abandoned" (>= 365 days since publish) signal.
    upstream_latest_published_at TEXT
        CHECK (upstream_latest_published_at IS NULL OR upstream_latest_published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR upstream_latest_published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR upstream_latest_published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Per-package same-version-push override. NULL = inherit the org version_overwrite_policy.
    -- 'allow' = grant overwrite even when the org policy is 'exception' (blocked by default).
    -- 'block' = deny overwrite even when the org policy is 'allow' (allowed by default).
    -- Ignored when the org policy is 'block' (hard lockdown; no per-package escape hatch).
    same_version_push_override TEXT
                               CHECK (same_version_push_override IN ('allow','block')),
    -- Package-level metadata surfaced in the UI, captured at hosted publish and proxy
    -- first-fetch from the artifact manifest (npm package.json, PyPI METADATA, NuGet .nuspec,
    -- Maven .pom, Cargo.toml). All nullable; existing rows stay NULL until the next
    -- publish/fetch repopulates them (no historical backfill).
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
        CHECK (yanked_at IS NULL OR yanked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR yanked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR yanked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    first_fetch INTEGER NOT NULL DEFAULT 0,  -- 1 if this was a cache-miss proxy fetch
    last_used   TEXT    -- ISO 8601 UTC; updated on each download
        CHECK (last_used IS NULL OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Cumulative count of served downloads (every 'download' + 'first_fetch' event:
    -- proxy first-fetch, protocol-client pulls, and UI downloads). Monotonic; survives
    -- activity-log pruning so it remains an all-time total.
    download_count INTEGER NOT NULL DEFAULT 0,
    vuln_checked_at TEXT    -- ISO 8601 UTC; set after OSV vulnerability scan
        CHECK (vuln_checked_at IS NULL OR vuln_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR vuln_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR vuln_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
    published_at TEXT
        CHECK (published_at IS NULL OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Hex SHA-1 of the artefact bytes. Captured on every npm publish (the packument
    -- dist.shasum field uses SHA-1 by spec) and from upstream packuments on proxy first-fetch.
    -- NULL for PyPI / NuGet versions and for legacy rows pre-dating the column.
    checksum_sha1 TEXT,
    -- Upstream-published integrity hash, stored VERBATIM in upstream's native encoding so
    -- operators can copy-paste against the public registry's UI without re-encoding:
    --   npm   → 'sha512-{base64}' (the SRI form printed on npmjs.com)
    --   NuGet → '{base64}'        (packageHash as written in the registration leaf)
    --   PyPI  → '{hex}'           (sha256 from the #sha256= simple-index fragment)
    -- Algorithm column tags how to interpret the value. For hosted npm publishes the same
    -- pair carries the artefact's sha512 SRI ('sha512-sri') — the publisher's dist.integrity
    -- claim when the client sent one, otherwise computed server-side from the uploaded
    -- bytes — so the packument can emit dist.integrity. NULL for non-npm uploaded versions
    -- and for legacy rows pre-dating the column.
    upstream_integrity_value TEXT,
    upstream_integrity_algorithm TEXT,  -- 'sha256' | 'sha512-sri' | 'sha512-b64'
    -- Trailing path segment of blob_key. Populated at insert time by the repository so
    -- the PyPI/npm/NuGet file-download lookups can hit an equality index instead of the
    -- previous leading-wildcard LIKE on blob_key. NULL is reserved for legacy rows that
    -- pre-date the column; the additive backfill migration in SchemaInitializer fills
    -- them in from blob_key's last '/' segment.
    filename    TEXT,
    -- ISO 8601 UTC; set after the last upstream deprecation metadata refresh.
    -- NULL on rows that pre-date the deprecation refresh service or have never been checked.
    deprecation_checked_at TEXT
        CHECK (deprecation_checked_at IS NULL OR deprecation_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR deprecation_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR deprecation_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- ISO 8601 UTC; first time this version was observed REMOVED from the upstream registry
    -- (npm unpublish, PyPI delete, registry takedown). NULL = still published upstream.
    -- Distinct from deprecated (still published, advised against): revoked = gone entirely.
    -- Reset to NULL if the version reappears upstream. Set by DeprecationRefreshService.
    revoked_at TEXT
        CHECK (revoked_at IS NULL OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Operational-risk signal: count of upstream STABLE versions strictly newer than this one,
    -- using each ecosystem's native version ordering (NuGet.Versioning, PEP 440, semver, Maven
    -- ComparableVersion). NULL = unknown (hosted-only package with no upstream counterpart,
    -- air-gapped, unsupported ecosystem, or not yet refreshed) — rendered UNSCORED, never 0.
    -- Refreshed by DeprecationRefreshService and seeded on proxy first-fetch.
    versions_behind INTEGER,
    -- Supply-chain signal: 1 when the artefact ships an install/lifecycle script that runs
    -- automatically on install (npm preinstall/install/postinstall, a PyPI sdist setup.py,
    -- a NuGet tools install.ps1/init.ps1 or build .targets/.props). Captured at proxy
    -- first-fetch and hosted publish by ScriptDetectionService; drives the install-script
    -- block-gate arm. 0 on rows that pre-date the column and on artefacts with no script.
    has_install_script INTEGER NOT NULL DEFAULT 0,
    -- Discriminator describing which script kind fired, e.g. 'npm:postinstall',
    -- 'pypi:setup.py', 'nuget:install.ps1', 'nuget:msbuild'. NULL when has_install_script is 0.
    install_script_kind TEXT,
    -- Provenance/signature-verification outcome at proxy ingest: 'verified' (a pinned trust
    -- anchor produced a valid signature over the canonical signing payload), 'failed' (a
    -- signature was present but did not verify or chained to no pinned key), or 'unsigned' (the
    -- upstream published no signature). NULL when verification was not applicable (policy off,
    -- ecosystem without a verifier, hosted origin) or for rows that pre-date the column. Drives
    -- the provenance block-gate arm.
    provenance_status TEXT,
    -- Identity of the verifying signer (the trust-anchor keyid) when provenance_status is
    -- 'verified'. NULL for every other status.
    provenance_signer TEXT,
    -- Install-relevant manifest subset captured at hosted npm publish from the tarball's
    -- package.json (bin, dependencies, optionalDependencies, peerDependencies,
    -- peerDependenciesMeta, bundleDependencies, engines, os, cpu, libc, directories,
    -- _hasShrinkwrap), stored as one JSON object. Merged into the packument's per-version
    -- objects so npm/npx can resolve bin links and transitive dependencies. NULL for proxy
    -- rows (the upstream packument is served directly), for non-npm rows, and for hosted
    -- rows published before the column existed (those render the legacy minimal shape).
    manifest_json TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- ISO 8601 UTC; stamped when a same-version re-push overwrites this row's bytes.
    -- NULL means never overwritten, in which case the effective pushed date is created_at.
    updated_at  TEXT
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (package_id, version)
);

-- personal-data: included — the subject's personal access tokens
CREATE TABLE IF NOT EXISTS user_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings, e.g. ["publish:npm"].
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at  TEXT
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_used_at TEXT    -- updated (throttled ~60s) when the token authenticates a request.
        CHECK (last_used_at IS NULL OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

CREATE TABLE IF NOT EXISTS service_tokens (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    capabilities TEXT,           -- JSON array of capability strings.
    description TEXT,            -- optional free-text label set at creation time.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at  TEXT
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_used_at TEXT    -- updated (throttled ~60s) when the token authenticates a request.
        CHECK (last_used_at IS NULL OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

-- personal-data: included — invites the subject created, and invites addressed to their email
CREATE TABLE IF NOT EXISTS invites (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner','auditor')),
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    accepted_at TEXT
        CHECK (accepted_at IS NULL OR accepted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR accepted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR accepted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
-- Prevent duplicate pending invites: only one unaccepted invite per (org, email) at a time.
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    consumed_at TEXT
        CHECK (consumed_at IS NULL OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    consumed_at TEXT
        CHECK (consumed_at IS NULL OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_ect_user_pending ON email_change_tokens(user_id) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS allowlist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    purl_pattern TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, purl_pattern)
);

CREATE TABLE IF NOT EXISTS blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,  -- regex matched against the full package PURL
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ecosystem, pattern)
);

-- Review queue for policy-gate blocks. Every automatic block (deprecated, release-age,
-- malicious, KEV, EPSS, vuln-score — not manual blocks, which are already a human decision)
-- upserts a pending row here while the request still returns 403, so an org admin can review
-- and approve (sets the version's manual allow override) or deny (sets manual block).
-- UNIQUE(org_id, purl) is the state machine: repeat blocks refresh the pending row via
-- ON CONFLICT DO UPDATE ... WHERE state='pending' and never resurrect a decided one.
-- package_version_id is NULL for first-fetch blocks where no version row exists yet; an
-- approved version-less row unblocks the next first fetch of that purl.
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
        CHECK (decided_at IS NULL OR decided_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR decided_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR decided_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    note                TEXT,           -- optional reviewer note recorded with the decision
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, purl)
);

CREATE INDEX IF NOT EXISTS idx_quarantine_org_state ON quarantine(org_id, state, updated_at DESC);

-- Per-tenant alert center. One row per raised occurrence of a supply-chain signal (a new
-- quarantine review item, or a vulnerability whose severity meets the org's threshold).
-- UNIQUE(org_id, type, source_ref) is the entire dedup mechanism: raising re-inserts the same
-- natural key and the conflict is a no-op, so a repeat trigger never produces a second alert.
-- source_ref is type-specific: the quarantine row id for 'quarantine_new', or
-- "vulnId:ecosystem:packageName" for 'vuln_severity' (one alert per advisory-per-package, not
-- per version). state is a single shared active/dismissed flag — all admins in an org see and
-- dismiss the same list. slack_status/slack_error and email_status/email_error record the
-- terminal outcome of the async Slack/email delivery attempts; they never gate whether the alert
-- itself is visible in the panel.
CREATE TABLE IF NOT EXISTS alert (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    type         TEXT NOT NULL CHECK (type IN ('quarantine_new', 'vuln_severity')),
    severity     TEXT,           -- CRITICAL | HIGH | MEDIUM | LOW | NULL (quarantine alerts carry no CVSS severity)
    source_ref   TEXT NOT NULL,  -- dedup key body; see table comment for the per-type shape
    ecosystem    TEXT,
    purl         TEXT,
    title        TEXT NOT NULL,
    detail       TEXT,           -- JSON detail, same convention as quarantine.detail
    state        TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'dismissed')),
    dismissed_by TEXT REFERENCES users(id),
    dismissed_at TEXT
        CHECK (dismissed_at IS NULL OR dismissed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR dismissed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR dismissed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    slack_status TEXT,           -- 'sent' | 'failed' | NULL (Slack off, or delivery not yet attempted)
    slack_error  TEXT,
    email_status TEXT,           -- 'sent' | 'failed' | NULL (email off, or delivery not yet attempted)
    email_error  TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, type, source_ref)
);
CREATE INDEX IF NOT EXISTS idx_alert_org_state ON alert(org_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_dismissed_by ON alert(dismissed_by);

-- One row per org holding the alert-raising toggles, the vulnerability severity floor, and the
-- optional Slack/email delivery channels. An absent row means the all-on/Slack-off/email-off
-- defaults below — there is no backfill migration; every org reads through the same default path
-- via AlertSettingsRepository. slack_webhook_url and email_smtp_password are envelope-encrypted at
-- rest (enc:v1: prefix) and require DEPENDABLY_MASTER_KEY to be configured before they can be
-- stored. The slack_consecutive_failures/slack_failing_since/slack_last_error/slack_last_status
-- columns (and their email_ counterparts) mirror webhook_subscription's failure-health model so
-- AlertSlackQueue/AlertEmailQueue can reuse the same auto-disable arithmetic (20 consecutive
-- failures or 48h of sustained failure). email_inherit_instance selects between the instance-level
-- SMTP transport (InstanceSmtpConfig) and the org's own email_smtp_* columns; when neither
-- resolves, the channel is silently disabled rather than falling back to some other transport.
CREATE TABLE IF NOT EXISTS alert_settings (
    org_id                     TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    quarantine_alerts_enabled INTEGER NOT NULL DEFAULT 1,
    vuln_alerts_enabled       INTEGER NOT NULL DEFAULT 1,
    vuln_min_severity         TEXT NOT NULL DEFAULT 'HIGH' CHECK (vuln_min_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    slack_enabled              INTEGER NOT NULL DEFAULT 0,
    slack_webhook_url          TEXT,   -- enc:v1: envelope-encrypted; NULL when Slack is disabled/unset
    slack_last_delivery_at     TEXT
        CHECK (slack_last_delivery_at IS NULL OR slack_last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR slack_last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR slack_last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    slack_last_status          TEXT,   -- 'ok' | 'failed' | NULL (never delivered)
    slack_consecutive_failures INTEGER NOT NULL DEFAULT 0,
    slack_failing_since        TEXT
        CHECK (slack_failing_since IS NULL OR slack_failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR slack_failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR slack_failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    slack_last_error           TEXT,
    email_enabled              INTEGER NOT NULL DEFAULT 0,
    email_inherit_instance     INTEGER NOT NULL DEFAULT 1,
    email_recipients           TEXT,   -- comma-separated; NULL/empty = nothing sends
    email_smtp_host            TEXT,
    email_smtp_port            INTEGER,
    email_smtp_security        TEXT CHECK (email_smtp_security IS NULL OR email_smtp_security IN ('starttls', 'ssl', 'none')),
    email_smtp_username        TEXT,
    email_smtp_password        TEXT,   -- enc:v1: envelope-encrypted; write-only, NULL when unset
    email_smtp_from            TEXT,
    email_last_delivery_at     TEXT
        CHECK (email_last_delivery_at IS NULL OR email_last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR email_last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR email_last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    email_last_status          TEXT,   -- 'ok' | 'failed' | NULL (never delivered)
    email_consecutive_failures INTEGER NOT NULL DEFAULT 0,
    email_failing_since        TEXT
        CHECK (email_failing_since IS NULL OR email_failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR email_failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR email_failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    email_last_error           TEXT,
    created_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

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
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (org_id, ecosystem, name)
);

-- NuGet symbol-server (SSQP) index. Maps a Portable-PDB debug-id key to the exact PDB entry
-- inside a stored .snupkg so a debugger can fetch a single PDB by GUID+age via
-- GET /nuget/symbols/{pdb}/{key}/{pdb}. Populated on symbol push (one row per contained PDB).
-- ssqp_key and pdb_filename are stored lowercased and matched case-insensitively per the SSQP
-- protocol. Tenant-scoped on org_id; each row references the owning package_versions row.
CREATE TABLE IF NOT EXISTS nuget_symbol_index (
    id                 TEXT PRIMARY KEY,
    org_id             TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    package_version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    pdb_filename       TEXT NOT NULL,   -- lowercased PDB file name (e.g. mylib.pdb)
    ssqp_key           TEXT NOT NULL,   -- lowercased 40-hex key: GUID (N format) + 'ffffffff' age
    snupkg_blob_key    TEXT NOT NULL,   -- blob key of the stored .snupkg holding this PDB
    entry_path         TEXT NOT NULL,   -- path of the PDB entry within the .snupkg ZIP
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ssqp_key, pdb_filename, package_version_id)
);
-- Primary SSQP resolution path: (org, key, filename) lookup.
CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_lookup ON nuget_symbol_index(org_id, ssqp_key, pdb_filename);
-- FK-column index so cascade delete on package_versions does not table-scan.
CREATE INDEX IF NOT EXISTS idx_nuget_symbol_index_pv ON nuget_symbol_index(package_version_id);

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
    ecosystem   TEXT NOT NULL,   -- 'rpm' | 'npm' | 'nuget' | 'pypi' | 'maven' | 'apk'
    anchor_kind TEXT NOT NULL,   -- 'pgp' | 'spki' | 'x509' | 'sigstore_root' | 'trusted_publisher' | 'rekor_key' | 'rsa'
    key_id      TEXT,            -- optional key fingerprint / subject for display
    material    TEXT NOT NULL,   -- public key material: armored PGP / base64 DER / PEM / JSON
    label       TEXT,            -- operator-supplied display label
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    created_by  TEXT             -- user id of the operator who added this anchor
);
-- FK-column index: cascade deletes on orgs scan this table without it.
-- Also the hot read path: resolve all anchors for (org, ecosystem) at verify time.
CREATE INDEX IF NOT EXISTS idx_signature_trust_anchor_org_eco
    ON signature_trust_anchor(org_id, ecosystem);

-- personal-data: included — security/config rows attributed to the subject (source_ip history)
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    -- 'tenant' for per-tenant business events; 'system' for operator events (tenant.created,
    -- tenant.deleted, tenant.restored, tenant.hard_deleted, system_admin.password_reset, etc).
    -- /api/v1/system/audit filters by scope='system'; tenant audit endpoints filter by
    -- scope='tenant' AND org_id = caller's tid.
    scope       TEXT NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','system')),
    -- No FK to orgs: rows are retained for forensic purposes after an org is deleted.
    org_id      TEXT,
    actor_id    TEXT,
    -- Discriminator for actor_id: 'user' (users.id) or 'service' (service_tokens.id). NULL
    -- means anonymous (only possible on pull paths when AnonymousPull=1) OR a legacy row
    -- written before this column existed — the list query falls back to a users join for
    -- back-compat. Set explicitly by every new write so service-token actors render as
    -- 'service:<name>' instead of being indistinguishable from anonymous.
    actor_kind  TEXT,
    action      TEXT NOT NULL,
    ecosystem   TEXT,
    purl        TEXT,
    detail      TEXT,           -- JSON
    source_ip   TEXT,           -- canonical remote IP (IPv4-mapped IPv6 collapsed); null for background paths
    -- Millisecond precision, matching AuditRepository's NowMs() writer: SIEM's since/until window
    -- and pagination cursor (ListAuthEventsAsync) compare this column at millisecond precision,
    -- so a second-precision DEFAULT-written row would silently fall outside every future window.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_audit_log_scope ON audit_log(scope, created_at DESC);
-- Retention sweep index: RetentionService pseudonymizes then deletes rows by created_at age
-- across every scope, so the sweep needs a scope-independent index on the age column.
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- personal-data: included — activity-feed rows attributed to the subject (source_ip history)
CREATE TABLE IF NOT EXISTS activity (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,  -- 'pypi' | 'npm' | 'nuget' for package events; 'auth' for login/lockout
    purl        TEXT,           -- null for non-package events (auth)
    event_type  TEXT NOT NULL,  -- 'push' | 'pull' | 'first_fetch' | 'delete' | 'vuln_scan' | 'login.success' | 'login.failure' | 'login.locked'
    actor_id    TEXT,
    actor_kind  TEXT,           -- see audit_log.actor_kind; 'user' | 'service' | NULL
    detail      TEXT,
    source_ip   TEXT,           -- captured for HTTP-originated events (downloads, push, delete, blocked_*); null for background paths
    -- Millisecond precision, matching AuditRepository.LogActivityAsync's NowMs() writer: the
    -- activity feed's since window (OrgAuditController) compares this column at millisecond
    -- precision.
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
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
        CHECK (published_at IS NULL OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    modified_at     TEXT
        CHECK (modified_at IS NULL OR modified_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR modified_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR modified_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    fetched_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (fetched_at IS NULL OR fetched_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR fetched_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR fetched_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Threat-feed enrichment, refreshed by ThreatFeedRefreshService against the advisory's CVE
    -- aliases. is_kev = 1 when any alias is in the CISA Known Exploited Vulnerabilities catalog
    -- (recomputed each pass, so catalog removals clear it). epss_score is the maximum FIRST.org
    -- EPSS exploitation probability (0..1) across the aliases; NULL = no alias known to EPSS or
    -- not yet checked. The *_checked_at stamps record the last refresh per feed.
    is_kev          INTEGER NOT NULL DEFAULT 0,
    kev_checked_at  TEXT
        CHECK (kev_checked_at IS NULL OR kev_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR kev_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR kev_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    epss_score      REAL,
    epss_checked_at TEXT
        CHECK (epss_checked_at IS NULL OR epss_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR epss_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR epss_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

CREATE TABLE IF NOT EXISTS package_version_vulns (
    -- Surrogate PK so cache_artifact-owned rows can exist without a package_versions FK.
    id                  TEXT PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (checked_at IS NULL OR checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
        CHECK (locked_until IS NULL OR locked_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR locked_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR locked_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_attempt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (last_attempt IS NULL OR last_attempt GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_attempt GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_attempt GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
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
        CHECK (window_start IS NULL OR window_start GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR window_start GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR window_start GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    send_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email_hash, purpose)
);

CREATE INDEX IF NOT EXISTS idx_packages_org_ecosystem ON packages(org_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_vulns_ecosystem_pkg ON vulnerabilities(ecosystem, package_name);
-- vuln_id FK index: cascade deletes on vulnerabilities scan the child table without this.
-- package_version_id and cache_artifact_id are covered by the partial unique indexes above.
CREATE INDEX IF NOT EXISTS idx_pkg_version_vulns_vuln ON package_version_vulns(vuln_id);
CREATE INDEX IF NOT EXISTS idx_package_versions_package ON package_versions(package_id);
-- Hot path: PyPI/npm/NuGet downloads resolve a file to a version row by trailing filename.
-- A leading-wildcard `blob_key LIKE '%/' || filename` lookup cannot be served from any
-- index, forcing a full scan of package_versions on every download. This index serves the
-- equality lookup on the normalized `filename` column instead.
CREATE INDEX IF NOT EXISTS idx_package_versions_filename ON package_versions(filename);
CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_org ON activity(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_tokens_hash ON user_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_service_tokens_hash ON service_tokens(token_hash);
-- FK-column indexes: SQLite and Postgres do not auto-index foreign key columns; without these,
-- cascade deletes on the parent table cause full child-table scans. Indexes for tables
-- defined later in this file are placed adjacent to those tables below.
CREATE INDEX IF NOT EXISTS idx_user_tokens_org ON user_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_user_tokens_user ON user_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_service_tokens_org ON service_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_version ON quarantine(package_version_id);
CREATE INDEX IF NOT EXISTS idx_quarantine_decided_by ON quarantine(decided_by);
CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by);
CREATE INDEX IF NOT EXISTS idx_reserved_namespace_created_by ON reserved_namespace(created_by);

-- License governance
CREATE TABLE IF NOT EXISTS package_version_licenses (
    id                  TEXT PRIMARY KEY,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    license_spdx        TEXT NOT NULL,                  -- SPDX identifier e.g. MIT, Apache-2.0
    source              TEXT NOT NULL DEFAULT 'upstream',   -- 'upstream' | 'sbom' | 'manual'
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, license_spdx)
);

CREATE TABLE IF NOT EXISTS license_blocklist (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    license_spdx TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, license_spdx)
);

CREATE INDEX IF NOT EXISTS idx_pkg_version_licenses ON package_version_licenses(package_version_id);

-- RPM metadata. One row per artifact carrying everything the RPM header parser pulls from
-- a .rpm upload. Arrays (requires/provides/files/changelogs) are stored as JSON strings so
-- the repodata generator can re-emit them as XML without a second query roundtrip.
-- Each row is owned by exactly one package_versions row (owner_kind='package_version') or
-- one cache_artifact row (owner_kind='cache_artifact'); the respective FK is set and the
-- other is NULL. Partial unique indexes enforce per-arm dedup.
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
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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

-- Repodata generation state. One row per (org, arch); dirty flag drives the async
-- rebuild service. generation increments each rebuild so concurrent rebuilds detect
-- stale generations and back off without rewriting the same arch twice.
CREATE TABLE IF NOT EXISTS rpm_repodata_state (
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    arch          TEXT NOT NULL,
    last_built_at TEXT
        CHECK (last_built_at IS NULL OR last_built_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_built_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_built_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    dirty         INTEGER NOT NULL DEFAULT 1,
    generation    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, arch)
);

-- Maven: one package_versions row per (groupId:artifactId, version) but multiple files
-- per version (JAR + POM + sources JAR + javadoc + checksum sidecars). This table tracks
-- the per-file extension/classifier/blob mapping so the controller can answer arbitrary
-- file-suffix requests without re-parsing PURLs at the DB layer.
-- Each row is owned by exactly one package_versions row (owner_kind='package_version') or
-- one cache_artifact row (owner_kind='cache_artifact'); the respective FK is set and the
-- other is NULL. Partial unique indexes enforce per-arm dedup.
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
    origin              TEXT NOT NULL DEFAULT 'uploaded',  -- 'uploaded' | 'proxy'
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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

-- PyPI: one package_versions row per (name, version) but multiple distribution files per
-- version (wheel + sdist + per-platform wheels), mirroring how pypi.org stores a release.
-- Each hosted file maps to its own blob with its own filename/size/checksum so the simple
-- index lists every file and /packages/{file} serves exactly the blob whose filename was
-- requested. Hosted-only: proxy-origin PyPI files live in cache_artifact. The parent
-- package_versions row keeps the version identity (version, purl) and carries the SUM of
-- its files' sizes so tenant quota accounting stays symmetric on delete. org_id is
-- denormalized from the owning package (npm_dist_tags precedent) so the download-by-filename
-- lookup is org-filtered without a second join.
CREATE TABLE IF NOT EXISTS package_version_files (
    id                  TEXT PRIMARY KEY,
    package_version_id  TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    filename            TEXT NOT NULL,
    blob_key            TEXT NOT NULL,
    size_bytes          INTEGER NOT NULL DEFAULT 0,
    checksum_sha256     TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (package_version_id, filename)
);
-- The UNIQUE(package_version_id, filename) index covers the version FK (leftmost member);
-- this one covers the org FK cascade and the org-scoped filename resolution on download.
CREATE INDEX IF NOT EXISTS idx_package_version_files_org_filename
    ON package_version_files (org_id, filename);

-- OCI / Docker registry storage. Manifests and blobs are both content-addressed; this
-- table is the metadata index. Bytes live under BlobKeys.OciBlob in the blob store.
-- media_type tags whether the row is a manifest (manifest.v2+json,
-- vnd.oci.image.index.v1+json, etc.) or a layer (vnd.oci.image.layer.v1.tar+gzip etc.).
-- Tenant binding: every lookup MUST filter on org_id; manifests / layers can be shared
-- across repos within an org but never across orgs.
CREATE TABLE IF NOT EXISTS oci_blobs (
    digest        TEXT NOT NULL,           -- '{algo}:{hex}'
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    media_type    TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    blob_key      TEXT NOT NULL,           -- BlobKeys.OciBlob(...)
    cached_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (cached_at IS NULL OR cached_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR cached_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR cached_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    upstream_checked_at TEXT
        CHECK (upstream_checked_at IS NULL OR upstream_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR upstream_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR upstream_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    origin        TEXT NOT NULL DEFAULT 'uploaded',  -- 'uploaded' (local push) or 'proxy' (upstream cache)
    config_digest       TEXT,    -- image manifests only: the config blob digest parsed from the manifest body
    license_spdx        TEXT,    -- SPDX expression from the config's org.opencontainers.image.licenses label
    license_checked_at  TEXT    -- stamped when the config bytes were read (label present or not); NULL = config not yet seen
        CHECK (license_checked_at IS NULL OR license_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR license_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR license_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (digest, org_id)
);
CREATE INDEX IF NOT EXISTS idx_oci_blobs_org ON oci_blobs(org_id);
CREATE INDEX IF NOT EXISTS idx_oci_blobs_org_config_digest ON oci_blobs(org_id, config_digest);

-- tag → digest mapping. Each tag points at exactly one manifest digest at a time.
CREATE TABLE IF NOT EXISTS oci_tags (
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    -- No FK to oci_blobs: a tag may validly dangle to a GC'd or not-yet-stored manifest.
    -- Dangling tags are resolved lazily; the OCI pull path re-fetches the manifest on miss.
    digest      TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_revalidated TEXT    -- per-tag TTL revalidation timestamp; NULL forces a re-check on first access
        CHECK (last_revalidated IS NULL OR last_revalidated GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_revalidated GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_revalidated GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (org_id, repository, tag)
);
CREATE INDEX IF NOT EXISTS idx_oci_tags_repository ON oci_tags(org_id, repository);

-- manifest → referenced-blob edges: the reference graph an OCI image forms over oci_blobs.
-- An image manifest references its config blob and every layer; an image index references its
-- child manifests. Layers are shared by design (content-addressing is the point), across
-- repositories and across images, so "is this layer still needed" is a graph question that
-- oci_blobs alone cannot answer — the row records that a digest exists for the org, not who
-- depends on it. Without these edges the only safe policy is to never reclaim an OCI blob.
--
-- Recorded on both write paths (hosted push and proxy pull) as the manifest body is parsed, and
-- backfilled for manifests stored before the graph existed by re-parsing their bytes.
--
-- Absence is not "no references": a manifest with no rows here is one whose closure is unknown,
-- and callers must treat it as un-evictable rather than as a leaf. That distinction is what keeps
-- an incomplete graph from authorizing a delete.
--
-- No FK on either digest: edges legitimately outlive the blobs they name (a partially-pulled
-- index records children before their bytes arrive), and a dangling edge is harmless — it can
-- only ever make the refcount more conservative.
CREATE TABLE IF NOT EXISTS oci_manifest_blobs (
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    manifest_digest TEXT NOT NULL,   -- the referencing manifest / index
    blob_digest     TEXT NOT NULL,   -- config, layer, or child manifest it references
    recorded_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (recorded_at IS NULL OR recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (org_id, manifest_digest, blob_digest)
);
-- The refcount direction: "which manifests still reference this blob". Leftmost-column coverage
-- for the org FK cascade comes from the PK.
CREATE INDEX IF NOT EXISTS idx_oci_manifest_blobs_org_blob
    ON oci_manifest_blobs(org_id, blob_digest);

-- In-progress OCI blob upload sessions (push). A `docker push` opens a session via
-- POST /v2/{name}/blobs/uploads/, streams the blob via PATCH chunks, then finalizes with
-- PUT ...?digest=. Blob bytes are staged on local disk (PROXY_STAGING_PATH) keyed by
-- upload_id; this table carries the tenant binding (so a session can only be advanced by the
-- org that opened it) and the running byte count used for cumulative upload-size enforcement.
-- Rows are deleted on finalize or abort.
CREATE TABLE IF NOT EXISTS oci_uploads (
    upload_id      TEXT NOT NULL,
    org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repository     TEXT NOT NULL,
    staging_path   TEXT NOT NULL,
    received_bytes INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
    -- Copyleft strength is NOT published by SPDX; sourced from a curated overlay
    -- (BlueOak/ChooseALicense/FSF). Identifiers absent from the overlay get 'unclassified'.
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
    expires_at  TEXT NOT NULL    -- ISO 8601 UTC; row can be deleted after this time
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_seen_at TEXT
        CHECK (last_seen_at IS NULL OR last_seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at  TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_token ON mfa_trusted_devices(token_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_user ON mfa_trusted_devices(user_id, realm);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_tenant ON mfa_trusted_devices(tenant_id);

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
    last_test_at        TEXT
        CHECK (last_test_at IS NULL OR last_test_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_test_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_test_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_test_email     TEXT,
    last_test_claims    TEXT,                          -- JSON array of {type,values[]} from latest test
    idp_signing_cert_override TEXT,                    -- base64 X.509 admin-pinned override; sole trust anchor when set
    role_attribute      TEXT,                          -- claim type to read roles from; NULL = built-in list
    role_mapping        TEXT,                          -- JSON object {"<idp value>": "owner|admin|member|auditor"}
    default_role        TEXT NOT NULL DEFAULT 'member', -- role when no mapping matches
    -- Opt-in ceiling raise for IdP-driven role assignment: 0 = the IdP may auto-assign
    -- member/auditor only; 1 = the IdP may also assign admin. 'owner' is never IdP-assignable.
    idp_can_assign_admin INTEGER NOT NULL DEFAULT 0,
    -- Stage of the last emitted cert-expiry alert for this tenant's effective IdP signing cert.
    -- NULL = no alert emitted yet (or cert changed/cleared since the last alert). Tracks whether
    -- the daily sweep needs to emit a new event for the current expiry window ('30','14','7','1',
    -- 'expired'). Reset to NULL whenever the metadata cert or the override cert is replaced.
    cert_expiry_alert_stage TEXT,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

-- One-shot correlation-id store for SAML admin-test runs. The signed test cookie carries a
-- cid (Guid) that maps back to a row here; ACS atomically stamps consumed_at on first use,
-- so a leaked or replayed cookie can't drive a second IdP round-trip. Rows expire after the
-- cookie TTL (15 minutes) and are GC'd by the retention pass.
-- personal-data: excluded — actor_id is a provenance stamp on org IdP-configuration diagnostics
CREATE TABLE IF NOT EXISTS saml_test_runs (
    cid          TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor_id     TEXT,
    issued_at    TEXT NOT NULL
        CHECK (issued_at IS NULL OR issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at   TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    consumed_at  TEXT
        CHECK (consumed_at IS NULL OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_saml_test_runs_expires ON saml_test_runs(expires_at);
-- FK-column index: tenant_id is not the PK; without this, cascade deletes on orgs scan the table.
CREATE INDEX IF NOT EXISTS idx_saml_test_runs_tenant ON saml_test_runs(tenant_id);

-- One-time-use store binding SP-initiated AuthnRequests to their responses. /saml/login inserts
-- the AuthnRequest id; ACS consumes it by matching the response's InResponseTo. An unsolicited
-- (IdP-initiated) or replayed response has no consumable pending row and is rejected — the SAML
-- analogue of an OAuth state check. Rows expire after the request TTL and are pruned on write.
CREATE TABLE IF NOT EXISTS saml_pending_requests (
    request_id   TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    issued_at    TEXT NOT NULL
        CHECK (issued_at IS NULL OR issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR issued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at   TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    consumed_at  TEXT
        CHECK (consumed_at IS NULL OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_saml_pending_requests_expires ON saml_pending_requests(expires_at);
-- FK-column index: tenant_id is not the PK; without this, cascade deletes on orgs scan the table.
CREATE INDEX IF NOT EXISTS idx_saml_pending_requests_tenant ON saml_pending_requests(tenant_id);

-- Replay guard for production SAML logins. ACS records each accepted assertion's signed ID
-- (per tenant) the first time it is seen; presenting the same assertion again within its
-- validity window finds the row already present and is rejected. expires_at tracks the
-- assertion's NotOnOrAfter so the guard remembers it at least as long as it could be replayed;
-- rows are pruned on write once expired. The key is (tenant_id, assertion_id): each tenant has
-- exactly one IdP (tenant_saml_config is keyed by org_id), so idp_entity_id is recorded for
-- audit but is intentionally not part of the key.
CREATE TABLE IF NOT EXISTS saml_consumed_assertions (
    tenant_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    assertion_id  TEXT NOT NULL,
    idp_entity_id TEXT,
    consumed_at   TEXT NOT NULL
        CHECK (consumed_at IS NULL OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR consumed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at    TEXT NOT NULL
        CHECK (expires_at IS NULL OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (tenant_id, assertion_id)
);
CREATE INDEX IF NOT EXISTS idx_saml_consumed_assertions_expires ON saml_consumed_assertions(expires_at);

-- IdP-issued identities linked to local users. Identity is (idp_entity_id, nameid) — never
-- email. NameID is the IdP's stable subject identifier; email can change in the IdP without
-- breaking login. Multiple IdPs per user is supported by design (UNIQUE allows many rows
-- per user_id). email_snapshot is recorded for audit/UX only.
-- personal-data: included — the subject's linked SAML identities (NameID, email snapshot)
CREATE TABLE IF NOT EXISTS external_identities (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idp_entity_id   TEXT NOT NULL,
    nameid          TEXT NOT NULL,
    email_snapshot  TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_login_at   TEXT
        CHECK (last_login_at IS NULL OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_login_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, idp_entity_id, nameid)
);
CREATE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(user_id);

-- ── Multitenant architecture ─────────────────────────────────────────
-- New tables and columns introduced by the multitenant architecture roadmap. Each
-- table here keeps the org_id-first composite-index convention from older tables.

-- Per-tenant package name claims. Three states: unclaimed (default; reject local writes),
-- local_only (proxy disabled, local writes accepted), mixed (both, local wins on collision).
-- personal-data: excluded — created_by is a provenance stamp on org package-name claim governance
CREATE TABLE IF NOT EXISTS claim (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('unclaimed','local_only','mixed')),
    reason      TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    deleted_at  TEXT
        CHECK (deleted_at IS NULL OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS idx_claim_org_state ON claim (org_id, state);
-- FK-column index: created_by references users(id) but is not covered by any other index.
CREATE INDEX IF NOT EXISTS idx_claim_created_by ON claim(created_by);

-- Append-only history of claim transitions. Forensic record + UI history view.
-- personal-data: excluded — actor_id is a provenance stamp on an org-owned claim-history row
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
        CHECK (occurred_at IS NULL OR occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_claim_history_org_time ON claim_history (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_claim_history_claim ON claim_history (claim_id, occurred_at DESC);
-- FK-column index: actor_id references users(id) but is not covered by any other index.
CREATE INDEX IF NOT EXISTS idx_claim_history_actor ON claim_history(actor_id);

-- Name-ownership binding. The first hosted publisher of a (org, ecosystem, purl_name) is
-- recorded here as its owner (trust-on-first-use). When PUBLISH_NAME_BINDING enforcement is
-- on, later hosted publishes to the same name are authorized against this owner, so a token
-- scoped only to publish an ecosystem cannot seize a name a different principal already owns.
-- owner_id is a users.id (owner_kind='user') or a service_tokens.id (owner_kind='service') —
-- no FK, because the referent table depends on owner_kind (mirrors audit_log.actor_id).
-- The row is keyed to the org, never to the packages row, so it SURVIVES deletion of the last
-- hosted version: it is the tombstone that stops a deleted internal-only name from silently
-- reverting to upstream (public-registry) resolution — the dependency-confusion resurrection
-- guard read by ClaimResolver. An explicit claim overrides it (operator escape hatch).
CREATE TABLE IF NOT EXISTS package_name_binding (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    purl_name   TEXT NOT NULL,   -- canonical PurlNormalizer identity, matching packages.purl_name
    owner_kind  TEXT NOT NULL CHECK (owner_kind IN ('user','service')),
    owner_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ecosystem, purl_name)
);
-- Point lookups filter (org_id, ecosystem, purl_name); the UNIQUE index (org_id leftmost)
-- covers both them and the org-cascade delete, so no additional index is needed.

-- Additional principals explicitly permitted to publish to an already-bound name. A grant is
-- the deliberate operator opt-in that lets a second token/user co-publish a name owned by a
-- different principal (a rotated CI token, or a shared package). Keyed like the binding;
-- grantee_id/grantee_kind identify the co-publisher the same way owner_id/owner_kind do.
-- personal-data: excluded — created_by is a provenance stamp on an org-owned authorization row
CREATE TABLE IF NOT EXISTS package_name_grant (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    purl_name     TEXT NOT NULL,
    grantee_kind  TEXT NOT NULL CHECK (grantee_kind IN ('user','service')),
    grantee_id    TEXT NOT NULL,
    created_by    TEXT REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ecosystem, purl_name, grantee_kind, grantee_id)
);
-- Grant lookups filter (org_id, ecosystem, purl_name); the UNIQUE index (that prefix
-- leftmost) covers them and the org-cascade delete.
-- FK-column index: created_by references users(id) but is not covered by any other index.
CREATE INDEX IF NOT EXISTS idx_package_name_grant_created_by ON package_name_grant(created_by);

-- Version-granular delete tombstone. One row per (org, ecosystem, purl_name, version) whose
-- hosted version row has been hard-deleted, so the coordinate is remembered after the
-- package_versions row (and possibly its parent packages row) is gone. The publish dedup gate
-- reads it: a republish of a tombstoned coordinate is refused under exactly the policy that
-- would refuse an overwrite of the live version, so delete-then-republish cannot smuggle
-- different bytes past an immutable-version policy. Distinct from package_name_binding, which
-- is name-granular and answers "who owns this name"; this is version-granular and answers
-- "have these coordinates already been spent". Rows are recorded on the interactive hosted
-- version-delete path only — proxy/cache-plane evictions and retention GC leave no tombstone.
-- content_hash carries the digest of the removed artifact so an operator investigating a
-- refused republish can tell a re-upload of the same bytes from a substitution.
CREATE TABLE IF NOT EXISTS package_version_tombstone (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    purl_name     TEXT NOT NULL,   -- canonical PurlNormalizer identity, matching packages.purl_name
    version       TEXT NOT NULL,
    content_hash  TEXT,            -- sha256 hex of the deleted artifact; NULL when unrecorded
    deleted_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (deleted_at IS NULL OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR deleted_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ecosystem, purl_name, version)
);
-- Point lookups filter (org_id, ecosystem, purl_name, version); the UNIQUE index (org_id
-- leftmost) covers both them and the org-cascade delete, so no additional index is needed.

-- Global shared proxy-cache index. One row per (ecosystem, name, version, filename).
-- No tenant column: the artifact is content-addressed and shared across tenants.
-- last_accessed_at drives LRU eviction; per-tenant access lives in tenant_artifact_access.
-- purl is the canonical package identity for cross-ecosystem lookups; no UNIQUE constraint
-- because Maven maps one purl to many filenames (jar + pom + sources + javadoc sidecars).
-- Supply-chain columns (provenance, install_script, vuln) are reserved capacity: written
-- at ingest but not yet read by any query in community. See community/enterprise boundary rule.
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
    first_cached_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (first_cached_at IS NULL OR first_cached_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR first_cached_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR first_cached_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_accessed_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (last_accessed_at IS NULL OR last_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Canonical PURL for this artifact. No UNIQUE: Maven maps one purl to many filenames.
    purl                TEXT,
    -- Hex SHA-1 of the artifact bytes (npm packument shasum field uses SHA-1 by spec).
    checksum_sha1       TEXT,
    -- ISO 8601 UTC; upstream first-publish timestamp captured at ingest. NULL when unavailable.
    published_at        TEXT
        CHECK (published_at IS NULL OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR published_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Upstream deprecation message when set; NULL when not deprecated.
    deprecated          TEXT,
    -- ISO 8601 UTC; last time the deprecation state was refreshed from upstream.
    deprecation_checked_at TEXT
        CHECK (deprecation_checked_at IS NULL OR deprecation_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR deprecation_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR deprecation_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- ISO 8601 UTC; first time this version was observed REMOVED from the upstream registry.
    -- NULL = still published upstream. Reset to NULL if the version reappears. Distinct from
    -- deprecated (still published, advised against). Set by DeprecationRefreshService.
    revoked_at          TEXT
        CHECK (revoked_at IS NULL OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Operational-risk signal: count of upstream STABLE versions strictly newer than this one.
    -- See package_versions.versions_behind for the full rationale; NULL = unknown, never 0.
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
        CHECK (vuln_checked_at IS NULL OR vuln_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR vuln_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR vuln_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- ISO 8601 UTC; set after the last license-extraction pass against this artifact. NULL =
    -- never scanned for licenses. Stamped by LicenseBackfillService so artifacts ingested
    -- before ingest-time license capture existed are extracted exactly once, and a
    -- persistently-unparseable artifact is not rescanned forever.
    license_checked_at  TEXT
        CHECK (license_checked_at IS NULL OR license_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR license_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR license_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- JSON install-manifest subset (dependencies/optionalDependencies/bin/engines), same shape as
    -- package_versions.manifest_json. Populated at npm proxy first-fetch from the tarball's
    -- package.json; NULL for artifacts cached before ingest-time capture existed (backfilled lazily
    -- on next fetch) and for every non-npm ecosystem.
    manifest_json       TEXT,
    UNIQUE (ecosystem, name, version, filename)
);
CREATE INDEX IF NOT EXISTS idx_cache_artifact_lru ON cache_artifact (last_accessed_at);
CREATE INDEX IF NOT EXISTS idx_cache_artifact_purl ON cache_artifact (purl);

-- Per-tenant access tracking on the shared cache. Answers "which tenants pulled X" for
-- vulnerability response. Upserted on every cache hit and lazy fetch. Per-tenant policy
-- state (manual_block_state, yanked) mirrors the package_versions columns but applies
-- to proxy-origin artifacts before a version row exists; reserved capacity in community.
CREATE TABLE IF NOT EXISTS tenant_artifact_access (
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cache_artifact_id   TEXT NOT NULL REFERENCES cache_artifact(id) ON DELETE CASCADE,
    first_accessed_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (first_accessed_at IS NULL OR first_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR first_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR first_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_accessed_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (last_accessed_at IS NULL OR last_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_accessed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    access_count        INTEGER NOT NULL DEFAULT 1,
    -- Per-tenant manual policy override: NULL = follow auto policy, 'blocked' = manual block,
    -- 'allowed' = manual override of auto-block. Mirrors package_versions.manual_block_state.
    manual_block_state  TEXT,
    -- Per-tenant yank: 1 when an operator has yanked this artifact for this tenant.
    yanked              INTEGER NOT NULL DEFAULT 0,
    -- Optional reason recorded when yanked = 1.
    yank_reason         TEXT,
    -- ISO 8601 UTC; most recent time any user in this tenant downloaded this artifact.
    last_used           TEXT
        CHECK (last_used IS NULL OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Cumulative download count for this tenant. Monotonic; survives activity-log pruning.
    download_count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, cache_artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_artifact_access_artifact
    ON tenant_artifact_access (cache_artifact_id);

-- Typed audit events. Replaces the freeform audit_log gradually; both tables coexist.
-- Envelope columns are required; payload is JSON. event_id is UUIDv7.
-- personal-data: included — structured audit events attributed to the subject (source_ip/user_agent)
CREATE TABLE IF NOT EXISTS audit_event (
    event_id            TEXT PRIMARY KEY,                    -- UUIDv7
    schema_version      INTEGER NOT NULL DEFAULT 1,
    event_type          TEXT NOT NULL,                       -- e.g. 'package.publish'
    -- ON DELETE SET NULL retains the event row after org deletion for forensic purposes.
    -- NULL also covers cross-tenant platform events that have no org scope.
    org_id              TEXT REFERENCES orgs(id) ON DELETE SET NULL,
    tenant_resolver     TEXT NOT NULL,                       -- single | multi | header | bound
    actor_type          TEXT NOT NULL CHECK (actor_type IN ('user','api_token','system')),
    actor_id            TEXT,
    request_id          TEXT,
    source_ip           TEXT,
    user_agent          TEXT,
    outcome             TEXT NOT NULL CHECK (outcome IN ('accepted','rejected','error')),
    payload             TEXT NOT NULL,                       -- JSON; per-event-type shape
    -- Millisecond precision (matches AuditEmitter's ToUtcIsoMillis() writer): this append-only
    -- forensic table needs a deterministic order for events sharing a wall-clock second, exactly
    -- like audit_log/activity.
    occurred_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (occurred_at IS NULL OR occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_time ON audit_event (org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_org_type ON audit_event (org_id, event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor ON audit_event (org_id, actor_id, occurred_at DESC);
-- Retention-sweep index: the reaper's DELETE filters on a bare occurred_at range with no
-- org_id, so none of the org-scoped indexes above can serve it — this one exists purely to
-- keep that sweep an index range scan instead of a full-table scan.
CREATE INDEX IF NOT EXISTS idx_audit_event_occurred_at ON audit_event (occurred_at);

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
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
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
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    completed_at    TEXT
        CHECK (completed_at IS NULL OR completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_tenant_provisioning_jobs_org ON tenant_provisioning_jobs(org_id, kind);

-- Per-run history for IHostedService background workers. Replaces the in-memory
-- last-success dictionary on DependablyMeter with a persistent record. Written by
-- BackgroundJobScope.Dispose() fire-and-forget; surfaced in the sysadmin Audit page
-- "Background Jobs" tab. id is a GUID-N; run_id matches the OTel trace correlation id
-- attached to the activity. outcome is the same vocabulary BackgroundJobScope already
-- emits to the histogram ('success' | 'server_error' | 'cancelled'). No automatic
-- retention yet — rows accumulate until a retention pass ages them out.
CREATE TABLE IF NOT EXISTS background_job_runs (
    id              TEXT PRIMARY KEY,
    job_name        TEXT NOT NULL,
    operation       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    started_at      TEXT NOT NULL
        CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    finished_at     TEXT NOT NULL
        CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    duration_ms     INTEGER NOT NULL,
    outcome         TEXT NOT NULL,
    error_message   TEXT
);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_started_at
    ON background_job_runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_background_job_runs_job_started
    ON background_job_runs(job_name, started_at DESC);

-- Content-addressed negative cache for upstream 404 responses.
-- The key is SHA-256(resolved-upstream-URL)[..32], where the resolved URL includes the org's
-- upstream base host, not just the artifact path/filename. Rows are therefore shared across
-- tenants that resolve the same host (intended dedup) but distinct across tenants whose per-org
-- upstreams point at different hosts — so one org's 404 can never suppress another org's fetch
-- against a host that does have the artifact.
-- TTL is enforced at query time (fetched_at >= now - ttl), not by a background sweep.
CREATE TABLE IF NOT EXISTS upstream_negative_cache (
    url_key     TEXT NOT NULL,   -- SHA-256(url)[..32] hex
    ecosystem   TEXT NOT NULL,
    fetched_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (fetched_at IS NULL OR fetched_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR fetched_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR fetched_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
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
        CHECK (computed_at IS NULL OR computed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR computed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR computed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    duration_ms INTEGER NOT NULL DEFAULT 0
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
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (package_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_npm_dist_tags_org ON npm_dist_tags(org_id, package_id);

-- Cargo sparse index metadata. One row per package_versions row carrying the full
-- newline-delimited JSON index line for that version. The index line encodes deps,
-- features, cksum, yanked, and links as defined by the Cargo sparse registry spec.
-- Tenant-scoped via JOIN to packages.org_id; every query must join through package_versions
-- → packages and filter on packages.org_id.
-- Each row is owned by exactly one package_versions row (owner_kind='package_version') or
-- one cache_artifact row (owner_kind='cache_artifact'); the respective FK is set and the
-- other is NULL. Partial unique indexes enforce per-arm dedup.
CREATE TABLE IF NOT EXISTS cargo_metadata (
    -- AUTOINCREMENT retained for compatibility with existing databases created by the additive
    -- migration path; changing the PK type would require a table rebuild on every install.
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    -- NULL when owner_kind='cache_artifact'; NOT NULL for the 'package_version' arm.
    version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
    index_line  TEXT NOT NULL,  -- full JSON line for this version as served in the sparse index
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
-- A tenant may block install scripts globally via org_settings.block_install_scripts='block'
-- while permitting specific known-good packages here. Each entry scopes the exemption to a
-- single (org, ecosystem, name) tuple; version_pattern optionally restricts to matching
-- versions (NULL = all versions). Matching uses simple trailing-glob semantics on version
-- strings; NULL matches any version.
-- personal-data: excluded — created_by is a provenance stamp on org allowlist config
CREATE TABLE IF NOT EXISTS install_script_allowlist (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ecosystem        TEXT NOT NULL,       -- 'npm' | 'pypi' | 'nuget' | 'maven' | 'cargo' | 'golang' | 'rpm' | 'oci'
    name             TEXT NOT NULL,       -- exact package name (purl name segment)
    version_pattern  TEXT,                -- NULL = all versions; non-NULL = exact or trailing-* glob
    created_by       TEXT REFERENCES users(id),
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    UNIQUE (org_id, ecosystem, name, version_pattern)
);
-- Primary lookup path: all allowlist entries for a given org.
CREATE INDEX IF NOT EXISTS idx_install_script_allowlist_org ON install_script_allowlist(org_id);
-- FK-column index: cascade delete on users scans this table without it.
CREATE INDEX IF NOT EXISTS idx_install_script_allowlist_created_by ON install_script_allowlist(created_by);

-- Admin-authored banners (tenant-scoped or system-wide). Mirrors the scope-discriminated
-- audit_log design: scope='tenant' rows carry a non-null org_id; scope='system' rows have
-- org_id IS NULL. No FK on org_id (rows may outlive a tenant soft-delete;
-- TenantHardDeleteService explicitly deletes scope='tenant' rows on hard-delete).
-- personal-data: excluded — created_by is authorship provenance on an org/instance announcement; the subject's own dismissals ARE exported, via banner_dismissals
CREATE TABLE IF NOT EXISTS banners (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL DEFAULT 'tenant' CHECK (scope IN ('tenant','system')),
    org_id      TEXT,                           -- non-null for scope='tenant'; NULL for scope='system'
    severity    TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warn','alert')),
    body        TEXT NOT NULL,
    link_url    TEXT,                           -- optional; must be http/https scheme
    link_label  TEXT,                           -- optional; rendered as anchor text
    target_role TEXT NOT NULL DEFAULT 'all' CHECK (target_role IN ('all','member','admin','owner','auditor')),
    starts_at   TEXT NOT NULL    -- ISO-8601 UTC Z string
        CHECK (starts_at IS NULL OR starts_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR starts_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR starts_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    ends_at     TEXT NOT NULL    -- ISO-8601 UTC Z string; ends_at > starts_at
        CHECK (ends_at IS NULL OR ends_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR ends_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR ends_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_by  TEXT,                           -- actor id; no FK (mirrors audit_log.actor_id)
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
-- Serves the active-banner resolution query: both resolution arms (scope='system' and
-- scope='tenant' AND org_id=@orgId) filter on enabled and ends_at.
CREATE INDEX IF NOT EXISTS idx_banners_resolution ON banners(scope, org_id, enabled, ends_at);

-- Per-user server-side dismissal records. Cascade-delete when the banner or user is deleted.
-- personal-data: included — banners the subject dismissed
CREATE TABLE IF NOT EXISTS banner_dismissals (
    banner_id   TEXT NOT NULL REFERENCES banners(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dismissed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (dismissed_at IS NULL OR dismissed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR dismissed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR dismissed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (banner_id, user_id)
);
-- FK-column index: cascade deletes on users scan this table without it.
CREATE INDEX IF NOT EXISTS idx_banner_dismissals_user ON banner_dismissals(user_id);

-- User-configured outbound webhooks for package events (publish, yank, vuln). Each row is
-- one endpoint subscription for an org. The HMAC signing secret is encrypted at rest via
-- EnvelopeProtector (enc:v1: prefix) when DEPENDABLY_MASTER_KEY is configured; plaintext
-- is rejected at save time. Secret is write-only: GET responses never return the value.
-- The dispatcher auto-disables a subscription after 20 consecutive failures OR when it has
-- been failing continuously for 48 hours, whichever comes first. Re-enable resets all
-- failure counters.
CREATE TABLE IF NOT EXISTS webhook_subscription (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    url                  TEXT NOT NULL,
    -- HMAC signing secret (enc:v1: envelope-encrypted at rest). NULL when no secret is set.
    secret               TEXT,
    -- JSON array of event type strings, e.g. ["package.publish","package.yank"].
    event_types          TEXT NOT NULL DEFAULT '[]',
    enabled              INTEGER NOT NULL DEFAULT 1,
    description          TEXT,
    -- ISO 8601 UTC; set after every terminal delivery attempt (success or all retries exhausted).
    last_delivery_at     TEXT
        CHECK (last_delivery_at IS NULL OR last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR last_delivery_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- 'ok' | 'failed' | NULL (never delivered). Only updated after terminal outcome.
    last_status          TEXT,
    -- Running count of consecutive delivery failures. Reset to 0 on success.
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    -- ISO 8601 UTC; set when the first failure in the current consecutive-failure run
    -- is recorded. Reset to NULL on success.
    failing_since        TEXT
        CHECK (failing_since IS NULL OR failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR failing_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- Free-text last error string; recorded on terminal failure and cleared on success.
    last_error           TEXT,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (created_at IS NULL OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);
-- Delivery fan-out query: enabled subscriptions for an org, indexed for fast event-type matching.
CREATE INDEX IF NOT EXISTS idx_webhook_sub_org_enabled ON webhook_subscription(org_id, enabled);

-- Single-writer mutual-exclusion lock over a shared SQLite database file. SQLite tolerates
-- exactly one writing process; two dependably processes pointed at one shared volume corrupt
-- each other's assumptions. On startup a file-backed SQLite deployment claims the sole row
-- (id = 'primary'): a live foreign heartbeat fails startup fast, a stale one (crashed
-- predecessor) is taken over, and a running node refreshes heartbeat_at on a timer. The row is
-- deleted on graceful shutdown so an immediate restart need not wait out the staleness window.
-- Instance-global (one lock for the whole file), so there is no org_id column. Postgres carries
-- the table for schema parity but never writes it — Postgres is a legitimately multi-writer store
-- and the guard is SQLite-only.
CREATE TABLE IF NOT EXISTS instance_lock (
    -- Fixed sentinel 'primary' so the table holds at most one row.
    id           TEXT PRIMARY KEY,
    -- Random GUID minted once per process at startup; identifies the lock holder.
    instance_id  TEXT NOT NULL,
    -- Operator-facing label for the holder (container hostname) in the takeover error message.
    hostname     TEXT,
    -- ISO 8601 UTC of the last heartbeat refresh; freshness is measured against this.
    heartbeat_at TEXT NOT NULL
        CHECK (heartbeat_at IS NULL OR heartbeat_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR heartbeat_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR heartbeat_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    -- ISO 8601 UTC of when this holder first acquired the lock.
    acquired_at  TEXT NOT NULL
        CHECK (acquired_at IS NULL OR acquired_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z' OR acquired_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' OR acquired_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
);

-- NOTE: SchemaInitializer also runs ALTER TABLE statements for the columns above.
-- Those are no-ops on fresh installs (duplicate column error is swallowed / IF NOT EXISTS).
-- They exist solely to add the columns to databases created before those columns were
-- included in the CREATE TABLE blocks. Schema.sql is the authoritative complete schema.
