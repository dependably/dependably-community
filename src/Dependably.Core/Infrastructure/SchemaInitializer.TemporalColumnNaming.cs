namespace Dependably.Infrastructure;

/// <summary>
/// Structural identification of "temporal" TEXT columns — the ones the canonical-timestamp CHECK
/// (<see cref="UtcTimestamp.TemporalCheckRegex"/> / <see cref="TemporalCheckPredicate"/>) applies to
/// in <c>Schema.sql</c> / <c>Schema.pg.sql</c>. Naming-convention based: a column ending in
/// <c>_at</c> or <c>_since</c>, per the convention documented in <c>schema-migrations.md</c> §
/// "Schema.sql conventions", plus a handful of established exceptions named below.
///
/// This is convention-based and reviewer-enforced, not itself gated by an independent, hand-audited
/// pin: <c>TemporalCheckConstraintComplianceTests</c> uses this exact predicate as its own filter
/// when deriving which columns must carry the CHECK, so a column that follows neither the naming
/// convention nor the exception list below is invisible to both the schema and the test in the same
/// way. A newly-added temporal column with an unconventional name needs a human to notice and add it
/// to <see cref="NonSuffixedTemporalColumns"/> — nothing here catches the omission automatically.
///
/// Fresh installs on both providers get the CHECK straight from the <c>CREATE TABLE</c> blocks using
/// this same column set (kept in lockstep by eye, cross-checked against every TEXT column in
/// <c>Schema.sql</c>). Existing Postgres databases are brought up to the same constraint by
/// <see cref="SchemaInitializer.TemporalCheckRetrofit"/> — which derives its column set from the
/// CHECK text actually present in <c>Schema.pg.sql</c>, not from this predicate, so a column the
/// naming convention misses is missed identically by the schema and the retrofit rather than
/// inconsistently. Existing SQLite databases are never retrofitted: SQLite cannot
/// <c>ALTER ADD CONSTRAINT</c>; every writer of these columns is already canonical, and the
/// every-boot sweep in <see cref="SchemaInitializer.TimestampNormalization"/> self-heals any legacy
/// shape a stale binary still produces.
/// </summary>
public sealed partial class SchemaInitializer
{
    // Naming-convention exceptions: genuinely temporal TEXT columns whose name does not carry the
    // *_at / *_since suffix. Cross-checked by eye against every TEXT column in Schema.sql; a column
    // added later under a different non-suffixed name needs adding here too — see the class summary
    // for why nothing catches that omission automatically.
    private static readonly HashSet<string> NonSuffixedTemporalColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "last_used", "locked_until", "last_attempt", "window_start", "last_revalidated",
    };

    /// <summary>Structural naming-convention test — see the class summary and <see cref="NonSuffixedTemporalColumns"/>.</summary>
    internal static bool IsTemporalColumnName(string column) =>
        column.EndsWith("_at", StringComparison.OrdinalIgnoreCase) ||
        column.EndsWith("_since", StringComparison.OrdinalIgnoreCase) ||
        NonSuffixedTemporalColumns.Contains(column);

    // Blue-green waivers for the canonical-UTC shape CHECK, one per column the previous release
    // already declared. SchemaBackwardCompatibilityComplianceTests reports every CHECK clause added
    // to a surviving column, because a constraint the previous release never ran against can reject
    // values it writes — and the predicate shape (here a GLOB disjunction on SQLite, a `~` regex on
    // Postgres) carries no proof either way.
    //
    // The reason is the same for all of them, and it is the whole justification: the CHECK is
    // declared in the CREATE TABLE blocks, so it reaches fresh installs directly; existing SQLite
    // databases never gain it (SQLite cannot ALTER ADD CONSTRAINT), and existing Postgres
    // databases gain it only when SchemaInitializer.TemporalCheckRetrofit runs — so a previous
    // release's slot can still be writing to a table that carries no such constraint. On a fresh install both slots write
    // through UtcTimestamp, whose output is canonical by construction, and the every-boot sweep in
    // TimestampNormalization rewrites any legacy shape a stale binary produced. The full-schema
    // audit of that claim is TemporalCheckConstraintSqliteTests / -PostgresTests.
    //
    // Each column carries its own marker on purpose. A wildcard form would be a standing exemption
    // for every future table's column of that name, and it would silence the other hazards the gate
    // reports on the same object — a dropped column, a narrowed value set, a lost DEFAULT — not just
    // this one constraint. The markers become dead weight the moment the previous release also
    // declares the CHECK, and are then deleted in one sweep.
    //
    // backcompat-ok: activity.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert.dismissed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert_settings.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert_settings.email_failing_since — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert_settings.email_last_delivery_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert_settings.slack_failing_since — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert_settings.slack_last_delivery_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: alert_settings.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: allowlist.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: audit_event.occurred_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: audit_log.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: background_job_runs.finished_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: background_job_runs.started_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: banner_dismissals.dismissed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: banners.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: banners.ends_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: banners.starts_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: blocklist.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.deprecation_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.first_cached_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.last_accessed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.license_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.published_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.revoked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: cache_artifact.vuln_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: claim.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: claim.deleted_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: claim.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: claim_history.occurred_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: external_identities.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: external_identities.last_login_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: install_script_allowlist.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: instance_lock.acquired_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: instance_lock.heartbeat_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: invites.accepted_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: invites.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: invites.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: jwt_revocations.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: license_allowlist.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: license_blocklist.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: login_attempts.last_attempt — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: login_attempts.locked_until — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: maven_version_files.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: mfa_trusted_devices.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: mfa_trusted_devices.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: mfa_trusted_devices.last_seen_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: npm_dist_tags.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: npm_dist_tags.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: nuget_symbol_index.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: oci_blobs.cached_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: oci_blobs.license_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: oci_blobs.upstream_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: oci_tags.last_revalidated — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: oci_tags.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: oci_uploads.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: org_stats_snapshot.computed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: orgs.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: orgs.deleted_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_version_files.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_version_licenses.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_version_vulns.checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.deprecation_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.last_used — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.published_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.revoked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.vuln_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: package_versions.yanked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: packages.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: packages.upstream_latest_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: packages.upstream_latest_published_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: password_reset_tokens.consumed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: password_reset_tokens.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: password_reset_tokens.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: quarantine.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: quarantine.decided_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: quarantine.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: reserved_namespace.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: rpm_metadata.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: rpm_repodata_state.last_built_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_consumed_assertions.consumed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_consumed_assertions.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_pending_requests.consumed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_pending_requests.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_pending_requests.issued_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_test_runs.consumed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_test_runs.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: saml_test_runs.issued_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: service_tokens.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: service_tokens.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: service_tokens.last_used_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: signature_trust_anchor.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: system_admins.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: system_admins.last_login_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: system_admins.password_reset_issued_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_artifact_access.first_accessed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_artifact_access.last_accessed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_artifact_access.last_used — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_provisioning_jobs.completed_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_provisioning_jobs.started_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_saml_config.last_test_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_saml_config.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: tenant_storage.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: upstream_negative_cache.fetched_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: upstream_registry.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: upstream_source_pin.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: user_tokens.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: user_tokens.expires_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: user_tokens.last_used_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: users.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: users.last_login_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: users.password_reset_issued_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: vulnerabilities.epss_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: vulnerabilities.fetched_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: vulnerabilities.kev_checked_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: vulnerabilities.modified_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: vulnerabilities.published_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: webhook_subscription.created_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: webhook_subscription.failing_since — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: webhook_subscription.last_delivery_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
    // backcompat-ok: webhook_subscription.updated_at — canonical-UTC shape CHECK, fresh installs only; no RunOnceAsync retrofit, writers already canonical.
}
