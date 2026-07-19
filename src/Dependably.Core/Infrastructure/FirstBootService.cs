using System.Data.Common;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure;

/// <summary>
/// Runs on first boot only. The trigger is a single invariant — "the system has zero state" —
/// regardless of deployment mode:
///
///   needsBootstrap = users.count + system_admins.count + orgs.count == 0
///
/// Once any row exists in any of those tables, this method does nothing on subsequent restarts.
/// On a partial-failure mid-bootstrap, the serialized transaction rolls back cleanly so the
/// next start retries from a known-empty state.
///
/// The action branches by <c>DEPLOYMENT_MODE</c>:
///   - <c>single</c> (default): create one tenant + the bootstrap admin as that tenant's owner.
///   - <c>multi</c> or <c>header</c>: create the system_admin only. No tenant is auto-created.
///   - <c>edge</c>: create one tenant and seed its upstream rows to the configured master; no
///     admin or user account is created — an edge node is a headless cache with no login.
///
/// The single/multi branches delegate BCrypt admin creation to <see cref="IAdminBootstrapper"/>.
/// A protocol-only edge host registers no bootstrapper: single/multi bootstrap is then impossible
/// by construction (an edge only ever runs the BCrypt-free edge branch), while the full management
/// host always registers one and the flow is identical to before the split.
///
/// When an <see cref="EnvelopeProtector"/> is configured, instance secrets are written with
/// the <c>enc:v1:</c> envelope so fresh installs never store plaintext secrets on disk.
/// </summary>
public sealed class FirstBootService
{
    private readonly IMetadataStore _db;
    private readonly IConfiguration _config;
    private readonly ILogger<FirstBootService> _logger;
    private readonly EnvelopeProtector _envelope;
    private readonly IAdminBootstrapper? _adminBootstrapper;

    public FirstBootService(
        IMetadataStore db,
        IConfiguration config,
        ILogger<FirstBootService> logger,
        EnvelopeProtector envelope,
        IAdminBootstrapper? adminBootstrapper = null)
    {
        _db = db;
        _config = config;
        _logger = logger;
        _envelope = envelope;
        _adminBootstrapper = adminBootstrapper;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Serialise concurrent first-boot attempts (e.g. blue/green deploys racing against the
        // same DB) and ensure partial state rolls back atomically. Provider-aware: SQLite uses
        // BEGIN IMMEDIATE; Postgres opens a transaction and takes a transaction-scoped advisory
        // lock (BEGIN IMMEDIATE is a SQLite-only syntax that Postgres rejects).
        await conn.BeginSerializedAsync(_db.Provider, ct);
        try
        {
            // xtenant: instance-wide first-boot check; the whole point is to find whether
            // any tenant or admin exists at all before seeding the default org.
            int totalRows = await conn.ExecuteScalarAsync<int>(
                """
                SELECT
                    (SELECT COUNT(*) FROM users) +
                    (SELECT COUNT(*) FROM system_admins) +
                    (SELECT COUNT(*) FROM orgs)
                """);

            if (totalRows > 0)
            {
                await conn.ExecuteAsync("ROLLBACK");
                return;
            }

            _logger.LogInformation("First boot detected — initializing instance.");

            // JWT secret is needed in both modes — generate once per install. The same
            // generate/envelope/persist steps back the operator-triggered rotation path
            // (RotateJwtSecretAsync below), so there is exactly one implementation of "how
            // jwt_secret gets written".
            await StoreJwtSecretAsync(conn);

            // MFA encryption key seeds alongside the JWT secret so both are present from
            // first boot. MfaEncryptionKeyProvider handles the generate-if-missing path for
            // upgraded installs, making this DO UPDATE SET value safe (idempotent overwrite
            // within the same first-boot transaction).
            string mfaKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            string mfaStored = _envelope.IsConfigured ? _envelope.Protect(mfaKey) : mfaKey;
            await conn.ExecuteAsync(
                """
                INSERT INTO instance_settings (key, value) VALUES ('mfa_encryption_key', @value)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                new { value = mfaStored });

            await SeedInstanceSettingsAsync(conn);

            string mode = (_config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();

            if (mode == "edge")
            {
                await BootstrapEdgeAsync(conn, _config, _envelope);
            }
            else if (mode is "multi" or "header")
            {
                RequireAdminBootstrapper(mode).BootstrapMulti(conn, _config);
            }
            else
            {
                await RequireAdminBootstrapper(mode).BootstrapSingleAsync(conn, _config, _envelope);
            }

            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }
    }

    /// <summary>
    /// Regenerates <c>jwt_secret</c> for an already-bootstrapped instance and persists it under
    /// the same envelope policy as first boot. Guarded to the already-bootstrapped case: a
    /// missing <c>jwt_secret</c> row means first boot has not run yet, and rotating before an
    /// initial secret exists would race <see cref="RunAsync"/> rather than replace anything.
    ///
    /// This is the persist half of rotation only, and committing it changes behaviour
    /// immediately: the login path reads <c>jwt_secret</c> live on every login, so the next token
    /// minted anywhere is signed with the new secret. The validation half belongs to the
    /// management host — its JwtBearer scheme resolves the signing key per validation from
    /// <c>JwtSigningKeyProvider</c>, which re-reads this row. Callers in that process must reload
    /// the provider after this returns so the change is effective before they report success;
    /// other replicas converge on the provider's own refresh interval. Callers that skip the
    /// reload leave their replica validating against the superseded secret while minting under
    /// the new one — every session on it breaks until the refresh lands.
    ///
    /// There is no old-key grace period by design; see <c>JwtSigningKeyProvider</c> for the
    /// reasoning. Every session signed under the previous secret stops validating.
    ///
    /// This method lives in the shared Core closure (no reference to JwtBearerOptions, which is
    /// management-only) because it owns the single implementation of "how jwt_secret gets
    /// written". The operator-facing trigger is
    /// <c>POST /api/v1/system/jwt-secret/rotate</c> (<c>SystemController.JwtSecret.cs</c>).
    /// </summary>
    public async Task RotateJwtSecretAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.BeginSerializedAsync(_db.Provider, ct);
        try
        {
            // xtenant: jwt_secret is an instance-wide secret, not scoped to any single tenant.
            _ = await conn.ExecuteScalarAsync<string?>(
                "SELECT value FROM instance_settings WHERE key = 'jwt_secret'")
                ?? throw new InvalidOperationException(
                    "Cannot rotate jwt_secret: no jwt_secret row exists yet. First boot has not "
                    + "completed on this instance — rotation only applies after an initial secret "
                    + "has been generated.");

            await StoreJwtSecretAsync(conn);
            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }

        _logger.LogWarning(
            "jwt_secret rotated — every session token signed under the previous secret stops " +
            "validating as each replica picks up the new value. Logins mint under it immediately.");
    }

    // Generates a fresh 32-byte jwt_secret and persists it (envelope-protected when a master key
    // is configured, plaintext otherwise). Shared by first boot and operator-triggered rotation
    // so there is exactly one implementation of "how jwt_secret gets written".
    private async Task StoreJwtSecretAsync(DbConnection conn)
    {
        string jwtSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        string jwtStored = _envelope.IsConfigured ? _envelope.Protect(jwtSecret) : jwtSecret;
        await conn.ExecuteAsync(
            """
            INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', @value)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            new { value = jwtStored });
    }

    // The single/multi branches create a BCrypt-hashed admin account, which only a management
    // host wires up. A protocol-only edge host registers no bootstrapper and can never reach
    // these branches (it always runs edge mode); a management host always registers one. A null
    // here therefore signals a host misconfigured for the requested mode — fail closed with a
    // message rather than silently skipping admin creation.
    private IAdminBootstrapper RequireAdminBootstrapper(string mode) =>
        _adminBootstrapper
        ?? throw new InvalidOperationException(
            $"DEPLOYMENT_MODE={mode} requires an admin account, but no IAdminBootstrapper is "
            + "registered. This host builds only the protocol surface (no management plane); run "
            + "DEPLOYMENT_MODE=edge, or use the full image for single/multi/header modes.");

    private static async Task BootstrapEdgeAsync(DbConnection conn, IConfiguration config, EnvelopeProtector envelope)
    {
        // A headless edge node needs a single implicit org to anchor the org-scoped
        // upstream_registry rows and the org-scoped query stack, but NO admin user, no
        // must_change_password account, and no management identity: an edge serves registry
        // reads only and creates nothing authoritative. The seeded rows point every ecosystem at
        // the master rather than the public registries.
        string orgSlug = config["DEFAULT_TENANT_SLUG"] ?? config["DEFAULT_ORG_SLUG"] ?? "edge";
        string orgId = NewId();

        conn.Execute(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = orgSlug });

        conn.Execute(
            "INSERT INTO org_settings (org_id) VALUES (@org_id)",
            new { org_id = orgId });

        string masterUrl = (config["EDGE_MASTER_URL"] ?? "").Trim();
        string masterToken = (config["EDGE_MASTER_TOKEN"] ?? "").Trim();
        await EdgeUpstreamSeeder.SeedForEdgeAsync(conn, orgId, masterUrl, masterToken, envelope);

        // Inbound client auth: seed the optional pre-shared EDGE_ACCESS_TOKEN as a reader
        // service token, or enable anonymous_pull when absent. The per-boot reseed in
        // StartupService keeps this current on rotation and emits the anonymous-mode warning;
        // seeding here means the first request after first boot is already gated correctly.
        await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, orgId, config["EDGE_ACCESS_TOKEN"]);
    }

    private async Task SeedInstanceSettingsAsync(DbConnection conn)
    {
        // Env var overrides take precedence; otherwise seed the InstanceSettingDefaults
        // baseline so the operator UI never loads blank and the DB matches the runtime
        // fallbacks in RetentionService / SiemController / upload-limit checks.
        var settings = new Dictionary<string, string>
        {
            ["max_upload_bytes"] = _config["MAX_UPLOAD_BYTES"] ?? InstanceSettingDefaults.MaxUploadBytes,
            ["max_upload_bytes_pypi"] = _config["MAX_UPLOAD_BYTES_PYPI"] ?? InstanceSettingDefaults.MaxUploadBytesPyPi,
            ["max_upload_bytes_npm"] = _config["MAX_UPLOAD_BYTES_NPM"] ?? InstanceSettingDefaults.MaxUploadBytesNpm,
            ["max_upload_bytes_nuget"] = _config["MAX_UPLOAD_BYTES_NUGET"] ?? InstanceSettingDefaults.MaxUploadBytesNuGet,
            ["gc_schedule"] = _config["GC_SCHEDULE"] ?? InstanceSettingDefaults.GcSchedule,
            ["siem_max_lookback_days"] = _config["SIEM_MAX_LOOKBACK_DAYS"] ?? InstanceSettingDefaults.SiemMaxLookbackDays,
            ["max_active_tokens_per_tenant"] = _config["MAX_ACTIVE_TOKENS_PER_TENANT"] ?? InstanceSettingDefaults.MaxActiveTokensPerTenant,
            ["max_concurrent_oci_uploads_per_tenant"] = _config["MAX_CONCURRENT_OCI_UPLOADS_PER_TENANT"] ?? InstanceSettingDefaults.MaxConcurrentOciUploadsPerTenant,
        };

        // Storage quota default is optional: only seed when the env var is set so
        // existing installs that upgrade do not suddenly acquire an arbitrary ceiling.
        string? quotaEnv = _config["DEFAULT_STORAGE_QUOTA_BYTES"];
        if (!string.IsNullOrWhiteSpace(quotaEnv))
        {
            settings["default_storage_quota_bytes"] = quotaEnv;
        }

        foreach (var (key, value) in settings)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO instance_settings (key, value) VALUES (@key, @value)
                ON CONFLICT(key) DO NOTHING
                """,
                new { key, value });
        }
    }

    private static string NewId() => Guid.NewGuid().ToString("N");
}
