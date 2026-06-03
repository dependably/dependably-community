using System.Data.Common;
using System.Security.Cryptography;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Runs on first boot only. The trigger is a single invariant — "the system has zero state" —
/// regardless of deployment mode:
///
///   needsBootstrap = users.count + system_admins.count + orgs.count == 0
///
/// Once any row exists in any of those tables, this method does nothing on subsequent restarts.
/// On a partial-failure mid-bootstrap, BEGIN IMMEDIATE rolls back cleanly so the next start
/// retries from a known-empty state.
///
/// The action branches by <c>DEPLOYMENT_MODE</c>:
///   - <c>single</c> (default): create one tenant + the bootstrap admin as that tenant's owner.
///   - <c>multi</c>:            create the system_admin only. No tenant is auto-created.
/// </summary>
public sealed class FirstBootService
{
    private readonly IMetadataStore _db;
    private readonly IConfiguration _config;
    private readonly ILogger<FirstBootService> _logger;

    public FirstBootService(IMetadataStore db, IConfiguration config, ILogger<FirstBootService> logger)
    {
        _db = db;
        _config = config;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // BEGIN IMMEDIATE: serialise concurrent first-boot attempts (e.g. blue/green deploys
        // racing against the same DB file) and ensure partial state rolls back atomically.
        await conn.ExecuteAsync("BEGIN IMMEDIATE");
        try
        {
            // xtenant: instance-wide first-boot check; the whole point is to find whether
            // any tenant or admin exists at all before seeding the default org.
            var totalRows = await conn.ExecuteScalarAsync<int>(
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

            // JWT secret is needed in both modes — generate once per install.
            var jwtSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            await conn.ExecuteAsync(
                """
                INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', @value)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                new { value = jwtSecret });

            await SeedInstanceSettingsAsync(conn);

            var mode = (_config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();

            if (mode == "multi")
            {
                BootstrapMulti(conn, _config);
            }
            else
            {
                await BootstrapSingleAsync(conn, _config);
            }

            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }
    }

    private static async Task BootstrapSingleAsync(DbConnection conn, IConfiguration config)
    {
        var orgSlug = config["DEFAULT_TENANT_SLUG"] ?? config["DEFAULT_ORG_SLUG"] ?? "default";
        var orgId = NewId();

        conn.Execute(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = orgSlug });

        conn.Execute(
            "INSERT INTO org_settings (org_id) VALUES (@org_id)",
            new { org_id = orgId });

        // Seed the standard public upstreams so the default org keeps proxying out of the box.
        await UpstreamRegistrySeeder.SeedForOrgAsync(conn, orgId, config);

        var rawPassword = config["FIRST_BOOT_ADMIN_PASSWORD"]
            ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        var adminEmail = config["FIRST_BOOT_ADMIN_EMAIL"] ?? "admin@dependably.local";
        var adminId = NewId();

        // 1:1 user:tenant model — tenant_id and role live on the user row directly.
        // must_change_password = 1 forces rotation since the seeded password may have been
        // logged or env-stored.
        conn.Execute(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role, must_change_password)
            VALUES (@id, @tenantId, @email, @hash, 'owner', 1)
            """,
            new { id = adminId, tenantId = orgId, email = adminEmail, hash = passwordHash });

        PrintCredentials(adminEmail, rawPassword, "tenant owner (single mode)");
    }

    private static void BootstrapMulti(DbConnection conn, IConfiguration config)
    {
        // Multi mode bootstrap: create only the system_admin. No tenant. No tenant user.
        var rawPassword = config["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"]
            ?? config["FIRST_BOOT_ADMIN_PASSWORD"]
            ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        var email = config["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] ?? "system@dependably.local";
        var id = NewId();

        conn.Execute(
            """
            INSERT INTO system_admins (id, email, password_hash, must_change_password)
            VALUES (@id, @email, @hash, 1)
            """,
            new { id, email, hash = passwordHash });

        PrintCredentials(email, rawPassword, "system_admin (multi mode)");
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
        };

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

    private static void PrintCredentials(string email, string password, string label)
    {
        var border = new string('=', 60);
        Console.WriteLine();
        Console.WriteLine(border);
        Console.WriteLine($"  DEPENDABLY FIRST BOOT — {label.ToUpperInvariant()}");
        Console.WriteLine($"  SAVE THESE CREDENTIALS — printed once.");
        Console.WriteLine(border);
        Console.WriteLine($"  Email   : {email}");
        Console.WriteLine($"  Password: {password}");
        Console.WriteLine(border);
        Console.WriteLine();
    }

    private static string NewId() => Guid.NewGuid().ToString("N");
}
