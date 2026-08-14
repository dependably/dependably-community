using System.Data.Common;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure;

/// <summary>
/// Creates the first-boot administrator account for <c>single</c> mode (a tenant owner) and
/// <c>multi</c>/<c>header</c> mode (a system_admin). Both hash the password with BCrypt, so this
/// lives on the management side of the assembly split — a protocol-only edge host registers no
/// implementation and therefore never creates an admin account.
///
/// <see cref="FirstBootService"/> calls these inside its first-boot serialized transaction; this
/// type opens no connection and issues no COMMIT/ROLLBACK of its own.
/// </summary>
public sealed class AdminBootstrapper : IAdminBootstrapper
{
    public async Task BootstrapSingleAsync(DbConnection conn, IConfiguration config, EnvelopeProtector envelope)
    {
        string orgSlug = config["DEFAULT_TENANT_SLUG"] ?? config["DEFAULT_ORG_SLUG"] ?? "default";
        string orgId = NewId();

        conn.Execute(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = orgSlug });

        conn.Execute(
            "INSERT INTO org_settings (org_id) VALUES (@org_id)",
            new { org_id = orgId });

        // Seed the standard public upstreams (plus any configured upstream auth) so the default
        // org keeps proxying out of the box.
        await UpstreamRegistrySeeder.SeedForOrgAsync(conn, orgId, config, envelope);

        string rawPassword = config["FIRST_BOOT_ADMIN_PASSWORD"]
            ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        string adminEmail = EmailNormalizer.Normalize(
            config["FIRST_BOOT_ADMIN_EMAIL"] ?? "admin@dependably.local");
        string adminId = NewId();

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

    public void BootstrapMulti(DbConnection conn, IConfiguration config)
    {
        // Multi-tenant mode bootstrap (multi and header): create only the system_admin.
        // No tenant is auto-created — tenants are provisioned through the management API.
        string rawPassword = config["FIRST_BOOT_SYSTEM_ADMIN_PASSWORD"]
            ?? config["FIRST_BOOT_ADMIN_PASSWORD"]
            ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(rawPassword, workFactor: 12);
        string email = EmailNormalizer.Normalize(
            config["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] ?? "system@dependably.local");
        string id = NewId();

        conn.Execute(
            """
            INSERT INTO system_admins (id, email, password_hash, must_change_password)
            VALUES (@id, @email, @hash, 1)
            """,
            new { id, email, hash = passwordHash });

        PrintCredentials(email, rawPassword, "system_admin (multi-tenant mode)");
    }

    private static void PrintCredentials(string email, string password, string label)
    {
        string border = new('=', 60);
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
