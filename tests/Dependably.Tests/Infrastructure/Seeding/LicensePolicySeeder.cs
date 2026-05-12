using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

/// <summary>
/// Seeds license-policy state for an org: enforcement mode + allowlist/blocklist entries.
/// The org row + org_settings row must already exist (created via <see cref="OrgSeeder"/>).
/// </summary>
public static class LicensePolicySeeder
{
    public static async Task SetModeAsync(
        IMetadataStore db, string orgId, string mode, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE org_settings SET license_enforcement_mode = @mode WHERE org_id = @orgId",
            new { mode, orgId });
    }

    public static async Task AddAllowlistEntryAsync(
        IMetadataStore db, string orgId, string spdx, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO license_allowlist (id, org_id, license_spdx)
            VALUES (@id, @orgId, @spdx)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx });
    }

    public static async Task AddBlocklistEntryAsync(
        IMetadataStore db, string orgId, string spdx, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO license_blocklist (id, org_id, license_spdx)
            VALUES (@id, @orgId, @spdx)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, spdx });
    }
}
