using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

public static class AllowlistSeeder
{
    public static async Task InsertAsync(
        IMetadataStore db, string orgId, string purlPattern, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO allowlist (id, org_id, purl_pattern) VALUES (@id, @orgId, @pattern)",
            new { id = Guid.NewGuid().ToString("N"), orgId, pattern = purlPattern });
    }
}
