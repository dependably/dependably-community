using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

public static class AllowlistSeeder
{
    public static async Task InsertAsync(
        IMetadataStore db, string orgId, string ecosystem, string purlPattern, CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO allowlist (id, org_id, ecosystem, purl_pattern) VALUES (@id, @orgId, @ecosystem, @pattern)",
            new { id = Guid.NewGuid().ToString("N"), orgId, ecosystem, pattern = purlPattern });
    }
}
