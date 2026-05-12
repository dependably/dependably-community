using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

public static class BlocklistSeeder
{
    public static async Task<string> InsertAsync(
        IMetadataStore db, string orgId, string ecosystem, string pattern, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO blocklist (id, org_id, ecosystem, pattern) VALUES (@id, @orgId, @ecosystem, @pattern)",
            new { id, orgId, ecosystem, pattern });
        return id;
    }
}
