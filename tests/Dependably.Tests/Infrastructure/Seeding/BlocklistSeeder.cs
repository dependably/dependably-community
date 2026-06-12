using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

public static class BlocklistSeeder
{
    public static async Task<string> InsertAsync(
        IMetadataStore db, string orgId, string pattern, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO blocklist (id, org_id, pattern) VALUES (@id, @orgId, @pattern)",
            new { id, orgId, pattern });
        return id;
    }
}
