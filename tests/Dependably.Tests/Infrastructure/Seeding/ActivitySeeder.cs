using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

public static class ActivitySeeder
{
    public static async Task InsertAsync(
        IMetadataStore db,
        string orgId,
        string ecosystem,
        string eventType,
        string? actorId = null,
        string? purl = null,
        DateTimeOffset? createdAt = null,
        CancellationToken ct = default)
    {
        await using var conn = await db.OpenAsync(ct);
        if (createdAt is null)
        {
            await conn.ExecuteAsync("""
                INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id)
                VALUES (@id, @orgId, @ecosystem, @purl, @eventType, @actorId)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, ecosystem, purl, eventType, actorId });
        }
        else
        {
            await conn.ExecuteAsync("""
                INSERT INTO activity (id, org_id, ecosystem, purl, event_type, actor_id, created_at)
                VALUES (@id, @orgId, @ecosystem, @purl, @eventType, @actorId, @createdAt)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    ecosystem,
                    purl,
                    eventType,
                    actorId,
                    createdAt = createdAt.Value.ToString("yyyy-MM-ddTHH:mm:ssZ")
                });
        }
    }
}
