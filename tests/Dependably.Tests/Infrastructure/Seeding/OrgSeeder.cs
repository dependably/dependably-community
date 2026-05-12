using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

/// <summary>
/// Inserts a row into <c>orgs</c> + a default row into <c>org_settings</c>. Returns the
/// generated id. Purely additive — never mutates an existing org. Callers that want a
/// stable slug pass it in; otherwise a unique slug is generated.
/// </summary>
public static class OrgSeeder
{
    public static async Task<string> InsertAsync(IMetadataStore db, string slug, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id, slug });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@id)",
            new { id });
        return id;
    }
}
