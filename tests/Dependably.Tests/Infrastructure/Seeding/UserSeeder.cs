using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

/// <summary>
/// Inserts a user row referencing an existing org. The caller must have already inserted
/// the org — UserSeeder does NOT auto-create one. This is the "explicit relationships"
/// rule from the test plan: implicit defaults make tests harder to reason about.
/// </summary>
public static class UserSeeder
{
    public static async Task<string> InsertAsync(
        IMetadataStore db,
        string orgId,
        string email,
        string role = "member",
        string password = "Password12345",
        string accountStatus = "active",
        CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4);
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role, account_status)
            VALUES (@id, @orgId, @email, @hash, @role, @accountStatus)
            """,
            new { id, orgId, email, hash = passwordHash, role, accountStatus });
        return id;
    }
}
