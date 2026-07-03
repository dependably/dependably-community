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
    /// <param name="password">
    /// Password to hash and store. Pass <c>null</c> to seed a passwordless (SSO-only) account —
    /// an empty <c>password_hash</c>, matching how JIT-provisioned SAML users are created.
    /// </param>
    public static async Task<string> InsertAsync(
        IMetadataStore db,
        string orgId,
        string email,
        string role = "member",
        string? password = "Password12345",
        string accountStatus = "active",
        CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string passwordHash = password is null ? "" : BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4);
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role, account_status)
            VALUES (@id, @orgId, @email, @hash, @role, @accountStatus)
            """,
            new { id, orgId, email, hash = passwordHash, role, accountStatus });
        return id;
    }
}
