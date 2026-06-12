using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

public static class SystemAdminSeeder
{
    public static async Task<string> InsertAsync(
        IMetadataStore db, string email, string password = "Password12345", CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 4);
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO system_admins (id, email, password_hash) VALUES (@id, @email, @hash)",
            new { id, email, hash });
        return id;
    }
}
