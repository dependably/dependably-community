using Dapper;

namespace Dependably.Infrastructure.Hex;

/// <summary>Resolves the display name a Hex client shows for the caller (<c>GET /users/me</c>): a user token's email, or nothing for a service token.</summary>
public sealed class HexIdentityLookup
{
    private readonly IMetadataStore _db;

    public HexIdentityLookup(IMetadataStore db) => _db = db;

    public async Task<string?> DisplayNameForAsync(string orgId, TokenRecord token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token.UserId))
        {
            return null;
        }

        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT email FROM users WHERE id = @id AND tenant_id = @orgId",
            new { id = token.UserId, orgId });
    }
}
