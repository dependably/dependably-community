using System.Security.Cryptography;
using System.Text;
using Dapper;

namespace Dependably.Infrastructure;

public sealed class TokenRepository
{
    private readonly IMetadataStore _db;

    public TokenRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Resolves a raw token string to a TokenRecord via indexed lookup on the stored SHA-256 hash.
    /// Returns null if not found or expired.
    /// </summary>
    public async Task<TokenRecord?> ResolveAsync(string rawToken, CancellationToken ct = default)
    {
        var incomingHashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        var incomingHex = Convert.ToHexString(incomingHashBytes).ToLowerInvariant();

        await using var conn = await _db.OpenAsync(ct);

        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Use indexed lookup by full hash — token_hash is SHA-256 of the raw token,
        // so a direct equality check is safe and avoids a full table scan.
        var userToken = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string UserId, string? Capabilities, string CreatedAt, string? ExpiresAt)>(
            """
            SELECT id, org_id, user_id, capabilities, created_at, expires_at
            FROM tokens
            WHERE token_hash = @hash AND (expires_at IS NULL OR expires_at > @now)
            """,
            new { hash = incomingHex, now });

        if (userToken.Id is not null)
        {
            return new TokenRecord
            {
                Id = userToken.Id, OrgId = userToken.OrgId, UserId = userToken.UserId,
                Capabilities = userToken.Capabilities,
                CreatedAt = DateTimeOffset.Parse(userToken.CreatedAt),
                ExpiresAt = userToken.ExpiresAt is not null ? DateTimeOffset.Parse(userToken.ExpiresAt) : null
            };
        }

        var cicdToken = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string? Capabilities, string CreatedAt, string? ExpiresAt)>(
            """
            SELECT id, org_id, capabilities, created_at, expires_at
            FROM cicd_tokens
            WHERE token_hash = @hash AND (expires_at IS NULL OR expires_at > @now)
            """,
            new { hash = incomingHex, now });

        if (cicdToken.Id is not null)
        {
            return new TokenRecord
            {
                Id = cicdToken.Id, OrgId = cicdToken.OrgId, UserId = null,
                Capabilities = cicdToken.Capabilities,
                CreatedAt = DateTimeOffset.Parse(cicdToken.CreatedAt),
                ExpiresAt = cicdToken.ExpiresAt is not null ? DateTimeOffset.Parse(cicdToken.ExpiresAt) : null
            };
        }

        return null;
    }

    public static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Issues a user token. <paramref name="capabilities"/> is the canonical JSON capability
    /// array produced by <c>Capabilities.TryNormalizeAndAuthorize</c> at the controller
    /// boundary — the repository assumes it's already validated and writes it verbatim.
    /// </summary>
    public async Task<(string RawToken, TokenRecord Record)> CreateUserTokenAsync(
        string orgId, string userId, string capabilities,
        DateTimeOffset? expiresAt, CancellationToken ct = default)
    {
        var raw = Security.TokenGenerator.Generate();
        var hash = HashToken(raw);
        var id = Guid.NewGuid().ToString("N");
        var expiresStr = expiresAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO tokens (id, org_id, user_id, token_hash, capabilities, expires_at) VALUES (@id, @orgId, @userId, @hash, @capabilities, @expires)",
            new { id, orgId, userId, hash, capabilities, expires = expiresStr });

        return (raw, new TokenRecord
        {
            Id = id, OrgId = orgId, UserId = userId, Capabilities = capabilities,
            CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = expiresAt
        });
    }

    public async Task<TokenRecord?> GetTokenByIdAsync(string tokenId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string UserId, string? Capabilities, string CreatedAt, string? ExpiresAt)>(
            "SELECT id, org_id, user_id, capabilities, created_at, expires_at FROM tokens WHERE id = @id",
            new { id = tokenId });
        if (row.Id is null) return null;
        return new TokenRecord
        {
            Id = row.Id, OrgId = row.OrgId, UserId = row.UserId, Capabilities = row.Capabilities,
            CreatedAt = DateTimeOffset.Parse(row.CreatedAt),
            ExpiresAt = row.ExpiresAt is not null ? DateTimeOffset.Parse(row.ExpiresAt) : null
        };
    }

    public async Task DeleteTokenAsync(string tokenId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM tokens WHERE id = @id", new { id = tokenId });
    }

    public async Task<IReadOnlyList<TokenRecord>> ListUserTokensAsync(string orgId, string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string UserId, string? Capabilities, string CreatedAt, string? ExpiresAt)>(
            "SELECT id, org_id, user_id, capabilities, created_at, expires_at FROM tokens WHERE org_id = @orgId AND user_id = @userId ORDER BY created_at DESC",
            new { orgId, userId });
        return rows.Select(t => new TokenRecord
            {
                Id = t.Id, OrgId = t.OrgId, UserId = t.UserId, Capabilities = t.Capabilities,
                CreatedAt = DateTimeOffset.Parse(t.CreatedAt),
                ExpiresAt = t.ExpiresAt is not null ? DateTimeOffset.Parse(t.ExpiresAt) : null
            })
            .ToList();
    }

    /// <summary>
    /// CI/CD-token sibling of <see cref="CreateUserTokenAsync"/>. <paramref name="capabilities"/>
    /// is the canonical JSON array supplied by the controller after validation.
    /// </summary>
    public async Task<(string RawToken, CicdTokenRecord Record)> CreateCicdTokenAsync(
        string orgId, string name, string capabilities,
        DateTimeOffset? expiresAt, CancellationToken ct = default)
    {
        var raw = Security.TokenGenerator.Generate();
        var hash = HashToken(raw);
        var id = Guid.NewGuid().ToString("N");
        var expiresStr = expiresAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO cicd_tokens (id, org_id, name, token_hash, capabilities, expires_at) VALUES (@id, @orgId, @name, @hash, @capabilities, @expires)",
            new { id, orgId, name, hash, capabilities, expires = expiresStr });

        return (raw, new CicdTokenRecord
        {
            Id = id, OrgId = orgId, Name = name, Capabilities = capabilities,
            CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = expiresAt
        });
    }

    public async Task DeleteCicdTokenAsync(string tokenId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM cicd_tokens WHERE id = @id", new { id = tokenId });
    }

    public async Task<IReadOnlyList<CicdTokenRecord>> ListCicdTokensAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string Name, string? Capabilities, string CreatedAt, string? ExpiresAt)>(
            "SELECT id, org_id, name, capabilities, created_at, expires_at FROM cicd_tokens WHERE org_id = @orgId ORDER BY created_at DESC",
            new { orgId });
        return rows.Select(t => new CicdTokenRecord
            {
                Id = t.Id, OrgId = t.OrgId, Name = t.Name, Capabilities = t.Capabilities,
                CreatedAt = DateTimeOffset.Parse(t.CreatedAt),
                ExpiresAt = t.ExpiresAt is not null ? DateTimeOffset.Parse(t.ExpiresAt) : null
            })
            .ToList();
    }
}
