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
        var userToken = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string UserId, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            """
            SELECT id, org_id, user_id, capabilities, description, created_at, expires_at, last_used_at
            FROM user_tokens
            WHERE token_hash = @hash AND (expires_at IS NULL OR expires_at > @now)
            """,
            new { hash = incomingHex, now });

        if (userToken.Id is not null)
        {
            return new TokenRecord
            {
                Id = userToken.Id, OrgId = userToken.OrgId, UserId = userToken.UserId,
                Capabilities = userToken.Capabilities,
                Description = userToken.Description,
                CreatedAt = DateTimeOffset.Parse(userToken.CreatedAt),
                ExpiresAt = userToken.ExpiresAt is not null ? DateTimeOffset.Parse(userToken.ExpiresAt) : null,
                LastUsedAt = userToken.LastUsedAt is not null ? DateTimeOffset.Parse(userToken.LastUsedAt) : null,
                Source = TokenSource.User
            };
        }

        var serviceToken = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            """
            SELECT id, org_id, capabilities, description, created_at, expires_at, last_used_at
            FROM service_tokens
            WHERE token_hash = @hash AND (expires_at IS NULL OR expires_at > @now)
            """,
            new { hash = incomingHex, now });

        if (serviceToken.Id is not null)
        {
            return new TokenRecord
            {
                Id = serviceToken.Id, OrgId = serviceToken.OrgId, UserId = null,
                Capabilities = serviceToken.Capabilities,
                Description = serviceToken.Description,
                CreatedAt = DateTimeOffset.Parse(serviceToken.CreatedAt),
                ExpiresAt = serviceToken.ExpiresAt is not null ? DateTimeOffset.Parse(serviceToken.ExpiresAt) : null,
                LastUsedAt = serviceToken.LastUsedAt is not null ? DateTimeOffset.Parse(serviceToken.LastUsedAt) : null,
                Source = TokenSource.Service
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
        DateTimeOffset? expiresAt, string? description = null, CancellationToken ct = default)
    {
        var raw = Security.TokenGenerator.Generate();
        var hash = HashToken(raw);
        var id = Guid.NewGuid().ToString("N");
        var expiresStr = expiresAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, description, expires_at) VALUES (@id, @orgId, @userId, @hash, @capabilities, @description, @expires)",
            new { id, orgId, userId, hash, capabilities, description, expires = expiresStr });

        return (raw, new TokenRecord
        {
            Id = id, OrgId = orgId, UserId = userId, Capabilities = capabilities,
            Description = description,
            CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = expiresAt,
            Source = TokenSource.User
        });
    }

    public async Task<TokenRecord?> GetTokenByIdAsync(string tokenId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string UserId, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            "SELECT id, org_id, user_id, capabilities, description, created_at, expires_at, last_used_at FROM user_tokens WHERE id = @id",
            new { id = tokenId });
        if (row.Id is null) return null;
        return new TokenRecord
        {
            Id = row.Id, OrgId = row.OrgId, UserId = row.UserId, Capabilities = row.Capabilities,
            Description = row.Description,
            CreatedAt = DateTimeOffset.Parse(row.CreatedAt),
            ExpiresAt = row.ExpiresAt is not null ? DateTimeOffset.Parse(row.ExpiresAt) : null,
            LastUsedAt = row.LastUsedAt is not null ? DateTimeOffset.Parse(row.LastUsedAt) : null,
            Source = TokenSource.User
        };
    }

    public async Task DeleteTokenAsync(string tokenId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM user_tokens WHERE id = @id", new { id = tokenId });
    }

    public async Task<IReadOnlyList<TokenRecord>> ListUserTokensAsync(string orgId, string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string UserId, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            "SELECT id, org_id, user_id, capabilities, description, created_at, expires_at, last_used_at FROM user_tokens WHERE org_id = @orgId AND user_id = @userId ORDER BY created_at DESC",
            new { orgId, userId });
        return rows.Select(t => new TokenRecord
            {
                Id = t.Id, OrgId = t.OrgId, UserId = t.UserId, Capabilities = t.Capabilities,
                Description = t.Description,
                CreatedAt = DateTimeOffset.Parse(t.CreatedAt),
                ExpiresAt = t.ExpiresAt is not null ? DateTimeOffset.Parse(t.ExpiresAt) : null,
                LastUsedAt = t.LastUsedAt is not null ? DateTimeOffset.Parse(t.LastUsedAt) : null,
                Source = TokenSource.User
            })
            .ToList();
    }

    /// <summary>
    /// Service-token sibling of <see cref="CreateUserTokenAsync"/>. <paramref name="capabilities"/>
    /// is the canonical JSON array supplied by the controller after validation.
    /// </summary>
    public async Task<(string RawToken, ServiceTokenRecord Record)> CreateServiceTokenAsync(
        string orgId, string name, string capabilities,
        DateTimeOffset? expiresAt, string? description = null, CancellationToken ct = default)
    {
        var raw = Security.TokenGenerator.Generate();
        var hash = HashToken(raw);
        var id = Guid.NewGuid().ToString("N");
        var expiresStr = expiresAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, description, expires_at) VALUES (@id, @orgId, @name, @hash, @capabilities, @description, @expires)",
            new { id, orgId, name, hash, capabilities, description, expires = expiresStr });

        return (raw, new ServiceTokenRecord
        {
            Id = id, OrgId = orgId, Name = name, Capabilities = capabilities,
            Description = description,
            CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = expiresAt
        });
    }

    public async Task DeleteServiceTokenAsync(string tokenId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM service_tokens WHERE id = @id", new { id = tokenId });
    }

    public async Task<IReadOnlyList<ServiceTokenRecord>> ListServiceTokensAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string Name, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            "SELECT id, org_id, name, capabilities, description, created_at, expires_at, last_used_at FROM service_tokens WHERE org_id = @orgId ORDER BY created_at DESC",
            new { orgId });
        return rows.Select(t => new ServiceTokenRecord
            {
                Id = t.Id, OrgId = t.OrgId, Name = t.Name, Capabilities = t.Capabilities,
                Description = t.Description,
                CreatedAt = DateTimeOffset.Parse(t.CreatedAt),
                ExpiresAt = t.ExpiresAt is not null ? DateTimeOffset.Parse(t.ExpiresAt) : null,
                LastUsedAt = t.LastUsedAt is not null ? DateTimeOffset.Parse(t.LastUsedAt) : null,
            })
            .ToList();
    }

    /// <summary>
    /// Records a successful auth against <paramref name="tokenId"/> in the appropriate table.
    /// Throttled in-SQL: the UPDATE is a no-op unless the existing <c>last_used_at</c> is NULL
    /// or older than <paramref name="minIntervalSeconds"/> (default 60s). One indexed write
    /// keyed on PK; cheap to call on every authenticated request.
    /// </summary>
    public async Task TouchLastUsedAsync(
        string tokenId,
        TokenSource source,
        int minIntervalSeconds = 60,
        CancellationToken ct = default)
    {
        // Two full SQL constants, dispatched by enum — no string composition, no caller input
        // anywhere near the query text. Keeps the parameterized-SQL rule and removes the
        // dynamic-SQL hotspot that interpolation would trigger.
        const string updateUser =
            "UPDATE user_tokens SET last_used_at = @now WHERE id = @id AND (last_used_at IS NULL OR last_used_at < @threshold)";
        const string updateService =
            "UPDATE service_tokens SET last_used_at = @now WHERE id = @id AND (last_used_at IS NULL OR last_used_at < @threshold)";

        var sql = source switch
        {
            TokenSource.User => updateUser,
            TokenSource.Service => updateService,
            _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Unknown token source"),
        };

        var nowDto = DateTimeOffset.UtcNow;
        var now = nowDto.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var threshold = nowDto.AddSeconds(-minIntervalSeconds).ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(sql, new { id = tokenId, now, threshold });
    }
}
