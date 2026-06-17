using System.Security.Cryptography;
using System.Text;
using Dapper;

namespace Dependably.Infrastructure;

public sealed class TokenRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public TokenRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Resolves a raw token string to a TokenRecord via indexed lookup on the stored SHA-256 hash.
    /// Returns null if not found or expired.
    /// </summary>
    public async Task<TokenRecord?> ResolveAsync(string rawToken, CancellationToken ct = default)
    {
        byte[] incomingHashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        string incomingHex = Convert.ToHexString(incomingHashBytes).ToLowerInvariant();

        await using var conn = await _db.OpenAsync(ct);

        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Single UNION ALL query collapses the previous two-round-trip lookup
        // (user_tokens THEN service_tokens) into one. token_hash is SHA-256 of a
        // securely-generated token, so the same hash cannot appear in both tables — at
        // most one branch matches. The `source` literal column lets us route the result
        // back to the right TokenSource without a second query. Both branches stay
        // indexed via idx_user_tokens_hash / idx_service_tokens_hash.
        //
        // User tokens are credentials *of a user*: the INNER JOIN ties each token to an
        // owner row that still exists in the token's tenant (u.tenant_id = t.org_id) and
        // is account_status = 'active'. Locking or disabling an account therefore cuts off
        // its API tokens immediately — the rows stay in user_tokens (inert) and resume
        // working only if an operator re-activates the account. Removing the user deletes
        // the rows outright via the user_id ON DELETE CASCADE.
        var (Id, OrgId, UserId, Capabilities, Description, CreatedAt, ExpiresAt, LastUsedAt, Source) = await conn.QuerySingleOrDefaultAsync<(
            string Id, string OrgId, string? UserId, string? Capabilities,
            string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt,
            string Source)>(
            """
            SELECT t.id, t.org_id, t.user_id, t.capabilities, t.description, t.created_at, t.expires_at, t.last_used_at, 'user' AS source
            FROM user_tokens t
            JOIN users u ON u.id = t.user_id AND u.tenant_id = t.org_id
            WHERE t.token_hash = @hash
              AND (t.expires_at IS NULL OR t.expires_at > @now)
              AND u.account_status = 'active'
            UNION ALL
            SELECT id, org_id, NULL AS user_id, capabilities, description, created_at, expires_at, last_used_at, 'service' AS source
            FROM service_tokens
            WHERE token_hash = @hash AND (expires_at IS NULL OR expires_at > @now)
            LIMIT 1
            """,
            new { hash = incomingHex, now });

        return Id is null
            ? null
            : new TokenRecord
            {
                Id = Id,
                OrgId = OrgId,
                UserId = UserId,
                Capabilities = Capabilities,
                Description = Description,
                CreatedAt = DateTimeOffset.Parse(CreatedAt),
                ExpiresAt = ExpiresAt is not null ? DateTimeOffset.Parse(ExpiresAt) : null,
                LastUsedAt = LastUsedAt is not null ? DateTimeOffset.Parse(LastUsedAt) : null,
                Source = Source == "service" ? TokenSource.Service : TokenSource.User,
            };
    }

    public static string HashToken(string rawToken)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
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
        string raw = Security.TokenGenerator.Generate();
        string hash = HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string? expiresStr = expiresAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, description, expires_at) VALUES (@id, @orgId, @userId, @hash, @capabilities, @description, @expires)",
            new { id, orgId, userId, hash, capabilities, description, expires = expiresStr });

        return (raw, new TokenRecord
        {
            Id = id,
            OrgId = orgId,
            UserId = userId,
            Capabilities = capabilities,
            Description = description,
            CreatedAt = _time.GetUtcNow(),
            ExpiresAt = expiresAt,
            Source = TokenSource.User
        });
    }

    public async Task<TokenRecord?> GetTokenByIdAsync(string tokenId, string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (Id, OrgId, UserId, Capabilities, Description, CreatedAt, ExpiresAt, LastUsedAt) =
            await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string UserId,
                string? Capabilities, string? Description, string CreatedAt,
                string? ExpiresAt, string? LastUsedAt)>(
            "SELECT id, org_id, user_id, capabilities, description, created_at, expires_at, last_used_at FROM user_tokens WHERE id = @id AND org_id = @orgId",
            new { id = tokenId, orgId });
        return Id is null
            ? null
            : new TokenRecord
            {
                Id = Id,
                OrgId = OrgId,
                UserId = UserId,
                Capabilities = Capabilities,
                Description = Description,
                CreatedAt = DateTimeOffset.Parse(CreatedAt),
                ExpiresAt = ExpiresAt is not null ? DateTimeOffset.Parse(ExpiresAt) : null,
                LastUsedAt = LastUsedAt is not null ? DateTimeOffset.Parse(LastUsedAt) : null,
                Source = TokenSource.User
            };
    }

    /// <summary>
    /// Deletes a user token scoped to its org. Returns the number of rows removed (0 when the
    /// id does not belong to <paramref name="orgId"/>), so callers reject cross-tenant deletes.
    /// </summary>
    public async Task<int> DeleteTokenAsync(string tokenId, string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM user_tokens WHERE id = @id AND org_id = @orgId", new { id = tokenId, orgId });
    }

    public async Task<IReadOnlyList<TokenRecord>> ListUserTokensAsync(string orgId, string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string UserId, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            "SELECT id, org_id, user_id, capabilities, description, created_at, expires_at, last_used_at FROM user_tokens WHERE org_id = @orgId AND user_id = @userId ORDER BY created_at DESC",
            new { orgId, userId });
        return rows.Select(t => new TokenRecord
        {
            Id = t.Id,
            OrgId = t.OrgId,
            UserId = t.UserId,
            Capabilities = t.Capabilities,
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
        string raw = Security.TokenGenerator.Generate();
        string hash = HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string? expiresStr = expiresAt?.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, description, expires_at) VALUES (@id, @orgId, @name, @hash, @capabilities, @description, @expires)",
            new { id, orgId, name, hash, capabilities, description, expires = expiresStr });

        return (raw, new ServiceTokenRecord
        {
            Id = id,
            OrgId = orgId,
            Name = name,
            Capabilities = capabilities,
            Description = description,
            CreatedAt = _time.GetUtcNow(),
            ExpiresAt = expiresAt
        });
    }

    /// <summary>
    /// Deletes a service token scoped to its org. Returns the number of rows removed (0 when
    /// the id does not belong to <paramref name="orgId"/>), so callers reject cross-tenant deletes.
    /// </summary>
    public async Task<int> DeleteServiceTokenAsync(string tokenId, string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM service_tokens WHERE id = @id AND org_id = @orgId", new { id = tokenId, orgId });
    }

    public async Task<IReadOnlyList<ServiceTokenRecord>> ListServiceTokensAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string Name, string? Capabilities, string? Description, string CreatedAt, string? ExpiresAt, string? LastUsedAt)>(
            "SELECT id, org_id, name, capabilities, description, created_at, expires_at, last_used_at FROM service_tokens WHERE org_id = @orgId ORDER BY created_at DESC",
            new { orgId });
        return rows.Select(t => new ServiceTokenRecord
        {
            Id = t.Id,
            OrgId = t.OrgId,
            Name = t.Name,
            Capabilities = t.Capabilities,
            Description = t.Description,
            CreatedAt = DateTimeOffset.Parse(t.CreatedAt),
            ExpiresAt = t.ExpiresAt is not null ? DateTimeOffset.Parse(t.ExpiresAt) : null,
            LastUsedAt = t.LastUsedAt is not null ? DateTimeOffset.Parse(t.LastUsedAt) : null,
        })
            .ToList();
    }

    /// <summary>
    /// Resolves a presented <see cref="TokenRecord"/> to the identifier returned by
    /// <c>GET /npm/-/whoami</c>. User tokens return the owner's <c>users.email</c>; service
    /// tokens return <c>service:&lt;service_tokens.name&gt;</c> so npm callers see a stable
    /// human-readable identifier instead of an empty string. Both lookups are parameterized
    /// and filtered on <c>org_id</c> to stay consistent with the rest of the tenant-scoped
    /// SQL surface (the token row's <c>org_id</c> is the source of truth — cross-tenant
    /// presentation is already rejected upstream by <see cref="TokenAuthExtensions.ResolveTokenAsync(HttpRequest, TokenRepository, string, CancellationToken)"/>).
    /// Returns null when the row is gone between auth and lookup.
    /// </summary>
    public async Task<string?> GetWhoAmIIdentifierAsync(TokenRecord token, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        if (token.Source == TokenSource.User)
        {
            return token.UserId is null
                ? null
                : await conn.ExecuteScalarAsync<string?>(
                "SELECT email FROM users WHERE id = @userId AND tenant_id = @orgId",
                new { userId = token.UserId, orgId = token.OrgId });
        }

        string? name = await conn.ExecuteScalarAsync<string?>(
            "SELECT name FROM service_tokens WHERE id = @id AND org_id = @orgId",
            new { id = token.Id, orgId = token.OrgId });
        return name is null ? null : $"service:{name}";
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

        string sql = source switch
        {
            TokenSource.User => updateUser,
            TokenSource.Service => updateService,
            _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Unknown token source"),
        };

        var nowDto = _time.GetUtcNow();
        string now = nowDto.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string threshold = nowDto.AddSeconds(-minIntervalSeconds).ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(sql, new { id = tokenId, now, threshold });
    }
}
