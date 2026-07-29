using System.Security.Cryptography;
using System.Text;
using Dapper;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure;

public class TokenRepository
{
    // 1-second sliding TTL on token-resolve reads, mirroring OrgRepository.SettingsCacheTtl.
    // Every authenticated request on every protocol surface resolves its bearer/basic token
    // through this indexed lookup; at sustained RPS (a CI-install burst hammering the same
    // service token) that serializes through SQLite's single-writer WAL readers the same way
    // the org-settings hot path did before it was cached. The cache key is the resolved token's
    // own SHA-256 hash, so a hit can only ever return the resolution computed for that exact
    // token — two distinct raw tokens never share a hash, so there is no path for one tenant's
    // resolution to be served from another tenant's cache entry.
    //
    // Only a confirmed <see cref="TokenSource.Service"/> resolution is ever cached — never a
    // user-token hit, and never a miss. A user token's validity is entangled with state that
    // must take effect on the very next request, not after a TTL: account lock/disable cuts
    // off its tokens immediately (the account_status join below; see
    // TokenAccountStatusTests.DisabledUser_TokenRejected_ReactivationRestoresIt), and a
    // password change deletes the user's rows outright (see
    // PasswordChangeTests.ChangePassword_InvalidatesOtherSessionsAndPreChangeApiTokens). A
    // cached miss is just as unsafe here as a cached hit: caching "unauthenticated" for a
    // user token that resolved to null because the account was disabled would keep denying it
    // for up to the TTL after the account is re-activated. Service tokens carry none of that
    // entanglement (no owning user, no account_status join, no password-change cascade), and a
    // reused CI/service token across a burst of rapid installs is exactly the scenario this
    // cache exists for — so caching stays scoped to that one safe case.
    private static readonly TimeSpan TokenResolveCacheTtl = TimeSpan.FromSeconds(1);

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly IMemoryCache? _cache;

    public TokenRepository(IMetadataStore db, TimeProvider time, IMemoryCache? cache = null)
    {
        _db = db;
        _time = time;
        _cache = cache;
    }

    private static string TokenResolveCacheKey(string tokenHashHex) => "token-resolve:" + tokenHashHex;

    /// <summary>
    /// Resolves a raw token string to a TokenRecord via indexed lookup on the stored SHA-256 hash.
    /// Returns null if not found or expired. A confirmed service-token hit is cached for
    /// <see cref="TokenResolveCacheTtl"/> keyed on the token's own hash; user-token hits and every
    /// miss always re-query — see the class-level remarks for why.
    /// </summary>
    public async Task<TokenRecord?> ResolveAsync(string rawToken, CancellationToken ct = default)
    {
        byte[] incomingHashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        string incomingHex = Convert.ToHexString(incomingHashBytes).ToLowerInvariant();

        string cacheKey = TokenResolveCacheKey(incomingHex);
        if (_cache is not null && _cache.TryGetValue(cacheKey, out TokenRecord? cachedRecord))
        {
            return cachedRecord;
        }

        await using var conn = await _db.OpenAsync(ct);

        string now = _time.GetUtcNow().ToUtcIso();

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

        var resolved = Id is null
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

        // Only cache a confirmed service-token resolution — see the class-level remarks for
        // why user-token hits and misses are deliberately excluded. Size = 1 counts as one
        // logical slot against the global memory-cache SizeLimit.
        if (_cache is not null && resolved is { Source: TokenSource.Service })
        {
            _cache.Set(cacheKey, resolved, new MemoryCacheEntryOptions
            {
                SlidingExpiration = TokenResolveCacheTtl,
                AbsoluteExpirationRelativeToNow = TokenResolveCacheTtl,
                Size = 1,
            });
        }

        return resolved;
    }

    public static string HashToken(string rawToken)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // The capability set a token carries is its ceiling — an API token never falls back to its
    // owner's role — so a null, empty, or empty-array value mints a row that authenticates and
    // then fails every capability-gated route. Refusing it at the only two write paths is what
    // keeps the state the `purge_legacy_null_capability_tokens` migration cleared from returning.
    private static void RequireGrantingCapabilities(string capabilities)
    {
        if (string.IsNullOrWhiteSpace(capabilities) || capabilities.Trim() == "[]")
        {
            throw new ArgumentException(
                "A token must be issued with at least one capability; it never inherits its owner's role.",
                nameof(capabilities));
        }
    }

    /// <summary>
    /// Issues a user token. <paramref name="capabilities"/> is the canonical JSON capability
    /// array produced by <c>Capabilities.TryNormalizeAndAuthorize</c> at the controller
    /// boundary — the repository assumes it's already validated and writes it verbatim.
    /// A capability-less value is refused: the authorization layer denies such a token
    /// outright, so writing one mints a row that authenticates and grants nothing.
    /// </summary>
    public async Task<(string RawToken, TokenRecord Record)> CreateUserTokenAsync(
        string orgId, string userId, string capabilities,
        DateTimeOffset? expiresAt, string? description = null, CancellationToken ct = default)
    {
        RequireGrantingCapabilities(capabilities);
        string raw = Security.TokenGenerator.Generate();
        string hash = HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string? expiresStr = expiresAt?.ToUtcIso();

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
    /// is the canonical JSON array supplied by the controller after validation, and is
    /// refused when it grants nothing, for the reason given on <see cref="CreateUserTokenAsync"/>.
    /// </summary>
    public async Task<(string RawToken, ServiceTokenRecord Record)> CreateServiceTokenAsync(
        string orgId, string name, string capabilities,
        DateTimeOffset? expiresAt, string? description = null, CancellationToken ct = default)
    {
        RequireGrantingCapabilities(capabilities);
        string raw = Security.TokenGenerator.Generate();
        string hash = HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string? expiresStr = expiresAt?.ToUtcIso();

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
    /// Decides in-process whether a <see cref="TouchLastUsedAsync"/> write is warranted for a
    /// token whose current <c>last_used_at</c> is <paramref name="lastUsedAt"/> (already carried
    /// on the <see cref="TokenRecord"/> from the resolve query). Returns <c>true</c> when the
    /// value is NULL or older than <paramref name="minIntervalSeconds"/> — the same predicate the
    /// in-SQL guard applies. Callers on the authenticated hot path skip the write entirely when
    /// this returns <c>false</c> so a semantically-no-op UPDATE never opens a WAL write
    /// transaction and contends the single SQLite writer; the in-SQL guard remains as the
    /// cross-process race protection.
    /// </summary>
    public bool ShouldTouchLastUsed(DateTimeOffset? lastUsedAt, int minIntervalSeconds = 60)
        => lastUsedAt is not { } last || last < _time.GetUtcNow().AddSeconds(-minIntervalSeconds);

    /// <summary>
    /// Records a successful auth against <paramref name="tokenId"/> in the appropriate table.
    /// Throttled in-SQL: the UPDATE is a no-op unless the existing <c>last_used_at</c> is NULL
    /// or older than <paramref name="minIntervalSeconds"/> (default 60s). One indexed write
    /// keyed on PK. Hot-path callers gate this behind <see cref="ShouldTouchLastUsed"/> so the
    /// no-op case never opens a write transaction; the in-SQL guard stays for cross-process races.
    /// </summary>
    public virtual async Task TouchLastUsedAsync(
        string tokenId,
        TokenSource source,
        int minIntervalSeconds = 60,
        CancellationToken ct = default)
    {
        // Two full SQL constants, dispatched by enum — no string composition, no caller input
        // anywhere near the query text. Keeps the parameterized-SQL rule and removes the
        // dynamic-SQL hotspot that interpolation would trigger.
        // xtenant: both keyed by the token PK that ResolveAsync returned for the presented
        // secret's SHA-256 hash — the row is the caller's own token, never a supplied id.
        const string updateUser =
            "UPDATE user_tokens SET last_used_at = @now WHERE id = @id AND (last_used_at IS NULL OR last_used_at < @threshold)";
        // xtenant: service-token arm of the same hash-resolved PK touch.
        const string updateService =
            "UPDATE service_tokens SET last_used_at = @now WHERE id = @id AND (last_used_at IS NULL OR last_used_at < @threshold)";

        string sql = source switch
        {
            TokenSource.User => updateUser,
            TokenSource.Service => updateService,
            _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Unknown token source"),
        };

        var nowDto = _time.GetUtcNow();
        string now = nowDto.ToUtcIso();
        string threshold = nowDto.AddSeconds(-minIntervalSeconds).ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(sql, new { id = tokenId, now, threshold });
    }
}
