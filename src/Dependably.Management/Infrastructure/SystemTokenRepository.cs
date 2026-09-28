using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// A token minted at the apex that authenticates the tenant-lifecycle and usage-limit actions on
/// <c>SystemController</c> without an interactive session — CI, Terraform, and provisioning
/// scripts use it in place of a system_admin JWT. Sibling of <see cref="TokenRepository"/>, kept
/// separate because the two rows have nothing in common beyond "a hashed secret": no org, no
/// capability set, one fixed instance-wide cap rather than a per-tenant one, and an owner in
/// <c>system_admins</c> rather than a tenant user.
/// </summary>
public sealed class SystemTokenRepository
{
    /// <summary>
    /// Distinguishing prefix on every raw token, ahead of the generated secret. Lets
    /// <c>SystemTokenAuthenticationHandler</c> return <c>NoResult()</c> on a JWT or a tenant
    /// <c>ApiToken</c> secret without a database round trip, and makes a leaked token
    /// recognisable to secret scanners and grep alike.
    /// </summary>
    public const string TokenPrefix = "dpsys_";

    /// <summary>Instance-wide ceiling on active (non-expired) system tokens, across every owner.</summary>
    private const int MaxActiveTokens = 50;

    // Fixed key for the serialized-insert critical section below. Every caller shares this one
    // key (unlike TokenRepository.InsertUnderTenantCapAsync, which is keyed per tenant) because
    // the cap this enforces is instance-wide, not per-owner.
    private const string CapLockKey = "system-tokens";

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public SystemTokenRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Resolves a raw <c>dpsys_…</c> token to a <see cref="SystemTokenRecord"/> via indexed
    /// lookup on the stored SHA-256 hash. The owner join requires <c>account_status = 'active'</c>
    /// so disabling or locking the minting admin stops every token they own from resolving on the
    /// very next request — there is no resolve cache, unlike <see cref="TokenRepository"/>, because
    /// system-plane traffic is low and revocation must take effect immediately.
    /// </summary>
    public async Task<SystemTokenRecord?> ResolveAsync(string rawToken, CancellationToken ct = default)
    {
        string hash = TokenRepository.HashToken(rawToken);
        string now = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        var (Id, Name, CreatedBy, Description, CreatedAt, ExpiresAt, LastUsedAt) =
            await conn.QuerySingleOrDefaultAsync<(string Id, string Name, string CreatedBy,
                string? Description, string CreatedAt, string ExpiresAt, string? LastUsedAt)>(
            """
            SELECT t.id, t.name, t.created_by, t.description, t.created_at, t.expires_at, t.last_used_at
            FROM system_tokens t
            JOIN system_admins sa ON sa.id = t.created_by AND sa.account_status = 'active'
            WHERE t.token_hash = @hash AND t.expires_at > @now
            """,
            new { hash, now });

        return Id is null
            ? null
            : new SystemTokenRecord
            {
                Id = Id,
                Name = Name,
                CreatedBy = CreatedBy,
                Description = Description,
                CreatedAt = DateTimeOffset.Parse(CreatedAt),
                ExpiresAt = DateTimeOffset.Parse(ExpiresAt),
                LastUsedAt = LastUsedAt is not null ? DateTimeOffset.Parse(LastUsedAt) : null,
            };
    }

    /// <summary>
    /// Mints a token under the instance-wide <see cref="MaxActiveTokens"/> cap, counted and
    /// inserted inside one serialized critical section so concurrent mints cannot all observe the
    /// same under-cap count and all insert past it — the same shape as
    /// <c>TokenRepository.InsertUnderTenantCapAsync</c>, reusing
    /// <see cref="MetadataTransactionExtensions.BeginTenantSerializedAsync"/> with the fixed
    /// <see cref="CapLockKey"/> in place of a tenant id, since this ceiling has no tenant to key on.
    ///
    /// <para>
    /// The insert itself is conditioned, inside the same transaction, on the owner still being
    /// <c>account_status = 'active'</c> with <c>token_version</c> matching
    /// <paramref name="callerTokenVersion"/> — the version snapshotted in the caller's JWT
    /// <c>tver</c> claim at the moment it authenticated. This closes the race the outer
    /// JwtBearer/<c>SystemAdminTokenVersionStore</c> check cannot: that check is cache-backed (up
    /// to 60s TTL on a single-replica deployment) and runs once, before this method is even
    /// called, so a password change or admin-initiated reset landing in the DB after the JWT
    /// validated but before this INSERT commits would otherwise still mint a durable credential
    /// under a session that is, at that instant, already invalidated everywhere else.
    /// </para>
    /// </summary>
    /// <exception cref="SystemTokenCapExceededException">The instance is already at its ceiling.</exception>
    /// <exception cref="SystemTokenOwnerSessionStaleException">
    /// The owner's account is no longer active, or <paramref name="callerTokenVersion"/> no
    /// longer matches the stored <c>token_version</c>.
    /// </exception>
    public async Task<(string RawToken, SystemTokenRecord Record)> CreateAsync(
        string createdBy, string name, DateTimeOffset expiresAt, long callerTokenVersion,
        string? description = null, CancellationToken ct = default)
    {
        string raw = TokenPrefix + Security.TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string expiresStr = expiresAt.ToUtcIso();
        string now = _time.GetUtcNow().ToUtcIso();

        string? ownerEmail;
        await using var conn = await _db.OpenAsync(ct);
        await conn.BeginTenantSerializedAsync(_db.Provider, CapLockKey, ct);
        try
        {
            long active = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
                "SELECT COUNT(*) FROM system_tokens WHERE expires_at > @now",
                new { now }, cancellationToken: ct));

            if (active >= MaxActiveTokens)
            {
                await conn.ExecuteAsync(new CommandDefinition("ROLLBACK", cancellationToken: ct));
                throw new SystemTokenCapExceededException((int)active, MaxActiveTokens);
            }

            // INSERT ... SELECT ... WHERE EXISTS(...) — parameterized on both providers, and the
            // WHERE gate is evaluated inside this transaction against the live row, not against a
            // value read earlier in the request pipeline. Zero rows affected means the owner
            // check failed: same shape whether the account was disabled/locked or token_version
            // moved on, so the caller sees one refusal either way.
            int inserted = await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO system_tokens (id, name, token_hash, created_by, description, expires_at)
                SELECT @id, @name, @hash, @createdBy, @description, @expires
                WHERE EXISTS (
                    SELECT 1 FROM system_admins
                    WHERE id = @createdBy AND account_status = 'active' AND token_version = @callerTokenVersion
                )
                """,
                new { id, name, hash, createdBy, description, expires = expiresStr, callerTokenVersion },
                cancellationToken: ct));

            if (inserted == 0)
            {
                await conn.ExecuteAsync(new CommandDefinition("ROLLBACK", cancellationToken: ct));
                throw new SystemTokenOwnerSessionStaleException(createdBy);
            }

            ownerEmail = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
                "SELECT email FROM system_admins WHERE id = @createdBy",
                new { createdBy }, cancellationToken: ct));

            await conn.ExecuteAsync(new CommandDefinition("COMMIT", cancellationToken: ct));
        }
        catch (SystemTokenCapExceededException)
        {
            throw;
        }
        catch (SystemTokenOwnerSessionStaleException)
        {
            throw;
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }

        return (raw, new SystemTokenRecord
        {
            Id = id,
            Name = name,
            CreatedBy = createdBy,
            OwnerEmail = ownerEmail,
            Description = description,
            CreatedAt = _time.GetUtcNow(),
            ExpiresAt = expiresAt,
        });
    }

    /// <summary>Lists every system token, newest first, with the owner's email resolved for display.</summary>
    public async Task<IReadOnlyList<SystemTokenRecord>> ListAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string Name, string CreatedBy, string? OwnerEmail,
            string? Description, string CreatedAt, string ExpiresAt, string? LastUsedAt)>(
            """
            SELECT t.id, t.name, t.created_by, sa.email as OwnerEmail,
                   t.description, t.created_at, t.expires_at, t.last_used_at
            FROM system_tokens t
            LEFT JOIN system_admins sa ON sa.id = t.created_by
            ORDER BY t.created_at DESC
            """);

        return rows.Select(t => new SystemTokenRecord
        {
            Id = t.Id,
            Name = t.Name,
            CreatedBy = t.CreatedBy,
            OwnerEmail = t.OwnerEmail,
            Description = t.Description,
            CreatedAt = DateTimeOffset.Parse(t.CreatedAt),
            ExpiresAt = DateTimeOffset.Parse(t.ExpiresAt),
            LastUsedAt = t.LastUsedAt is not null ? DateTimeOffset.Parse(t.LastUsedAt) : null,
        }).ToList();
    }

    /// <summary>Revokes one token by id. Returns the number of rows removed (0 when the id does not exist).</summary>
    public async Task<int> DeleteAsync(string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync("DELETE FROM system_tokens WHERE id = @id", new { id });
    }

    /// <summary>
    /// Revokes every token owned by <paramref name="adminId"/>. Called from the compromise-response
    /// path (an admin-initiated reset of another admin's password) so a credential rotation on the
    /// owner cuts off every token minted under the old session too, not just the owner's own login.
    ///
    /// Takes the same <see cref="CapLockKey"/> serialized section as <see cref="CreateAsync"/> —
    /// under READ COMMITTED (Postgres), a mint whose INSERT ran before this reset's token_version
    /// bump committed, but whose own COMMIT lands after this DELETE, would otherwise survive the
    /// reset. Serializing the two against each other closes that window.
    /// </summary>
    public async Task<int> DeleteByOwnerAsync(string adminId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.BeginTenantSerializedAsync(_db.Provider, CapLockKey, ct);
        try
        {
            int deleted = await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM system_tokens WHERE created_by = @adminId", new { adminId }, cancellationToken: ct));
            await conn.ExecuteAsync(new CommandDefinition("COMMIT", cancellationToken: ct));
            return deleted;
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }
    }

    /// <summary>Same 60-second throttle rule as <see cref="TokenRepository.ShouldTouchLastUsed"/>.</summary>
    public bool ShouldTouchLastUsed(DateTimeOffset? lastUsedAt, int minIntervalSeconds = 60)
        => lastUsedAt is not { } last || last < _time.GetUtcNow().AddSeconds(-minIntervalSeconds);

    /// <summary>Throttled last-used stamp, mirroring <see cref="TokenRepository.TouchLastUsedAsync"/>.</summary>
    public async Task TouchLastUsedAsync(string tokenId, int minIntervalSeconds = 60, CancellationToken ct = default)
    {
        var nowDto = _time.GetUtcNow();
        string now = nowDto.ToUtcIso();
        string threshold = nowDto.AddSeconds(-minIntervalSeconds).ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE system_tokens SET last_used_at = @now WHERE id = @id AND (last_used_at IS NULL OR last_used_at < @threshold)",
            new { id = tokenId, now, threshold });
    }
}

public class SystemTokenRecord
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    /// <summary>Owner's email, resolved by <see cref="SystemTokenRepository.ListAsync"/> and <see cref="SystemTokenRepository.CreateAsync"/>.</summary>
    public string? OwnerEmail { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
}
