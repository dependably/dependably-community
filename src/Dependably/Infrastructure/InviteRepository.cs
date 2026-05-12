using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Security;

namespace Dependably.Infrastructure;

public sealed class InviteRepository
{
    private readonly IMetadataStore _db;

    public InviteRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Creates a new 24-hour invite. Returns (rawToken, record).
    /// If SMTP_HOST is not configured, the caller is responsible for logging the link.
    /// </summary>
    public async Task<(string RawToken, InviteRecord Record)> CreateAsync(
        string orgId, string email, string createdByUserId, string role = "member", CancellationToken ct = default)
    {
        var raw = TokenGenerator.Generate();
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        var id = Guid.NewGuid().ToString("N");
        var expiresAt = DateTimeOffset.UtcNow.AddHours(24);
        var expiresStr = expiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at)
            VALUES (@id, @orgId, @email, @role, @hash, @createdBy, @expires)
            """,
            new { id, orgId, email, role, hash, createdBy = createdByUserId, expires = expiresStr });

        return (raw, new InviteRecord
        {
            Id = id, OrgId = orgId, Email = email, Role = role, CreatedBy = createdByUserId,
            CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = expiresAt, AcceptedAt = null
        });
    }

    public async Task<IReadOnlyList<InviteRecord>> ListAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string Email, string Role, string CreatedBy, string CreatedAt, string ExpiresAt, string? AcceptedAt)>(
            """
            SELECT id, org_id, email, role, created_by, created_at, expires_at, accepted_at
            FROM invites WHERE org_id = @orgId ORDER BY created_at DESC
            """,
            new { orgId });

        return rows.Select(r => new InviteRecord
            {
                Id = r.Id, OrgId = r.OrgId, Email = r.Email, Role = r.Role, CreatedBy = r.CreatedBy,
                CreatedAt = DateTimeOffset.Parse(r.CreatedAt),
                ExpiresAt = DateTimeOffset.Parse(r.ExpiresAt),
                AcceptedAt = r.AcceptedAt is not null ? DateTimeOffset.Parse(r.AcceptedAt) : null
            })
            .ToList();
    }

    public async Task DeleteAsync(string inviteId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("DELETE FROM invites WHERE id = @id", new { id = inviteId });
    }

    /// <summary>
    /// Resolves an invite token and marks it as accepted.
    /// Returns the invite record on success, null if expired/not found/already accepted.
    /// </summary>
    public async Task<InviteRecord?> AcceptAsync(string rawToken, CancellationToken ct = default)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();

        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<(string Id, string OrgId, string Email, string Role, string CreatedBy, string CreatedAt, string ExpiresAt, string? AcceptedAt)>(
            "SELECT id, org_id, email, role, created_by, created_at, expires_at, accepted_at FROM invites WHERE token_hash = @hash",
            new { hash });

        if (row.Id is null) return null;

        var expiresAt = DateTimeOffset.Parse(row.ExpiresAt);
        if (expiresAt < DateTimeOffset.UtcNow) return null;
        if (row.AcceptedAt is not null) return null;

        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await conn.ExecuteAsync(
            "UPDATE invites SET accepted_at = @now WHERE id = @id",
            new { now, id = row.Id });

        return new InviteRecord
        {
            Id = row.Id, OrgId = row.OrgId, Email = row.Email, Role = row.Role,
            CreatedBy = row.CreatedBy,
            CreatedAt = DateTimeOffset.Parse(row.CreatedAt), ExpiresAt = expiresAt,
            AcceptedAt = DateTimeOffset.UtcNow
        };
    }
}
