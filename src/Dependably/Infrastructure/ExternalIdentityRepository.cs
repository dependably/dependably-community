using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Persistence for <see cref="ExternalIdentity"/>: IdP-issued identities linked to local users.
/// Identity is the (org_id, idp_entity_id, nameid) triple — never email — so login keeps
/// working when the IdP changes the user's email and cross-IdP collisions on the same email
/// are impossible.
/// </summary>
public sealed class ExternalIdentityRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public ExternalIdentityRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    public async Task<ExternalIdentity?> FindAsync(
        string orgId, string idpEntityId, string nameId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<ExternalIdentity>(
            """
            SELECT id            AS Id,
                   org_id        AS OrgId,
                   user_id       AS UserId,
                   idp_entity_id AS IdpEntityId,
                   nameid        AS NameId,
                   email_snapshot AS EmailSnapshot,
                   created_at    AS CreatedAt,
                   last_login_at AS LastLoginAt
            FROM external_identities
            WHERE org_id = @orgId AND idp_entity_id = @idpEntityId AND nameid = @nameId
            """,
            new { orgId, idpEntityId, nameId });
    }

    public async Task<ExternalIdentity> LinkAsync(
        string orgId, string userId, string idpEntityId, string nameId, string? emailSnapshot,
        CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        var nowDto = _time.GetUtcNow();
        string now = nowDto.ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO external_identities
                (id, org_id, user_id, idp_entity_id, nameid, email_snapshot, created_at, last_login_at)
            VALUES (@id, @orgId, @userId, @idpEntityId, @nameId, @emailSnapshot, @now, @now)
            """,
            new { id, orgId, userId, idpEntityId, nameId, emailSnapshot, now });
        return new ExternalIdentity
        {
            Id = id,
            OrgId = orgId,
            UserId = userId,
            IdpEntityId = idpEntityId,
            NameId = nameId,
            EmailSnapshot = emailSnapshot,
            CreatedAt = nowDto,
            LastLoginAt = nowDto,
        };
    }

    public async Task UpdateLastLoginAsync(
        string id, string? emailSnapshot, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: id is the external_identities PK resolved by the org-scoped FindAsync in
        // LoginService (LoginViaExternalIdentityAsync); the row is already bound to the tenant.
        await conn.ExecuteAsync(
            """
            UPDATE external_identities
            SET last_login_at = @now,
                email_snapshot = COALESCE(@emailSnapshot, email_snapshot)
            WHERE id = @id
            """,
            new
            {
                id,
                emailSnapshot,
                now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
    }

    public async Task<IReadOnlyList<ExternalIdentity>> ListByUserAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ExternalIdentity>(
            """
            SELECT id            AS Id,
                   org_id        AS OrgId,
                   user_id       AS UserId,
                   idp_entity_id AS IdpEntityId,
                   nameid        AS NameId,
                   email_snapshot AS EmailSnapshot,
                   created_at    AS CreatedAt,
                   last_login_at AS LastLoginAt
            FROM external_identities
            WHERE user_id = @userId
            ORDER BY created_at DESC
            """,
            new { userId });
        return rows.ToList();
    }
}
