using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// A publish principal, identified independently of any request body: the tuple persisted on
/// <c>package_name_binding.owner_*</c> / <c>package_name_grant.grantee_*</c>. <see cref="Kind"/>
/// is <c>'user'</c> (<see cref="Id"/> is a <c>users.id</c>) or <c>'service'</c> (<see cref="Id"/>
/// is a <c>service_tokens.id</c>) — the same discriminator pair as <c>audit_log.actor_kind</c> /
/// <c>actor_id</c>. Built from the resolved token, never from a route/body field, so the
/// authorization decision keys on who authenticated, not on what they claimed to be.
/// </summary>
public readonly record struct NamePrincipal(string Kind, string Id)
{
    /// <summary>
    /// Projects a resolved token's actor identity into a principal, or null when the caller is
    /// anonymous/background (no actor id) — a null principal is never bound and never enforced.
    /// </summary>
    public static NamePrincipal? From(string? actorKind, string? actorId)
        => string.IsNullOrEmpty(actorId) || string.IsNullOrEmpty(actorKind)
            ? null
            : new NamePrincipal(actorKind, actorId);

    /// <summary>
    /// Derives the publish principal from a resolved token. A user token maps to its owning
    /// <c>users.id</c> (so a user's several tokens are one principal); a service token maps to its
    /// own <c>service_tokens.id</c> — a service token carries no user id, so the token itself is
    /// the stable identity. Null for an unresolved/anonymous caller.
    /// </summary>
    public static NamePrincipal? FromToken(TokenRecord? token)
        => token switch
        {
            null => null,
            { Source: TokenSource.Service } => new NamePrincipal(ActorKinds.Service, token.Id),
            { UserId: { Length: > 0 } uid } => new NamePrincipal(ActorKinds.User, uid),
            _ => null,
        };
}

/// <summary>
/// Persistence for the name-ownership model: <c>package_name_binding</c> (one owner per
/// <c>(org, ecosystem, purl_name)</c>, recorded on first hosted publish) and
/// <c>package_name_grant</c> (additional principals allowed to co-publish a bound name).
/// A thin Dapper layer; the authorization rules live in <see cref="Security.NameBindingGate"/>.
/// </summary>
public sealed class NameBindingRepository
{
    private readonly IMetadataStore _db;

    public NameBindingRepository(IMetadataStore db) { _db = db; }

    public async Task<NameBinding?> GetBindingAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<NameBinding>(
            """
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, purl_name AS PurlName,
                   owner_kind AS OwnerKind, owner_id AS OwnerId, created_at AS CreatedAt
            FROM package_name_binding
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
            """,
            new { orgId, ecosystem, purlName });
    }

    /// <summary>
    /// <see langword="true"/> when a binding row exists for the coordinate — i.e. the org has
    /// hosted-published this name at least once. Read by <see cref="ClaimResolver"/> as the
    /// resurrection tombstone: a once-hosted name stays <c>local_only</c> even after its last
    /// version is deleted, so it never silently reverts to upstream resolution.
    /// </summary>
    public async Task<bool> HasBindingAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // SQLite surfaces EXISTS as 0/1, Postgres as boolean — Dapper maps both to bool.
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS (
                SELECT 1 FROM package_name_binding
                WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName)
            """,
            new { orgId, ecosystem, purlName });
    }

    /// <summary>
    /// Binds the name to <paramref name="owner"/> on first hosted publish (trust-on-first-use).
    /// Race-safe: <c>ON CONFLICT DO NOTHING</c> lets two concurrent first-publishes converge on a
    /// single owner, then the winner is re-read by coordinate. Returns the resolved binding.
    /// </summary>
    public async Task<NameBinding> BindIfAbsentAsync(
        string orgId, string ecosystem, string purlName, NamePrincipal owner, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_name_binding (id, org_id, ecosystem, purl_name, owner_kind, owner_id)
            VALUES (@id, @orgId, @ecosystem, @purlName, @ownerKind, @ownerId)
            ON CONFLICT (org_id, ecosystem, purl_name) DO NOTHING
            """,
            new { id, orgId, ecosystem, purlName, ownerKind = owner.Kind, ownerId = owner.Id });

        return (await GetBindingAsync(orgId, ecosystem, purlName, ct))!;
    }

    public async Task<bool> HasGrantAsync(
        string orgId, string ecosystem, string purlName, NamePrincipal grantee, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS (
                SELECT 1 FROM package_name_grant
                WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
                  AND grantee_kind = @granteeKind AND grantee_id = @granteeId)
            """,
            new { orgId, ecosystem, purlName, granteeKind = grantee.Kind, granteeId = grantee.Id });
    }

    /// <summary>Records a co-publish grant. Idempotent (<c>ON CONFLICT DO NOTHING</c>).</summary>
    public async Task AddGrantAsync(
        string orgId, string ecosystem, string purlName, NamePrincipal grantee,
        string? createdBy, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_name_grant
                (id, org_id, ecosystem, purl_name, grantee_kind, grantee_id, created_by)
            VALUES (@id, @orgId, @ecosystem, @purlName, @granteeKind, @granteeId, @createdBy)
            ON CONFLICT (org_id, ecosystem, purl_name, grantee_kind, grantee_id) DO NOTHING
            """,
            new { id, orgId, ecosystem, purlName, granteeKind = grantee.Kind, granteeId = grantee.Id, createdBy });
    }

    public async Task<IReadOnlyList<NameGrant>> ListGrantsAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<NameGrant>(
            """
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, purl_name AS PurlName,
                   grantee_kind AS GranteeKind, grantee_id AS GranteeId,
                   created_by AS CreatedBy, created_at AS CreatedAt
            FROM package_name_grant
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
            ORDER BY created_at
            """,
            new { orgId, ecosystem, purlName });
        return rows.ToList();
    }

    /// <summary>
    /// Deletes a grant by id, scoped to <paramref name="orgId"/>. Returns rows removed (0 when the
    /// id belongs to another tenant or does not exist) so callers stay idempotent without
    /// revealing cross-tenant existence — the org_id predicate enforces isolation.
    /// </summary>
    public async Task<int> RemoveGrantAsync(string orgId, string grantId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM package_name_grant WHERE id = @grantId AND org_id = @orgId",
            new { grantId, orgId });
    }

    /// <summary>
    /// Reads one grant by id within <paramref name="orgId"/>, so a revoke can audit what it removed
    /// rather than just the opaque id. Null when the id belongs to another tenant — the same
    /// org-scoped predicate <see cref="RemoveGrantAsync"/> uses, so the two agree on visibility.
    /// </summary>
    public async Task<NameGrant?> GetGrantAsync(string orgId, string grantId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<NameGrant>(
            """
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, purl_name AS PurlName,
                   grantee_kind AS GranteeKind, grantee_id AS GranteeId,
                   created_by AS CreatedBy, created_at AS CreatedAt
            FROM package_name_grant
            WHERE id = @grantId AND org_id = @orgId
            """,
            new { grantId, orgId });
    }

    /// <summary>
    /// Every name bound within <paramref name="orgId"/>, optionally narrowed to one ecosystem.
    /// This is the admin read that makes grant management usable: a co-publish grant only means
    /// anything against a name that is already bound, so the caller needs to see what exists.
    /// </summary>
    public async Task<IReadOnlyList<NameBinding>> ListBindingsAsync(
        string orgId, string? ecosystem = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<NameBinding>(
            """
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, purl_name AS PurlName,
                   owner_kind AS OwnerKind, owner_id AS OwnerId, created_at AS CreatedAt
            FROM package_name_binding
            WHERE org_id = @orgId
              AND (@ecosystem IS NULL OR ecosystem = @ecosystem)
            ORDER BY ecosystem, purl_name
            """,
            new { orgId, ecosystem });
        return rows.ToList();
    }

    /// <summary>
    /// <see langword="true"/> when <paramref name="principal"/> names a principal that exists
    /// inside <paramref name="orgId"/>: a <c>users</c> row in this tenant, or a
    /// <c>service_tokens</c> row owned by this org.
    ///
    /// <para>
    /// This is the check that keeps grant creation from becoming a cross-tenant write. The grantee
    /// id arrives in a request body, so without it an admin could name another tenant's user or
    /// service token and mint a row authorizing that foreign principal to publish here — the grant
    /// row's own <c>org_id</c> would look perfectly well-scoped while the principal it points at is
    /// not. Resolving the id against this org's roster is what closes that.
    /// </para>
    /// </summary>
    public async Task<bool> GranteeExistsInOrgAsync(
        string orgId, NamePrincipal principal, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        if (string.Equals(principal.Kind, ActorKinds.User, StringComparison.Ordinal))
        {
            return await conn.ExecuteScalarAsync<bool>(
                "SELECT EXISTS (SELECT 1 FROM users WHERE id = @id AND tenant_id = @orgId)",
                new { id = principal.Id, orgId });
        }

        if (string.Equals(principal.Kind, ActorKinds.Service, StringComparison.Ordinal))
        {
            return await conn.ExecuteScalarAsync<bool>(
                "SELECT EXISTS (SELECT 1 FROM service_tokens WHERE id = @id AND org_id = @orgId)",
                new { id = principal.Id, orgId });
        }

        // An unknown kind resolves to nothing rather than to "allowed". The CHECK constraint on
        // grantee_kind would reject the insert anyway; the decision is made here, deliberately.
        return false;
    }
}

public sealed class NameBinding
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string PurlName { get; init; } = "";
    public string OwnerKind { get; init; } = "";
    public string OwnerId { get; init; } = "";
    public string CreatedAt { get; init; } = "";

    /// <summary><see langword="true"/> when <paramref name="principal"/> is this name's owner.</summary>
    public bool IsOwnedBy(NamePrincipal principal)
        => string.Equals(OwnerKind, principal.Kind, StringComparison.Ordinal)
        && string.Equals(OwnerId, principal.Id, StringComparison.Ordinal);
}

public sealed class NameGrant
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string PurlName { get; init; } = "";
    public string GranteeKind { get; init; } = "";
    public string GranteeId { get; init; } = "";
    public string? CreatedBy { get; init; }
    public string CreatedAt { get; init; } = "";
}
