using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Per-org upstream proxy registries. Each (org, ecosystem) owns a priority-ordered list
/// (ascending <c>position</c>, lowest tried first). The proxy fetch path walks the list and
/// falls through to the next entry on miss/unreachable; an empty list disables proxying for
/// that ecosystem. Mirrors the shape of <see cref="AllowlistRepository"/>.
/// </summary>
public sealed class UpstreamRegistryRepository
{
    private readonly IMetadataStore _db;

    public UpstreamRegistryRepository(IMetadataStore db) => _db = db;

    /// <summary>The ecosystems whose upstream lists are user-configurable through this table.</summary>
    public static readonly IReadOnlyList<string> SupportedEcosystems =
        ["pypi", "npm", "nuget", "maven", "rpm"];

    public static bool IsSupportedEcosystem(string? ecosystem) =>
        ecosystem is not null && SupportedEcosystems.Contains(ecosystem);

    /// <summary>All entries for an org, ordered by ecosystem then priority.</summary>
    public async Task<IReadOnlyList<UpstreamRegistryEntry>> ListAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<UpstreamRegistryEntry>(
            """
            SELECT id, org_id AS OrgId, ecosystem AS Ecosystem, name AS Name,
                   url AS Url, position AS Position, created_at AS CreatedAt
            FROM upstream_registry
            WHERE org_id = @orgId
            ORDER BY ecosystem, position, created_at
            """,
            new { orgId });
        return rows.ToList();
    }

    /// <summary>The configured registry URLs for one (org, ecosystem) in priority order.</summary>
    public async Task<IReadOnlyList<string>> ListUrlsForEcosystemAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<string>(
            """
            SELECT url
            FROM upstream_registry
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            ORDER BY position, created_at
            """,
            new { orgId, ecosystem });
        return rows.ToList();
    }

    /// <summary>
    /// Appends a registry at the bottom of the (org, ecosystem) priority list. The new
    /// <c>position</c> is one past the current max so the entry is tried last.
    /// </summary>
    public async Task<UpstreamRegistryEntry> AddAsync(
        string orgId, string ecosystem, string url, string? name, CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        var nextPosition = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COALESCE(MAX(position), -1) + 1
            FROM upstream_registry
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            """,
            new { orgId, ecosystem });

        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, name, url, position)
            VALUES (@id, @orgId, @ecosystem, @name, @url, @position)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, ecosystem, name, url, position = nextPosition });

        return new UpstreamRegistryEntry
        {
            Id = id, OrgId = orgId, Ecosystem = ecosystem, Name = name,
            Url = url, Position = nextPosition, CreatedAt = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>Deletes a registry, scoped to its owning org (BOLA-safe).</summary>
    public async Task DeleteAsync(string orgId, string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE id = @id AND org_id = @orgId",
            new { id = entryId, orgId });
    }

    /// <summary>
    /// Reassigns <c>position</c> across the (org, ecosystem) list to match <paramref name="orderedIds"/>.
    /// Only ids that belong to this (org, ecosystem) are repositioned; unknown ids are ignored, and
    /// any entries omitted from the list keep their relative order after the supplied ones.
    /// </summary>
    public async Task ReorderAsync(
        string orgId, string ecosystem, IReadOnlyList<string> orderedIds, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            var existing = (await conn.QueryAsync<string>(
                "SELECT id FROM upstream_registry WHERE org_id = @orgId AND ecosystem = @ecosystem",
                new { orgId, ecosystem }, dbTx)).ToHashSet();

            // Honour the requested order first, then append any entries the caller left out so no
            // row loses its position.
            var ordered = orderedIds.Where(existing.Contains).ToList();
            ordered.AddRange(existing.Where(id => !ordered.Contains(id)));

            for (var i = 0; i < ordered.Count; i++)
            {
                await conn.ExecuteAsync(
                    "UPDATE upstream_registry SET position = @position WHERE id = @id AND org_id = @orgId",
                    new { position = i, id = ordered[i], orgId }, dbTx);
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }
}
