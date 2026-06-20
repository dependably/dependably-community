using Dapper;
using Dependably.Infrastructure;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Protocol;

/// <summary>
/// Per-org allowlist that exempts specific packages from the install-script block-gate arm
/// (arm 9). A tenant may set <c>block_install_scripts = 'block'</c> globally while permitting
/// known-good packages here. Reads are served from a short-TTL per-org cache matching the
/// <see cref="ReservedNamespaceService"/> shape; mutations invalidate the org's cache entry.
///
/// Version matching:
/// <list type="bullet">
/// <item>A <c>NULL</c> <see cref="InstallScriptAllowlistEntry.VersionPattern"/> matches every
/// version of the package — the most common allowlist shape.</item>
/// <item>A non-null pattern without a trailing <c>*</c> is an exact version match (ordinal).</item>
/// <item>A non-null pattern with a trailing <c>*</c> is a prefix glob — e.g. <c>1.*</c> matches
/// <c>1.2.3</c> and <c>1.0.0-beta</c> but not <c>2.0.0</c>.</item>
/// </list>
/// Ecosystem and name comparisons are case-insensitive (OrdinalIgnoreCase) for parity with the
/// reserved-namespace service and the block-gate's own PURL extraction.
/// </summary>
public sealed class InstallScriptAllowlistService
{
    public static readonly IReadOnlyList<string> SupportedEcosystems =
        ["npm", "pypi", "nuget", "maven", "cargo", "golang", "rpm", "oci"];

    private readonly IMetadataStore _db;
    private readonly IMemoryCache _cache;
    private readonly TimeProvider _time;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    public InstallScriptAllowlistService(IMetadataStore db, IMemoryCache cache, TimeProvider time)
    {
        _db = db;
        _cache = cache;
        _time = time;
    }

    private static string CacheKey(string orgId) => $"install-script-allowlist:{orgId}";

    /// <summary>Returns all allowlist entries for <paramref name="orgId"/>, served from cache.</summary>
    public async Task<IReadOnlyList<InstallScriptAllowlistEntry>> ListAsync(
        string orgId, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(CacheKey(orgId), out IReadOnlyList<InstallScriptAllowlistEntry>? cached)
            && cached is not null)
        {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<InstallScriptAllowlistEntry>(
            """
            SELECT id, org_id AS OrgId, ecosystem, name, version_pattern AS VersionPattern,
                   created_by AS CreatedBy, created_at AS CreatedAt
            FROM install_script_allowlist WHERE org_id = @orgId
            ORDER BY ecosystem, name
            """,
            new { orgId });
        var list = (IReadOnlyList<InstallScriptAllowlistEntry>)rows.ToList();
        _cache.Set(CacheKey(orgId), list, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = CacheTtl,
            Size = 1,
        });
        return list;
    }

    /// <summary>
    /// Adds an entry. Idempotent via <c>ON CONFLICT DO NOTHING</c> on the
    /// <c>UNIQUE(org_id, ecosystem, name, version_pattern)</c> constraint.
    /// </summary>
    public async Task<InstallScriptAllowlistEntry> AddAsync(
        string orgId, string ecosystem, string name, string? versionPattern, string? createdBy,
        CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO install_script_allowlist
                (id, org_id, ecosystem, name, version_pattern, created_by)
            VALUES (@id, @orgId, @ecosystem, @name, @versionPattern, @createdBy)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, ecosystem, name, versionPattern, createdBy });
        _cache.Remove(CacheKey(orgId));
        return new InstallScriptAllowlistEntry
        {
            Id = id,
            OrgId = orgId,
            Ecosystem = ecosystem,
            Name = name,
            VersionPattern = versionPattern,
            CreatedBy = createdBy,
            CreatedAt = _time.GetUtcNow(),
        };
    }

    /// <summary>
    /// Deletes an entry scoped to <paramref name="orgId"/>. Returns rows removed (0 when the
    /// id belongs to another tenant or does not exist) so the caller stays idempotent without
    /// revealing cross-tenant existence — the org_id predicate enforces isolation.
    /// </summary>
    public async Task<int> DeleteAsync(string orgId, string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "DELETE FROM install_script_allowlist WHERE id = @id AND org_id = @orgId",
            new { id = entryId, orgId });
        if (rows > 0)
        {
            _cache.Remove(CacheKey(orgId));
        }

        return rows;
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> at <paramref name="version"/>
    /// is on the install-script allowlist for <c>(org, ecosystem)</c>. A <c>NULL</c>
    /// <c>version_pattern</c> row matches any version. Non-null patterns support an optional
    /// trailing <c>*</c> glob; exact otherwise (ordinal). Ecosystem and name comparisons are
    /// OrdinalIgnoreCase.
    /// </summary>
    public async Task<bool> IsAllowlistedAsync(
        string orgId, string ecosystem, string name, string version, CancellationToken ct = default)
    {
        var entries = await ListAsync(orgId, ct);
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.Ecosystem, ecosystem, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.Equals(entry.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // NULL version_pattern matches every version.
            if (entry.VersionPattern is null || MatchesVersionPattern(entry.VersionPattern, version))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Pure version-pattern test: exact match or prefix glob (trailing <c>*</c>), ordinal.
    /// A null or empty pattern never matches — callers should treat null as "match all"
    /// before calling this helper.
    /// </summary>
    public static bool MatchesVersionPattern(string pattern, string version) =>
        !string.IsNullOrEmpty(pattern) && !string.IsNullOrEmpty(version)
        && (pattern.EndsWith('*')
            ? version.StartsWith(pattern[..^1], StringComparison.Ordinal)
            : string.Equals(pattern, version, StringComparison.Ordinal));
}

/// <summary>A single install-script allowlist entry, mapping one (org, ecosystem, name) tuple
/// to the optional version pattern that scopes the exemption.</summary>
public sealed class InstallScriptAllowlistEntry
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Name { get; init; } = "";
    public string? VersionPattern { get; init; }
    public string? CreatedBy { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}
