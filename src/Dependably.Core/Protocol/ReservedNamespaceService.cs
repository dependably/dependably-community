using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Protocol;

/// <summary>
/// Operator-reserved namespaces — the explicit half of the dependency-confusion guard.
/// A package name matching a reserved pattern for its ecosystem never consults upstream:
/// metadata endpoints skip the upstream merge and download paths refuse the proxy fetch,
/// both with the same silent-404 semantics as a <c>local_only</c> claim. Hosted serving is
/// unaffected — reserving a namespace does not block publishing into it.
///
/// Pattern semantics per ecosystem:
/// <list type="bullet">
/// <item>npm — exact name or trailing-<c>*</c> glob; ordinal compare on lowercased names
/// (<c>@acme/*</c> reserves the whole scope).</item>
/// <item>pypi — exact or trailing-<c>*</c> glob; both sides are PEP 503-normalized before
/// comparing, matching what the controllers store as <c>purl_name</c>.</item>
/// <item>nuget — exact or trailing-<c>*</c> glob, OrdinalIgnoreCase (NuGet ids are
/// case-insensitive).</item>
/// <item>maven — dot-boundary groupId prefix: <c>com.acme</c> reserves <c>com.acme</c> and
/// every <c>com.acme.*</c> groupId but not <c>com.acmecorp</c>. A trailing <c>*</c> /
/// <c>.*</c> on the stored pattern is tolerated and folds into the same semantics.</item>
/// <item>cargo — exact or trailing-<c>*</c> glob, ordinal on lowercased names (crates.io is a
/// flat, case-folded namespace), same shape as npm.</item>
/// <item>golang — slash-boundary module-path prefix, the <c>/</c> analog of maven's dot
/// boundary: <c>github.com/acme</c> reserves <c>github.com/acme</c> and every
/// <c>github.com/acme/*</c> path but not <c>github.com/acmecorp</c>. Case-sensitive (Ordinal) —
/// Go module paths are case-significant (the proxy's bang-encoding exists for exactly this).</item>
/// </list>
///
/// Reads are served from a short-TTL per-org cache (same shape as
/// <see cref="BlocklistRepository"/>) so the hot proxy paths cost one dictionary hit;
/// mutations invalidate the org's entry.
/// </summary>
public sealed partial class ReservedNamespaceService
{
    public static readonly IReadOnlyList<string> SupportedEcosystems = ["npm", "pypi", "nuget", "maven", "cargo", "golang"];

    private readonly IMetadataStore _db;
    private readonly IMemoryCache _cache;
    private readonly TimeProvider _time;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    public ReservedNamespaceService(IMetadataStore db, IMemoryCache cache, TimeProvider time)
    {
        _db = db;
        _cache = cache;
        _time = time;
    }

    private static string CacheKey(string orgId) => $"reserved-namespace:{orgId}";

    public async Task<IReadOnlyList<ReservedNamespaceEntry>> ListAsync(
        string orgId, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(CacheKey(orgId), out IReadOnlyList<ReservedNamespaceEntry>? cached) && cached is not null)
        {
            return cached;
        }

        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ReservedNamespaceEntry>(
            """
            SELECT id, org_id AS OrgId, ecosystem, pattern,
                   created_by AS CreatedBy, created_at AS CreatedAt
            FROM reserved_namespace WHERE org_id = @orgId
            ORDER BY ecosystem, pattern
            """,
            new { orgId });
        var list = (IReadOnlyList<ReservedNamespaceEntry>)rows.ToList();
        _cache.Set(CacheKey(orgId), list, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = CacheTtl,
            Size = 1,
        });
        return list;
    }

    public async Task<ReservedNamespaceEntry> AddAsync(
        string orgId, string ecosystem, string pattern, string? createdBy, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern, created_by)
            VALUES (@id, @orgId, @ecosystem, @pattern, @createdBy)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, ecosystem, pattern, createdBy });
        _cache.Remove(CacheKey(orgId));
        return new ReservedNamespaceEntry
        {
            Id = id,
            OrgId = orgId,
            Ecosystem = ecosystem,
            Pattern = pattern,
            CreatedBy = createdBy,
            CreatedAt = _time.GetUtcNow(),
        };
    }

    /// <summary>
    /// Deletes an entry, scoped to <paramref name="orgId"/>. Returns rows removed (0 when the
    /// id belongs to another tenant or does not exist) so the caller can stay idempotent
    /// without revealing cross-tenant existence — the org_id predicate enforces isolation.
    /// </summary>
    public async Task<int> DeleteAsync(string orgId, string entryId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            "DELETE FROM reserved_namespace WHERE id = @id AND org_id = @orgId",
            new { id = entryId, orgId });
        if (rows > 0)
        {
            _cache.Remove(CacheKey(orgId));
        }

        return rows;
    }

    /// <summary>
    /// <see langword="true"/> when <paramref name="name"/> (the purl name; for maven, the
    /// groupId) matches any reserved pattern for <c>(org, ecosystem)</c>. Callers treat a
    /// reserved name exactly like a <c>local_only</c> claim: skip the upstream merge,
    /// refuse the proxy fetch, serve hosted content normally.
    /// </summary>
    public async Task<bool> IsReservedAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        var entries = await ListAsync(orgId, ct);
        foreach (var entry in entries)
        {
            if (string.Equals(entry.Ecosystem, ecosystem, StringComparison.OrdinalIgnoreCase)
                && Matches(ecosystem, entry.Pattern, name))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Pure pattern match — see class doc for the per-ecosystem rules.</summary>
    public static bool Matches(string ecosystem, string pattern, string name) =>
        !string.IsNullOrEmpty(pattern) && !string.IsNullOrEmpty(name)
        && ecosystem.ToLowerInvariant() switch
        {
            "maven" => MatchesMavenGroupId(pattern, name),
            "golang" => MatchesGoModulePath(pattern, name),
            "nuget" => MatchesGlob(pattern, name, StringComparison.OrdinalIgnoreCase),
            "pypi" => MatchesGlob(
                NormalizePyPiStem(TrimTrailingStar(pattern, out bool pypiGlob)) + (pypiGlob ? "*" : ""),
                NormalizePyPiStem(name),
                StringComparison.Ordinal),
            // npm and cargo (lowercase-canonical, flat namespaces): ordinal on lowercase.
            _ => MatchesGlob(pattern.ToLowerInvariant(), name.ToLowerInvariant(), StringComparison.Ordinal),
        };

    // Exact match, or prefix match when the pattern ends with '*'.
    private static bool MatchesGlob(string pattern, string name, StringComparison cmp)
    {
        string stem = TrimTrailingStar(pattern, out bool isGlob);
        return isGlob ? name.StartsWith(stem, cmp) : string.Equals(name, stem, cmp);
    }

    private static string TrimTrailingStar(string pattern, out bool isGlob)
    {
        isGlob = pattern.EndsWith('*');
        return isGlob ? pattern[..^1] : pattern;
    }

    // Dot-boundary groupId prefix: 'com.acme' covers 'com.acme' and 'com.acme.<anything>'
    // but never 'com.acmecorp'. Trailing '*' / '.*' / '.' spellings collapse to the same
    // boundary-safe prefix — a maven reservation is always a whole groupId subtree.
    private static bool MatchesMavenGroupId(string pattern, string groupId)
    {
        string prefix = pattern.TrimEnd('*').TrimEnd('.');
        return prefix.Length != 0
            && (groupId == prefix
                || groupId.StartsWith(prefix + ".", StringComparison.Ordinal));
    }

    // Slash-boundary module-path prefix — the '/' analog of MatchesMavenGroupId: 'github.com/acme'
    // covers 'github.com/acme' and 'github.com/acme/<anything>' but never 'github.com/acmecorp'.
    // Trailing '*' / '/*' / '/' spellings collapse to the same boundary-safe prefix. Ordinal
    // (case-sensitive) because Go module paths are case-significant.
    private static bool MatchesGoModulePath(string pattern, string module)
    {
        string prefix = pattern.TrimEnd('*').TrimEnd('/');
        return prefix.Length != 0
            && (module == prefix
                || module.StartsWith(prefix + "/", StringComparison.Ordinal));
    }

    // PEP 503 name normalization — runs of '-', '_', '.' collapse to '-', lowercased.
    // Mirrors PyPiController.NormalizePyPiName so patterns compare against stored purl names.
    private static string NormalizePyPiStem(string value)
        => PyPiNameSeparatorRegex().Replace(value, "-").ToLowerInvariant();

    [GeneratedRegex(@"[-_.]+", RegexOptions.None, matchTimeoutMilliseconds: 2000)]
    private static partial Regex PyPiNameSeparatorRegex();
}

public sealed class ReservedNamespaceEntry
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Pattern { get; init; } = "";
    public string? CreatedBy { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}
