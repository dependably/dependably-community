using System.Text.RegularExpressions;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
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
/// <item>apk — exact name or trailing-<c>*</c> glob, ordinal on lowercased names (Alpine's
/// package namespace is flat and conventionally lowercase), the same shape as npm and cargo.</item>
/// <item>terraform — exact or trailing-<c>*</c> glob, ordinal on lowercased names, the same
/// shape as npm and cargo; the reserved name is the provider's source address
/// (<c>registry.terraform.io/acme/internal</c>), which is what a dependency-confusion attempt
/// would have to collide with.</item>
/// <item>hex — exact or trailing-<c>*</c> glob, ordinal on lowercased names (hex.pm's package
/// namespace is flat and lower-case by rule), the same shape as npm and cargo.</item>
/// </list>
///
/// Reads are served from a short-TTL per-org cache (<see cref="ReservedNamespaceListCache"/>,
/// same shape as <see cref="BlocklistRepository"/>) so the hot proxy paths cost one dictionary
/// hit; mutations invalidate the org's entry. A fill that raced a concurrent mutation is guarded
/// by the same per-org generation token as <see cref="BlocklistRepository"/>, so a namespace just
/// reserved can never be masked by a stale cached list for a full TTL.
///
/// A mutation also expires every answer derived from the old list: the org's rendered-metadata
/// epoch (<see cref="OrgCacheEpochStore"/>) and its package-lookup outcomes
/// (<see cref="PackageLookupCache"/>). A pattern covers names that cannot be enumerated (a
/// group-level <c>com.acme</c> spans every <c>com.acme.*</c> coordinate), so per-key eviction
/// cannot reach them; one org-wide call does, and it runs in both directions — a newly reserved
/// name stops serving upstream-merged documents, and a lifted reservation stops serving the
/// local-only ones. The call is <see cref="MetadataInvalidationCoordinator.InvalidateOrg"/>,
/// which also broadcasts the change, so in a multi-replica deployment every replica clears its
/// list, epoch and lookup outcomes for the org within one pub/sub round trip; a lost broadcast
/// leaves a peer on its TTLs.
/// </summary>
public sealed partial class ReservedNamespaceService
{
    public static readonly IReadOnlyList<string> SupportedEcosystems = ["npm", "pypi", "nuget", "maven", "cargo", "golang", "apk", "terraform", "hex"];

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;
    private readonly ReservedNamespaceListCache _listCache;
    private readonly MetadataInvalidationCoordinator? _invalidation;
    private readonly OrgWideCacheEviction _localEviction;

    /// <param name="db">Metadata store holding <c>reserved_namespace</c>.</param>
    /// <param name="cache">Backs the list cache when <paramref name="listCache"/> is not supplied.</param>
    /// <param name="time">Clock for <see cref="ReservedNamespaceEntry.CreatedAt"/>.</param>
    /// <param name="cacheEpoch">The rendered-metadata epoch a mutation expires when no coordinator is supplied.</param>
    /// <param name="lookupCache">The lookup outcomes a mutation expires when no coordinator is supplied.</param>
    /// <param name="listCache">
    /// The shared list cache. The host registers one singleton for this service and for
    /// <see cref="OrgWideCacheEviction"/>, so a received org-wide invalidation clears the list
    /// this service reads.
    /// </param>
    /// <param name="invalidation">
    /// The coordinator that expires and broadcasts an org-wide change. Without one (a test
    /// composing the service by hand) a mutation runs the same <see cref="OrgWideCacheEviction"/>
    /// over the stores passed here and broadcasts nothing.
    /// </param>
    // Dependency-injection constructor; every parameter after the first three is optional so a
    // test can compose the service from only the stores it asserts on.
#pragma warning disable S107
    public ReservedNamespaceService(
        IMetadataStore db,
        IMemoryCache cache,
        TimeProvider time,
        OrgCacheEpochStore? cacheEpoch = null,
        PackageLookupCache? lookupCache = null,
        ReservedNamespaceListCache? listCache = null,
        MetadataInvalidationCoordinator? invalidation = null)
#pragma warning restore S107
    {
        _db = db;
        _time = time;
        _listCache = listCache ?? new ReservedNamespaceListCache(cache);
        _invalidation = invalidation;
        _localEviction = new OrgWideCacheEviction(_listCache, orgs: null, cacheEpoch, lookupCache);
    }

    // Test seam (InternalsVisibleTo Dependably.Tests): the live generation-guard count, asserted
    // to drain when a cached entry expires or is evicted so the map cannot grow unbounded.
    internal int FillGuardCount => _listCache.FillGuardCount;

    // Expires the cached list and every answer derived from it (rendered metadata, lookup
    // outcomes) for the org, on this replica and, through the coordinator, on every peer.
    private void InvalidateOrgCaches(string orgId)
    {
        if (_invalidation is not null)
        {
            _invalidation.InvalidateOrg(orgId);
        }
        else
        {
            _localEviction.Evict(orgId);
        }
    }

    public Task<IReadOnlyList<ReservedNamespaceEntry>> ListAsync(
        string orgId, CancellationToken ct = default) =>
        _listCache.GetOrReadAsync(orgId, readCt => ReadListAsync(orgId, readCt), ct);

    private async Task<IReadOnlyList<ReservedNamespaceEntry>> ReadListAsync(string orgId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ReservedNamespaceEntry>(
            """
            SELECT id, org_id AS OrgId, ecosystem, pattern,
                   created_by AS CreatedBy, created_at AS CreatedAt
            FROM reserved_namespace WHERE org_id = @orgId
            ORDER BY ecosystem, pattern
            """,
            new { orgId });
        return rows.ToList();
    }

    /// <summary>
    /// Adds a reservation and returns the stored entry — the existing one when the org already
    /// reserves the same (ecosystem, pattern). See <see cref="TryAddAsync"/> for a caller that
    /// needs to tell the two apart.
    /// </summary>
    public async Task<ReservedNamespaceEntry> AddAsync(
        string orgId, string ecosystem, string pattern, string? createdBy, CancellationToken ct = default) =>
        (await TryAddAsync(orgId, ecosystem, pattern, createdBy, ct)).Entry;

    /// <summary>
    /// Adds a reservation. <c>Created</c> is <see langword="false"/> when the org already reserves
    /// the same (ecosystem, pattern): nothing is written, no cache is invalidated, and
    /// <c>Entry</c> is the row already stored, so its id is one a later delete actually removes.
    /// </summary>
    public async Task<(ReservedNamespaceEntry Entry, bool Created)> TryAddAsync(
        string orgId, string ecosystem, string pattern, string? createdBy, CancellationToken ct = default)
    {
        // A conflicting row deleted between the insert and the read leaves nothing reserved, so
        // the add is retried rather than reporting a row that no longer exists. Bounded: only an
        // add racing a delete of the same pattern on every attempt gets that far.
        const int maxAttempts = 3;
        for (int attempt = 1; ; attempt++)
        {
            var (entry, created) = await InsertOrReadAsync(orgId, ecosystem, pattern, createdBy, ct);
            if (entry is not null)
            {
                return (entry, created);
            }

            if (attempt == maxAttempts)
            {
                throw new InvalidOperationException(
                    "The reserved namespace was removed concurrently on every attempt to add it.");
            }
        }
    }

    private async Task<(ReservedNamespaceEntry? Entry, bool Created)> InsertOrReadAsync(
        string orgId, string ecosystem, string pattern, string? createdBy, CancellationToken ct)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync(ct);
        int inserted = await conn.ExecuteAsync(
            """
            INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern, created_by)
            VALUES (@id, @orgId, @ecosystem, @pattern, @createdBy)
            ON CONFLICT DO NOTHING
            """,
            new { id, orgId, ecosystem, pattern, createdBy });
        if (inserted > 0)
        {
            InvalidateOrgCaches(orgId);
            return (new ReservedNamespaceEntry
            {
                Id = id,
                OrgId = orgId,
                Ecosystem = ecosystem,
                Pattern = pattern,
                CreatedBy = createdBy,
                CreatedAt = _time.GetUtcNow(),
            }, true);
        }

        var existing = await conn.QuerySingleOrDefaultAsync<ReservedNamespaceEntry>(
            """
            SELECT id, org_id AS OrgId, ecosystem, pattern,
                   created_by AS CreatedBy, created_at AS CreatedAt
            FROM reserved_namespace
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND pattern = @pattern
            """,
            new { orgId, ecosystem, pattern });
        return (existing, false);
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
            InvalidateOrgCaches(orgId);
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

    /// <summary>
    /// Whether a reserved name stands behind an upstream Maven metadata URL for
    /// <paramref name="orgId"/>, and so whether that URL may be fetched from upstream at all. Every
    /// path that fetches Maven metadata from upstream decides it here, before the request, so a
    /// reserved name is never disclosed to upstream and no upstream answer for it feeds the
    /// served metadata, version tracking, or a package lookup.
    ///
    /// <c>g/a/maven-metadata.xml</c> has two readings: the artifact-level document for coordinate
    /// <c>g:a</c>, and the group-level document for group <c>g.a</c> (the plugin-prefix document
    /// Maven reads to resolve a short plugin prefix). Both readings share one upstream URL, so
    /// fetching it consults upstream about both names, and the URL is reserved when either is.
    /// The artifact reading is checked on its groupId, the same name the artifact download's guard
    /// checks; the group-level reading is checked on <c>g.a</c>.
    ///
    /// Version-level SNAPSHOT metadata (<c>g/a/v/maven-metadata.xml</c>,
    /// <paramref name="versionLevel"/> true) has no group-level reading, so only the groupId
    /// applies there.
    ///
    /// The decision covers upstream only: hosted and cached versions of <c>g:a</c> still serve
    /// from the local catalogue. The group-level document itself carries no version: every
    /// version a client resolves through it is decided by the artifact-level metadata and the
    /// artifact fetch, as for any other coordinate.
    /// </summary>
    public async Task<bool> IsMavenMetadataPathReservedAsync(
        string orgId, string groupId, string artifactId, bool versionLevel, CancellationToken ct = default)
        => await IsReservedAsync(orgId, "maven", groupId, ct)
            || (!versionLevel && await IsReservedAsync(orgId, "maven", $"{groupId}.{artifactId}", ct));

    /// <summary>
    /// Whether <paramref name="purlName"/> is reserved for <paramref name="orgId"/> in
    /// <paramref name="ecosystem"/>, and so whether any upstream registry may be asked about it at
    /// all. Every server-side path that consults upstream about a package by its stored purl name
    /// (the upstream-latest resolve behind the first-fetch seed, a package lookup, the daily
    /// deprecation refresh) decides it here, before its first request, so a reserved name is never
    /// disclosed to upstream and no upstream answer for it is recorded or served.
    ///
    /// The name is matched in the form each protocol handler's own reserved check uses, so the
    /// decision is the one a client request for the same name already gets:
    /// <list type="bullet">
    /// <item>npm — the unescaped package name (<c>@scope/pkg</c>); a purl name stored with its scope
    /// percent-encoded is unescaped first, as the packument URL is.</item>
    /// <item>maven — <c>groupId:artifactId</c>, decided by
    /// <see cref="IsMavenMetadataPathReservedAsync"/> on both readings of its metadata URL.</item>
    /// <item>golang — the module path. A name carrying Go proxy bang-encoding
    /// (<c>github.com/!burnt!sushi</c>, which a package lookup accepts as typed) is decoded first,
    /// because the upstream URL built from it names the decoded module. A name whose <c>!</c>
    /// sequences are not valid bang-encoding is treated as reserved: it does not name a module
    /// this decision can match, so it never reaches upstream unchecked.</item>
    /// <item>pypi, nuget, cargo, hex — the purl name as stored (PEP 503-normalized for PyPI);
    /// <see cref="Matches"/> applies each ecosystem's own normalization and case rule.</item>
    /// </list>
    ///
    /// The decision covers upstream only: hosted and already-cached versions of a reserved name
    /// still serve from the local catalogue.
    /// </summary>
    public Task<bool> IsUpstreamNameReservedAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        switch (ecosystem)
        {
            case "npm":
                return IsReservedAsync(orgId, "npm", PurlNormalizer.NpmPackageName(purlName), ct);
            case "maven":
                int sep = purlName.IndexOf(':');
                return sep > 0 && sep < purlName.Length - 1
                    ? IsMavenMetadataPathReservedAsync(
                        orgId, purlName[..sep], purlName[(sep + 1)..], versionLevel: false, ct)
                    : IsReservedAsync(orgId, "maven", purlName, ct);
            case "golang":
                return GoController.TryDecodeBangEncoding(purlName, out string module)
                    ? IsReservedAsync(orgId, "golang", module, ct)
                    : Task.FromResult(true);
            default:
                return IsReservedAsync(orgId, ecosystem, purlName, ct);
        }
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
