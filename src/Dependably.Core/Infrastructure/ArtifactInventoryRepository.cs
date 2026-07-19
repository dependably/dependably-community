using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Reads the canonical artifact read model (<c>artifact_inventory</c>, <c>artifact_license</c>,
/// <c>org_storage_bytes</c>).
///
/// The point is not that the SQL gets shorter. It is that a caller here cannot be blind to half an
/// org's inventory: the view already spans both catalogues, so the filters a caller writes apply to
/// everything the org holds. In particular <c>ecosystem = 'oci'</c> matches an image however it
/// arrived — a tag push catalogues it in <c>package_versions</c>, a proxy pull in
/// <c>cache_artifact</c> — where the same predicate written against one table catches one of the two.
///
/// The model is ORG-SCOPED, and that is a real boundary, not an incidental one. An instance-wide
/// sweep that deliberately operates on the global cache plane — the vulnerability scan, which scans a
/// shared artifact once for the whole instance rather than once per tenant holding it — must NOT be
/// routed through here: the inventory reaches a proxied artifact only through
/// <c>tenant_artifact_access</c>, so doing so would quietly change which artifacts get scanned.
///
/// Views carry no constraints and are never written through. A row keys back to its physical table by
/// owner_kind + owner_id, and every UPDATE and DELETE still goes to the table.
/// </summary>
public sealed class ArtifactInventoryRepository
{
    private readonly IMetadataStore _db;
    private readonly PackageRepository _packages;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly VulnerabilityRepository _vulns;

    public ArtifactInventoryRepository(
        IMetadataStore db,
        PackageRepository packages,
        CacheArtifactRepository cacheArtifacts,
        VulnerabilityRepository vulns)
    {
        _db = db;
        _packages = packages;
        _cacheArtifacts = cacheArtifacts;
        _vulns = vulns;
    }

    /// <summary>
    /// Every version of a package the org can serve, from either catalogue, as the rich
    /// <see cref="PackageVersion"/> the serve paths and the package-detail page render.
    ///
    /// This is the one place the two catalogues are merged for serving. It was previously copied
    /// into nine call sites — every protocol handler that lists versions, plus the management API —
    /// and each copy was a place a future one could be written against the uploaded catalogue alone
    /// and go blind to every proxied version of the package. There is now nothing to forget.
    ///
    /// A proxied version whose version string already exists on the uploaded plane is dropped: an
    /// org that pushes a private override of a name it also proxies serves its own artifact, and the
    /// name must not list the version twice.
    ///
    /// It merges in C# rather than reading <c>artifact_inventory</c> on purpose. A PackageVersion
    /// carries per-plane facts the view does not project — the vulnerability gate signals behind
    /// IsMalicious, and the synthetic row's Filename, without which the blob tail is unservable —
    /// and re-projecting them from the view would be regression surface for no gain. The view's job
    /// is to make an org's inventory queryable in one relation; this is the shape the serve paths
    /// actually need.
    /// </summary>
    public async Task<IReadOnlyList<PackageVersion>> ListServeableVersionsAsync(
        string orgId, string packageId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        var uploadedVersions = await _packages.GetVersionsAsync(packageId, ct);
        var proxyEntries = await _cacheArtifacts.ListServeFactsForNameAsync(orgId, ecosystem, purlName, ct);

        if (proxyEntries.Count == 0)
        {
            return uploadedVersions;
        }

        var uploadedVersionSet = uploadedVersions
            .Select(v => v.Version)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Loaded once for the whole page: the synthetic rows carry IsMalicious from these.
        var proxyIds = proxyEntries.Select(e => e.Id).ToList();
        var proxySignals = proxyIds.Count > 0
            ? await _vulns.GetGateSignalsBatchForCacheArtifactsAsync(proxyIds, ct)
            : new Dictionary<string, VulnGateSignals>();

        var synthetic = proxyEntries
            .Where(e => !uploadedVersionSet.Contains(e.Version))
            .Select(e => e.ToPackageVersionSynthetic(proxySignals))
            .ToList();

        if (synthetic.Count == 0)
        {
            return uploadedVersions;
        }

        var combined = new List<PackageVersion>(uploadedVersions.Count + synthetic.Count);
        combined.AddRange(uploadedVersions);
        combined.AddRange(synthetic);
        return combined;
    }

    /// <summary>
    /// Collapses proxy-origin entries that share the same version string down to one row.
    ///
    /// <see cref="ListServeableVersionsAsync"/> returns one synthetic entry per <c>cache_artifact</c>
    /// row, and that is deliberately file-level, not version-level: PyPI's Simple Index legitimately
    /// lists a separate href per distribution file (sdist, each wheel) under the same version, so the
    /// shared method must not collapse there. NuGet is different — its proxy first-fetch mirrors the
    /// flatcontainer trio verbatim, so one proxied version casts three rows (<c>.nupkg</c>,
    /// <c>.nuspec</c>, <c>.sha512</c>) that all share a version string, and a version-level renderer
    /// (registration index, search, the management package page) must show that version exactly once.
    /// Call this only from a renderer that is version-level — never from a file-level one such as the
    /// PyPI Simple Index.
    ///
    /// The <c>.nupkg</c> row wins each group: it is the artifact the NuGet client actually installs,
    /// so its size/checksum/blob-key are the metadata a caller should render for the version. Falling
    /// back to an arbitrary row in the group (e.g. <c>.sha512</c>, whose <c>SizeBytes</c>/
    /// <c>ChecksumSha256</c> describe the detached hash file, not the package) would render the wrong
    /// metadata for the version. Uploaded (non-proxy) entries are already one-per-version and pass
    /// through untouched.
    /// </summary>
    public static IReadOnlyList<PackageVersion> DedupeProxyVersionsByVersion(IReadOnlyList<PackageVersion> versions)
    {
        bool hasDuplicateProxyVersion = versions
            .Where(v => v.Origin == "proxy")
            .GroupBy(v => v.Version, StringComparer.OrdinalIgnoreCase)
            .Any(g => g.Count() > 1);
        if (!hasDuplicateProxyVersion)
        {
            return versions;
        }

        var result = new List<PackageVersion>(versions.Count);
        result.AddRange(versions.Where(v => v.Origin != "proxy"));
        result.AddRange(versions
            .Where(v => v.Origin == "proxy")
            .GroupBy(v => v.Version, StringComparer.OrdinalIgnoreCase)
            .Select(PreferNupkgRow));
        return result;
    }

    // Picks the .nupkg row out of a group of same-version proxy entries — see the "wins each
    // group" reasoning on DedupeProxyVersionsByVersion. Falls back to the group's first entry
    // (ORDER BY first_cached_at DESC from ListServeFactsForNameAsync) for the reachable case
    // where the .nupkg row hasn't landed yet: each file type is fetched and recorded
    // independently at /flatcontainer/{id}/{version}/{file}, so a version can render with only
    // its sidecar metadata (.nuspec/.sha512) present until the .nupkg is fetched. That is
    // degraded metadata for one render, never a duplicate and never a dropped version — the
    // fallback fails safe.
    private static PackageVersion PreferNupkgRow(IGrouping<string, PackageVersion> group) =>
        group.FirstOrDefault(v =>
            v.Filename is not null && v.Filename.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
        ?? group.First();

    /// <summary>
    /// Bytes the org has stored, across every plane.
    ///
    /// This reads <c>org_storage_bytes</c> rather than summing the inventory, and the distinction is
    /// permanent: a catalogue row for an OCI image sizes its <b>manifest</b> — a few KB — never its
    /// layers, and an image pushed by digest reference casts no catalogue row at all. Summing
    /// <c>artifact_inventory.size_bytes</c> is a wrong answer for storage and always will be.
    ///
    /// This is the number the publish path enforces a quota against and the number the admin tenant
    /// list shows an operator. They read the same definition, so they cannot disagree about the same
    /// org.
    /// </summary>
    public async Task<long> ComputeStorageBytesAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(SUM(total_bytes), 0) FROM org_storage_bytes WHERE org_id = @orgId",
            new { orgId });
    }

    /// <summary>
    /// Version + yanked facts for a batch of packages, across both catalogues, in one round trip —
    /// the existence/count counterpart to <see cref="ListServeableVersionsAsync"/>.
    ///
    /// Search and autocomplete need to know, for every name-matching package (which can be an
    /// entire org's catalogue on an empty query), whether it has at least one listed version — and
    /// for autocomplete, whether one meets the prerelease filter — to report an accurate
    /// <c>totalHits</c>. Resolving that per package through <see cref="ListServeableVersionsAsync"/>
    /// is 2-3 round trips each, which turns a single request into an org-size-scaling fan-out. This
    /// returns only the version string and yanked flag every match decision needs, batched by
    /// package_id, so the decision costs one query regardless of how many packages match the name
    /// filter. The caller still fetches the richer <see cref="PackageVersion"/> projection via
    /// <see cref="ListServeableVersionsAsync"/> for the page it actually returns.
    /// </summary>
    public async Task<ILookup<string, ArtifactVersionFact>> ListVersionFactsForPackagesAsync(
        string orgId, string ecosystem, IReadOnlyList<string> packageIds, CancellationToken ct = default)
    {
        if (packageIds.Count == 0)
        {
            return Array.Empty<ArtifactVersionFact>().ToLookup(f => f.PackageId);
        }

        await using var conn = await _db.OpenAsync(ct);
        const string sql = """
            SELECT package_id AS PackageId, version AS Version, yanked AS Yanked
            FROM artifact_inventory
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND package_id IN @packageIds
            """;
        // The @packageIds token is swapped for a literal (@id0, @id1, ...) list before the query
        // reaches Dapper — see DapperInClause for why Dapper's own IN @packageIds auto-expansion
        // cannot be trusted here (it silently binds the whole list as one Postgres array parameter
        // instead, which IN never accepts).
        var (idsClause, idsParams) = DapperInClause.Expand("id", packageIds);
        idsParams.Add("orgId", orgId);
        idsParams.Add("ecosystem", ecosystem);
        var rows = await conn.QueryAsync<ArtifactVersionFact>(sql.Replace("@packageIds", idsClause), idsParams);
        return rows.ToLookup(f => f.PackageId);
    }

    /// <summary>
    /// Every version of a package the org can serve, from either catalogue, newest first. A package
    /// an org both proxies and privately overrides carries rows on both planes and yields both here.
    /// </summary>
    public async Task<IReadOnlyList<InventoryRow>> ListForPackageAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<InventoryRow>(
            """
            SELECT org_id       AS OrgId,
                   owner_kind   AS OwnerKind,
                   owner_id     AS OwnerId,
                   package_id   AS PackageId,
                   ecosystem    AS Ecosystem,
                   name         AS Name,
                   display_name AS DisplayName,
                   version      AS Version,
                   filename     AS Filename,
                   purl         AS Purl,
                   blob_key     AS BlobKey,
                   size_bytes   AS SizeBytes,
                   origin       AS Origin,
                   published_at AS PublishedAt,
                   yanked       AS Yanked,
                   deprecated   AS Deprecated,
                   revoked_at   AS RevokedAt,
                   versions_behind AS VersionsBehind,
                   vuln_checked_at AS VulnCheckedAt,
                   oci_digest   AS OciDigest
            FROM artifact_inventory
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND name = @purlName
            ORDER BY created_at DESC
            """,
            new { orgId, ecosystem, purlName });
        return rows.AsList();
    }
}

/// <summary>
/// One artifact an org holds. <see cref="OwnerKind"/> + <see cref="OwnerId"/> key it back to the
/// physical table — <c>package_versions</c> for an uploaded artifact, <c>cache_artifact</c> for a
/// proxied one — which is what a writer dispatches on.
///
/// <see cref="PackageId"/> is nullable on purpose: an org reaches a proxied artifact through
/// <c>tenant_artifact_access</c> alone and can hold one with no <c>packages</c> row at all.
///
/// <see cref="SizeBytes"/> is this row's blob. For an OCI image that is the manifest, never the
/// layers — see <see cref="ArtifactInventoryRepository.ComputeStorageBytesAsync"/>.
/// </summary>
public sealed class InventoryRow
{
    public string OrgId { get; set; } = "";
    public string OwnerKind { get; set; } = "";
    public string OwnerId { get; set; } = "";
    public string? PackageId { get; set; }
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Version { get; set; } = "";
    public string? Filename { get; set; }
    public string? Purl { get; set; }
    public string BlobKey { get; set; } = "";
    public long SizeBytes { get; set; }
    public string Origin { get; set; } = "";
    public string? PublishedAt { get; set; }
    public long Yanked { get; set; }
    public string? Deprecated { get; set; }
    public string? RevokedAt { get; set; }
    public long? VersionsBehind { get; set; }
    public string? VulnCheckedAt { get; set; }
    public string? OciDigest { get; set; }
}

/// <summary>
/// One version's existence/yanked fact for a package, as returned by
/// <see cref="ArtifactInventoryRepository.ListVersionFactsForPackagesAsync"/>. Deliberately thin —
/// a match/count decision needs only the version string and yanked flag, not the full
/// <see cref="PackageVersion"/> projection.
///
/// <see cref="Yanked"/> is <c>long</c>, mirroring <see cref="InventoryRow.Yanked"/> — SQLite's
/// INTEGER 0/1 maps cleanly there, whereas Dapper's constructor-matching for a positional record
/// requires the exact column type and rejects a <c>bool</c> parameter against an INTEGER column.
/// </summary>
public sealed class ArtifactVersionFact
{
    public string PackageId { get; set; } = "";
    public string Version { get; set; } = "";
    public long Yanked { get; set; }
    public bool IsYanked => Yanked != 0;
}
