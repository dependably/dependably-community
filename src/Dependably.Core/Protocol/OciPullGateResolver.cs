using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;

namespace Dependably.Protocol;

/// <summary>
/// What the OCI pull gate knows about one manifest digest for one org: the org's own scan facts
/// for the image that owns it, the manual override on the org's own catalogue row, and the owning
/// image's digest, which is the image's quarantine identity.
/// </summary>
/// <param name="OwnerDigest">The digest of the image the facts belong to: the requested digest
/// itself for an image the org holds, or the parent index's digest for a platform manifest reached
/// through the reference graph. One approval of the owner therefore covers every platform.</param>
/// <param name="Owners">Every owning image when several indexes reference the digest, each with
/// the <c>package_versions.id</c> it carries when the org hosts it. That id is the quarantine row's
/// version link, which is what lets an approve or deny set the manual override on a hosted image; a
/// proxied image has no version row and is reached through its cache coordinate instead.</param>
/// <param name="Held">False when the org holds no catalogue row for the digest or for any image
/// that lists it: nothing has queued it for scanning yet.</param>
public sealed record OciPullGateContext(
    OciGateFacts Facts, string? ManualState, string OwnerDigest, bool Held = true,
    IReadOnlyList<OciPullOwner>? Owners = null);

/// <summary>One image that owns a pulled digest: its digest, and its <c>package_versions.id</c> when hosted.</summary>
public sealed record OciPullOwner(string Digest, string? HostedVersionId);

/// <summary>
/// Resolves the facts the OCI pull gate evaluates, for every manifest-returning OCI path through
/// one read so a cache hit, an upstream miss, a stale serve, a HEAD and a blob-route read of the
/// same (org, digest) get the same verdict.
///
/// <para><b>Owner.</b> Resolved only through the requesting org's own <c>packages</c> /
/// <c>package_versions</c> or <c>tenant_artifact_access</c> row, never by digest alone, with the
/// hosted row winning when both exist (the version page's rule). A digest the org holds no row for
/// is resolved through the org's reference graph (<c>oci_manifest_blobs</c>) to every index in the
/// same repository that lists it, which is recorded at fetch time and so answers before any scan;
/// with several parents the strictest facts win. A digest that is neither an owner nor a child of
/// one has no result: unscanned. A digest the org holds as an image of its own is answered from
/// its own facts, but a manual block on any index that lists it still applies.</para>
///
/// <para><b>Facts.</b> Read from the org's scan tables only
/// (<see cref="OciScanRepository.GetGateFactsAsync"/>); the shared cache-plane signal rows are never
/// consulted, because a tenant's scan result is never written there.</para>
/// </summary>
public sealed class OciPullGateResolver
{
    private readonly IMetadataStore _db;
    private readonly OciScanRepository _scans;
    private readonly VulnerabilityRepository _vulns;
    private readonly IOciScanCoverage _coverage;

    public OciPullGateResolver(
        IMetadataStore db, OciScanRepository scans, VulnerabilityRepository vulns, IOciScanCoverage coverage)
    {
        _db = db;
        _scans = scans;
        _vulns = vulns;
        _coverage = coverage;
    }

    /// <summary>
    /// The gate context for <paramref name="repository"/>@<paramref name="digest"/> in
    /// <paramref name="orgId"/>. Throws when a read fails; the caller decides the fail posture.
    /// </summary>
    public async Task<OciPullGateContext> ResolveAsync(
        string orgId, string repository, string digest, CancellationToken ct = default)
    {
        var owners = await ResolveOwnersAsync(orgId, repository, digest, ct);
        if (owners.Count == 0)
        {
            return new OciPullGateContext(
                OciGateFacts.Absent(await _coverage.IsCoveredAsync(orgId, ct)), null, digest, Held: false);
        }

        string freshCutoff = await _vulns.FreshnessCutoffAsync(ct);
        var ownerIds = owners.Select(o => o.Owner.Id).Distinct(StringComparer.Ordinal).ToList();
        var stored = await _scans.GetGateFactsAsync(orgId, ownerIds, freshCutoff, ct);

        // A platform manifest reached through its index: an index whose result records which
        // manifest each platform was, and lists no row for this one, did not scan this platform.
        // Its findings on the other platforms still count against the image (the union across
        // platforms is the image's verdict), but it is no complete answer for this one.
        var notCovering = owners[0].Digest == digest
            ? new HashSet<string>(StringComparer.Ordinal)
            : await _scans.GetOwnersNotCoveringAsync(orgId, ownerIds, digest, ct);

        var perOwner = new List<OciGateFacts>(owners.Count);
        bool? scannerLive = null;
        foreach (string ownerId in owners.Select(o => o.Owner.Id))
        {
            if (stored.TryGetValue(ownerId, out var facts))
            {
                perOwner.Add(notCovering.Contains(ownerId)
                    ? facts with { HasResult = false, GapCount = 0 }
                    : facts);
                continue;
            }

            scannerLive ??= await _coverage.IsCoveredAsync(orgId, ct);
            perOwner.Add(OciGateFacts.Absent(scannerLive.Value));
        }

        return new OciPullGateContext(
            OciGateFacts.Strictest(perOwner), StrictestManualState(owners), owners[0].Digest,
            Owners: owners.DistinctBy(o => o.Digest, StringComparer.Ordinal)
                .Select(o => new OciPullOwner(o.Digest, o.Owner.PackageVersionId)).ToList());
    }

    // A manual block on any owner refuses; a manual allow short-circuits only when every owner
    // carries one, so allowing one index does not wave through a platform another index holds.
    private static string? StrictestManualState(IReadOnlyList<ResolvedOwner> owners) =>
        owners.Any(o => o.ManualState == "blocked") ? "blocked"
        : owners.All(o => o.ManualState == "allowed") ? "allowed"
        : null;

    /// <summary>
    /// True when <paramref name="orgId"/> already knows <paramref name="digest"/> as a manifest,
    /// whatever media type its blob row carries: a hosted version or a pulled image catalogued
    /// under that digest, or a platform listed by an image index the org holds. The blob route
    /// uses this so a manifest stored under a generic type is still gated.
    /// </summary>
    public async Task<bool> IsKnownManifestAsync(string orgId, string digest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (indexClause, parameters) = DapperInClause.Expand("indexType", IndexMediaTypes);
        parameters.Add("orgId", orgId);
        parameters.Add("digest", digest);
        // rawsql: indexClause is a DapperInClause-built parameterized IN list over two constants.
        return await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS(
                SELECT 1 FROM package_versions pv JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND pv.version = @digest)
            OR EXISTS(
                SELECT 1 FROM tenant_artifact_access taa JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.filename = 'manifest' AND ca.version = @digest)
            OR EXISTS(
                SELECT 1 FROM oci_manifest_blobs g
                JOIN oci_blobs parent ON parent.org_id = g.org_id AND parent.digest = g.manifest_digest
                WHERE g.org_id = @orgId AND g.blob_digest = @digest AND parent.media_type IN @indexTypes)
            """.Replace("@indexTypes", indexClause, StringComparison.Ordinal),
            parameters);
    }

    private static readonly IReadOnlyList<string> IndexMediaTypes =
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];

    private sealed record ResolvedOwner(OciScanOwner Owner, string Digest, string? ManualState);

    private async Task<List<ResolvedOwner>> ResolveOwnersAsync(
        string orgId, string repository, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var direct = await ReadDirectOwnerAsync(conn, orgId, repository, digest);

        // xtenant: org_id filter scopes the parent lookup to the caller's own reference graph.
        var parentDigests = (await conn.QueryAsync<string>(
            """
            SELECT manifest_digest FROM oci_manifest_blobs
            WHERE org_id = @orgId AND blob_digest = @digest
            ORDER BY manifest_digest
            """,
            new { orgId, digest })).AsList();

        var parents = new List<ResolvedOwner>();
        foreach (string parent in parentDigests.Where(p => !string.Equals(p, digest, StringComparison.Ordinal)))
        {
            if (await ReadDirectOwnerAsync(conn, orgId, repository, parent) is { } owner)
            {
                parents.Add(owner);
            }
        }

        if (direct is null)
        {
            return parents;
        }

        // A platform catalogued as an image of its own (pulled by digest before its index) keeps
        // its own facts, but a manual block on any index that lists it still refuses it: the
        // strictest manual state wins, as it does across several parents.
        return parents.Any(p => p.ManualState == "blocked") && direct.ManualState != "blocked"
            ? [direct with { ManualState = "blocked" }]
            : [direct];
    }

    private static async Task<ResolvedOwner?> ReadDirectOwnerAsync(
        System.Data.Common.DbConnection conn, string orgId, string repository, string digest)
    {
        // plane-ok: the hosted half of a deliberate two-statement read; the proxy plane is the tenant_artifact_access query below, consulted only when no hosted row exists.
        var hosted = await conn.QueryFirstOrDefaultAsync<OwnerRow>(
            """
            SELECT pv.id AS Id, pv.manual_block_state AS ManualState
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND p.purl_name = @repository AND pv.version = @digest
            ORDER BY pv.id
            """,
            new { orgId, repository, digest });
        if (hosted is not null)
        {
            return new ResolvedOwner(OciScanOwner.Hosted(hosted.Id), digest, hosted.ManualState);
        }

        var proxied = await conn.QueryFirstOrDefaultAsync<OwnerRow>(
            """
            SELECT ca.id AS Id, taa.manual_block_state AS ManualState
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.filename = 'manifest'
              AND ca.name = @repository AND ca.version = @digest
            ORDER BY ca.id
            """,
            new { orgId, repository, digest });
        return proxied is null ? null : new ResolvedOwner(OciScanOwner.Proxied(proxied.Id), digest, proxied.ManualState);
    }

    // A class with setters so Dapper maps the columns by name on both providers.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "ManualState is populated by Dapper's column mapping.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3459:Unassigned members should be removed",
        Justification = "ManualState is populated by Dapper's column mapping.")]
    private sealed class OwnerRow
    {
        public string Id { get; set; } = "";
        public string? ManualState { get; set; }
    }
}
