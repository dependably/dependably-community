using Dapper;
using Dependably.Protocol;

namespace Dependably.Infrastructure.OciScan;

/// <summary>How a posted result ended.</summary>
public enum OciScanResultOutcome
{
    /// <summary>Stored; the job is done.</summary>
    Stored,

    /// <summary>The caller no longer holds the job's lease; nothing was written.</summary>
    LeaseLost,

    /// <summary>The body broke the contract; nothing was written.</summary>
    Invalid,

    /// <summary>
    /// A match result named an inventory a re-extraction has since replaced; nothing was written,
    /// and the job stays leased to the caller.
    /// </summary>
    InventoryChanged,

    /// <summary>
    /// The result names an advisory the instance does not store, and the advisory source it would
    /// be fetched from could not be reached; nothing was written, and the job is retried.
    /// </summary>
    AdvisorySourceUnavailable,
}

/// <summary>The outcome, and for <see cref="OciScanResultOutcome.Invalid"/> which field and why.</summary>
/// <para>For <see cref="OciScanResultOutcome.Invalid"/>, <see cref="ErrorKey"/> is a SharedResource
/// key and <see cref="ErrorArgs"/> its format arguments, so the controller answers in the caller's
/// language.</para>
public sealed record OciScanResultStatus(
    OciScanResultOutcome Outcome, string? Field = null, string? ErrorKey = null, object[]? ErrorArgs = null)
{
    public static readonly OciScanResultStatus Stored = new(OciScanResultOutcome.Stored);
    public static readonly OciScanResultStatus LeaseLost = new(OciScanResultOutcome.LeaseLost);
    public static readonly OciScanResultStatus InventoryChanged = new(OciScanResultOutcome.InventoryChanged);
    public static readonly OciScanResultStatus AdvisorySourceUnavailable =
        new(OciScanResultOutcome.AdvisorySourceUnavailable);

    public static OciScanResultStatus Invalid(string field, string errorKey, params object[] args) =>
        new(OciScanResultOutcome.Invalid, field, errorKey, args);
}

/// <summary>
/// Stores a scanner's result for a leased job.
///
/// <list type="number">
///   <item>The body is validated in full first; a result that breaks the contract writes nothing.</item>
///   <item>Each advisory id is resolved by <see cref="OciScanAdvisoryResolver"/>: one the instance
///   stores is linked as stored, one it does not is fetched from the registry's own advisory source
///   and stored, keyed to the package it was first matched on, and one the source does not know is
///   dropped. The body's advisory records are never stored: <c>vulnerabilities</c> is shared by
///   every tenant. An unreachable source refuses the whole result for a retry. These writes run
///   before the transaction: the repository opens its own connection for each, which a held SQLite
///   write transaction would block.</item>
///   <item>One transaction closes the job, but only while the caller still holds its lease, and
///   replaces the org's components, findings and per-platform coverage for the image.</item>
///   <item>For a hosted image the advisories are then linked to the version, links the new
///   inventory no longer supports are pruned, the version is stamped, and the same alerts as
///   Dependably's own scan are raised; the activity row records new and cleared links and the
///   webhook carries only newly linked advisories. A proxied image's shared <c>cache_artifact</c>
///   row is never touched: the result is this tenant's view of it.</item>
/// </list>
///
/// <para>A full result is accepted on a <c>rematch</c> job too, and treated as a re-extraction:
/// a scanner that predates rematch can be handed one during a blue-green cutover, and its scan
/// of the image is still correct.</para>
/// </summary>
public sealed partial class OciScanResultWriter
{
    /// <summary>The activity type of the per-image row a hosted image's result writes.</summary>
    public const string ActivityType = "oci_scan";

    private readonly IMetadataStore _db;
    private readonly OciScanAdvisoryResolver _advisories;
    private readonly VulnerabilityScanService _scans;
    private readonly TimeProvider _time;
    private readonly OciPlatformManifestReader? _platforms;

    public OciScanResultWriter(
        IMetadataStore db, OciScanAdvisoryResolver advisories, VulnerabilityScanService scans, TimeProvider time,
        // Maps each scanned platform to the manifest it describes; absent leaves manifest_digest
        // NULL, which the sweep's backfill fills later.
        OciPlatformManifestReader? platforms = null)
    {
        _db = db;
        _advisories = advisories;
        _scans = scans;
        _time = time;
        _platforms = platforms;
    }

    public async Task<OciScanResultStatus> WriteAsync(
        OciScanJob job, OciScanResultRequest body, CancellationToken ct = default)
    {
        var (invalid, _) = Validate(body);
        if (invalid is not null)
        {
            return invalid;
        }

        var platforms = body.Platforms!;

        var resolution = await _advisories.ResolveAsync(
            platforms.SelectMany(p => p.Components!).SelectMany(component => (component.Vulns ?? []).Select(vuln =>
                new OciScanAdvisoryRef(vuln.Id!, component.Ecosystem!, component.SourceName ?? component.Name!))),
            ct);
        if (resolution.SourceUnavailable && _advisories.MayDefer(job))
        {
            return OciScanResultStatus.AdvisorySourceUnavailable;
        }

        // Advisory id as the scanner sent it -> the vulnerabilities row it is stored under. An id
        // the advisory source did not confirm has no entry: its findings are not recorded, and the
        // platforms that named it carry a coverage gap saying so.
        var stored = resolution.Resolved.ToDictionary(r => r.Key, r => r.Value.VulnId, StringComparer.Ordinal);
        platforms = platforms.Select(p => p with
        {
            Gaps = [.. p.Gaps ?? [], .. AdvisoryGaps(
                p.Components!.SelectMany(c => (c.Vulns ?? []).Select(v => v.Id!)), resolution)],
        }).ToList();

        // Read before the transaction: it touches the blob store, and a held SQLite write
        // transaction must not wait on it.
        var platformMap = _platforms is null ? null : await _platforms.ReadAsync(job.OrgId, job.Digest, ct);

        string now = _time.GetUtcNow().ToUtcIsoMillis();
        await using (var conn = await _db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            int closed = await conn.ExecuteAsync(
                """
                UPDATE oci_scan_jobs
                SET state = 'done', lease_expires_at = NULL, last_error = NULL,
                    updated_at = @now, completed_at = @now
                WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now
                  AND attempts = @attempt
                """,
                new { orgId = job.OrgId, jobId = job.Id, attempt = job.Attempts, now }, tx);
            if (closed != 1)
            {
                await tx.RollbackAsync(ct);
                return OciScanResultStatus.LeaseLost;
            }

            string? digestWhenMapUnread = _platforms is null ? null : OciScanRepository.UnreadableMapDigest;
            await ReplaceImageRowsAsync(
                conn, tx, job, platforms, stored, now,
                platform => platformMap is null
                    ? digestWhenMapUnread
                    : platformMap.ManifestDigestFor(platform) ?? OciScanRepository.UnlistedPlatformDigest);
            await tx.CommitAsync(ct);
        }

        if (job.Owner.IsHosted)
        {
            var found = resolution.Resolved.Values.ToList();
            await _scans.RecordHostedImageFindingsAsync(
                job.Owner.Id, PurlNormalizer.Oci(job.Repository, job.Digest), "oci", job.Repository, job.OrgId,
                found, ActivityType, platforms.Sum(p => p.Gaps?.Count ?? 0), quietWhenUnchanged: false, ct);
        }

        return OciScanResultStatus.Stored;
    }

    /// <summary>
    /// The coverage gaps one platform carries for the advisory ids it named that the advisory
    /// source did not confirm: none when every id resolved. They are matching gaps, never content
    /// gaps, so the next match drops them once the ids resolve.
    /// </summary>
    internal static IEnumerable<string> AdvisoryGaps(IEnumerable<string> ids, OciScanAdvisoryResolution resolution)
    {
        var named = ids.ToHashSet(StringComparer.Ordinal);
        int unknown = named.Count(resolution.Unknown.Contains);
        int unverified = named.Count(resolution.Unverified.Contains);
        if (unknown > 0)
        {
            yield return $"advisories not recorded: {unknown} advisory id(s) the advisory source does not hold";
        }

        if (unverified > 0)
        {
            yield return $"advisories not recorded: {unverified} advisory id(s) {UnverifiedGapMarker}; "
                + "the next match retries them";
        }
    }

    /// <summary>
    /// The phrase every unverified-advisory gap carries. The sweep finds the results that hold one
    /// by it, to queue them again whether or not the org's scanner claims rematch jobs.
    /// </summary>
    internal const string UnverifiedGapMarker = "not yet verified against the advisory source";

    private static async Task ReplaceImageRowsAsync(
        System.Data.Common.DbConnection conn, System.Data.Common.DbTransaction tx, OciScanJob job,
        IReadOnlyList<OciScanPlatformResult> platforms, Dictionary<string, string> stored, string now,
        Func<string, string?> manifestDigestFor)
    {
        var owner = job.Owner;
        var ownerArgs = new
        {
            orgId = job.OrgId,
            ownerKind = owner.Kind,
            packageVersionId = owner.PackageVersionId,
            cacheArtifactId = owner.CacheArtifactId,
        };

        // A new result replaces the image's previous one for this org; findings cascade with their
        // component.
        await conn.ExecuteAsync(
            """
            DELETE FROM oci_image_components
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
            """,
            ownerArgs, tx);
        await conn.ExecuteAsync(
            """
            DELETE FROM oci_scan_coverage
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
            """,
            ownerArgs, tx);

        var componentRows = new List<object?[]>();
        var findingRows = new List<object?[]>();
        foreach (var platform in platforms)
        {
            var gaps = platform.Gaps ?? [];
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_scan_coverage (
                    id, org_id, owner_kind, package_version_id, cache_artifact_id, platform,
                    scanner_version, extraction_version, osv_source, scanned_at, gaps_json, gap_count,
                    entrypoint_kind, closure_bounded, content_gaps_json, matched_at, manifest_digest)
                VALUES (
                    @id, @orgId, @ownerKind, @packageVersionId, @cacheArtifactId, @platform,
                    @scannerVersion, @extractionVersion, @osvSource, @now, @gapsJson, @gapCount,
                    @entrypointKind, @closureBounded, @contentGapsJson, @now, @manifestDigest)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    ownerArgs.orgId,
                    ownerArgs.ownerKind,
                    ownerArgs.packageVersionId,
                    ownerArgs.cacheArtifactId,
                    platform = platform.Platform,
                    scannerVersion = platform.ScannerVersion,
                    extractionVersion = platform.ExtractionVersion,
                    osvSource = platform.OsvSource,
                    now,
                    gapsJson = System.Text.Json.JsonSerializer.Serialize(gaps),
                    gapCount = gaps.Count,
                    entrypointKind = platform.EntrypointKind,
                    closureBounded = platform.ClosureBounded ? 1 : 0,
                    // Null when the scanner does not classify its gaps: a legacy row, which the
                    // sweep re-extracts rather than re-matches.
                    contentGapsJson = platform.ContentGaps is { } contentGaps
                        ? System.Text.Json.JsonSerializer.Serialize(contentGaps)
                        : null,
                    // No reader wired leaves NULL (the reference graph decides). A reader that
                    // returned nothing means the map could not be read just now: record that as a
                    // non-covering answer, since NULL would read as covering every platform.
                    manifestDigest = manifestDigestFor(platform.Platform!),
                }, tx);

            foreach (var component in platform.Components!)
            {
                string componentId = Guid.NewGuid().ToString("N");
                componentRows.Add(ComponentRow(componentId, job, platform, component));

                // Two advisory ids the scanner reported separately can resolve to one stored row
                // through an alias; the finding is recorded once.
                findingRows.AddRange((component.Vulns ?? [])
                    .Where(v => stored.ContainsKey(v.Id!))
                    .GroupBy(v => stored[v.Id!], StringComparer.Ordinal)
                    .Select(g => FindingRow(job.OrgId, componentId, g.Key, g.First().Reachability ?? "unknown",
                        g.First().NotObservedBasis, g.First().Confidence)));
            }
        }

        await OciScanMultiRowInsert.ExecuteAsync(conn, tx, InsertComponentsSql, ComponentColumns, componentRows);
        await OciScanMultiRowInsert.ExecuteAsync(conn, tx, InsertFindingsSql, FindingColumns, findingRows);
    }

    private const string InsertComponentsSql = """
        INSERT INTO oci_image_components (
            id, org_id, owner_kind, package_version_id, cache_artifact_id, platform,
            purl, ecosystem, name, version, source_name, source_version,
            layer_index, layer_diff_id, layer_instruction, files_present, files_removed,
            in_entrypoint_closure, owned_by_purl,
            reachability_status, not_observed_basis, confidence)
        VALUES {rows}
        """;

    // The parameter of each column above, in order.
    private static readonly string[] ComponentColumns =
    [
        "id", "orgId", "ownerKind", "packageVersionId", "cacheArtifactId", "platform",
        "purl", "ecosystem", "name", "version", "sourceName", "sourceVersion",
        "layerIndex", "layerDiffId", "layerInstruction", "filesPresent", "filesRemoved",
        "inEntrypointClosure", "ownedByPurl",
        "verdictStatus", "verdictBasis", "verdictConfidence",
    ];

    internal const string InsertFindingsSql = """
        INSERT INTO oci_component_vulns (
            id, org_id, component_id, vuln_id, reachability_status, not_observed_basis, confidence)
        VALUES {rows}
        """;

    internal static readonly string[] FindingColumns =
        ["id", "orgId", "componentId", "vulnId", "reachability", "notObservedBasis", "confidence"];

    // One component of a platform, as a row of InsertComponentsSql.
    private static object?[] ComponentRow(
        string componentId, OciScanJob job, OciScanPlatformResult platform, OciScanComponent component) =>
    [
        componentId, job.OrgId, job.Owner.Kind, job.Owner.PackageVersionId, job.Owner.CacheArtifactId,
        platform.Platform, component.Purl, component.Ecosystem, component.Name, component.Version,
        component.SourceName, component.SourceVersion, component.LayerIndex, component.LayerDiffId,
        component.LayerInstruction, component.FilesPresent, component.FilesRemoved,
        component.InEntrypointClosure is bool b ? (b ? 1 : 0) : null, component.OwnedByPurl,
        component.Verdict?.Status, component.Verdict?.NotObservedBasis, component.Verdict?.Confidence,
    ];

    // One finding, as a row of InsertFindingsSql.
    internal static object?[] FindingRow(
        string orgId, string componentId, string vulnId, string reachability, string? notObservedBasis,
        string? confidence) =>
        [Guid.NewGuid().ToString("N"), orgId, componentId, vulnId, reachability, notObservedBasis, confidence];

    /// <summary>
    /// Checks the whole body against the contract and parses its advisories. Returns the first
    /// problem found, or the parsed advisories keyed by id.
    /// </summary>
    internal static (OciScanResultStatus? Invalid, Dictionary<string, OsvAdvisory> Advisories) Validate(
        OciScanResultRequest body)
    {
        var advisories = new Dictionary<string, OsvAdvisory>(StringComparer.Ordinal);
        if (body.Platforms is not { Count: > 0 } platforms)
        {
            return (OciScanResultStatus.Invalid("platforms", "error.ociScan.platformsRequired"), advisories);
        }

        if (platforms.Count > OciScanLimits.MaxPlatforms)
        {
            return (OciScanResultStatus.Invalid("platforms", "error.ociScan.platformsMax", OciScanLimits.MaxPlatforms), advisories);
        }

        // Counted before anything else is parsed, so an oversized body is refused cheaply.
        long findings = platforms.SelectMany(p => p.Components ?? []).Sum(c => (long)(c.Vulns?.Count ?? 0));
        if (findings > OciScanLimits.MaxFindings)
        {
            return (OciScanResultStatus.Invalid("findings", "error.ociScan.findingsMax", OciScanLimits.MaxFindings), advisories);
        }

        if (ParseAdvisories(body.Advisories ?? [], advisories) is { } advisoryProblem)
        {
            return (advisoryProblem, advisories);
        }

        var seenPlatforms = new HashSet<string>(StringComparer.Ordinal);
        int components = 0;
        foreach (var platform in platforms)
        {
            if (ValidatePlatform(platform, seenPlatforms) is { } platformProblem)
            {
                return (platformProblem, advisories);
            }

            components += platform.Components?.Count ?? 0;
            if (platform.Components is null || components > OciScanLimits.MaxComponents)
            {
                return (OciScanResultStatus.Invalid("components", "error.ociScan.componentsInvalid", OciScanLimits.MaxComponents), advisories);
            }

            if (ValidateComponents(platform.Components, advisories) is { } problem)
            {
                return (problem, advisories);
            }
        }

        return (null, advisories);
    }

    // Parses every advisory record into advisories, keyed by id. Returns the first problem found,
    // or null when every record parsed.
    private static OciScanResultStatus? ParseAdvisories(
        IReadOnlyList<System.Text.Json.JsonElement> records, Dictionary<string, OsvAdvisory> advisories)
    {
        if (records.Count > OciScanLimits.MaxAdvisories)
        {
            return OciScanResultStatus.Invalid("advisories", "error.ociScan.advisoriesMax", OciScanLimits.MaxAdvisories);
        }

        foreach (var record in records)
        {
            var advisory = OsvRecordParser.TryParse(record);
            if (advisory is null || advisory.Id.Length > OciScanLimits.MaxTextLength)
            {
                return OciScanResultStatus.Invalid("advisories", "error.ociScan.advisoryInvalid");
            }

            advisories[advisory.Id] = advisory;
        }

        return null;
    }

    // A platform's own fields, checked before its components. gaps stays the full union, so a
    // reader that ignores contentGaps still sees every gap; contentGaps only says which of them a
    // rematch must keep.
    private static OciScanResultStatus? ValidatePlatform(
        OciScanPlatformResult platform, HashSet<string> seenPlatforms)
    {
        return Blank(platform.Platform) || !seenPlatforms.Add(platform.Platform!)
            || Blank(platform.ScannerVersion) || Blank(platform.ExtractionVersion) || Blank(platform.OsvSource)
            || TooLong(platform.EntrypointKind)
            ? OciScanResultStatus.Invalid("platforms", "error.ociScan.platformInvalid")
            : platform.Gaps is { } gaps
                && (gaps.Count > OciScanLimits.MaxGapsPerPlatform || gaps.Any(g => Blank(g) || TooLong(g)))
            ? OciScanResultStatus.Invalid("gaps", "error.ociScan.gapsInvalid", OciScanLimits.MaxGapsPerPlatform)
            : platform.ContentGaps is { } contentGaps
                && !contentGaps.All(g => (platform.Gaps ?? []).Contains(g, StringComparer.Ordinal))
            ? OciScanResultStatus.Invalid("contentGaps", "error.ociScan.contentGapsNotSubset")
            : null;
    }

    private static OciScanResultStatus? ValidateComponents(
        IReadOnlyList<OciScanComponent> components, Dictionary<string, OsvAdvisory> advisories)
    {
        foreach (var component in components)
        {
            if (ValidateComponent(component, advisories) is { } problem)
            {
                return problem;
            }
        }

        return null;
    }

    private static OciScanResultStatus? ValidateComponent(
        OciScanComponent component, Dictionary<string, OsvAdvisory> advisories)
    {
        if (Blank(component.Purl) || Blank(component.Ecosystem) || Blank(component.Name) || Blank(component.Version)
            || TooLong(component.Purl) || TooLong(component.Ecosystem) || TooLong(component.Name)
            || TooLong(component.Version) || TooLong(component.SourceName) || TooLong(component.SourceVersion)
            || TooLong(component.LayerDiffId) || TooLong(component.LayerInstruction) || TooLong(component.OwnedByPurl))
        {
            return OciScanResultStatus.Invalid("components", "error.ociScan.componentInvalid", OciScanLimits.MaxTextLength);
        }

        if (component.Verdict is { } verdict
            && (verdict.Status is null || !OciScanLimits.Reachability.Contains(verdict.Status)
                || TooLong(verdict.NotObservedBasis) || TooLong(verdict.Confidence)))
        {
            return OciScanResultStatus.Invalid("verdict", "error.ociScan.verdictInvalid", OciScanLimits.MaxTextLength);
        }

        var vulns = component.Vulns ?? [];
        return vulns.Count > OciScanLimits.MaxVulnsPerComponent
            ? OciScanResultStatus.Invalid("vulns", "error.ociScan.vulnsMax", OciScanLimits.MaxVulnsPerComponent)
            : ValidateVulns(vulns, advisories);
    }

    private static OciScanResultStatus? ValidateVulns(
        IReadOnlyList<OciScanComponentVuln> vulns, Dictionary<string, OsvAdvisory> advisories)
    {
        foreach (var vuln in vulns)
        {
            if (Blank(vuln.Id) || !advisories.ContainsKey(vuln.Id!))
            {
                return OciScanResultStatus.Invalid("vulns", "error.ociScan.vulnUnknown");
            }

            if (vuln.Reachability is not null && !OciScanLimits.Reachability.Contains(vuln.Reachability))
            {
                return OciScanResultStatus.Invalid("vulns", "error.ociScan.reachabilityInvalid");
            }

            if (TooLong(vuln.NotObservedBasis) || TooLong(vuln.Confidence))
            {
                return OciScanResultStatus.Invalid("vulns", "error.ociScan.vulnTextTooLong", OciScanLimits.MaxTextLength);
            }
        }

        return null;
    }

    private static bool Blank(string? value) => string.IsNullOrWhiteSpace(value);

    private static bool TooLong(string? value) => value is { Length: > OciScanLimits.MaxTextLength };
}
