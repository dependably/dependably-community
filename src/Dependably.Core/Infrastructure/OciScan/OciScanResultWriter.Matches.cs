using System.Text.Json;
using Dapper;
using Dependably.Protocol;

namespace Dependably.Infrastructure.OciScan;

/// <summary>What a stored match wrote, for the controller's audit row.</summary>
public sealed record OciScanMatchSummary(int Platforms, int Findings, int Advisories);

public sealed partial class OciScanResultWriter
{
    /// <summary>
    /// Stores a rematch job's new findings for the image's stored inventory, without touching the
    /// inventory itself.
    ///
    /// <list type="number">
    ///   <item>The body is validated in full first, against the caps and against the stored
    ///   inventory: every component id must be one of this org's components of the job's image on
    ///   the named platform, and every advisory a finding names must have a record.</item>
    ///   <item>Each advisory id is resolved before the transaction as for a scan result (see
    ///   <see cref="OciScanAdvisoryResolver"/>), keyed to the first component that names it by the
    ///   same <c>SourceName ?? Name</c> rule; the body's advisory records are never stored, and an
    ///   unreachable advisory source refuses the result for a retry.</item>
    ///   <item>One transaction closes the job (while the caller still holds its lease and attempt,
    ///   and only as a rematch), checks that every posted coverage id is still the image's stored
    ///   inventory, replaces the image's findings, copying each component's stored verdict, and
    ///   rewrites each platform's gaps as its stored content gaps plus the posted matching gaps.
    ///   A coverage id a re-extraction replaced meanwhile writes nothing.</item>
    ///   <item>For a hosted image the version's links, alerts, activity and webhook then follow
    ///   as for a scan result; a proxied image's shared rows are never touched.</item>
    /// </list>
    /// </summary>
    public async Task<(OciScanResultStatus Status, OciScanMatchSummary? Summary)> WriteMatchesAsync(
        OciScanJob job, OciScanMatchRequest body, CancellationToken ct = default)
    {
        var (invalid, _) = ValidateMatches(body);
        return invalid is not null ? (invalid, null) : await WriteValidatedMatchesAsync(job, body, ct);
    }

    /// <summary>
    /// <see cref="WriteMatchesAsync"/> for a body <see cref="ValidateMatches"/> has already passed,
    /// so a caller that validated first does not validate twice. The body's advisory records are
    /// only validated, never stored.
    /// </summary>
    public async Task<(OciScanResultStatus Status, OciScanMatchSummary? Summary)> WriteValidatedMatchesAsync(
        OciScanJob job, OciScanMatchRequest body, CancellationToken ct = default)
    {
        var platforms = body.Platforms!;

        // The inventory token is checked before the findings: a re-extraction since the scanner's
        // inventory read replaces every component id too, and that is a 409 the scanner can act
        // on, not a malformed body. The transaction checks the token again under the write.
        await using (var conn = await _db.OpenAsync(ct))
        {
            if (InventoryReplaced(platforms, await LoadCoverageAsync(conn, null, job)))
            {
                return (OciScanResultStatus.InventoryChanged, null);
            }
        }

        var components = await LoadMatchComponentsAsync(job, ct);
        if (CheckFindingsAgainstInventory(platforms, components) is { } problem)
        {
            return (problem, null);
        }

        var resolution = await _advisories.ResolveAsync(
            platforms.SelectMany(p => p.Findings ?? []).SelectMany(finding =>
            {
                var component = components[finding.ComponentId!];
                return (finding.Vulns ?? []).Select(id =>
                    new OciScanAdvisoryRef(id, component.Ecosystem, component.SourceName ?? component.Name));
            }),
            ct);
        if (resolution.SourceUnavailable && _advisories.MayDefer(job))
        {
            return (OciScanResultStatus.AdvisorySourceUnavailable, null);
        }

        // Advisory id as the scanner sent it -> the vulnerabilities row it is stored under. An id
        // the advisory source did not confirm has no entry: its findings are not recorded, and the
        // platforms that named it carry a matching gap saying so.
        var stored = resolution.Resolved.ToDictionary(r => r.Key, r => r.Value.VulnId, StringComparer.Ordinal);
        platforms = platforms.Select(p => p with
        {
            MatchGaps = [.. p.MatchGaps ?? [], .. AdvisoryGaps(
                (p.Findings ?? []).SelectMany(f => f.Vulns ?? []), resolution)],
        }).ToList();

        string now = _time.GetUtcNow().ToUtcIsoMillis();
        OciScanResultStatus? replaced;
        bool gapsChanged;
        int gapCount;
        await using (var conn = await _db.OpenAsync(ct))
        await using (var tx = await conn.BeginTransactionAsync(ct))
        {
            int closed = await conn.ExecuteAsync(
                """
                UPDATE oci_scan_jobs
                SET state = 'done', lease_expires_at = NULL, last_error = NULL,
                    updated_at = @now, completed_at = @now
                WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now
                  AND attempts = @attempt AND kind = 'rematch'
                """,
                new { orgId = job.OrgId, jobId = job.Id, attempt = job.Attempts, now }, tx);
            if (closed != 1)
            {
                await tx.RollbackAsync(ct);
                return (OciScanResultStatus.LeaseLost, null);
            }

            (replaced, gapsChanged, gapCount) = await ReplaceFindingsAsync(conn, tx, job, platforms, components, stored, now);
            if (replaced is not null)
            {
                await tx.RollbackAsync(ct);
                return (replaced, null);
            }

            await tx.CommitAsync(ct);
        }

        if (job.Owner.IsHosted)
        {
            var found = resolution.Resolved.Values.ToList();
            // A rematch that changes no link and no gap is the daily confirmation of what the image
            // already shows; it writes no activity row of its own.
            await _scans.RecordHostedImageFindingsAsync(
                job.Owner.Id, PurlNormalizer.Oci(job.Repository, job.Digest), "oci", job.Repository, job.OrgId,
                found, ActivityType, gapCount, quietWhenUnchanged: !gapsChanged, ct);
        }

        return (OciScanResultStatus.Stored, new OciScanMatchSummary(
            platforms.Count,
            platforms.SelectMany(p => p.Findings ?? []).Sum(f => (f.Vulns ?? []).Count(stored.ContainsKey)),
            stored.Count));
    }

    // Inside the job's transaction: confirms the posted coverage ids are still the image's stored
    // inventory, then replaces findings and matching gaps. Returns a refusal, or null when written
    // with whether any platform's gaps differ from what it held before and the gaps it now holds.
    private static async Task<(OciScanResultStatus? Refusal, bool GapsChanged, int Gaps)> ReplaceFindingsAsync(
        System.Data.Common.DbConnection conn, System.Data.Common.DbTransaction tx, OciScanJob job,
        IReadOnlyList<OciScanMatchPlatform> platforms, IReadOnlyDictionary<string, MatchComponent> components,
        Dictionary<string, string> stored, string now)
    {
        var owner = job.Owner;
        var ownerArgs = new
        {
            orgId = job.OrgId,
            ownerKind = owner.Kind,
            packageVersionId = owner.PackageVersionId,
            cacheArtifactId = owner.CacheArtifactId,
        };

        var coverage = await LoadCoverageAsync(conn, tx, job);
        if (InventoryReplaced(platforms, coverage))
        {
            return (OciScanResultStatus.InventoryChanged, false, 0);
        }

        // Every stored platform must be re-matched: findings are replaced for the whole image, so
        // a platform left out would lose its findings without being matched again.
        if (coverage.Count != platforms.Count)
        {
            return (OciScanResultStatus.Invalid("platforms", "error.ociScan.platformsIncomplete"), false, 0);
        }

        int totalGaps = 0;

        await conn.ExecuteAsync(
            """
            DELETE FROM oci_component_vulns
            WHERE org_id = @orgId AND component_id IN (
                SELECT id FROM oci_image_components
                WHERE org_id = @orgId AND owner_kind = @ownerKind
                  AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId))
            """,
            ownerArgs, tx);

        var findingRows = new List<object?[]>();
        bool gapsChanged = false;
        foreach (var platform in platforms)
        {
            foreach (var finding in platform.Findings ?? [])
            {
                var component = components[finding.ComponentId!];
                // Two advisory ids the scanner reported separately can resolve to one stored row
                // through an alias; the finding is recorded once.
                findingRows.AddRange((finding.Vulns ?? []).Where(stored.ContainsKey).Select(v => stored[v])
                    .Distinct(StringComparer.Ordinal)
                    .Select(vulnId => FindingRow(ownerArgs.orgId, component.Id, vulnId,
                        component.ReachabilityStatus ?? "unknown", component.NotObservedBasis, component.Confidence)));
            }

            var (coverageId, _, contentGapsJson, previousGapsJson) = coverage[platform.CoverageId!];
            var contentGaps = JsonSerializer.Deserialize<List<string>>(contentGapsJson!) ?? [];
            var gaps = contentGaps
                .Concat(platform.MatchGaps ?? [])
                .Distinct(StringComparer.Ordinal)
                .ToList();
            var previousGaps = previousGapsJson is null ? [] : JsonSerializer.Deserialize<List<string>>(previousGapsJson) ?? [];
            gapsChanged |= !previousGaps.ToHashSet(StringComparer.Ordinal).SetEquals(gaps);
            totalGaps += gaps.Count;
            await conn.ExecuteAsync(
                """
                UPDATE oci_scan_coverage
                SET gaps_json = @gapsJson, gap_count = @gapCount, osv_source = @osvSource,
                    scanner_version = @scannerVersion, matched_at = @now
                WHERE org_id = @orgId AND id = @coverageId
                """,
                new
                {
                    ownerArgs.orgId,
                    coverageId,
                    gapsJson = JsonSerializer.Serialize(gaps),
                    gapCount = gaps.Count,
                    osvSource = platform.OsvSource,
                    scannerVersion = platform.ScannerVersion,
                    now,
                }, tx);
        }

        await OciScanMultiRowInsert.ExecuteAsync(conn, tx, InsertFindingsSql, FindingColumns, findingRows);
        return (null, gapsChanged, totalGaps);
    }

    // The org's stored coverage rows of the job's image, keyed by id: the inventory tokens.
    private static async Task<Dictionary<string, (string Id, string Platform, string? ContentGapsJson, string? GapsJson)>> LoadCoverageAsync(
        System.Data.Common.DbConnection conn, System.Data.Common.DbTransaction? tx, OciScanJob job)
    {
        var rows = await conn.QueryAsync<(string Id, string Platform, string? ContentGapsJson, string? GapsJson)>(
            """
            SELECT id AS Id, platform AS Platform, content_gaps_json AS ContentGapsJson, gaps_json AS GapsJson
            FROM oci_scan_coverage
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
            """,
            new
            {
                orgId = job.OrgId,
                ownerKind = job.Owner.Kind,
                packageVersionId = job.Owner.PackageVersionId,
                cacheArtifactId = job.Owner.CacheArtifactId,
            },
            tx);
        return rows.ToDictionary(c => c.Id, StringComparer.Ordinal);
    }

    // A posted coverage id that is gone, names another platform, or now names a legacy row means a
    // re-extraction replaced the inventory this match was computed against.
    private static bool InventoryReplaced(
        IReadOnlyList<OciScanMatchPlatform> platforms,
        IReadOnlyDictionary<string, (string Id, string Platform, string? ContentGapsJson, string? GapsJson)> coverage)
        => platforms.Any(p => !coverage.TryGetValue(p.CoverageId!, out var row)
            || row.Platform != p.Platform || row.ContentGapsJson is null);

    // The org's stored components of the job's image, keyed by id. Bounded by what a scan result
    // could store (OciScanLimits.MaxComponents).
    private async Task<IReadOnlyDictionary<string, MatchComponent>> LoadMatchComponentsAsync(
        OciScanJob job, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<MatchComponent>(
            """
            SELECT id AS Id, platform AS Platform, ecosystem AS Ecosystem, name AS Name,
                   source_name AS SourceName, reachability_status AS ReachabilityStatus,
                   not_observed_basis AS NotObservedBasis, confidence AS Confidence
            FROM oci_image_components
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
            """,
            new
            {
                orgId = job.OrgId,
                ownerKind = job.Owner.Kind,
                packageVersionId = job.Owner.PackageVersionId,
                cacheArtifactId = job.Owner.CacheArtifactId,
            });
        return rows.ToDictionary(r => r.Id, StringComparer.Ordinal);
    }

    // Every finding must name a stored component of this image on the platform it is posted
    // under, at most once.
    private static OciScanResultStatus? CheckFindingsAgainstInventory(
        IReadOnlyList<OciScanMatchPlatform> platforms, IReadOnlyDictionary<string, MatchComponent> components)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var platform in platforms)
        {
            foreach (string componentId in (platform.Findings ?? []).Select(finding => finding.ComponentId!))
            {
                if (!components.TryGetValue(componentId, out var component)
                    || component.Platform != platform.Platform
                    || !seen.Add(componentId))
                {
                    return OciScanResultStatus.Invalid("findings", "error.ociScan.findingUnknown");
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Checks a match body against the caps and parses its advisories. Returns the first problem
    /// found, or the parsed advisories keyed by id. The checks against the stored inventory come
    /// after, in <see cref="WriteMatchesAsync"/>.
    /// </summary>
    public static (OciScanResultStatus? Invalid, Dictionary<string, OsvAdvisory> Advisories) ValidateMatches(
        OciScanMatchRequest body)
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

        long advisoryLinks = platforms.SelectMany(p => p.Findings ?? []).Sum(f => (long)(f.Vulns?.Count ?? 0));
        if (advisoryLinks > OciScanLimits.MaxFindings)
        {
            return (OciScanResultStatus.Invalid("findings", "error.ociScan.findingsMax", OciScanLimits.MaxFindings), advisories);
        }

        if (ParseAdvisories(body.Advisories ?? [], advisories) is { } advisoryProblem)
        {
            return (advisoryProblem, advisories);
        }

        var seenPlatforms = new HashSet<string>(StringComparer.Ordinal);
        int findings = 0;
        foreach (var platform in platforms)
        {
            if (ValidateMatchPlatform(platform, seenPlatforms) is { } platformProblem)
            {
                return (platformProblem, advisories);
            }

            findings += platform.Findings?.Count ?? 0;
            if (findings > OciScanLimits.MaxComponents)
            {
                return (OciScanResultStatus.Invalid("findings", "error.ociScan.componentsInvalid", OciScanLimits.MaxComponents), advisories);
            }

            foreach (var finding in platform.Findings ?? [])
            {
                if (ValidateFinding(finding, advisories) is { } problem)
                {
                    return (problem, advisories);
                }
            }
        }

        return (null, advisories);
    }

    // A matched platform's own fields, checked before its findings.
    private static OciScanResultStatus? ValidateMatchPlatform(
        OciScanMatchPlatform platform, HashSet<string> seenPlatforms)
    {
        return Blank(platform.Platform) || !seenPlatforms.Add(platform.Platform!) || Blank(platform.CoverageId)
            || Blank(platform.ScannerVersion) || Blank(platform.OsvSource)
            || TooLong(platform.CoverageId) || TooLong(platform.ScannerVersion) || TooLong(platform.OsvSource)
            ? OciScanResultStatus.Invalid("platforms", "error.ociScan.matchPlatformInvalid")
            : platform.MatchGaps is { } gaps
                && (gaps.Count > OciScanLimits.MaxGapsPerPlatform || gaps.Any(g => Blank(g) || TooLong(g)))
            ? OciScanResultStatus.Invalid("matchGaps", "error.ociScan.gapsInvalid", OciScanLimits.MaxGapsPerPlatform)
            : null;
    }

    private static OciScanResultStatus? ValidateFinding(
        OciScanMatchFinding finding, Dictionary<string, OsvAdvisory> advisories)
    {
        if (Blank(finding.ComponentId) || TooLong(finding.ComponentId))
        {
            return OciScanResultStatus.Invalid("findings", "error.ociScan.findingUnknown");
        }

        var vulns = finding.Vulns ?? [];
        return vulns.Count > OciScanLimits.MaxVulnsPerComponent
            ? OciScanResultStatus.Invalid("vulns", "error.ociScan.vulnsMax", OciScanLimits.MaxVulnsPerComponent)
            : vulns.Any(id => Blank(id) || !advisories.ContainsKey(id))
            ? OciScanResultStatus.Invalid("vulns", "error.ociScan.vulnUnknown")
            : null;
    }

    // A positional record: every column is text, so Dapper binds it through the constructor.
    private sealed record MatchComponent(
        string Id,
        string Platform,
        string Ecosystem,
        string Name,
        string? SourceName,
        string? ReachabilityStatus,
        string? NotObservedBasis,
        string? Confidence);
}
