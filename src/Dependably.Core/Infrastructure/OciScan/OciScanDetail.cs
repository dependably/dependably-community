using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Infrastructure.OciScan;

// Dapper rows. Classes with setters rather than positional records: Dapper converts each column
// to the property's type, which absorbs Postgres INTEGER (int) against SQLite INTEGER (long).

/// <summary>One platform row of a stored result, with its component counts.</summary>
public sealed class OciScanPlatformRow
{
    public string Platform { get; set; } = "";
    public string ScannedAt { get; set; } = "";
    public string ScannerVersion { get; set; } = "";
    public string ExtractionVersion { get; set; } = "";
    public string OsvSource { get; set; } = "";
    public string? EntrypointKind { get; set; }
    public long ClosureBounded { get; set; }
    public string GapsJson { get; set; } = "[]";

    /// <summary>When the findings were last matched against OSV; the scan time until a re-match.</summary>
    public string MatchedAt { get; set; } = "";
    public long ComponentCount { get; set; }
    public long AffectedComponentCount { get; set; }
}

/// <summary>One component of a stored result, with its full finding count.</summary>
public sealed class OciScanComponentRow
{
    public string Id { get; set; } = "";
    public string Purl { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string? SourceName { get; set; }
    public string? SourceVersion { get; set; }
    public long? LayerIndex { get; set; }
    public string? LayerDiffId { get; set; }
    public string? LayerInstruction { get; set; }
    public long? InEntrypointClosure { get; set; }
    public string? OwnedByPurl { get; set; }
    public long FindingCount { get; set; }
}

/// <summary>One finding on a component, with its advisory's details.</summary>
public sealed class OciScanFindingRow
{
    public string ComponentId { get; set; } = "";
    public string OsvId { get; set; } = "";
    public string Reachability { get; set; } = "";
    public string? NotObservedBasis { get; set; }
    public string? Confidence { get; set; }
    public string? AliasesJson { get; set; }
    public string? Summary { get; set; }
    public string? Severity { get; set; }
    public double? CvssScore { get; set; }
}

// The response of GET /api/v1/packages/oci/{name}/{digest}/scan, serialized camelCase.

/// <summary>
/// One org's stored scan detail for one image. <c>State</c> is <c>scanned</c>, <c>unscanned</c>
/// or <c>no_feed</c>; without a stored result <c>Platforms</c> is empty and <c>Components</c> null.
/// </summary>
public sealed record OciScanDetail(
    string State,
    OciScanJobView? Job,
    IReadOnlyList<OciScanPlatformView> Platforms,
    IReadOnlyDictionary<string, OciScanAdvisoryView> Advisories,
    OciScanComponentPage? Components)
{
    /// <summary>
    /// The org's moving tags that observed this image upstream but still serve an earlier digest,
    /// because the promotion gate (release age, or under scan enforcement the image's own scan)
    /// has not passed it yet. Omitted when there is none. A hold that has lasted days usually
    /// means the scanner is not running.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<OciPendingHoldView>? PendingHolds { get; init; }
}

/// <summary>A tag holding this image as its pending digest, and the digest it still serves.</summary>
public sealed record OciPendingHoldView(string Tag, string ServingDigest, string PendingSince);

/// <summary>
/// The org's scan job for an unscanned image: <c>none</c>, <c>pending</c> or <c>failed</c>, with
/// its attempt count for the last two. The job's error text is scanner-supplied and never shown.
/// </summary>
public sealed record OciScanJobView(
    string State,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Attempts);

public sealed record OciScanPlatformView(
    string Platform,
    string ScannedAt,
    string ScannerVersion,
    string ExtractionVersion,
    string OsvSource,
    string? EntrypointKind,
    bool ClosureBounded,
    IReadOnlyList<string> Gaps,
    int ComponentCount,
    int AffectedComponentCount,
    string MatchedAt);

public sealed record OciScanAdvisoryView(
    IReadOnlyList<string> Aliases, string? Summary, string? Severity, double? CvssScore);

public sealed record OciScanComponentPage(
    string Platform, int Total, int Offset, int Limit, IReadOnlyList<OciScanComponentView> Items);

public sealed record OciScanComponentView(
    string Purl,
    string Ecosystem,
    string Name,
    string Version,
    string? SourceName,
    string? SourceVersion,
    int? LayerIndex,
    string? LayerDiffId,
    string? LayerInstruction,
    bool? InEntrypointClosure,
    string? OwnedByPurl,
    int FindingCount,
    IReadOnlyList<OciScanFindingView> Findings);

public sealed record OciScanFindingView(
    string OsvId, string Reachability, string? NotObservedBasis, string? Confidence);

/// <summary>The outcome of a scan-detail read.</summary>
public enum OciScanDetailOutcome
{
    Found,

    /// <summary>The org can see no such image. Every not-visible case reads the same.</summary>
    NotFound,

    /// <summary>The requested platform is not one the image's result holds.</summary>
    UnknownPlatform,
}

/// <summary>
/// Reads one image's stored scan detail for the version page: every platform's coverage, one
/// platform's components a page at a time, and the findings on them. Every statement is keyed by
/// the caller's org; a proxied image row is shared, but its scan rows are the org's own.
/// </summary>
public sealed class OciScanDetailReader
{
    /// <summary>Default and maximum component page sizes.</summary>
    public const int DefaultLimit = 100;
    public const int MaxLimit = 500;

    /// <summary>Findings listed per component; a component's full count travels beside them.</summary>
    public const int MaxFindingsPerComponent = 50;

    private readonly OciScanRepository _repo;
    private readonly IOciScanCoverage _coverage;

    public OciScanDetailReader(OciScanRepository repo, IOciScanCoverage coverage)
    {
        _repo = repo;
        _coverage = coverage;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "The parameter list is the call's declared inputs; a bundling type would hide which of them each "
                        + "caller supplies.")]
    public async Task<(OciScanDetailOutcome Outcome, OciScanDetail? Detail)> ReadAsync(
        string orgId, string repository, string digest, string? platform, bool affectedOnly, int offset, int limit,
        CancellationToken ct = default)
    {
        var owner = await _repo.ResolveImageOwnerAsync(orgId, repository, digest, ct);
        if (owner is null)
        {
            return (OciScanDetailOutcome.NotFound, null);
        }

        var (outcome, detail) = await ReadOwnedAsync(orgId, owner, platform, affectedOnly, offset, limit, ct);
        if (detail is null)
        {
            return (outcome, null);
        }

        var holds = await _repo.GetPendingHoldsAsync(orgId, repository, digest, ct);
        return (outcome, holds.Count == 0 ? detail : detail with { PendingHolds = holds });
    }

    private async Task<(OciScanDetailOutcome Outcome, OciScanDetail? Detail)> ReadOwnedAsync(
        string orgId, OciScanOwner owner, string? platform, bool affectedOnly, int offset, int limit,
        CancellationToken ct)
    {
        var empty = new Dictionary<string, OciScanAdvisoryView>(StringComparer.Ordinal);

        // As the version row does: with scanning off no result is read, so the image has no feed.
        if (!_coverage.Enabled)
        {
            return (OciScanDetailOutcome.Found, new OciScanDetail(OciScanProjection.NoFeed, null, [], empty, null));
        }

        var platformRows = await _repo.GetPlatformsAsync(orgId, owner, ct);
        if (platformRows.Count == 0)
        {
            bool covered = await _coverage.IsCoveredAsync(orgId, ct);
            string state = OciScanProjection.State(hasResult: false, covered);
            var job = state == OciScanProjection.Unscanned
                ? JobView(await _repo.GetScanJobStateAsync(orgId, owner, ct))
                : null;
            return (OciScanDetailOutcome.Found, new OciScanDetail(state, job, [], empty, null));
        }

        string selected = platform ?? platformRows[0].Platform;
        if (!platformRows.Any(p => p.Platform == selected))
        {
            return (OciScanDetailOutcome.UnknownPlatform, null);
        }

        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, MaxLimit);
        var (components, total) = await _repo.GetComponentPageAsync(
            orgId, owner, selected, affectedOnly, offset, limit, ct);
        var findings = (await _repo.GetFindingsAsync(
            orgId, components.Select(c => c.Id).ToList(), MaxFindingsPerComponent, ct))
            .ToLookup(f => f.ComponentId);

        var advisories = new Dictionary<string, OciScanAdvisoryView>(StringComparer.Ordinal);
        foreach (var f in findings.SelectMany(g => g))
        {
            advisories.TryAdd(f.OsvId, new OciScanAdvisoryView(ParseStrings(f.AliasesJson), f.Summary, f.Severity, f.CvssScore));
        }

        var items = components.Select(c => new OciScanComponentView(
            c.Purl, c.Ecosystem, c.Name, c.Version, c.SourceName, c.SourceVersion,
            c.LayerIndex is null ? null : (int)c.LayerIndex.Value, c.LayerDiffId, c.LayerInstruction,
            c.InEntrypointClosure is null ? null : c.InEntrypointClosure.Value != 0, c.OwnedByPurl,
            (int)c.FindingCount,
            findings[c.Id].Select(f => new OciScanFindingView(f.OsvId, f.Reachability, f.NotObservedBasis, f.Confidence))
                .ToList())).ToList();

        var platforms = platformRows.Select(p => new OciScanPlatformView(
            p.Platform, p.ScannedAt, p.ScannerVersion, p.ExtractionVersion, p.OsvSource, p.EntrypointKind,
            p.ClosureBounded != 0, ParseStrings(p.GapsJson), (int)p.ComponentCount, (int)p.AffectedComponentCount, p.MatchedAt))
            .ToList();

        return (OciScanDetailOutcome.Found, new OciScanDetail(
            OciScanProjection.Scanned, null, platforms, advisories,
            new OciScanComponentPage(selected, total, offset, limit, items)));
    }

    /// <summary>
    /// The job state an unscanned image shows. A job that finished without leaving a result reads
    /// as none: nothing is queued and nothing failed.
    /// </summary>
    internal static OciScanJobView JobView((string State, int Attempts)? job) => job switch
    {
        { State: "pending" } j => new OciScanJobView("pending", j.Attempts),
        { State: "failed" } j => new OciScanJobView("failed", j.Attempts),
        _ => new OciScanJobView("none", null),
    };

    // A JSON array of strings, as stored. A non-array reads as empty.
    private static IReadOnlyList<string> ParseStrings(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString()!)
                    .ToList()
                : [];
        }
        catch (JsonException)
        {
            // Shown verbatim rather than dropped: a gap list that cannot be read must stay visible.
            return [json];
        }
    }
}
