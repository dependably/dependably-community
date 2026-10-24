using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Read-only "check a package before you add it" lookup: resolves upstream metadata for a
/// candidate (ecosystem, name, version) without ingesting it, queries <see cref="IOsvSource"/>
/// for advisories, and evaluates the org's block/license policy against the result via the
/// same pure core the proxy serve path uses (<see cref="BlockGateService.Evaluate"/>).
///
/// Nothing is written to the blob store, <c>package_versions</c>, or <c>cache_artifact</c> — the
/// only DB activity is reads (org settings, license allow/blocklists, cached KEV/EPSS
/// enrichment). <see cref="LicenseRepository.CheckPolicyAsync"/> is called read-only; this is
/// its first production caller, informational only under <c>off</c> mode.
///
/// Metadata support is per-ecosystem, and every ecosystem resolves "no version given -> evaluate
/// latest stable". npm and PyPI resolve deprecation, publish date, and SPDX license from their
/// JSON APIs. NuGet and Maven resolve version existence only (their registration/POM endpoints
/// are not walked at lookup time). Cargo reads the sparse index for version existence and
/// <c>yanked</c>, and adds license and publish date from the crates.io JSON API when — and only
/// when — the configured upstream is crates.io's own index, so a private mirror degrades to
/// index-only facts instead of reaching a host the operator never configured. Go reads
/// <c>@latest</c>/<c>.info</c> for version and publish date; a Go module carries no license or
/// deprecation signal outside its zip, which lookup never downloads. An air-gapped org or
/// instance suppresses every upstream fetch, so a lookup there still requires an explicit
/// version. So does an org with proxy passthrough off, whose upstreams are not consulted either
/// (<see cref="PackageLookupStatus.PassthroughOff"/> when no version is given). So does a name
/// the org has reserved in its ecosystem
/// (<see cref="ReservedNamespaceService.IsUpstreamNameReservedAsync"/>), which is never looked up
/// upstream: with a version it answers from the advisory and licence checks alone and says the
/// name is reserved (<see cref="PackageLookupResult.Reserved"/>); without one it is
/// <see cref="PackageLookupStatus.Reserved"/>. An ecosystem with no upstream configured for the
/// org is likewise a standing configuration, not an outage
/// (<see cref="PackageLookupStatus.UpstreamNotConfigured"/>). Only a fetch that was attempted and
/// failed is <see cref="PackageLookupStatus.UpstreamUnavailable"/>. A candidate's install-script
/// and provenance facts are never derivable at lookup time (no artifact is fetched), so those
/// <see cref="BlockGateService"/> arms are always neutral — callers should not read
/// <see cref="PackageLookupResult.Verdict"/> as a guarantee those checks ran. <see cref="PackageLookupResult.UnavailableChecks"/> reports only checks that
/// would normally run at lookup time but could not for this lookup, not the two
/// structurally-out-of-scope artifact arms.
/// </summary>
public sealed partial class PackageLookupService
{
    /// <summary>
    /// Ecosystems this endpoint accepts. The first seven are answered from OSV by PURL. apk and rpm
    /// are answered from OSV's release-scoped distro feeds and need a release
    /// (<see cref="PackageLookupRequest.Distro"/>, or one derived from the org's upstream). oci is
    /// answered from the org's own image-scan results, and terraform has no advisory source at all
    /// and says so (<see cref="AdvisorySourceInfo.NotApplicable"/>). None of the last four resolves
    /// upstream metadata, so each needs an explicit version.
    /// </summary>
    public static readonly IReadOnlyList<string> SupportedEcosystems =
        ["npm", "pypi", "nuget", "maven", "golang", "cargo", "hex", "apk", "rpm", "oci", "terraform"];

    // The ecosystems an advisory is looked up for by a bare PURL; apk and rpm need a release, oci
    // reads a scan result and terraform has no source, so none of those four can be resolved by a
    // coordinate alone (the vulnerability detail fallback).
    private static readonly HashSet<string> PurlQueryEcosystems =
        ["npm", "pypi", "nuget", "maven", "golang", "cargo", "hex"];

    // Ecosystems with a wired upstream metadata fetch (deprecation/publish-date/license and
    // "no version given -> evaluate latest stable"). Which facts each one yields varies — see the
    // per-ecosystem summary on the class — but every member can resolve a latest version, so an
    // omitted version is a hard failure only when no fetch is permitted at all (air-gap).
    private static readonly HashSet<string> MetadataSupportedEcosystems =
        ["npm", "pypi", "nuget", "maven", "cargo", "golang", "hex"];

    private readonly OrgRepository _orgs;
    private readonly UpstreamRegistryResolver _registries;
    private readonly UpstreamClient _upstream;
    private readonly IUpstreamLatestVersionResolver _latestResolver;
    private readonly IOsvSource _osv;
    private readonly VulnerabilityRepository _vulns;
    private readonly LicenseRepository _licenses;
    private readonly IAirGapMode _airGap;
    private readonly TimeProvider _time;
    private readonly PackageLookupCache _cache;
    private readonly OsvQueryCache _osvCache;
    private readonly ReservedNamespaceService _reservedNamespaces;
    private readonly Hex.HexMasterKeyResolver? _hexMasterKeys;
    private readonly Dependably.Infrastructure.OciScan.OciScanRepository? _ociScans;
    private readonly OciPullGateResolver? _ociPullGate;
    private readonly QuarantineRepository? _quarantine;
    private readonly Microsoft.Extensions.Logging.ILogger<PackageLookupService> _logger;

    // Each parameter is a distinct DI-registered collaborator this read-only lookup depends
    // on directly; grouping them into a wrapper type would just move the coupling without
    // reducing it.
#pragma warning disable S107 // constructor injection of independently-registered DI services
    public PackageLookupService(
        OrgRepository orgs,
        UpstreamRegistryResolver registries,
        UpstreamClient upstream,
        IUpstreamLatestVersionResolver latestResolver,
        IOsvSource osv,
        VulnerabilityRepository vulns,
        LicenseRepository licenses,
        IAirGapMode airGap,
        TimeProvider time,
        PackageLookupCache cache,
        ReservedNamespaceService reservedNamespaces,
        Hex.HexMasterKeyResolver? hexMasterKeys = null,
        Dependably.Infrastructure.OciScan.OciScanRepository? ociScans = null,
        OsvQueryCache? osvCache = null,
        OciPullGateResolver? ociPullGate = null,
        QuarantineRepository? quarantine = null,
        Microsoft.Extensions.Logging.ILogger<PackageLookupService>? logger = null)
#pragma warning restore S107
    {
        _orgs = orgs;
        _registries = registries;
        _upstream = upstream;
        _latestResolver = latestResolver;
        _osv = osv;
        _vulns = vulns;
        _licenses = licenses;
        _airGap = airGap;
        _time = time;
        _cache = cache;
        _reservedNamespaces = reservedNamespaces;
        _hexMasterKeys = hexMasterKeys;
        _ociScans = ociScans;
        _ociPullGate = ociPullGate;
        _quarantine = quarantine;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<PackageLookupService>.Instance;
        _osvCache = osvCache ?? new OsvQueryCache(time);
    }

    public async Task<PackageLookupOutcome> LookupAsync(PackageLookupRequest request, CancellationToken ct = default)
    {
        string ecosystem = (request.Ecosystem ?? string.Empty).Trim().ToLowerInvariant();
        if (!SupportedEcosystems.Contains(ecosystem))
        {
            return PackageLookupOutcome.UnsupportedEcosystem(ecosystem);
        }

        string name = (request.Name ?? string.Empty).Trim();
        var nameProblem = ValidateName(ecosystem, name);
        if (nameProblem is not null)
        {
            return PackageLookupOutcome.InvalidInput(nameProblem.Value.Field, nameProblem.Value.Code);
        }

        string? requestedVersion = string.IsNullOrWhiteSpace(request.Version) ? null : request.Version.Trim();
        if (requestedVersion is not null)
        {
            // ValidateUpstreamSegment (not Validate): the version is composed into an upstream
            // URL (the NuGet nuspec fetch), and no ecosystem's version grammar admits '%'.
            var vr = PathSafeValidator.ValidateUpstreamSegment(requestedVersion, "version");
            if (!vr.IsValid)
            {
                return PackageLookupOutcome.InvalidInput("version", "version.invalid");
            }
        }

        if (requestedVersion is null && !MetadataSupportedEcosystems.Contains(ecosystem))
        {
            return PackageLookupOutcome.VersionRequired(ecosystem);
        }

        var inputProblem = ValidateScopeInputs(ecosystem, requestedVersion, request.Distro, out var requestedScope);
        if (inputProblem is not null)
        {
            return PackageLookupOutcome.InvalidInput(inputProblem.Value.Field, inputProblem.Value.Code);
        }

        // An image's scan result lands asynchronously and nothing invalidates the cache when it
        // does, so an OCI answer is read fresh: caching "no scan result yet" would keep a scanned
        // image reading unverified for the cache's lifetime.
        if (ecosystem == "oci")
        {
            return await ComputeAsync(request.OrgId, ecosystem, name, requestedVersion, requestedScope, ct);
        }

        string cacheKey = PackageLookupCache.KeyFor(
            request.OrgId, ecosystem, name, requestedVersion, requestedScope?.OsvEcosystem);
        var cached = _cache.TryGet(cacheKey);
        if (cached is not null)
        {
            return cached;
        }

        var outcome = await _cache.SingleFlightAsync(cacheKey,
            () => ComputeAsync(request.OrgId, ecosystem, name, requestedVersion, requestedScope, ct), ct);
        return outcome;
    }

    private async Task<PackageLookupOutcome> ComputeAsync(
        string orgId, string ecosystem, string name, string? requestedVersion, DistroScope? requestedScope,
        CancellationToken ct)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct) ?? new OrgSettings { OrgId = orgId };
        bool airGapped = settings.AirGapped || _airGap.IsEnabled;

        // Proxy passthrough off is the org saying its upstreams are not to be consulted, so the
        // metadata fetch (which sends the candidate name with the org's stored upstream
        // credentials) is off too, as it is when air-gapped. A version-less lookup then has
        // nothing to resolve "latest" against and says why; an explicit version degrades to the
        // advisory and licence checks with the metadata checks listed as unavailable.
        bool passthroughOff = !airGapped && !settings.ProxyPassthroughEffective
            && MetadataSupportedEcosystems.Contains(ecosystem);
        if (passthroughOff && requestedVersion is null)
        {
            return PackageLookupOutcome.PassthroughOff(ecosystem);
        }

        bool metadataAllowed = !airGapped && !passthroughOff && MetadataSupportedEcosystems.Contains(ecosystem);

        // No ecosystem fetches the artifact itself at lookup time (that would be exactly the
        // ingest this feature deliberately avoids), so the two arms that need artifact bytes
        // (install-script detection, provenance verification) are always neutral in the shared
        // BlockGateService evaluation below. Being structurally out of scope for every lookup,
        // they are NOT reported in UnavailableChecks — that list carries only checks that
        // would normally run at lookup time but could not for THIS lookup (upstream
        // unreachable, air-gapped, unsupported ecosystem).
        var unavailable = new List<string>();

        var resolution = await ResolveVersionAsync(orgId, ecosystem, name, requestedVersion, metadataAllowed, ct);
        if (resolution.EarlyExit is not null)
        {
            return resolution.EarlyExit;
        }

        unavailable.AddRange(resolution.UnavailableAdditions);
        string version = resolution.Version!;
        var facts = resolution.Facts!;
        var (purl, advisoryQuery) = await QueryAdvisorySourceAsync(
            orgId, ecosystem, name, version, requestedScope, ct);
        if (advisoryQuery.Source.Status == AdvisorySourceInfo.UnavailableStatus)
        {
            unavailable.Add("vulnerabilities");
        }

        var analysis = await AnalyzeAdvisoriesAsync(advisoryQuery.Advisories, advisoryQuery.Available, ct);

        var licenseVerdict = await _licenses.CheckPolicyAsync(
            orgId, settings.LicenseEnforcementMode, facts.Spdx, ct);

        var now = _time.GetUtcNow();
        var ociPullVerdict = ecosystem == "oci" && settings.OciScanEnforcement == "block"
            ? await PreviewOciPullAsync(orgId, name, version, settings, now, ct)
            : (BlockVerdict?)null;

        var (overall, blockedReason) = DetermineOverall(
            facts, settings, analysis, advisoryQuery.Available, licenseVerdict,
            new LookupGateContext(now, VulnerabilityArmsEnforced(ecosystem, settings), ociPullVerdict),
            advisoryQuery.Source);

        var result = BuildResult(new LookupResultContext(
            purl, ecosystem, name, version, resolution.VersionInferred,
            overall, blockedReason, facts, settings, analysis, advisoryQuery.Available,
            licenseVerdict, settings.AirGapped || _airGap.IsEnabled, resolution.Reserved, unavailable,
            advisoryQuery.Source));

        return PackageLookupOutcome.Ok(result);
    }

    // Resolves the candidate's effective version and its upstream metadata facts (or an
    // immediate exit outcome — unsupported/not-found/version-required/unavailable). Isolates
    // the "no ecosystem fetches artifact bytes at lookup time" degrade-vs-fail branching that
    // otherwise dominates ComputeAsync's complexity.
    private async Task<VersionResolution> ResolveVersionAsync(
        string orgId, string ecosystem, string name, string? requestedVersion, bool metadataAllowed, CancellationToken ct)
    {
        bool metadataUsable = MetadataSupportedEcosystems.Contains(ecosystem) && metadataAllowed;
        var fetchOutcome = metadataUsable
            ? await FetchFactsAsync(ecosystem, orgId, name, requestedVersion, ct)
            : await ReservationOnlyOutcomeAsync(ecosystem, orgId, name, ct);

        return fetchOutcome?.Status switch
        {
            MetadataFetchStatus.NotFound => VersionResolution.Exit(
                PackageLookupOutcome.UpstreamNotFound(new PackageLookupNotFound(ecosystem, name, requestedVersion))),
            MetadataFetchStatus.Ok => ResolveFromFetchedFacts(fetchOutcome, requestedVersion),
            _ => ResolveWithoutMetadata(fetchOutcome, requestedVersion, ecosystem),
        };
    }

    private static VersionResolution ResolveFromFetchedFacts(FactsOutcome fetchOutcome, string? requestedVersion)
    {
        var unavailable = new List<string>();
        var facts = fetchOutcome.Facts!;
        if (facts.PublishedAt is null)
        {
            unavailable.Add("release_age");
        }

        // Deprecated is null both when a source resolved "not deprecated" (npm, PyPI, Cargo) and
        // when it carries no deprecation signal at all (NuGet, Maven, Go), so the flag — not the
        // value — decides. Reporting the unresolved case keeps the unavailable-checks list an
        // accurate account of what actually ran, which is the only thing that makes an "allowed"
        // verdict readable.
        if (!facts.DeprecationResolved)
        {
            unavailable.Add("deprecated");
        }

        if (facts.Spdx.Count == 0)
        {
            unavailable.Add("license");
        }

        return VersionResolution.Resolved(fetchOutcome.Version!, requestedVersion is null, facts, unavailable);
    }

    // Air-gapped (org- or instance-level, no outbound registry call), a name the org reserved,
    // no upstream configured for the ecosystem, or an upstream that was tried and failed. With
    // no version there is nothing to resolve "latest" against, and each cause is its own exit so
    // a standing configuration never reads as an outage: VersionRequired when no fetch was
    // permitted at all, Reserved and UpstreamNotConfigured for the two operator choices (both
    // permanent until the operator changes them, so retrying never helps), and
    // UpstreamUnavailable only when a fetch was attempted and failed. An EXPLICIT version
    // degrades gracefully instead: the lookup still returns an OSV + licence verdict with the
    // metadata-dependent checks marked unavailable, and a reserved name says so on the result.
    private static VersionResolution ResolveWithoutMetadata(
        FactsOutcome? fetchOutcome, string? requestedVersion, string ecosystem)
    {
        bool reserved = fetchOutcome?.Status == MetadataFetchStatus.Reserved;
        if (requestedVersion is null)
        {
            var exit = fetchOutcome?.Status switch
            {
                null => PackageLookupOutcome.VersionRequired(ecosystem),
                MetadataFetchStatus.Reserved => PackageLookupOutcome.Reserved(ecosystem),
                MetadataFetchStatus.NotConfigured => PackageLookupOutcome.UpstreamNotConfigured(ecosystem),
                _ => PackageLookupOutcome.UpstreamUnavailable(ecosystem),
            };
            return VersionResolution.Exit(exit);
        }

        return VersionResolution.Resolved(
            requestedVersion, false, VersionMetadataFacts.Unavailable,
            new List<string> { "release_age", "deprecated", "license" }, reserved);
    }

    // TryQueryAsync (not QueryAsync) because QueryAsync's contract is swallow-and-return-
    // empty on failure — indistinguishable from a genuine "no known advisories" answer. A
    // lookup verdict of "allowed" must mean OSV was actually consulted, so an unreached
    // source (network outage, 5xx, non-2xx) has to surface as unavailable here even though
    // it never throws.
    private async Task<AdvisoryQueryResult> QueryAdvisoriesAsync(string ecosystem, string purl, CancellationToken ct)
    {
        try
        {
            // A source holding no feed for the ecosystem (a local dump sideloaded without it)
            // answers empty for every package, which is silence rather than a clean result.
            if (!await _osv.HasCoverageFor(ecosystem))
            {
                return AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.NoOsvCoverage());
            }

            var osvResult = await _osv.TryQueryAsync(purl, ct);
            return osvResult.Reached
                ? new AdvisoryQueryResult(osvResult.Advisories, true, AdvisorySourceInfo.OsvChecked())
                : AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OsvUnreachable());
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            return AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OsvUnreachable());
        }
    }

    // Splits raw advisories into malware/scored/unscored, hydrates KEV/EPSS enrichment for
    // the ones OSV actually returned, and reduces that into the summary facts the block gate
    // and the response DTO both need.
    private async Task<AdvisoryAnalysis> AnalyzeAdvisoriesAsync(
        List<OsvAdvisory> rawAdvisories, bool advisoriesAvailable, CancellationToken ct)
    {
        var advisories = MergeDuplicateAdvisories(rawAdvisories);
        var malwareIds = advisories
            .Where(a => a.Id.StartsWith("MAL-", StringComparison.Ordinal))
            .Select(a => a.Id)
            .ToList();
        var scored = advisories
            .Where(a => a.CvssScore is not null && !a.Id.StartsWith("MAL-", StringComparison.Ordinal))
            .ToList();
        var unscored = advisories
            .Where(a => a.CvssScore is null && !a.Id.StartsWith("MAL-", StringComparison.Ordinal))
            .ToList();

        var kevEpss = advisoriesAvailable && advisories.Count > 0
            ? await ResolveKevEpssAsync(advisories, ct)
            : new Dictionary<string, AdvisoryEnrichment>();

        bool hasKev = advisories.Any(a => kevEpss.TryGetValue(a.Id, out var e) && e.IsKev);
        var epssValues = advisories
            .Select(a => kevEpss.TryGetValue(a.Id, out var e) ? e.EpssScore : null)
            .Where(v => v is not null)
            .Select(v => v!.Value)
            .ToList();
        double? maxEpss = epssValues.Count > 0 ? epssValues.Max() : null;
        double? maxCvss = scored.Count > 0 ? scored.Max(a => a.CvssScore) : null;

        var percentiles = advisories
            .Select(a => kevEpss.TryGetValue(a.Id, out var e) ? e.EpssPercentile : null)
            .Where(v => v is not null)
            .Select(v => v!.Value)
            .ToList();
        double? maxEpssPercentile = percentiles.Count > 0 ? percentiles.Max() : null;

        return new AdvisoryAnalysis(
            malwareIds, scored, unscored, kevEpss, hasKev, maxEpss, maxEpssPercentile, maxCvss, malwareIds.Count > 0);
    }

    // A source can return one advisory id several times (the local OSV index files an advisory
    // under every affected entry). Collapsing them keeps each id reported once and gives the
    // survivor the union of the aliases the copies carried. The first copy that has a CVSS score
    // wins, else the first copy.
    private static List<OsvAdvisory> MergeDuplicateAdvisories(List<OsvAdvisory> advisories)
    {
        return advisories
            .GroupBy(a => a.Id, StringComparer.Ordinal)
            .Select(g =>
            {
                var keeper = g.FirstOrDefault(a => a.CvssScore is not null) ?? g.First();
                if (g.Count() == 1)
                {
                    return keeper;
                }

                string[] aliases = g.SelectMany(a => a.Aliases ?? [])
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                return keeper with { Aliases = aliases };
            })
            .ToList();
    }

    // A live advisory is rarely linked to a stored row of its own, so KEV/EPSS is resolved across
    // its id and its aliases: the advisory is KEV when any matching stored row is, and its EPSS is
    // the highest known across them. A GHSA record for a CVE the threat feeds enriched under a
    // different row therefore still reports the CVE's exploitation signals. A row's KEV flag and
    // EPSS score are aggregates over every CVE the row names, so a sibling row is taken only when
    // each of its CVEs is one of the advisory's own (see RowSignalsBelongTo).
    private async Task<Dictionary<string, AdvisoryEnrichment>> ResolveKevEpssAsync(
        List<OsvAdvisory> advisories, CancellationToken ct)
    {
        var keysByAdvisory = advisories.ToDictionary(
            a => a.Id,
            a => new HashSet<string>(
                (a.Aliases ?? []).Append(a.Id).Where(k => !string.IsNullOrWhiteSpace(k)),
                StringComparer.OrdinalIgnoreCase),
            StringComparer.Ordinal);

        var rows = await _vulns.GetKevEpssRowsByIdsAndAliasesAsync(
            keysByAdvisory.Values.SelectMany(k => k).ToList(), ct);
        var rowAliases = rows.Select(r => (Row: r, Keys: RowKeys(r))).ToList();

        // The stored CISA catalogue and EPSS file cover CVEs no vulnerabilities row names (an
        // advisory this instance never scanned), so each is merged with the row-based answer.
        var cveKeys = keysByAdvisory.Values.SelectMany(k => k)
            .Where(k => k.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var catalogue = await _vulns.GetKevCatalogEntriesAsync(cveKeys, ct);
        var storedEpss = await _vulns.GetStoredEpssScoresAsync(cveKeys, ct);

        var result = new Dictionary<string, AdvisoryEnrichment>(StringComparer.Ordinal);
        foreach (var (advisoryId, keys) in keysByAdvisory)
        {
            var enrichment = new AdvisoryEnrichment(false, null, null);
            bool matched = false;
            foreach (var (row, rowKeys) in rowAliases)
            {
                if (!RowSignalsBelongTo(row, rowKeys, keys))
                {
                    continue;
                }

                matched = true;
                enrichment = enrichment.Merge(row.IsKev, row.EpssScore, row.EpssPercentile);
            }

            foreach (string key in keys)
            {
                string upper = key.ToUpperInvariant();
                if (catalogue.ContainsKey(upper))
                {
                    matched = true;
                    enrichment = enrichment.Merge(true, null, null);
                }

                if (storedEpss.TryGetValue(upper, out var score))
                {
                    matched = true;
                    enrichment = enrichment.Merge(false, score.Probability, score.Percentile);
                }
            }

            if (matched)
            {
                result[advisoryId] = enrichment;
            }
        }

        return result;
    }

    /// <summary>
    /// What the threat feeds say about one advisory across its id and aliases: KEV when any source
    /// is, and the highest EPSS probability and percentile any source holds. The two maxima are
    /// taken independently, as the gate's own aggregate query takes them.
    /// </summary>
    private sealed record AdvisoryEnrichment(bool IsKev, double? EpssScore, double? EpssPercentile)
    {
        public AdvisoryEnrichment Merge(bool isKev, double? epss, double? percentile) => new(
            IsKev || isKev,
            Max(EpssScore, epss),
            Max(EpssPercentile, percentile));

        private static double? Max(double? a, double? b) =>
            a is null ? b : b is null ? a : Math.Max(a.Value, b.Value);
    }

    /// <summary>
    /// Whether a stored row's KEV flag and EPSS score describe the advisory whose id and aliases
    /// are <paramref name="advisoryKeys"/>. A row stored under one of those ids is the advisory's
    /// own. Any other row that shares a key is a sibling, and its signals are an aggregate across
    /// every CVE it names: a distro record covering CVE-A (in KEV) and CVE-B is KEV, and carries
    /// CVE-A's score, because of CVE-A. Its signals are taken only when every CVE it names is one
    /// of the advisory's own, so a GHSA naming only CVE-B never inherits CVE-A's. The advisory's
    /// own CVEs are still answered individually from the stored catalogue and EPSS file.
    /// </summary>
    private static bool RowSignalsBelongTo(KevEpssRow row, HashSet<string> rowKeys, HashSet<string> advisoryKeys)
        => advisoryKeys.Contains(row.OsvId)
            || (rowKeys.Overlaps(advisoryKeys)
                && rowKeys.Where(k => k.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)).All(advisoryKeys.Contains));

    private static HashSet<string> RowKeys(KevEpssRow row)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { row.OsvId };
        if (!string.IsNullOrWhiteSpace(row.Aliases))
        {
            try
            {
                var aliases = System.Text.Json.JsonSerializer.Deserialize<List<string>>(row.Aliases);
                if (aliases is not null)
                {
                    keys.UnionWith(aliases.Where(a => !string.IsNullOrWhiteSpace(a)));
                }
            }
            catch (System.Text.Json.JsonException)
            {
                // Malformed alias JSON on a legacy row: it still matches on its own osv_id.
            }
        }

        return keys;
    }

    /// <summary>
    /// Whether the serve path of <paramref name="ecosystem"/> refuses a version on its advisories
    /// (the malicious, KEV, EPSS, SSVC and score arms). The OCI pull path refuses on them only when
    /// the org's <c>oci_scan_enforcement</c> is <c>block</c>; under <c>off</c> or <c>warn</c> an
    /// image with advisories still pulls, so an OCI lookup must not answer <c>blocked</c> for it:
    /// its advisories read as <c>warn</c> instead. Under <c>block</c> the OCI verdict is the pull
    /// gate's own (<see cref="LookupGateContext.OciPullVerdict"/>), which also refuses an image
    /// with no complete scan.
    /// </summary>
    private static bool VulnerabilityArmsEnforced(string ecosystem, OrgSettings settings)
        => ecosystem != "oci" || settings.OciScanEnforcement == "block";

    /// <summary>
    /// When the lookup is evaluated, whether its advisory arms can refuse, and, for an OCI image
    /// under <c>oci_scan_enforcement=block</c>, the verdict the pull gate would reach for it.
    /// </summary>
    private readonly record struct LookupGateContext(
        DateTimeOffset Now, bool AdvisoryArmsEnforced, BlockVerdict? OciPullVerdict = null);

    private static (string Overall, string? BlockedReason) DetermineOverall(
        VersionMetadataFacts facts, OrgSettings settings, AdvisoryAnalysis analysis,
        bool advisoriesAvailable, LicensePolicyVerdict licenseVerdict, LookupGateContext gate,
        AdvisorySourceInfo advisorySource)
    {
        var now = gate.Now;
        // vuln-facts-ok: this read-only "check before you add it" lookup never goes through
        // BlockGateService's own request/index paths — it evaluates a candidate the org has not
        // fetched yet, so there is no BlockGateRequest-shaped call site to route through.
        var gateFacts = new VersionFacts(
            ManualState: null,
            Deprecated: facts.Deprecated,
            PublishedAt: facts.PublishedAt,
            Scanned: advisoriesAvailable,
            // This lookup path never goes through VulnGateSignals — it reduces its own ad hoc
            // OSV query into AdvisoryAnalysis — so only the four signals it actually computes are
            // set; every other VulnFacts member stays at its unknown default.
            Vulnerability: VulnFacts.None with
            {
                IsMalicious = analysis.HasMalicious,
                IsKev = analysis.HasKev,
                Epss = analysis.MaxEpss,
                EpssPercentile = analysis.MaxEpssPercentile,
                Cvss = analysis.MaxCvss,
            },
            Origin: "proxy",
            HasInstallScript: false,
            ProvenanceStatus: null,
            InstallScriptAllowlisted: false,
            RevokedAt: null);

        var gatePolicy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: null,
            VerifyProvenanceMode: null,
            BlockRevokedMode: null,
            MaxEpssPercentileTolerance: settings.MaxEpssPercentileTolerance);

        // With the advisory arms unenforced they are evaluated as "not scanned", which every one of
        // them passes; what they would have refused is reported as a warning instead.
        // An OCI image under block is answered by the pull gate's own evaluation of the org's scan
        // facts, so the lookup and the pull cannot disagree about whether the image is refused.
        var enforcedFacts = gate.AdvisoryArmsEnforced ? gateFacts : gateFacts with { Scanned = false };
        var verdict = gate.OciPullVerdict ?? BlockGateService.Evaluate(enforcedFacts, gatePolicy, now);
        if (!verdict.Servable)
        {
            return ("blocked", new BlockOutcome(BlockDecision.Blocked, verdict.Arm).ReasonToken);
        }

        bool unenforcedRefusal = !gate.AdvisoryArmsEnforced
            && !BlockGateService.Evaluate(gateFacts, gatePolicy, now).Servable;
        bool warn = unenforcedRefusal
            || gate.OciPullVerdict is { WarnArm: not BlockArm.None }
            || advisorySource.Status == AdvisorySourceInfo.UnavailableStatus
            || (analysis.HasMalicious && settings.BlockMalicious == "warn")
            || (analysis.HasKev && settings.BlockKev == "warn")
            || (facts.Deprecated is not null && settings.BlockDeprecated == "warn")
            // A conditional licence warns rather than passing silently: the org recorded a
            // condition on it, and a pre-adoption check that reads "allowed" would tell a
            // developer the licence is fine when the org's own note says otherwise.
            || (settings.LicenseEnforcementMode != "off"
                && (!licenseVerdict.Allowed || licenseVerdict.IsConditional));
        return (warn ? "warn" : "allowed", null);
    }

    private static PackageLookupResult BuildResult(LookupResultContext c) => new(
        Purl: c.Purl,
        Ecosystem: c.Ecosystem,
        Name: c.Name,
        Version: c.Version,
        VersionInferred: c.VersionInferred,
        Verdict: c.Overall,
        BlockedReason: c.BlockedReason,
        Malware: new MalwareLookupCheck(c.Analysis.HasMalicious, c.Analysis.MalwareIds),
        Vulnerabilities: new VulnerabilityLookupCheck(
            Scored: c.Analysis.Scored.Select(a => new ScoredAdvisory(
                a.Id, a.CvssScore!.Value, a.Severity, c.Analysis.KevEpss.TryGetValue(a.Id, out var se) && se.IsKev,
                c.Analysis.KevEpss.TryGetValue(a.Id, out var se2) ? se2.EpssScore : null, a.Summary,
                AdvisoryAliases(a), AdvisoryFixedVersion(a, c.Ecosystem, c.Name, c.Version, c.AdvisorySource.Distro))).ToList(),
            Unscored: c.Analysis.Unscored.Select(a => new UnscoredAdvisory(
                a.Id, a.Summary, AdvisoryAliases(a), AdvisoryFixedVersion(a, c.Ecosystem, c.Name, c.Version, c.AdvisorySource.Distro))).ToList(),
            MaxCvss: c.Analysis.MaxCvss,
            HasKev: c.Analysis.HasKev,
            MaxEpss: c.Analysis.MaxEpss,
            Available: c.AdvisoriesAvailable),
        License: new LicenseLookupCheck(
            Spdx: c.Facts.Spdx,
            Mode: c.Settings.LicenseEnforcementMode,
            Allowed: c.Settings.LicenseEnforcementMode == "off" ? null : c.LicenseVerdict.Allowed,
            BlockedLicense: c.LicenseVerdict.BlockedLicense,
            Available: c.Facts.Spdx.Count > 0,
            ConditionalLicenses: c.Settings.LicenseEnforcementMode == "off"
                ? []
                : c.LicenseVerdict.ConditionalLicenses),
        AirGapped: c.AirGapped,
        Reserved: c.Reserved,
        UnavailableChecks: c.Unavailable,
        AdvisorySource: c.AdvisorySource);

    private static string BuildPurl(string ecosystem, string name, string version) => ecosystem switch
    {
        "npm" => PurlNormalizer.Npm(name, version),
        "pypi" => PurlNormalizer.PyPi(name, version),
        "nuget" => PurlNormalizer.NuGet(name, version),
        "maven" => BuildMavenPurl(name, version),
        "golang" => PurlNormalizer.Golang(name, version),
        "cargo" => PurlNormalizer.Cargo(name, version),
        "hex" => PurlNormalizer.Hex(name, version),
        "oci" => PurlNormalizer.Oci(name, version),
        "terraform" => PurlNormalizer.TerraformAddress(name, version),
        _ => throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "unsupported ecosystem"),
    };

    private static string BuildMavenPurl(string coordinate, string version)
    {
        int sep = coordinate.IndexOf(':');
        return PurlNormalizer.Maven(coordinate[..sep], coordinate[(sep + 1)..], version);
    }

    // Field-shape validation. Every accepted name is composed into an authenticated upstream
    // registry URL, so each path segment goes through PathSafeValidator.ValidateUpstreamSegment
    // (the base rules plus a '%' ban) — not the '%'-permissive Validate. The '%' ban matters
    // because the query value is decoded once by ASP.NET, so a double-encoded '%252e%252e%252f'
    // arrives as the literal string '%2e%2e%2f', clears the '..'/'/' rules, and would otherwise
    // be decoded to '../' by the upstream. npm and Maven layer their own shape checks on top
    // since both legitimately contain a segment separator ValidateUpstreamSegment rejects.
    private static (string Field, string Code)? ValidateName(string ecosystem, string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return ("name", "name.required");
        }

        if (ecosystem == "npm")
        {
            return Dependably.Api.NpmProtocol.NpmSharedHelpers.IsUpstreamSafeNpmName(name)
                ? null
                : ("name", "name.invalid");
        }

        if (ecosystem == "maven")
        {
            return ValidateMavenCoordinate(name);
        }

        if (ecosystem is "golang" or "oci" or "terraform")
        {
            // Go module paths, OCI repositories ("library/nginx") and Terraform addresses
            // ("hashicorp/aws") are path-shaped (e.g. "example.com/mod",
            // "github.com/foo/bar") — validate each '/'-separated segment individually rather
            // than the whole string, since ValidateUpstreamSegment itself rejects any separator.
            string[] segments = name.Split('/');
            bool allSegmentsSafe = Array.TrueForAll(
                segments, s => PathSafeValidator.ValidateUpstreamSegment(s, "name").IsValid);
            return allSegmentsSafe ? null : ("name", "name.invalid");
        }

        var vr = PathSafeValidator.ValidateUpstreamSegment(name, "name");
        return vr.IsValid ? null : ("name", "name.invalid");
    }

    // groupId:artifactId shape plus per-upstream-path-segment safety. The groupId becomes a URL
    // path via Replace('.', '/') in FetchMavenAsync, so every '.'-separated groupId sub-segment
    // is a distinct segment of the composed authenticated upstream URL and must clear the same
    // ValidateUpstreamSegment gate (its '%' ban stops double-encoded traversal). The artifactId
    // is validated unsplit — artifactIds legitimately contain dots (e.g.
    // "org.apache.felix.framework") and form a single upstream path segment.
    private static (string Field, string Code)? ValidateMavenCoordinate(string name)
    {
        int sep = name.IndexOf(':');
        if (sep <= 0 || sep == name.Length - 1)
        {
            return ("name", "maven.coordinateInvalid");
        }

        bool groupSafe = Array.TrueForAll(
            name[..sep].Split('.'),
            s => PathSafeValidator.ValidateUpstreamSegment(s, "name").IsValid);
        bool artifactSafe = PathSafeValidator.ValidateUpstreamSegment(name[(sep + 1)..], "name").IsValid;
        return groupSafe && artifactSafe ? null : ("name", "maven.coordinateInvalid");
    }

    // A thrown failure is transient/unreachable — not a definitive "this package/version does
    // not exist" answer. Mirrors UpstreamClient.IsTransientMetadataFailure's exception set plus
    // SsrfBlockedException (an operator-misconfigured upstream URL is not a "not found" either)
    // and AirGappedException (defence in depth — ComputeAsync already gates metadata calls on
    // AirGapped/IAirGapMode before reaching here).
    private static bool IsTransientUpstreamFailure(Exception ex) => ex switch
    {
        SsrfBlockedException => true,
        AirGappedException => true,
        UpstreamResponseTooLargeException => true,
        HttpRequestException => true,
        IOException => true,
        _ => false,
    };

    // Resolves "latest" via IUpstreamLatestVersionResolver and classifies the result. NoAnswer
    // set means the resolver produced no upstream answer and the caller returns it as-is:
    // Reserved when the name is reserved for the org and upstream was not consulted (a
    // reservation added after FetchFactsAsync's own check lands here), Unavailable when it hit a
    // network/timeout failure — never a false answer either way. NoAnswer null + Version null
    // means the resolver reached the upstream and found no latest (package unknown or genuinely
    // no stable release).
    private async Task<(string? Version, FactsOutcome? NoAnswer)> TryResolveLatestAsync(
        string ecosystem, string orgId, string name, CancellationToken ct)
    {
        try
        {
            var latest = await _latestResolver.ResolveAsync(ecosystem, orgId, name, ct);
            return latest.IsReserved ? (null, FactsOutcome.Reserved) : (latest.Version, null);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex))
        {
            return (null, FactsOutcome.Unavailable);
        }
    }

    // ── Per-ecosystem metadata fetch ────────────────────────────────────────────

    // A name the org has reserved never consults upstream: an explicit version still gets its
    // advisory and licence verdict, with the metadata-derived checks reported unavailable and the
    // result marked reserved, and an omitted version is the Reserved outcome. Decided once here,
    // before any per-ecosystem fetch,
    // so the secondary fetches (the NuGet nuspec licence read, the crates.io API leg, the
    // latest-version resolve) are never reached for a reserved name either.
    private async Task<FactsOutcome> FetchFactsAsync(
        string ecosystem, string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        return await _reservedNamespaces.IsUpstreamNameReservedAsync(orgId, ecosystem, name, ct)
            ? FactsOutcome.Reserved
            : ecosystem switch
            {
                "npm" => await FetchNpmAsync(orgId, name, requestedVersion, ct),
                "pypi" => await FetchPyPiAsync(orgId, name, requestedVersion, ct),
                "nuget" => await FetchNuGetAsync(orgId, name, requestedVersion, ct),
                "maven" => await FetchMavenAsync(orgId, name, requestedVersion, ct),
                "cargo" => await FetchCargoAsync(orgId, name, requestedVersion, ct),
                "golang" => await FetchGoAsync(orgId, name, requestedVersion, ct),
                "hex" => await FetchHexAsync(orgId, name, requestedVersion, ct),
                _ => throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "no metadata fetch wired"),
            };
    }


    // ── Internal per-fetch shapes ────────────────────────────────────────────────

    // NotConfigured: the org has no upstream for the ecosystem. Reserved: the org reserved the
    // name, so no upstream is consulted for it.
    private enum MetadataFetchStatus { Ok, NotFound, Unavailable, NotConfigured, Reserved }

    private sealed record FactsOutcome(MetadataFetchStatus Status, string? Version, VersionMetadataFacts? Facts)
    {
        public static FactsOutcome Ok(string version, VersionMetadataFacts facts) => new(MetadataFetchStatus.Ok, version, facts);
        public static readonly FactsOutcome NotFound = new(MetadataFetchStatus.NotFound, null, null);
        public static readonly FactsOutcome Unavailable = new(MetadataFetchStatus.Unavailable, null, null);
        public static readonly FactsOutcome NotConfigured = new(MetadataFetchStatus.NotConfigured, null, null);
        public static readonly FactsOutcome Reserved = new(MetadataFetchStatus.Reserved, null, null);
    }

    // DeprecationResolved distinguishes "this source answered 'not deprecated'" from "this source
    // has no deprecation signal to answer with" — both leave Deprecated null, but only the second
    // belongs in UnavailableChecks. Defaulted so the existing constructions that genuinely
    // resolved a deprecation state need no change at their call sites.
    private sealed record VersionMetadataFacts(
        DateTimeOffset? PublishedAt, string? Deprecated, IReadOnlyList<string> Spdx,
        bool DeprecationResolved = true)
    {
        public static readonly VersionMetadataFacts Unavailable =
            new(null, null, Array.Empty<string>(), DeprecationResolved: false);
    }

    // Outcome of a single per-source fetch attempt within a Fetch<Eco>Async loop: Result set
    // means the loop is done (return it to the caller); Result null + DefinitiveMiss means
    // this source answered "not found" but the next source in priority order still gets a
    // chance; Result null + !DefinitiveMiss (Continue) means this source was unreachable,
    // unhealthy, or unparsable and carries no signal either way.
    private sealed record SourceAttempt(FactsOutcome? Result, bool DefinitiveMiss)
    {
        public static readonly SourceAttempt Continue = new(null, false);
        public static readonly SourceAttempt Miss = new(null, true);
        public static SourceAttempt Done(FactsOutcome result) => new(result, false);
    }

    // Outcome of resolving the candidate's effective version: EarlyExit set means ComputeAsync
    // returns it immediately; otherwise Version/Facts are populated and UnavailableAdditions
    // lists which BlockGateService-facing checks this resolution couldn't derive.
    private sealed record VersionResolution(
        PackageLookupOutcome? EarlyExit, string? Version, bool VersionInferred,
        VersionMetadataFacts? Facts, IReadOnlyList<string> UnavailableAdditions, bool Reserved)
    {
        public static VersionResolution Exit(PackageLookupOutcome outcome) =>
            new(outcome, null, false, null, Array.Empty<string>(), false);

        public static VersionResolution Resolved(
            string version, bool versionInferred, VersionMetadataFacts facts,
            IReadOnlyList<string> unavailableAdditions, bool reserved = false) =>
            new(null, version, versionInferred, facts, unavailableAdditions, reserved);
    }

    private sealed record AdvisoryQueryResult(List<OsvAdvisory> Advisories, bool Available, AdvisorySourceInfo Source)
    {
        public static AdvisoryQueryResult Unavailable(AdvisorySourceInfo source) =>
            new(new List<OsvAdvisory>(), false, source);
    }

    private sealed record AdvisoryAnalysis(
        List<string> MalwareIds, List<OsvAdvisory> Scored, List<OsvAdvisory> Unscored,
        IReadOnlyDictionary<string, AdvisoryEnrichment> KevEpss,
        bool HasKev, double? MaxEpss, double? MaxEpssPercentile, double? MaxCvss, bool HasMalicious);

    // Bundles the fields BuildResult needs past the S107 constructor-injection threshold —
    // this is plain data assembly, not independently-registered collaborators, so a bundle
    // record is the cleaner fit than a pragma.
    private sealed record LookupResultContext(
        string Purl, string Ecosystem, string Name, string Version, bool VersionInferred,
        string Overall, string? BlockedReason, VersionMetadataFacts Facts, OrgSettings Settings,
        AdvisoryAnalysis Analysis, bool AdvisoriesAvailable, LicensePolicyVerdict LicenseVerdict,
        bool AirGapped, bool Reserved, IReadOnlyList<string> Unavailable, AdvisorySourceInfo AdvisorySource);
}

// ── Public request/response contract ────────────────────────────────────────────

/// <param name="Distro">The release an apk or rpm lookup is scoped to (<c>v3.20</c>, <c>Rocky Linux:9</c>);
/// ignored for every other ecosystem.</param>
public sealed record PackageLookupRequest(
    string OrgId, string? Ecosystem, string? Name, string? Version, string? Distro = null);

/// <summary>
/// How a lookup ended. <see cref="Reserved"/> and <see cref="UpstreamNotConfigured"/> are the two
/// version-less lookups that cannot resolve a latest version because of a standing operator
/// choice (the org reserved the name; the org has no upstream for the ecosystem). They are
/// distinct from <see cref="UpstreamUnavailable"/>, which is only ever an attempted fetch that
/// failed and so is the one outcome worth retrying.
/// </summary>
public enum PackageLookupStatus
{
    Ok,
    UnsupportedEcosystem,
    InvalidInput,
    VersionRequired,
    UpstreamNotFound,
    UpstreamUnavailable,
    Reserved,
    UpstreamNotConfigured,

    /// <summary>A version-less lookup in an org with proxy passthrough off: its upstreams are
    /// not consulted, so there is no latest version to resolve. A standing operator choice like
    /// <see cref="UpstreamNotConfigured"/>, not an outage.</summary>
    PassthroughOff,
}

/// <summary>
/// Outcome of a lookup: a computed <see cref="Result"/> (Status == Ok), a definitive
/// <see cref="NotFound"/> answer the controller returns as a 200 verdict-shaped body, or a reason
/// the controller maps to the matching RFC 7807 problem (422 for input problems and for a
/// version-less lookup that needs a version because of the org's configuration, 503 for an
/// upstream that was tried and could not be reached).
/// </summary>
public sealed record PackageLookupOutcome(
    PackageLookupStatus Status,
    PackageLookupResult? Result = null,
    string? Field = null,
    string? Reason = null,
    PackageLookupNotFound? NotFound = null)
{
    public static PackageLookupOutcome Ok(PackageLookupResult result) => new(PackageLookupStatus.Ok, result);
    public static PackageLookupOutcome UnsupportedEcosystem(string ecosystem) =>
        new(PackageLookupStatus.UnsupportedEcosystem, Reason: ecosystem);
    public static PackageLookupOutcome InvalidInput(string field, string code) =>
        new(PackageLookupStatus.InvalidInput, Field: field, Reason: code);
    public static PackageLookupOutcome VersionRequired(string ecosystem) =>
        new(PackageLookupStatus.VersionRequired, Reason: ecosystem);
    public static PackageLookupOutcome UpstreamNotFound(PackageLookupNotFound notFound) =>
        new(PackageLookupStatus.UpstreamNotFound, NotFound: notFound);
    public static PackageLookupOutcome UpstreamUnavailable(string ecosystem) =>
        new(PackageLookupStatus.UpstreamUnavailable, Reason: ecosystem);
    public static PackageLookupOutcome Reserved(string ecosystem) =>
        new(PackageLookupStatus.Reserved, Reason: ecosystem);
    public static PackageLookupOutcome UpstreamNotConfigured(string ecosystem) =>
        new(PackageLookupStatus.UpstreamNotConfigured, Reason: ecosystem);
    public static PackageLookupOutcome PassthroughOff(string ecosystem) =>
        new(PackageLookupStatus.PassthroughOff, Reason: ecosystem);
}

/// <summary>
/// The body served (200) when the upstream definitively has no such package or version. A lookup
/// is a query about a candidate, so "no such package" is an answer to it, not a failure of the
/// request — a mistyped name is the single most common way to reach this and does not warrant an
/// error status. <see cref="Found"/> is the discriminator against <see cref="PackageLookupResult"/>,
/// which carries the same flag set to true.
/// </summary>
public sealed record PackageLookupNotFound(string Ecosystem, string Name, string? Version)
{
    // Deliberately an instance property, not static: System.Text.Json only serializes instance
    // members, and LookupController's Ok(outcome.NotFound) response depends on "found" appearing
    // in the JSON body as the client-facing discriminator against PackageLookupResult. Marking it
    // static would silently drop the field from the wire response instead of failing to compile.
    [SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static",
        Justification = "Instance property is required for System.Text.Json to serialize it into the JSON response; a static member would silently vanish from the wire contract.")]
    [SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "Instance property is required for System.Text.Json to serialize it into the JSON response; a static member would silently vanish from the wire contract.")]
    public bool Found => false;
}

public sealed record PackageLookupResult(
    string Purl,
    string Ecosystem,
    string Name,
    string Version,
    bool VersionInferred,
    /// <summary>"allowed" | "warn" | "blocked" — "blocked" only ever comes from
    /// <see cref="BlockGateService.Evaluate"/>, the same core the proxy serve path uses.</summary>
    string Verdict,
    /// <summary>The firing arm's wire token (<see cref="BlockOutcome.ReasonToken"/>, e.g. "release_age") when <see cref="Verdict"/> is "blocked".</summary>
    string? BlockedReason,
    MalwareLookupCheck Malware,
    VulnerabilityLookupCheck Vulnerabilities,
    LicenseLookupCheck License,
    bool AirGapped,
    /// <summary>True when the org has reserved this name in its ecosystem, so upstream was not
    /// consulted: the verdict rests on the advisory and licence checks alone, and the
    /// upstream-derived checks are listed in <see cref="UnavailableChecks"/>.</summary>
    bool Reserved,
    IReadOnlyList<string> UnavailableChecks,
    /// <summary>Where the advisory answer came from, or why there is none. Present for every
    /// ecosystem: <c>status</c> "checked" with an empty advisory list is the explicit "consulted,
    /// nothing found".</summary>
    AdvisorySourceInfo AdvisorySource)
{
    /// <summary>Discriminates this shape from <see cref="PackageLookupNotFound"/> — both are
    /// served as 200, so the client branches on this flag rather than on the status code.</summary>
    [SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static",
        Justification = "Instance property is required for System.Text.Json to serialize it into the JSON response; a static member would silently vanish from the wire contract.")]
    [SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "Instance property is required for System.Text.Json to serialize it into the JSON response; a static member would silently vanish from the wire contract.")]
    public bool Found => true;
}

public sealed record MalwareLookupCheck(bool Detected, IReadOnlyList<string> AdvisoryIds);

/// <summary>
/// One CVSS-scored advisory. <see cref="Aliases"/> are the other ids the same flaw is published
/// under (never the advisory's own id); <see cref="FixedVersion"/> is the fix for the affected
/// range containing the queried version, null when no fix is published or it cannot be resolved.
/// </summary>
public sealed record ScoredAdvisory(
    string Id, double CvssScore, string? Severity, bool IsKev, double? Epss, string? Summary,
    IReadOnlyList<string> Aliases, string? FixedVersion);

/// <summary>An advisory with no CVSS score; <see cref="Aliases"/> and <see cref="FixedVersion"/> read as on <see cref="ScoredAdvisory"/>.</summary>
public sealed record UnscoredAdvisory(
    string Id, string? Summary, IReadOnlyList<string> Aliases, string? FixedVersion);

public sealed record VulnerabilityLookupCheck(
    IReadOnlyList<ScoredAdvisory> Scored,
    IReadOnlyList<UnscoredAdvisory> Unscored,
    double? MaxCvss,
    bool HasKev,
    double? MaxEpss,
    /// <summary>False when the OSV query itself failed — Scored/Unscored are then empty but
    /// that must not be read as "no known advisories".</summary>
    bool Available);

public sealed record LicenseLookupCheck(
    IReadOnlyList<string> Spdx,
    /// <summary>The org's LicenseEnforcementMode: 'off' | 'warn' | 'block'.</summary>
    string Mode,
    /// <summary>Null when Mode is 'off' (no verdict) or no SPDX identifiers were derivable.</summary>
    bool? Allowed,
    string? BlockedLicense,
    /// <summary>False when no SPDX identifiers could be derived from upstream metadata at
    /// lookup time (Allowed/BlockedLicense are then not meaningful, only informational).</summary>
    bool Available,
    /// <summary>Licences the candidate relies on that this org marked conditional. Non-empty
    /// means the package is usable but carries a condition the org wrote down — distinct from
    /// both a clean pass and a refusal. Empty when Mode is 'off'.</summary>
    IReadOnlyList<string> ConditionalLicenses);

// ── Bounded in-memory TTL cache ───────────────────────────────────────────────────

/// <summary>
/// Bounded in-memory TTL cache for repeated lookups of the same (org, purl) coordinate, following
/// the project's external-API-hydration house pattern: single-flight dedup per key (a burst of
/// identical concurrent lookups triggers exactly one upstream/OSV round trip), a small positive
/// TTL so a user re-checking the same candidate doesn't re-hit OSV/upstream on every keystroke,
/// and a bounded entry count with expiry-ordered eviction so an enumeration attack (many distinct
/// candidate names) cannot grow the map without bound. Singleton-scoped — shared across requests.
///
/// <see cref="InvalidateOrg"/> expires every outcome cached for one org without enumerating its
/// keys: each entry records the global invalidation sequence when its computation started, and
/// a read ignores an entry that started before its org's last invalidation. An outcome computed across an
/// invalidation is therefore stored already dead, so it cannot outlive the change it raced.
/// </summary>
public sealed class PackageLookupCache
{
    private const int MaxEntries = 2048;
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(2);
    private const int StripeCount = 32;

    private readonly ConcurrentDictionary<string, CachedEntry> _entries = new();

    // Invalidation bookkeeping. Every entry records the value of the global sequence when its
    // computation started; InvalidateOrg advances the sequence and records the new value as the
    // org's invalidation point, and an entry is live only if it started at or after both its
    // org's point and the floor. The per-org map is capped: past MaxInvalidatedOrgs the floor
    // is raised to the current sequence and then the map cleared (in that order: a lock-free
    // reader checks the map before the floor, so one that sees the cleared map must already
    // see the raised floor), which expires every outcome started
    // before then for every org. That costs one recomputation per cached lookup, once per
    // MaxInvalidatedOrgs distinct invalidated orgs, and keeps org ids arriving from peer
    // replicas from growing the map for the life of the process.
    private const int MaxInvalidatedOrgs = 4096;
    private readonly ConcurrentDictionary<string, long> _orgInvalidatedAt = new(StringComparer.Ordinal);
    private readonly Lock _invalidationLock = new();
    private long _sequence;
    private long _floor;
    private readonly SemaphoreSlim[] _stripes =
        Enumerable.Range(0, StripeCount).Select(_ => new SemaphoreSlim(1, 1)).ToArray();
    private readonly TimeProvider _time;

    public PackageLookupCache(TimeProvider time) => _time = time;

    public static string KeyFor(string orgId, string ecosystem, string name, string? version, string? scope = null) =>
        string.Join('\n', orgId, ecosystem, name, version ?? "", scope ?? "");

    public PackageLookupOutcome? TryGet(string key) =>
        _entries.TryGetValue(key, out var entry) && IsLive(key, entry, _time.GetUtcNow())
            ? entry.Outcome
            : null;

    /// <summary>
    /// Expires every outcome cached for <paramref name="orgId"/>, including one whose computation
    /// is in flight when this runs. Called when an input every lookup for the org reads (its
    /// reserved namespaces, its proxy settings) changes, on this replica or on a peer.
    /// </summary>
    public void InvalidateOrg(string orgId)
    {
        // Serialized with the cap's clear-and-raise-floor, so an invalidation point is never
        // recorded into a map that is then cleared below a floor it exceeds.
        lock (_invalidationLock)
        {
            long point = Interlocked.Increment(ref _sequence);
            _orgInvalidatedAt[orgId] = point;
            if (_orgInvalidatedAt.Count > MaxInvalidatedOrgs)
            {
                Volatile.Write(ref _floor, point);
                _orgInvalidatedAt.Clear();
            }
        }
    }

    // Test seam (InternalsVisibleTo Dependably.Tests): how many orgs hold an invalidation point.
    internal int InvalidatedOrgCount => _orgInvalidatedAt.Count;

    // The sequence value a computation starting now records on its entry.
    private long CurrentGeneration() => Volatile.Read(ref _sequence);

    // Reads take no lock. The writer raises the floor before it clears the map, so the map is
    // read first (left operand): a reader that finds the org's point already cleared then reads the floor that
    // replaced it.
    private bool StartedAfterLastInvalidation(string key, long started) =>
        (!_orgInvalidatedAt.TryGetValue(OrgOf(key), out long point) || started >= point)
        && started >= Volatile.Read(ref _floor);

    // KeyFor puts the org id first, before the first separator.
    private static string OrgOf(string key)
    {
        int separator = key.IndexOf('\n');
        return separator < 0 ? key : key[..separator];
    }

    private bool IsLive(string key, CachedEntry entry, DateTimeOffset now) =>
        now - entry.StoredAt < Ttl && StartedAfterLastInvalidation(key, entry.Generation);

    /// <summary>
    /// Runs <paramref name="compute"/> under a per-key stripe lock so concurrent identical
    /// lookups collapse into one upstream round trip, then caches the result (a computed
    /// verdict, a definitive not-found/unsupported outcome, and a reserved name, whose entry
    /// <see cref="InvalidateOrg"/> expires when the org's reservations change). A
    /// transient-unavailable outcome is not cached so the next call retries upstream, and
    /// neither is a no-upstream-configured outcome, because nothing invalidates the cache when
    /// an operator adds an upstream and the answer should change as soon as they do.
    /// </summary>
    public async Task<PackageLookupOutcome> SingleFlightAsync(
        string key, Func<Task<PackageLookupOutcome>> compute, CancellationToken ct)
    {
        var stripe = _stripes[(uint)key.GetHashCode() % StripeCount];
        await stripe.WaitAsync(ct);
        try
        {
            var cached = TryGet(key);
            if (cached is not null)
            {
                return cached;
            }

            // Captured before the computation reads anything, so an InvalidateOrg that lands
            // while it runs leaves the stored entry already expired.
            long generation = CurrentGeneration();
            var outcome = await compute();
            if (outcome.Status is not (PackageLookupStatus.UpstreamUnavailable
                or PackageLookupStatus.UpstreamNotConfigured))
            {
                Store(key, outcome, generation);
            }

            return outcome;
        }
        finally
        {
            stripe.Release();
        }
    }

    private void Store(string key, PackageLookupOutcome outcome, long generation)
    {
        if (_entries.Count >= MaxEntries)
        {
            Prune();
        }

        _entries[key] = new CachedEntry(outcome, _time.GetUtcNow(), generation);
    }

    private void Prune()
    {
        var now = _time.GetUtcNow();
        foreach (var kv in _entries)
        {
            if (!IsLive(kv.Key, kv.Value, now))
            {
                _entries.TryRemove(kv.Key, out _);
            }
        }

        int overBy = _entries.Count - MaxEntries + 1;
        if (overBy > 0)
        {
            foreach (var kv in _entries.OrderBy(e => e.Value.StoredAt).Take(overBy))
            {
                _entries.TryRemove(kv.Key, out _);
            }
        }
    }

    private sealed record CachedEntry(PackageLookupOutcome Outcome, DateTimeOffset StoredAt, long Generation);
}
