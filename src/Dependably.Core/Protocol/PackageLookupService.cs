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
/// version. A candidate's install-script and provenance facts are never derivable at lookup time
/// (no artifact is fetched), so those <see cref="BlockGateService"/> arms are always neutral —
/// callers should not read <see cref="PackageLookupResult.Verdict"/> as a guarantee those
/// checks ran. <see cref="PackageLookupResult.UnavailableChecks"/> reports only checks that
/// would normally run at lookup time but could not for this lookup, not the two
/// structurally-out-of-scope artifact arms.
/// </summary>
public sealed partial class PackageLookupService
{
    /// <summary>Ecosystems this endpoint accepts — the OSV-covered set named by the feature.</summary>
    public static readonly IReadOnlyList<string> SupportedEcosystems =
        ["npm", "pypi", "nuget", "maven", "golang", "cargo"];

    // Ecosystems with a wired upstream metadata fetch (deprecation/publish-date/license and
    // "no version given -> evaluate latest stable"). Which facts each one yields varies — see the
    // per-ecosystem summary on the class — but every member can resolve a latest version, so an
    // omitted version is a hard failure only when no fetch is permitted at all (air-gap).
    private static readonly HashSet<string> MetadataSupportedEcosystems =
        ["npm", "pypi", "nuget", "maven", "cargo", "golang"];

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
        PackageLookupCache cache)
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

        string cacheKey = PackageLookupCache.KeyFor(request.OrgId, ecosystem, name, requestedVersion);
        var cached = _cache.TryGet(cacheKey);
        if (cached is not null)
        {
            return cached;
        }

        var outcome = await _cache.SingleFlightAsync(cacheKey,
            () => ComputeAsync(request.OrgId, ecosystem, name, requestedVersion, ct), ct);
        return outcome;
    }

    private async Task<PackageLookupOutcome> ComputeAsync(
        string orgId, string ecosystem, string name, string? requestedVersion, CancellationToken ct)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct) ?? new OrgSettings { OrgId = orgId };
        bool metadataAllowed = !settings.AirGapped && !_airGap.IsEnabled && MetadataSupportedEcosystems.Contains(ecosystem);

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
        string purl = BuildPurl(ecosystem, name, version);

        var advisoryQuery = await QueryAdvisoriesAsync(purl, ct);
        if (!advisoryQuery.Available)
        {
            unavailable.Add("vulnerabilities");
        }

        var analysis = await AnalyzeAdvisoriesAsync(advisoryQuery.Advisories, advisoryQuery.Available, ct);

        var (licenseAllowed, blockedLicense) = await _licenses.CheckPolicyAsync(
            orgId, settings.LicenseEnforcementMode, facts.Spdx, ct);

        var (overall, blockedReason) = DetermineOverall(
            facts, settings, analysis, advisoryQuery.Available, licenseAllowed, _time.GetUtcNow());

        var result = BuildResult(new LookupResultContext(
            purl, ecosystem, name, version, resolution.VersionInferred,
            overall, blockedReason, facts, settings, analysis, advisoryQuery.Available,
            licenseAllowed, blockedLicense, settings.AirGapped || _airGap.IsEnabled, unavailable));

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
            : null;

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

    // No wired metadata source (golang/cargo), air-gapped (org- or instance-level, no
    // outbound registry call), or a reachable-but-unavailable/unconfigured upstream. A
    // version must be explicit in every one of these cases — there is no upstream to
    // resolve "latest" against, so an omitted version is a hard failure: VersionRequired
    // when there was never a metadata source to try, UpstreamUnavailable when a fetch
    // attempt genuinely failed. An EXPLICIT version degrades gracefully instead — the
    // lookup still returns an OSV + license verdict with the metadata-dependent checks
    // marked unavailable, matching the mixed-partial-failure house testing rule.
    private static VersionResolution ResolveWithoutMetadata(
        FactsOutcome? fetchOutcome, string? requestedVersion, string ecosystem)
    {
        if (requestedVersion is null)
        {
            var exit = fetchOutcome is null
                ? PackageLookupOutcome.VersionRequired(ecosystem)
                : PackageLookupOutcome.UpstreamUnavailable(ecosystem);
            return VersionResolution.Exit(exit);
        }

        return VersionResolution.Resolved(
            requestedVersion, false, VersionMetadataFacts.Unavailable,
            new List<string> { "release_age", "deprecated", "license" });
    }

    // TryQueryAsync (not QueryAsync) because QueryAsync's contract is swallow-and-return-
    // empty on failure — indistinguishable from a genuine "no known advisories" answer. A
    // lookup verdict of "allowed" must mean OSV was actually consulted, so an unreached
    // source (network outage, 5xx, non-2xx) has to surface as unavailable here even though
    // it never throws.
    private async Task<AdvisoryQueryResult> QueryAdvisoriesAsync(string purl, CancellationToken ct)
    {
        try
        {
            var osvResult = await _osv.TryQueryAsync(purl, ct);
            return new AdvisoryQueryResult(osvResult.Advisories, osvResult.Reached);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            return new AdvisoryQueryResult(new List<OsvAdvisory>(), false);
        }
    }

    // Splits raw advisories into malware/scored/unscored, hydrates KEV/EPSS enrichment for
    // the ones OSV actually returned, and reduces that into the summary facts the block gate
    // and the response DTO both need.
    private async Task<AdvisoryAnalysis> AnalyzeAdvisoriesAsync(
        List<OsvAdvisory> advisories, bool advisoriesAvailable, CancellationToken ct)
    {
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
            ? await _vulns.GetKevEpssByOsvIdsAsync(advisories.Select(a => a.Id).ToList(), ct)
            : new Dictionary<string, (bool IsKev, double? EpssScore)>();

        bool hasKev = advisories.Any(a => kevEpss.TryGetValue(a.Id, out var e) && e.IsKev);
        var epssValues = advisories
            .Select(a => kevEpss.TryGetValue(a.Id, out var e) ? e.EpssScore : null)
            .Where(v => v is not null)
            .Select(v => v!.Value)
            .ToList();
        double? maxEpss = epssValues.Count > 0 ? epssValues.Max() : null;
        double? maxCvss = scored.Count > 0 ? scored.Max(a => a.CvssScore) : null;

        return new AdvisoryAnalysis(malwareIds, scored, unscored, kevEpss, hasKev, maxEpss, maxCvss, malwareIds.Count > 0);
    }

    private static (string Overall, string? BlockedReason) DetermineOverall(
        VersionMetadataFacts facts, OrgSettings settings, AdvisoryAnalysis analysis,
        bool advisoriesAvailable, bool licenseAllowed, DateTimeOffset now)
    {
        var gateFacts = new VersionFacts(
            ManualState: null,
            Deprecated: facts.Deprecated,
            PublishedAt: facts.PublishedAt,
            Scanned: advisoriesAvailable,
            HasMalicious: analysis.HasMalicious,
            HasKev: analysis.HasKev,
            MaxEpss: analysis.MaxEpss,
            MaxCvss: analysis.MaxCvss,
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
            BlockRevokedMode: null);

        var verdict = BlockGateService.Evaluate(gateFacts, gatePolicy, now);
        if (!verdict.Servable)
        {
            return ("blocked", verdict.Arm.ToString());
        }

        bool warn = !advisoriesAvailable
            || (analysis.HasMalicious && settings.BlockMalicious == "warn")
            || (analysis.HasKev && settings.BlockKev == "warn")
            || (facts.Deprecated is not null && settings.BlockDeprecated == "warn")
            || (settings.LicenseEnforcementMode != "off" && !licenseAllowed);
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
                c.Analysis.KevEpss.TryGetValue(a.Id, out var se2) ? se2.EpssScore : null, a.Summary)).ToList(),
            Unscored: c.Analysis.Unscored.Select(a => new UnscoredAdvisory(a.Id, a.Summary)).ToList(),
            MaxCvss: c.Analysis.MaxCvss,
            HasKev: c.Analysis.HasKev,
            MaxEpss: c.Analysis.MaxEpss,
            Available: c.AdvisoriesAvailable),
        License: new LicenseLookupCheck(
            Spdx: c.Facts.Spdx,
            Mode: c.Settings.LicenseEnforcementMode,
            Allowed: c.Settings.LicenseEnforcementMode == "off" ? null : c.LicenseAllowed,
            BlockedLicense: c.BlockedLicense,
            Available: c.Facts.Spdx.Count > 0),
        AirGapped: c.AirGapped,
        UnavailableChecks: c.Unavailable);

    private static string BuildPurl(string ecosystem, string name, string version) => ecosystem switch
    {
        "npm" => PurlNormalizer.Npm(name, version),
        "pypi" => PurlNormalizer.PyPi(name, version),
        "nuget" => PurlNormalizer.NuGet(name, version),
        "maven" => BuildMavenPurl(name, version),
        "golang" => PurlNormalizer.Golang(name, version),
        "cargo" => PurlNormalizer.Cargo(name, version),
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

        if (ecosystem == "golang")
        {
            // Go module paths are domain/path-shaped (e.g. "example.com/mod",
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

    // Resolves "latest" via IUpstreamLatestVersionResolver and classifies the result:
    // Transient=true means the resolver itself hit a network/timeout failure (propagate as
    // Unavailable, never a false answer); Transient=false + Version=null means the resolver
    // reached the upstream and found no latest (package unknown or genuinely no stable release).
    private async Task<(string? Version, bool Transient)> TryResolveLatestAsync(
        string ecosystem, string orgId, string name, CancellationToken ct)
    {
        try
        {
            return ((await _latestResolver.ResolveAsync(ecosystem, orgId, name, ct)).Version, false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex))
        {
            return (null, true);
        }
    }

    // ── Per-ecosystem metadata fetch ────────────────────────────────────────────

    private Task<FactsOutcome> FetchFactsAsync(
        string ecosystem, string orgId, string name, string? requestedVersion, CancellationToken ct) => ecosystem switch
        {
            "npm" => FetchNpmAsync(orgId, name, requestedVersion, ct),
            "pypi" => FetchPyPiAsync(orgId, name, requestedVersion, ct),
            "nuget" => FetchNuGetAsync(orgId, name, requestedVersion, ct),
            "maven" => FetchMavenAsync(orgId, name, requestedVersion, ct),
            "cargo" => FetchCargoAsync(orgId, name, requestedVersion, ct),
            "golang" => FetchGoAsync(orgId, name, requestedVersion, ct),
            _ => throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "no metadata fetch wired"),
        };


    // ── Internal per-fetch shapes ────────────────────────────────────────────────

    private enum MetadataFetchStatus { Ok, NotFound, Unavailable, NotConfigured }

    private sealed record FactsOutcome(MetadataFetchStatus Status, string? Version, VersionMetadataFacts? Facts)
    {
        public static FactsOutcome Ok(string version, VersionMetadataFacts facts) => new(MetadataFetchStatus.Ok, version, facts);
        public static readonly FactsOutcome NotFound = new(MetadataFetchStatus.NotFound, null, null);
        public static readonly FactsOutcome Unavailable = new(MetadataFetchStatus.Unavailable, null, null);
        public static readonly FactsOutcome NotConfigured = new(MetadataFetchStatus.NotConfigured, null, null);
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
        VersionMetadataFacts? Facts, IReadOnlyList<string> UnavailableAdditions)
    {
        public static VersionResolution Exit(PackageLookupOutcome outcome) =>
            new(outcome, null, false, null, Array.Empty<string>());

        public static VersionResolution Resolved(
            string version, bool versionInferred, VersionMetadataFacts facts, IReadOnlyList<string> unavailableAdditions) =>
            new(null, version, versionInferred, facts, unavailableAdditions);
    }

    private sealed record AdvisoryQueryResult(List<OsvAdvisory> Advisories, bool Available);

    private sealed record AdvisoryAnalysis(
        List<string> MalwareIds, List<OsvAdvisory> Scored, List<OsvAdvisory> Unscored,
        IReadOnlyDictionary<string, (bool IsKev, double? EpssScore)> KevEpss,
        bool HasKev, double? MaxEpss, double? MaxCvss, bool HasMalicious);

    // Bundles the fields BuildResult needs past the S107 constructor-injection threshold —
    // this is plain data assembly, not independently-registered collaborators, so a bundle
    // record is the cleaner fit than a pragma.
    private sealed record LookupResultContext(
        string Purl, string Ecosystem, string Name, string Version, bool VersionInferred,
        string Overall, string? BlockedReason, VersionMetadataFacts Facts, OrgSettings Settings,
        AdvisoryAnalysis Analysis, bool AdvisoriesAvailable, bool LicenseAllowed, string? BlockedLicense,
        bool AirGapped, IReadOnlyList<string> Unavailable);
}

// ── Public request/response contract ────────────────────────────────────────────

public sealed record PackageLookupRequest(string OrgId, string? Ecosystem, string? Name, string? Version);

public enum PackageLookupStatus { Ok, UnsupportedEcosystem, InvalidInput, VersionRequired, UpstreamNotFound, UpstreamUnavailable }

/// <summary>
/// Outcome of a lookup: a computed <see cref="Result"/> (Status == Ok), a definitive
/// <see cref="NotFound"/> answer the controller returns as a 200 verdict-shaped body, or a reason
/// the controller maps to the matching RFC 7807 problem (422 for input problems, 502/503 for a
/// transient/unreachable upstream).
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
    /// <summary>The firing <see cref="BlockArm"/> name when <see cref="Verdict"/> is "blocked".</summary>
    string? BlockedReason,
    MalwareLookupCheck Malware,
    VulnerabilityLookupCheck Vulnerabilities,
    LicenseLookupCheck License,
    bool AirGapped,
    IReadOnlyList<string> UnavailableChecks)
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

public sealed record ScoredAdvisory(string Id, double CvssScore, string? Severity, bool IsKev, double? Epss, string? Summary);

public sealed record UnscoredAdvisory(string Id, string? Summary);

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
    bool Available);

// ── Bounded in-memory TTL cache ───────────────────────────────────────────────────

/// <summary>
/// Bounded in-memory TTL cache for repeated lookups of the same (org, purl) coordinate, following
/// the project's external-API-hydration house pattern: single-flight dedup per key (a burst of
/// identical concurrent lookups triggers exactly one upstream/OSV round trip), a small positive
/// TTL so a user re-checking the same candidate doesn't re-hit OSV/upstream on every keystroke,
/// and a bounded entry count with expiry-ordered eviction so an enumeration attack (many distinct
/// candidate names) cannot grow the map without bound. Singleton-scoped — shared across requests.
/// </summary>
public sealed class PackageLookupCache
{
    private const int MaxEntries = 2048;
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(2);
    private const int StripeCount = 32;

    private readonly ConcurrentDictionary<string, CachedEntry> _entries = new();
    private readonly SemaphoreSlim[] _stripes =
        Enumerable.Range(0, StripeCount).Select(_ => new SemaphoreSlim(1, 1)).ToArray();
    private readonly TimeProvider _time;

    public PackageLookupCache(TimeProvider time) => _time = time;

    public static string KeyFor(string orgId, string ecosystem, string name, string? version) =>
        string.Join('\n', orgId, ecosystem, name, version ?? "");

    public PackageLookupOutcome? TryGet(string key) =>
        _entries.TryGetValue(key, out var entry) && _time.GetUtcNow() - entry.StoredAt < Ttl
            ? entry.Outcome
            : null;

    /// <summary>
    /// Runs <paramref name="compute"/> under a per-key stripe lock so concurrent identical
    /// lookups collapse into one upstream round trip, then caches the result (both a computed
    /// verdict and a definitive not-found/unsupported outcome; a transient-unavailable outcome
    /// is intentionally not cached so the next call retries upstream).
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

            var outcome = await compute();
            if (outcome.Status != PackageLookupStatus.UpstreamUnavailable)
            {
                Store(key, outcome);
            }

            return outcome;
        }
        finally
        {
            stripe.Release();
        }
    }

    private void Store(string key, PackageLookupOutcome outcome)
    {
        if (_entries.Count >= MaxEntries)
        {
            Prune();
        }

        _entries[key] = new CachedEntry(outcome, _time.GetUtcNow());
    }

    private void Prune()
    {
        var now = _time.GetUtcNow();
        foreach (var kv in _entries)
        {
            if (now - kv.Value.StoredAt >= Ttl)
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

    private sealed record CachedEntry(PackageLookupOutcome Outcome, DateTimeOffset StoredAt);
}
