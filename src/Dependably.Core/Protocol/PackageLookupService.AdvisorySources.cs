using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Dependably.Protocol;

/// <summary>
/// The advisory source for each lookup ecosystem. The seven language ecosystems query OSV by
/// PURL. apk and rpm query OSV's release-scoped distro feeds. oci reads the org's own image-scan
/// result. terraform has no source and reports <see cref="AdvisorySourceInfo.NotApplicable"/>.
/// In every arm a source that could not be consulted is <c>unavailable</c>, never an empty
/// advisory list presented as a clean answer.
/// </summary>
public sealed partial class PackageLookupService
{
    // algorithm ":" hex, as the registry stores an image's version. A tag names a moving target
    // and the scan result is keyed by the digest it resolved to.
    [GeneratedRegex(@"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-fA-F]{32,}\z", RegexOptions.CultureInvariant)]
    private static partial Regex OciDigest();

    // An apk version carries its "-rN" package revision, and an rpm version is "[epoch:]version-release".
    // A bare version orders below the build that fixed it, so it could not be matched against an
    // advisory's fixed event and would read as unaffected.
    [GeneratedRegex(@"-r\d+\z", RegexOptions.CultureInvariant)]
    private static partial Regex ApkRevision();

    [GeneratedRegex(@"^(?:\d+:)?[^\s:-]+-[^\s:-]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex RpmEvr();

    // The release for apk and rpm, and the digest shape for oci. Field/code pairs map to the
    // controller's localized problem details.
    private static (string Field, string Code)? ValidateScopeInputs(
        string ecosystem, string? version, string? distro, out DistroScope? scope)
    {
        scope = null;
        bool badDigest = ecosystem == "oci" && (version is null || !OciDigest().IsMatch(version));
        bool badDistro = ecosystem is "apk" or "rpm" && !string.IsNullOrWhiteSpace(distro)
            && !DistroScopes.TryParse(ecosystem, distro, out scope);
        bool badRelease = version is not null
            && (ecosystem == "apk" ? !ApkRevision().IsMatch(version) : ecosystem == "rpm" && !RpmEvr().IsMatch(version));
        return badDigest
            ? ("version", "oci.digestRequired")
            : badRelease ? ("version", "version.releaseRequired")
            : badDistro ? ("distro", "distro.invalid") : null;
    }

    // The ecosystems with no upstream metadata fetch still honour the org's reserved names: the
    // name is reported reserved on the result, exactly as for an ecosystem that does fetch.
    private async Task<FactsOutcome?> ReservationOnlyOutcomeAsync(
        string ecosystem, string orgId, string name, CancellationToken ct) =>
        !MetadataSupportedEcosystems.Contains(ecosystem)
        && await _reservedNamespaces.IsUpstreamNameReservedAsync(orgId, ecosystem, name, ct)
            ? FactsOutcome.Reserved
            : null;

    private async Task<(string Purl, AdvisoryQueryResult Query)> QueryAdvisorySourceAsync(
        string orgId, string ecosystem, string name, string version, DistroScope? requestedScope, CancellationToken ct)
    {
        switch (ecosystem)
        {
            case "terraform":
                return (BuildPurl(ecosystem, name, version),
                    AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.NotApplicable()));
            case "oci":
                return (BuildPurl(ecosystem, name, version), await QueryOciScanAsync(orgId, name, version, ct));
            case "apk" or "rpm":
                return await QueryDistroAsync(orgId, ecosystem, name, version, requestedScope, ct);
            default:
                string purl = BuildPurl(ecosystem, name, version);
                return (purl, await QueryAdvisoriesAsync(ecosystem, purl, ct));
        }
    }

    // The release comes from the request, else from the org's configured upstream when every
    // upstream names the same one. With neither there is no feed to ask, which is reported as
    // such rather than answered from a guessed release.
    private async Task<(string Purl, AdvisoryQueryResult Query)> QueryDistroAsync(
        string orgId, string ecosystem, string name, string version, DistroScope? requestedScope, CancellationToken ct)
    {
        var scope = requestedScope;
        bool inferred = false;
        if (scope is null)
        {
            var sources = await _registries.ResolveAsync(orgId, ecosystem, ct);
            scope = DistroScopes.Derive(ecosystem, sources.Select(s => s.Url).ToList());
            inferred = scope is not null;
        }

        string purl = ecosystem == "apk"
            ? PurlNormalizer.ApkVersion(name, version)
            : PurlNormalizer.RpmEvr(name, version, DistroScopes.PurlNamespace(scope));
        if (scope is null)
        {
            return (purl, AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.DistroRequired()));
        }

        try
        {
            var result = await _osv.TryQueryDistroPackageAsync(scope, name, version, ct);
            if (!result.Reached)
            {
                return (purl, AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OsvUnreachable(scope, inferred)));
            }

            if (!result.Covered)
            {
                return (purl, AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.NoOsvCoverage(scope, inferred)));
            }

            if (result.Advisories.Count == 0)
            {
                return (purl, await ConfirmNameListedAsync(scope, name, inferred, ct));
            }

            return (purl, new AdvisoryQueryResult(result.Advisories, true, AdvisorySourceInfo.OsvChecked(scope, inferred)));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            return (purl, AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OsvUnreachable(scope, inferred)));
        }
    }

    // An empty answer is a clean result only for a name the release's feed files advisories
    // under, so an empty answer is accepted as clean only when the feed has advisories for the
    // name at all (queried at version "0", which every range that introduces at 0 contains): that
    // proves the name is a key the feed uses. A name the feed has never listed also covers a
    // package that has simply never had an advisory, and the two cannot be told apart, so it is
    // reported unavailable — the safe side. The reason differs by family because the likely cause
    // does. Alpine's feed is keyed by the ORIGIN package (openssl), not the sub-packages it builds
    // (libssl3), so an apk name is origin_unknown. An rpm name is name_unknown: a typo, a package
    // from a repository the feed does not cover (EPEL under Rocky Linux), or a Red Hat package
    // asked of the wrong stream (an AppStream package under ::baseos).
    private async Task<AdvisoryQueryResult> ConfirmNameListedAsync(
        DistroScope scope, string name, bool inferred, CancellationToken ct)
    {
        try
        {
            var probe = await _osvCache.GetOrComputeAsync(
                OsvQueryCache.OriginProbeKey(scope.OsvEcosystem, name),
                async () =>
                {
                    var fresh = await _osv.TryQueryDistroPackageAsync(scope, name, "0", ct);
                    return (fresh, fresh.Reached && fresh.Covered, OsvQueryCache.EstimateBytes(fresh.Advisories));
                },
                ct);
            return !probe.Reached || !probe.Covered
                ? AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OsvUnreachable(scope, inferred))
                : probe.Advisories.Count > 0
                    ? new AdvisoryQueryResult([], true, AdvisorySourceInfo.OsvChecked(scope, inferred))
                    : AdvisoryQueryResult.Unavailable(scope.IsApk
                        ? AdvisorySourceInfo.OriginUnknown(scope, inferred)
                        : AdvisorySourceInfo.NameUnknown(scope, inferred));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            return AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OsvUnreachable(scope, inferred));
        }
    }

    // The org's own stored scan of the image. A result with coverage gaps is partial: the
    // advisories it found are real and stay reported (and enforceable), but its silence is not a
    // clean answer, so it is marked unavailable and never "checked".
    private async Task<AdvisoryQueryResult> QueryOciScanAsync(
        string orgId, string repository, string digest, CancellationToken ct)
    {
        if (_ociScans is null)
        {
            return AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OciNoScanResult());
        }

        var scan = await _ociScans.FindLookupScanAsync(orgId, repository, digest, ct);
        if (scan is null)
        {
            return AdvisoryQueryResult.Unavailable(AdvisorySourceInfo.OciNoScanResult());
        }

        var advisories = scan.Advisories
            .Select(a => new OsvAdvisory(
                Id: a.OsvId,
                Aliases: ParseAliases(a.AliasesJson),
                Summary: a.Summary,
                Severity: a.Severity,
                CvssScore: a.CvssScore,
                AffectedPackages: [],
                Published: null,
                Modified: null,
                IsHydrated: true))
            .ToList();

        return scan.GapCount == 0
            ? new AdvisoryQueryResult(advisories, true, AdvisorySourceInfo.OciChecked(scan.MatchedAt))
            : new AdvisoryQueryResult(advisories, advisories.Count > 0, AdvisorySourceInfo.OciScanIncomplete(scan.MatchedAt));
    }

    /// <summary>
    /// The verdict the OCI pull gate would reach for <paramref name="repository"/>@<paramref name="digest"/>
    /// under <c>oci_scan_enforcement=block</c>, with no side effects: the gate's own facts read
    /// (<see cref="OciPullGateResolver"/>) evaluated by <see cref="BlockGateService.PreviewOciImage"/>,
    /// and an operator's approval past the <c>unscanned</c> arm honoured as the pull honours it, on
    /// every owning image. The licence arm is left to the lookup's own licence check. Facts that
    /// cannot be read refuse as unscanned, which is what the pull answers under <c>block</c>.
    /// </summary>
    private async Task<BlockVerdict> PreviewOciPullAsync(
        string orgId, string repository, string digest, OrgSettings settings, DateTimeOffset now, CancellationToken ct)
    {
        var unreadable = new BlockVerdict(Servable: false, Arm: BlockArm.Unscanned);
        if (_ociPullGate is null)
        {
            _logger.LogWarning(
                "Package lookup has no OCI scan resolver for {Repository}@{Digest} in org {OrgId}; answering unscanned.",
                repository, digest, orgId);
            return unreadable;
        }

        try
        {
            var context = await _ociPullGate.ResolveAsync(orgId, repository, digest, ct);
            var verdict = BlockGateService.PreviewOciImage(context.Facts, context.ManualState, settings, now);
            if (verdict.Servable || verdict.Arm != BlockArm.Unscanned || _quarantine is null)
            {
                return verdict;
            }

            var owners = context.Owners is { Count: > 0 } listed
                ? listed.Select(o => o.Digest).ToList()
                : [context.OwnerDigest];
            foreach (string owner in owners)
            {
                if (!await _quarantine.HasApprovedForGateAsync(
                        orgId, PurlNormalizer.Oci(repository, owner), BlockGateService.UnscannedGate, ct))
                {
                    return verdict;
                }
            }

            return new BlockVerdict(Servable: true, Arm: BlockArm.None);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Package lookup could not read OCI scan facts for {Repository}@{Digest} in org {OrgId} ({ExceptionType}); answering unscanned.",
                repository, digest, orgId, ex.GetType().Name);
            return unreadable;
        }
    }

    private static string[] ParseAliases(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
