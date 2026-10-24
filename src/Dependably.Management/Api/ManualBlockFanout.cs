using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Api;

/// <summary>Which rows the operator was looking at when they made a manual block decision.</summary>
internal enum ManualBlockOrigin
{
    /// <summary>A version as a whole: its uploaded rows when any exist, otherwise its proxied rows.</summary>
    Version,

    /// <summary>A review-queue entry for one uploaded row, named by <see cref="ManualBlockDecision.DecidedVersionId"/>.</summary>
    UploadedEntry,

    /// <summary>A review-queue entry for a proxied artifact, which has no uploaded row.</summary>
    ProxiedEntry,
}

/// <summary>
/// One manual block-gate decision: the version the operator decided, the state to write
/// (<c>blocked</c>, <c>allowed</c>, or null to clear the override), and where it was made.
/// </summary>
internal sealed record ManualBlockDecision(
    string OrgId,
    string Ecosystem,
    string PurlName,
    string Version,
    string? State,
    string? ActorId,
    ManualBlockOrigin Origin = ManualBlockOrigin.Version,
    string? DecidedVersionId = null);

/// <summary>
/// Writes a manual block-gate decision onto every row it covers, for the direct block/unblock
/// endpoints and the quarantine review queue alike, so the two surfaces cannot cover different
/// rows.
///
/// The coverage is asymmetric on purpose. A <c>blocked</c> decision on a PyPI version spreads to
/// every PEP 440-equal spelling on both planes: the uploaded <c>package_versions</c> rows and the
/// proxied <c>tenant_artifact_access</c> rows. An <c>allowed</c> decision short-circuits every
/// automatic gate arm (malicious, KEV, EPSS, release age, provenance, licence), so it covers only
/// the rows the operator reviewed: an uploaded version and its uploaded sibling spellings, or a
/// proxied artifact's rows under that exact spelling. An allow on an uploaded version never
/// allows a proxied file, which the simple index still lists and pip may prefer; it, and clearing
/// the override (null) on an uploaded version, only lifts a block that spread onto the proxied
/// rows of the release, returning them to no override so their automatic gate arms decide.
///
/// Every other ecosystem keeps one plane per decision: the uploaded row when one exists,
/// otherwise the proxied rows whose version <see cref="VersionIdentity"/> reports equal.
///
/// Each row a <c>blocked</c> or <c>allowed</c> decision flips has its pending review-queue entry
/// resolved to match, so a later decision on a sibling spelling cannot reverse a block.
/// </summary>
internal sealed class ManualBlockFanout
{
    private readonly PackageRepository _packages;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly TenantArtifactAccessRepository _tenantAccess;
    private readonly QuarantineRepository _quarantine;

    public ManualBlockFanout(
        PackageRepository packages,
        CacheArtifactRepository cacheArtifacts,
        TenantArtifactAccessRepository tenantAccess,
        QuarantineRepository quarantine)
    {
        _packages = packages;
        _cacheArtifacts = cacheArtifacts;
        _tenantAccess = tenantAccess;
        _quarantine = quarantine;
    }

    /// <summary>
    /// Applies <paramref name="decision"/> and returns the purl of every row it flipped, uploaded
    /// rows first. Empty when nothing matched.
    /// </summary>
    public async Task<IReadOnlyList<string>> ApplyAsync(ManualBlockDecision decision, CancellationToken ct)
    {
        bool isPyPi = decision.Ecosystem == "pypi";
        bool spreads = isPyPi && decision.State == "blocked";

        var uploaded = await ResolveUploadedAsync(decision, isPyPi, spreads, ct);
        var purls = new List<string>();
        foreach (var ver in uploaded)
        {
            await _packages.SetManualBlockStateAsync(ver.Id, decision.State, ct);
            if (decision.State is not null)
            {
                await _quarantine.ResolveForVersionAsync(decision.OrgId, ver.Id, decision.State, decision.ActorId, ct);
            }

            AddPurl(purls, ver.Purl);
        }

        // A proxy artifact carries no package_versions row; the cache-hit gate reads
        // tenant_artifact_access.manual_block_state instead (BlockGateRequest.ForProxyCacheFacts).
        bool coversProxied = spreads || decision.Origin switch
        {
            ManualBlockOrigin.ProxiedEntry => true,
            ManualBlockOrigin.Version => uploaded.Count == 0,
            _ => false,
        };
        if (!coversProxied)
        {
            if (isPyPi && uploaded.Count > 0)
            {
                await LiftSpreadBlocksAsync(decision, purls, ct);
            }

            return purls;
        }

        // A spreading block compares PEP 440 canonical forms; a PyPI allow or clear stays on the
        // exact spelling decided, since another spelling is another file with its own gate facts.
        Func<string?, bool> matchesVersion = isPyPi && !spreads
            ? v => string.Equals(v, decision.Version, StringComparison.Ordinal)
            : v => VersionIdentity.Equal(decision.Ecosystem, v, decision.Version);

        await ApplyToProxiedAsync(decision, matchesVersion, purls, ct);
        return purls;
    }

    // Writes the decision onto every proxied row whose version matches, resolves their quarantine
    // entries, and appends their purls.
    private async Task ApplyToProxiedAsync(
        ManualBlockDecision decision, Func<string?, bool> matchesVersion, List<string> purls, CancellationToken ct)
    {
        var proxyEntries = await _cacheArtifacts.ListServeFactsForNameAsync(
            decision.OrgId, decision.Ecosystem, decision.PurlName, ct);
        var matches = proxyEntries.Where(e => matchesVersion(e.Version)).ToList();
        foreach (var match in matches)
        {
            await _tenantAccess.SetManualBlockStateAsync(decision.OrgId, match.Id, decision.State, ct);
        }

        // Proxy quarantine rows carry no package_version_id and are keyed by purl instead.
        foreach (string matchPurl in matches
            .Select(m => m.Purl ?? $"pkg:{decision.Ecosystem}/{decision.PurlName}@{m.Version}")
            .Distinct(StringComparer.Ordinal))
        {
            if (decision.State is not null)
            {
                await _quarantine.ResolveForPurlAsync(decision.OrgId, matchPurl, decision.State, decision.ActorId, ct);
            }

            AddPurl(purls, matchPurl);
        }
    }

    // An allow or clear on an uploaded PyPI version lifts a block that a spreading decision wrote
    // onto the proxied rows of the same release; without it nothing could, since a shadowed proxied
    // row is hidden from the version list and a manual block queues no review entry. The lifted
    // rows go back to no override, never "allowed", and their quarantine entries are left alone,
    // so the automatic gate arms still hold a flagged file while a clean one serves again.
    private async Task LiftSpreadBlocksAsync(ManualBlockDecision decision, List<string> purls, CancellationToken ct)
    {
        var proxyEntries = await _cacheArtifacts.ListServeFactsForNameAsync(
            decision.OrgId, decision.Ecosystem, decision.PurlName, ct);
        foreach (var blocked in proxyEntries.Where(e =>
            e.ManualBlockState == "blocked"
            && VersionIdentity.Equal(decision.Ecosystem, e.Version, decision.Version)))
        {
            await _tenantAccess.SetManualBlockStateAsync(decision.OrgId, blocked.Id, null, ct);
            AddPurl(purls, blocked.Purl ?? $"pkg:{decision.Ecosystem}/{decision.PurlName}@{blocked.Version}");
        }
    }

    private static void AddPurl(List<string> purls, string? purl)
    {
        if (!string.IsNullOrEmpty(purl) && !purls.Contains(purl, StringComparer.Ordinal))
        {
            purls.Add(purl);
        }
    }

    // The uploaded rows the decision covers. An uploaded queue entry's own row is always included;
    // a PyPI block or allow on an uploaded row adds every PEP 440-equal uploaded spelling. A proxied
    // queue entry reaches the uploaded plane only when it spreads a block.
    private async Task<List<PackageVersion>> ResolveUploadedAsync(
        ManualBlockDecision decision, bool isPyPi, bool spreads, CancellationToken ct)
    {
        var rows = new List<PackageVersion>();
        string? packageId;
        string version = decision.Version;

        if (decision.Origin == ManualBlockOrigin.UploadedEntry)
        {
            var decided = decision.DecidedVersionId is null
                ? null
                : await _packages.GetVersionByIdAsync(decision.OrgId, decision.DecidedVersionId, ct);
            if (decided is null)
            {
                return rows;
            }

            rows.Add(decided);
            if (!isPyPi || decision.State is null)
            {
                return rows;
            }

            packageId = decided.PackageId;
            version = decided.Version;
        }
        else if (decision.Origin == ManualBlockOrigin.ProxiedEntry && !spreads)
        {
            return rows;
        }
        else
        {
            packageId = (await _packages.GetByPurlNameAsync(
                decision.OrgId, decision.Ecosystem, decision.PurlName, ct))?.Id;
        }

        if (packageId is null)
        {
            return rows;
        }

        await AddVersionRowsAsync(rows, packageId, decision.Ecosystem, version, isPyPi, ct);
        return rows;
    }

    // Adds the exact version row, or for PyPI every PEP 440-equal spelling, unless already present.
    private async Task AddVersionRowsAsync(
        List<PackageVersion> rows, string packageId, string ecosystem, string version, bool isPyPi, CancellationToken ct)
    {
        if (!isPyPi)
        {
            var exact = await _packages.ResolveHostedVersionAsync(packageId, ecosystem, version, ct);
            if (exact is not null && !rows.Exists(r => r.Id == exact.Id))
            {
                rows.Add(exact);
            }

            return;
        }

        foreach (var sibling in (await _packages.GetVersionsAsync(packageId, ct))
            .Where(v => VersionIdentity.Equal(ecosystem, v.Version, version)))
        {
            if (!rows.Exists(r => r.Id == sibling.Id))
            {
                rows.Add(sibling);
            }
        }
    }
}
