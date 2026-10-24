using System.Globalization;
using System.Text.Json;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that refreshes upstream metadata for proxy-cached package versions. Runs on
/// a cron schedule (<c>DEPRECATION_REFRESH_SCHEDULE</c> env var, default daily at 5am UTC).
///
/// The refreshed ecosystems are <see cref="DeprecationRefreshEcosystems.All"/>. Deprecation is
/// refreshed for npm, PyPI, Hex and NuGet — they expose a per-version deprecation, yank,
/// retirement or listing signal in one metadata resource; Maven, RPM, and OCI do not. For each
/// stale package, fetches the upstream packument (npm), project JSON (PyPI), signed package
/// resource (Hex, read only from an upstream with a configured public key) or registration index
/// (NuGet) and updates <c>deprecated</c>/<c>deprecation_checked_at</c> for every version row under
/// that package. NuGet's verdict is its listing state, read from each version's registration leaf
/// with the parser the first fetch uses (<see cref="NuGetUpstreamListingFetcher"/>):
/// an unlisted version is marked "Unlisted upstream" and a relisted one is cleared. A NuGet version
/// the answered index does not carry a leaf for gets no verdict that pass. Maven rows keep
/// whatever their first fetch recorded, because this pass reads no deprecation signal for them.
///
/// Only a live 2xx upstream answer is a verdict. A body the metadata cache serves past its TTL
/// because the upstream failed (<see cref="UpstreamMetadataResponse.IsStale"/>) is no answer from
/// that source, so the next source is asked: it is the last answer the upstream gave, which can
/// predate the deprecation, yank, unlisting or retirement the group records. The request-serving
/// path still relays stale bodies; only this pass declines to read them. When no configured source
/// gives a live answer — every source answers non-2xx (503, 429, 401/403, or 404 for a package no
/// source lists) or is served stale, or a Hex resource cannot be verified — the group records nothing: its <c>deprecated</c>, upstream-latest and
/// <c>versions_behind</c> facts stay as recorded and only this org's queue stamps move, so an
/// upstream outage never unblocks a version held under <c>block_deprecated=block_all</c>.
///
/// Upstream-latest is refreshed for npm, PyPI, NuGet, Maven and Hex: the same npm/PyPI/Hex fetch
/// yields the latest release, while NuGet/Maven resolve their latest-stable release via
/// <see cref="Protocol.IUpstreamLatestVersionResolver"/>. The result is written to
/// <c>packages.upstream_latest_version</c>, which drives the packages-list "Latest" indicator and
/// the package-detail "behind upstream" banner. Newly-proxied packages get their baseline
/// immediately from the first-fetch recorder, so this pass keeps the baseline current rather than
/// establishing it.
///
/// The same per-name upstream fetch also yields the full STABLE version set for every refreshed
/// ecosystem (<see cref="Protocol.UpstreamLatestVersion.StableVersionsDescending"/>), which is
/// recomputed into a per-version <c>versions_behind</c> operational-risk count on every
/// <c>cache_artifact</c> row for the group each pass, and mirrored onto any hosted
/// (<c>origin='uploaded'</c>) <c>package_versions</c> rows sharing the same package. NULL means
/// unknown (never 0) — an answer that enumerates no version set to count against, not "up to
/// date". A pass with no upstream answer leaves the recorded count as it is.
///
/// The pass enumerates the stale <c>cache_artifact</c> groups first, then a second set of
/// HOSTED-ONLY groups: packages that were once proxied — hence carry a seeded
/// <c>upstream_latest_checked_at</c> — but whose proxy rows were later evicted, leaving only
/// hosted versions. They have no <c>cache_artifact</c> row for the cache enumeration to find, so
/// without this second pass their <c>upstream_latest_version</c> and hosted <c>versions_behind</c>
/// would freeze at eviction time. A purely-internal name that was never proxied has a NULL
/// <c>upstream_latest_checked_at</c> and is deliberately never fetched.
///
/// A group whose name its org has reserved (<see cref="ReservedNamespaceService.IsUpstreamNameReservedAsync"/>)
/// is never fetched, whichever ecosystem it is in: no upstream request is made for it, and the
/// shared <c>cache_artifact</c> rows keep the upstream facts an org that does consult upstream
/// recorded.
///
/// Both group-enumeration queries — <see cref="CacheArtifactRepository.ListGroupsNeedingDeprecationRefreshAsync"/>
/// and <see cref="PackageRepository.ListHostedGroupsNeedingUpstreamRefreshAsync"/> — carry an
/// <c>o.status = 'active'</c> predicate excluding a suspended/archived/deleting org (see
/// TenantLifecycle) the same way they already exclude a soft-deleted or air-gapped one: this pass
/// fetches upstream metadata on the org's behalf, and TenantStatusEnforcementMiddleware has
/// already refused the upload path that would have produced these rows for a non-active org.
/// </summary>
public sealed class DeprecationRefreshService : ScheduledBackgroundService
{
    private readonly PackageRepository _packages;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly AuditRepository _audit;
    private readonly UpstreamClient _upstream;
    private readonly IUpstreamLatestVersionResolver _latestResolver;
    private readonly UpstreamRegistryResolver _registries;
    private readonly ReservedNamespaceService _reservedNamespaces;
    private readonly Hex.HexReleaseRepository _hexReleases;
    private readonly Protocol.Hex.HexMasterKeyResolver? _hexMasterKeys;
    private readonly IAirGapMode _airGap;
    private readonly IConfiguration _config;
    private readonly ILogger<DeprecationRefreshService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "DEPRECATION_REFRESH_SCHEDULE";
    protected override string DefaultCron => "0 5 * * *";
    protected override string? JitterEnvKey => "DEPRECATION_REFRESH_JITTER_SECONDS";
    protected override bool RunOnStartup => true;

    // Refreshes shared package/version rows and drives one-shot upstream fetches — with
    // RunOnStartup=true a rolling deploy would otherwise fire N simultaneous upstream sweeps.
    protected override bool RequiresLeaderLock => true;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Dependency-injection constructor: the parameter list is the declared dependency set.")]
    public DeprecationRefreshService(
        PackageRepository packages,
        CacheArtifactRepository cacheArtifacts,
        AuditRepository audit,
        UpstreamClient upstream,
        IUpstreamLatestVersionResolver latestResolver,
        UpstreamRegistryResolver registries,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<DeprecationRefreshService> logger,
        TimeProvider time,
        IDistributedLock locks,
        ReservedNamespaceService reservedNamespaces,
        Hex.HexReleaseRepository hexReleases,
        Protocol.Hex.HexMasterKeyResolver? hexMasterKeys = null)
        : base(config, logger, time, locks)
    {
        _packages = packages;
        _cacheArtifacts = cacheArtifacts;
        _audit = audit;
        _upstream = upstream;
        _latestResolver = latestResolver;
        _registries = registries;
        _reservedNamespaces = reservedNamespaces;
        _hexReleases = hexReleases;
        _airGap = airGap;
        _hexMasterKeys = hexMasterKeys;
        _config = config;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunRefreshPassAsync(ct);

    internal async Task RunRefreshPassAsync(CancellationToken ct)
    {
        // xtenant: groups upstream refresh work across every tenant that holds a package; each
        // write filters on the group's org_id.
        using var ownerScope = DbScope.CrossTenant("deprecation refresh");

        using var scope = BackgroundJobScope.Begin("deprecation-refresh", "deprecation.refresh_pass", _time);
        try
        {
            await RunRefreshPassInnerAsync(ct);
            scope.Complete();
        }
        catch (Exception ex)
        {
            scope.Fail(ex);
            throw;
        }
    }

    private async Task RunRefreshPassInnerAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled("deprecation-refresh"))
        {
            _logger.LogInformation("Deprecation refresh pass skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return;
        }

        int ageHours = int.TryParse(_config["DEPRECATION_REFRESH_AGE_HOURS"], out int h) && h > 0 ? h : 24;
        int batchSize = int.TryParse(_config["DEPRECATION_REFRESH_BATCH_SIZE"], out int bs) && bs > 0 ? bs : 500;
        int batchDelayMs = int.TryParse(_config["DEPRECATION_REFRESH_BATCH_DELAY_MS"], out int d) ? d : 500;

        _logger.LogInformation(
            "Deprecation refresh pass starting (ageHours={AgeHours}, batchSize={BatchSize}).",
            ageHours, batchSize);
        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var groups = await _cacheArtifacts.ListGroupsNeedingDeprecationRefreshAsync(ageHours, batchSize, _time, ct);
        var (cacheChecked, cacheUpdated) = await ProcessGroupsAsync(groups, batchDelayMs, ct);

        // Hosted-only groups: packages that were once proxied (so they carry a seeded
        // upstream_latest_checked_at) but no longer have a cache_artifact row — their proxy
        // versions were evicted, leaving only origin='uploaded' rows. The cache-plane enumeration
        // above cannot see them, so without this pass their upstream_latest_version and hosted
        // versions_behind would freeze at eviction time. Same per-name upstream fetch, same
        // processing — the cache-version list is just empty.
        var hostedGroups = await _packages.ListHostedGroupsNeedingUpstreamRefreshAsync(ageHours, batchSize, _time, ct);
        var (hostedChecked, hostedUpdated) = await ProcessGroupsAsync(hostedGroups, batchDelayMs, ct);

        int totalChecked = cacheChecked + hostedChecked;
        int totalUpdated = cacheUpdated + hostedUpdated;

        sw.Stop();
        _logger.LogInformation(
            "Deprecation refresh pass complete. Checked {Checked} versions across {Groups} packages, {Updated} updated, took {ElapsedMs}ms.",
            totalChecked, groups.Count, totalUpdated, sw.ElapsedMilliseconds);
    }

    // Runs ProcessGroupAsync over each group in order, stopping early on cancellation, with an
    // optional delay between groups to spread upstream fetch load. Shared by the cache-plane and
    // hosted-only refresh passes in RunRefreshPassInnerAsync above.
    private async Task<(int Checked, int Updated)> ProcessGroupsAsync(
        IReadOnlyList<(string Ecosystem, string Name, string OrgId)> groups, int batchDelayMs, CancellationToken ct)
    {
        int totalChecked = 0;
        int totalUpdated = 0;

        foreach (var group in groups)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var (checked_, updated) = await ProcessGroupAsync(group, ct);
            totalChecked += checked_;
            totalUpdated += updated;

            if (batchDelayMs > 0 && !ct.IsCancellationRequested)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(batchDelayMs), _time, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        return (totalChecked, totalUpdated);
    }

    /// <summary>
    /// Processes one (ecosystem, name, orgId) group: fetches upstream metadata once, records the
    /// upstream-latest on the packages row, writes <c>deprecated</c>/<c>deprecation_checked_at</c>
    /// to each <c>cache_artifact</c> row for the name, and mirrors <c>versions_behind</c> onto the
    /// hosted rows. Serves both the cache-plane groups and the hosted-only groups (a package with
    /// no <c>cache_artifact</c> row) — for the latter the cache-version list is simply empty, so
    /// only the packages row and hosted versions are updated.
    ///
    /// Every settled outcome ends by stamping this org's <c>tenant_artifact_access.refresh_checked_at</c>
    /// for the name, the per-org stamp the cache-plane enumeration selects on. The shared
    /// <c>cache_artifact</c> rows are stamped only where upstream gave a verdict, and those stamps
    /// do not schedule anything, so processing one org's group never makes another org's group for
    /// the same name read as fresh.
    /// </summary>
    private async Task<(int Checked, int Updated)> ProcessGroupAsync(
        (string Ecosystem, string Name, string OrgId) group,
        CancellationToken ct)
    {
        var (ecosystem, name, orgId) = group;

        if (!IsSupportedEcosystem(ecosystem))
        {
            return (0, 0);
        }

        // An org with proxy passthrough off (or air-gapped) sends nothing upstream, whatever
        // upstream rows it kept. The enumerations already exclude such orgs; this re-reads the
        // setting so a flip between enumeration and processing is honoured too.
        if (!await _cacheArtifacts.IsUpstreamAccessAllowedForOrgAsync(orgId, ct))
        {
            return (0, 0);
        }

        // Resolving the org's configured upstream sources decrypts every authenticated row's
        // stored secret (EnvelopeProtector.Unprotect), which throws on a missing/rotated master
        // key. That resolve — and the zero-rows "proxying deliberately disabled" check that
        // depends on it — must stay inside this try alongside the fetch, so a decrypt failure for
        // this one org lands in the same catch as any other upstream-fetch failure rather than
        // escaping ProcessGroupAsync uncaught and failing the whole refresh pass for every
        // other org.
        Dictionary<string, string?>? upstreamDeprecated;
        UpstreamLatestVersion upstreamLatest;
        IReadOnlyDictionary<string, Protocol.Hex.HexRetirementStatus>? hexRetirements = null;
        try
        {
            // A name this org has reserved is never looked up upstream. Decided before the
            // per-ecosystem fetch because npm, PyPI and Hex fetch their metadata directly rather
            // than through the resolver, so the resolver's own gate does not reach them; the
            // Reserved result is settled below like one the resolver returned.
            if (await _reservedNamespaces.IsUpstreamNameReservedAsync(orgId, ecosystem, name, ct))
            {
                upstreamDeprecated = new Dictionary<string, string?>();
                upstreamLatest = UpstreamLatestVersion.Reserved;
            }
            else
            {
                var sources = await _registries.ResolveAsync(orgId, ecosystem, ct);

                // Zero configured upstream sources for this (org, ecosystem) means proxying is
                // deliberately disabled — the empty=disabled contract UpstreamRegistryResolver
                // documents. Skip the fetch entirely rather than resolving an ambiguous "no data"
                // that would overwrite the recorded deprecation/upstream-latest state: yielding the
                // slot (touch-only, no write) means a later re-enable resumes cleanly instead of the
                // pass having read a disabled ecosystem as "unknown" upstream.
                if (sources.Count == 0)
                {
                    _logger.LogInformation(
                        "Deprecation refresh skipped for {Ecosystem}/{Package}: no upstream configured for this org.",
                        ecosystem, name);
                    await YieldGroupSlotAsync(ecosystem, name, orgId, ct);
                    return (0, 0);
                }

                (upstreamDeprecated, upstreamLatest, hexRetirements) =
                    await FetchUpstreamMetadataAsync(ecosystem, orgId, name, sources, ct);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to fetch upstream deprecation metadata for {Ecosystem}/{Package}: {ExceptionType}",
                ecosystem, name, ex.GetType().Name);
            await YieldGroupSlotAsync(ecosystem, name, orgId, ct);
            return (0, 0);
        }

        if (upstreamLatest.IsReserved)
        {
            await ClearReservedGroupAsync(ecosystem, name, orgId, ct);
            return (0, 0);
        }

        // No upstream answer: no source returned a 2xx (every one answered 503, 429, 401/403 or
        // 404), or, for Hex, no source yielded a verified resource. Nothing is recorded, so a
        // deprecation or retirement read earlier from a real answer is not cleared, and the
        // upstream-latest and versions-behind facts are not nulled, by a pass that got none.
        if (upstreamDeprecated is null)
        {
            _logger.LogInformation(
                "Deprecation refresh recorded nothing for {Ecosystem}/{Package}: no upstream source gave an answer.",
                ecosystem, name);
            await YieldGroupSlotAsync(ecosystem, name, orgId, ct);
            return (0, 0);
        }

        // Record upstream's declared latest version (and publish timestamp, when known) on the
        // packages row if one exists for this org. The packages table may not have a row when the
        // artifact was only ever accessed via the global plane; skip silently in that case.
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, name, ct);
        if (pkg is not null)
        {
            await _packages.UpdateUpstreamLatestAsync(pkg.Id, upstreamLatest.Version, upstreamLatest.PublishedAt, ct);
        }

        var versions = await _cacheArtifacts.ListVersionsForNameAsync(ecosystem, name, ct);
        var (checked_, updated, newlyRevoked) = await ProcessVersionsAsync(
            ecosystem, versions, upstreamDeprecated, upstreamLatest.StableVersionsDescending, ct);

        if (hexRetirements is not null)
        {
            await ApplyHexRetirementsAsync(versions, hexRetirements, ct);
        }

        // Mirror the versions-behind count onto any hosted (origin='uploaded') package_versions
        // rows under the same package — a private override of an otherwise-proxied name still
        // benefits from knowing how far behind upstream it sits. Uses the same stable-versions
        // list already fetched above; no additional upstream call.
        if (pkg is not null)
        {
            await UpdateHostedVersionsBehindAsync(pkg.Id, ecosystem, upstreamLatest.StableVersionsDescending, ct);
        }

        // A pass cancelled part-way through the version list leaves the group unstamped so the
        // next pass re-selects it and reaches the versions this one skipped.
        if (!ct.IsCancellationRequested)
        {
            await _cacheArtifacts.StampRefreshCheckedAtForOrgAsync(orgId, ecosystem, name, _time, ct);
        }

        await LogRevokedActivitiesAsync(orgId, ecosystem, name, newlyRevoked, ct);
        await LogRefreshSummaryAsync(orgId, ecosystem, name, checked_, updated, ct);

        return (checked_, updated);
    }

    /// <summary>
    /// Marks a group as attempted after its upstream fetch threw or no configured source gave an
    /// answer, or when the org has no upstream configured for the ecosystem, so it moves to the
    /// back of the refresh queue instead of holding the head of it.
    ///
    /// Both enumerations that feed this pass order by a per-org staleness stamp, never-processed
    /// first, and take a fixed batch — <c>ListGroupsNeedingDeprecationRefreshAsync</c> by
    /// <c>tenant_artifact_access.refresh_checked_at</c>, and
    /// <c>ListHostedGroupsNeedingUpstreamRefreshAsync</c> by <c>packages.upstream_latest_checked_at</c>.
    /// A group whose fetch throws every pass would otherwise be re-selected first every pass, and
    /// once batch-many such groups exist no other group is ever reached again.
    ///
    /// Only this org's attempt timestamps move. The shared <c>cache_artifact</c> rows are not
    /// written: their <c>deprecation_checked_at</c> records when upstream last gave a verdict, and
    /// another org caching the same name keeps its own place in the queue. The deprecation verdict
    /// and the recorded upstream-latest are left untouched — the fetch produced neither, and
    /// writing a null for either would turn a transient upstream outage into erased state.
    /// </summary>
    private async Task YieldGroupSlotAsync(string ecosystem, string name, string orgId, CancellationToken ct)
    {
        await _cacheArtifacts.StampRefreshCheckedAtForOrgAsync(orgId, ecosystem, name, _time, ct);

        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, name, ct);
        if (pkg is not null)
        {
            await _packages.TouchUpstreamLatestCheckedAtAsync(pkg.Id, ct);
        }
    }

    /// <summary>
    /// Settles a group whose name this org has reserved: upstream was not consulted, so no
    /// upstream fact is recorded and no version is marked deprecated or revoked. The org's own
    /// packages row and hosted versions read as having no known upstream latest (a baseline
    /// recorded before the reservation would otherwise keep reporting an upstream answer for a
    /// reserved name). The <c>cache_artifact</c> rows are shared with every org that caches the
    /// name, so they are not written at all: their deprecation verdict, its timestamp, and their
    /// versions-behind counts stay whatever an org that does consult upstream last recorded. Only
    /// this org's per-org refresh stamp moves, which keeps the group from holding the head of the
    /// refresh queue without making another org's group for the name read as fresh.
    /// </summary>
    private async Task ClearReservedGroupAsync(string ecosystem, string name, string orgId, CancellationToken ct)
    {
        await _cacheArtifacts.StampRefreshCheckedAtForOrgAsync(orgId, ecosystem, name, _time, ct);

        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, name, ct);
        if (pkg is not null)
        {
            await _packages.UpdateUpstreamLatestAsync(pkg.Id, null, null, ct);
            await UpdateHostedVersionsBehindAsync(pkg.Id, ecosystem, null, ct);
        }
    }

    // Recomputes versions_behind for every hosted (origin='uploaded') version under the package,
    // using the same upstream stable-versions list resolved for the proxy plane this pass. A
    // package can carry both proxy (cache_artifact) and hosted (package_versions) rows when an org
    // pushes a private override of a name it also proxies (see LoadCombinedVersionsForOrgAsync).
    private async Task UpdateHostedVersionsBehindAsync(
        string packageId, string ecosystem, IReadOnlyList<string>? stableVersionsDescending, CancellationToken ct)
    {
        var hostedVersions = await _packages.GetVersionsAsync(packageId, ct);
        foreach (var ver in hostedVersions)
        {
            if (ver.Origin != "uploaded" || ct.IsCancellationRequested)
            {
                continue;
            }

            int? behind = EcosystemVersionOrdering.CountNewerStable(ecosystem, stableVersionsDescending, ver.Version);
            await _packages.UpdateVersionsBehindAsync(ver.Id, behind, ct);
        }
    }

    // Applies the upstream deprecation value to each cache_artifact row for the group and, for
    // ecosystems whose upstream metadata enumerates the full per-version set, detects/clears
    // revocations. Returns the per-version counters plus the versions newly revoked this pass.
    private async Task<(int Checked, int Updated, List<(string Version, string? Purl)> NewlyRevoked)> ProcessVersionsAsync(
        string ecosystem,
        IReadOnlyList<(string Id, string Version, string? Deprecated, string? DeprecationCheckedAt, string? RevokedAt, string? Purl)> versions,
        Dictionary<string, string?> upstreamDeprecated,
        IReadOnlyList<string>? stableVersionsDescending,
        CancellationToken ct)
    {
        int checked_ = 0;
        int updated = 0;

        // Revocation detection runs only for ecosystems whose upstream metadata enumerates the
        // full per-version set (npm `versions`, PyPI `releases`) AND only when that fetch returned
        // a non-empty set. An empty set means an answer listing no versions, such as a
        // whole-package removal (or a Maven group, which carries no per-version metadata) — never
        // a per-version removal, so it must not produce a false revocation. A pass with no answer
        // at all never reaches here. NuGet never unpublishes a version, and its listing map can
        // lack a version only because a page was not read, so it never revokes either.
        bool detectRevocations = ecosystem is "npm" or "pypi" && upstreamDeprecated.Count > 0;

        // Maven answers carry no deprecation signal, so the pass writes no deprecation verdict for
        // them, rather than clearing a value with an empty map that only means "not read".
        bool recordsDeprecation = ecosystem is not "maven";

        // For npm, PyPI and Hex the map is the whole answer, so a version absent from it is not
        // deprecated. NuGet's map holds only the versions whose registration leaf was read this
        // pass (an index source that failed, or a page that could not be fetched, leaves versions
        // out), so an absent NuGet version gets no verdict and keeps what is recorded.
        bool absentIsVerdict = ecosystem is not "nuget";
        var newlyRevoked = new List<(string Version, string? Purl)>();

        foreach (var ver in versions)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            // Look up the upstream deprecated value for this version. An absent key is "not
            // deprecated" except for NuGet, where it is no verdict (see absentIsVerdict).
            string versionKey = ecosystem == "nuget" ? NuGetNormalization.NormalizeVersion(ver.Version) : ver.Version;
            bool hasVerdict = upstreamDeprecated.TryGetValue(versionKey, out string? upstreamValue) || absentIsVerdict;

            checked_++;
            DependablyMeter.DeprecationRefreshChecked.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem));

            if (recordsDeprecation && hasVerdict && upstreamValue != ver.Deprecated)
            {
                await _cacheArtifacts.UpdateDeprecationAsync(ver.Id, upstreamValue, _time, ct);
                updated++;
                DependablyMeter.DeprecationRefreshUpdated.Add(1,
                    new KeyValuePair<string, object?>("ecosystem", ecosystem));
            }
            else if (recordsDeprecation && hasVerdict)
            {
                await _cacheArtifacts.TouchDeprecationCheckedAtAsync(ver.Id, _time, ct);
            }

            // Recomputed every pass (independent of whether deprecated changed) — upstream keeps
            // publishing new versions even when this version's own deprecation state is stable.
            int? versionsBehind = EcosystemVersionOrdering.CountNewerStable(ecosystem, stableVersionsDescending, ver.Version);
            await _cacheArtifacts.UpdateVersionsBehindAsync(ver.Id, versionsBehind, ct);

            if (detectRevocations)
            {
                await ApplyRevocationAsync(ecosystem, ver, upstreamDeprecated, newlyRevoked, ct);
            }
        }

        return (checked_, updated, newlyRevoked);
    }

    // Sets or clears the revocation marker for one version based on whether it is still present
    // in the upstream-declared set: an absent version is newly revoked and recorded once for the
    // activity log, while a reappeared version clears a previously-set marker.
    private async Task ApplyRevocationAsync(
        string ecosystem,
        (string Id, string Version, string? Deprecated, string? DeprecationCheckedAt, string? RevokedAt, string? Purl) ver,
        Dictionary<string, string?> upstreamDeprecated,
        List<(string Version, string? Purl)> newlyRevoked,
        CancellationToken ct)
    {
        // ContainsKey (not TryGetValue): an absent key is the revocation signal, whereas a
        // present-but-null value is a published, non-deprecated version.
        bool presentUpstream = upstreamDeprecated.ContainsKey(ver.Version);
        if (!presentUpstream && ver.RevokedAt is null)
        {
            await _cacheArtifacts.SetRevokedAtAsync(ver.Id, _time, ct);
            DependablyMeter.VersionsRevoked.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem));
            if (!newlyRevoked.Any(r => r.Version == ver.Version))
            {
                newlyRevoked.Add((ver.Version, ver.Purl));
            }
        }
        else if (presentUpstream && ver.RevokedAt is not null)
        {
            // Reappeared upstream — clear the revocation marker.
            await _cacheArtifacts.ClearRevokedAtAsync(ver.Id, ct);
        }
    }

    // One forensic activity row per newly-revoked version (not per file row), since a
    // disappearance upstream can signal an upstream takedown of a compromised release.
    private async Task LogRevokedActivitiesAsync(
        string orgId, string ecosystem, string name,
        List<(string Version, string? Purl)> newlyRevoked, CancellationToken ct)
    {
        foreach (var (version, purl) in newlyRevoked)
        {
            try
            {
                string detail = System.Text.Json.JsonSerializer.Serialize(
                    new { version, revoked_at = _time.GetUtcNow().ToUtcIso() }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
                // audit-attribution-ok: scheduled deprecation-refresh sweep — runs off a
                // background timer with no inbound request, so there is no source IP to record.
                await _audit.LogActivityAsync(
                    orgId,
                    ecosystem: ecosystem,
                    purl: purl,
                    eventType: "version_revoked",
                    actorId: null,
                    actorKind: "system",
                    detail: detail,
                    ct: ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to log version_revoked activity for {OrgId}/{Package}@{Version}: {ExceptionType}",
                    orgId, name, version, ex.GetType().Name);
            }
        }
    }

    // Logs a single summary activity row for the group's refresh pass, when at least one version
    // was checked.
    private async Task LogRefreshSummaryAsync(
        string orgId, string ecosystem, string name, int checked_, int updated, CancellationToken ct)
    {
        if (checked_ <= 0)
        {
            return;
        }

        try
        {
            // audit-attribution-ok: scheduled deprecation-refresh sweep — runs off a background
            // timer with no inbound request, so there is no source IP to record.
            await _audit.LogActivityAsync(
                orgId,
                ecosystem: ecosystem,
                purl: null,
                eventType: "deprecation_refresh",
                actorId: null,
                actorKind: "system",
                detail: $"Checked {checked_} version(s) for {name}, {updated} updated",
                ct: ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to log deprecation_refresh activity for {OrgId}/{Package}: {ExceptionType}",
                orgId, name, ex.GetType().Name);
        }
    }

    // Hex advertises a cached release's retirement from its hex_release row, not from
    // cache_artifact.deprecated: the signed /packages resource this registry serves is built from
    // that row, so a retirement (or un-retirement) upstream reaches Mix and Rebar3 only once it is
    // written there too. Every cached release is set or cleared from the same verified resource
    // that produced the deprecation map.
    private async Task ApplyHexRetirementsAsync(
        IReadOnlyList<(string Id, string Version, string? Deprecated, string? DeprecationCheckedAt, string? RevokedAt, string? Purl)> versions,
        IReadOnlyDictionary<string, Protocol.Hex.HexRetirementStatus> retirements,
        CancellationToken ct)
    {
        foreach (var ver in versions)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            retirements.TryGetValue(ver.Version, out var retired);
            await _hexReleases.SetCachedRetirementAsync(ver.Id, retired?.Reason, retired?.Message, ct);
        }
    }

    private static bool IsSupportedEcosystem(string ecosystem) => DeprecationRefreshEcosystems.Contains(ecosystem);

    // A body the metadata cache served past its TTL because the upstream failed is the last answer
    // that source gave, not a current one, so it is no answer from that source and the next one
    // is asked.
    private void LogStaleAnswer(string ecosystem, string package) =>
        _logger.LogWarning(
            "{Ecosystem} metadata for {Package} was served stale from the metadata cache because the upstream failed; not reading it as an answer.",
            ecosystem, package);

    // A 2xx body that lacks the per-version object (npm `versions`, PyPI `releases`) is not a
    // packument or project document at all, such as a mirror's `{}` or error envelope, so it is no
    // answer from that source and the next one is asked.
    private void LogUnusableDocument(string ecosystem, string package) =>
        _logger.LogWarning(
            "{Ecosystem} metadata for {Package} carried no per-version object; not reading it as an answer.",
            ecosystem, package);

    // Per-version deprecation map plus upstream's declared latest version (and, where the
    // ecosystem's metadata carries one, its publish timestamp). npm/PyPI carry a per-version
    // deprecation signal AND a latest tag in one document. NuGet resolves its latest through the
    // resolver and its per-version listing state from the registration index; Maven has no
    // deprecation signal the pass reads, so its map is empty and ProcessVersionsAsync writes no
    // deprecation for it. A null map means no source gave an answer (for Hex, a verified one) and
    // the group records nothing — for every ecosystem. HexRetirements is the per-release
    // retirement status for Hex, null for every other ecosystem.
    private async Task<(Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest,
        IReadOnlyDictionary<string, Protocol.Hex.HexRetirementStatus>? HexRetirements)> FetchUpstreamMetadataAsync(
        string ecosystem, string orgId, string purlName, IReadOnlyList<UpstreamSource> sources, CancellationToken ct)
    {
        switch (ecosystem)
        {
            case "npm":
                {
                    var (deprecated, latest) = await FetchNpmMetadataAsync(sources, purlName, ct);
                    return (deprecated, latest, null);
                }
            case "pypi":
                {
                    var (deprecated, latest) = await FetchPyPiMetadataAsync(sources, purlName, ct);
                    return (deprecated, latest, null);
                }
            case "nuget":
                return await FetchNuGetMetadataAsync(orgId, purlName, sources, ct);
            case "maven":
                {
                    // The resolver returns no version when no source answered with a release
                    // (every source non-2xx, or none listing one): that is no answer, not a
                    // verdict that the package has no latest.
                    var latest = await _latestResolver.ResolveFreshAsync(ecosystem, orgId, purlName, ct);
                    return latest.IsReserved || latest.Version is not null
                        ? (new Dictionary<string, string?>(), latest, null)
                        : (null, UpstreamLatestVersion.None, null);
                }
            case "hex":
                return await FetchHexMetadataAsync(orgId, purlName, ct);
            default:
                return (new Dictionary<string, string?>(), UpstreamLatestVersion.None, null);
        }
    }

    // NuGet: the latest-stable release comes from the resolver (flatcontainer), and each
    // version's listing state from one registration-index read per package. Both reads decline a
    // body the metadata cache served stale. A resolver with no live answer is no answer for the
    // group, so the index is not read and nothing is recorded. When
    // the resolver answered but no index source did, the latest and versions-behind facts are
    // recorded and the empty listing map gives no version a deprecation verdict.
    private async Task<(Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest,
        IReadOnlyDictionary<string, Protocol.Hex.HexRetirementStatus>? HexRetirements)> FetchNuGetMetadataAsync(
        string orgId, string purlName, IReadOnlyList<UpstreamSource> sources, CancellationToken ct)
    {
        var latest = await _latestResolver.ResolveFreshAsync("nuget", orgId, purlName, ct);
        if (latest.IsReserved)
        {
            return (new Dictionary<string, string?>(), latest, null);
        }

        if (latest.Version is null)
        {
            return (null, UpstreamLatestVersion.None, null);
        }

        var listing = await NuGetUpstreamListingFetcher.FetchAsync(_upstream, sources, purlName, _logger, ct);
        if (listing is null)
        {
            _logger.LogInformation(
                "Deprecation refresh recorded no listing state for nuget/{Package}: no registration index source gave an answer.",
                purlName);
            return (new Dictionary<string, string?>(), latest, null);
        }

        return (new Dictionary<string, string?>(listing, StringComparer.OrdinalIgnoreCase), latest, null);
    }

    // Fetches the npm packument and extracts deprecated per version plus dist-tags.latest (and its
    // publish time from the packument's time[] map). The packument is a JSON object with a
    // "versions" property mapping version string → metadata. Within each version object,
    // "deprecated" is a string (or absent) per npm spec; the package's newest published version is
    // "dist-tags".latest.
    //
    // The upstream sources are resolved once by the caller (ProcessGroupAsync) through
    // UpstreamRegistryResolver — the same DB-backed, priority-ordered source the hosted proxy
    // handlers and UpstreamLatestVersionResolver use — so a private mirror and the
    // empty=disabled contract are honoured identically here rather than a hardcoded
    // public-registry default bypassing both, without a second decrypt pass over the same rows.
    private async Task<(Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest)> FetchNpmMetadataAsync(
        IReadOnlyList<UpstreamSource> sources, string purlName, CancellationToken ct)
    {
        // npm scoped packages have purlName encoded as %40scope%2Fpkg; the packument URL uses @scope/pkg.
        string packageName = PurlNormalizer.NpmPackageName(purlName);

        foreach (var source in sources)
        {
            // Abbreviated-document fallback for packuments past the metadata byte cap; the
            // abbreviated document still carries per-version "deprecated" and dist-tags, which is
            // all this method reads (the missing time[] map only nulls publishedAt).
            var response = await NpmPackumentFetcher.FetchAsync(
                _upstream, $"{source.Url}/{packageName}", source.AuthorizationHeader, _logger, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("npm packument fetch returned {StatusCode} for {Package}.", response.StatusCode, packageName);
                continue;
            }

            if (response.IsStale)
            {
                LogStaleAnswer("npm", packageName);
                continue;
            }

            using var doc = JsonDocument.Parse(response.Body);
            var parsed = ParseNpmPackument(doc.RootElement);
            if (parsed.Deprecated is null)
            {
                LogUnusableDocument("npm", packageName);
                continue;
            }

            return parsed;
        }

        // No configured source gave a live 2xx answer, so there is no verdict: the null map makes
        // the caller record nothing. Never fall back to a hardcoded public registry. (Zero
        // configured sources is filtered out by the caller before this method is ever invoked.)
        return (null, UpstreamLatestVersion.None);
    }

    // Hex: the signed package resource carries every release's retirement status — Hex's
    // deprecation — beside its publish time, so one verified fetch yields both the per-version
    // deprecation map and the latest stable, non-retired release. Every source is read through
    // the shared verified fetcher, which skips an upstream with no configured public key and,
    // asked for a fresh answer, a resource the metadata cache served stale; when no source yields
    // a live verified resource the map is null, so the caller records nothing.
    private async Task<(Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest,
        IReadOnlyDictionary<string, Protocol.Hex.HexRetirementStatus>? HexRetirements)> FetchHexMetadataAsync(
        string orgId, string purlName, CancellationToken ct)
    {
        var result = await Protocol.Hex.HexUpstreamPackageFetcher.FetchAsync(
            _upstream, _registries, orgId, purlName, _logger, _hexMasterKeys, requireFresh: true, ct);
        if (result.Package is null)
        {
            return (null, UpstreamLatestVersion.None, null);
        }

        var deprecated = new Dictionary<string, string?>(StringComparer.Ordinal);
        var retirements = new Dictionary<string, Protocol.Hex.HexRetirementStatus>(StringComparer.Ordinal);
        foreach (var release in result.Package.Releases)
        {
            if (release.Retired is { } retired)
            {
                deprecated[release.Version] = Protocol.Hex.HexIndexBuilder.RetirementAsDeprecation(retired);
                retirements[release.Version] = retired;
            }
        }

        var stable = Protocol.Hex.HexUpstreamPackageFetcher.StableVersionsDescending(result.Package);
        var latestRelease = stable.Count == 0 ? null : result.Package.Releases.FirstOrDefault(r => r.Version == stable[0]);
        var latest = stable.Count == 0
            ? UpstreamLatestVersion.None
            : new UpstreamLatestVersion(stable[0], latestRelease?.PublishedAt?.ToDateTimeOffset(), stable);
        return (deprecated, latest, retirements);
    }

    // Fetches the PyPI project JSON and extracts yanked status per release plus info.version (and
    // its publish time from the top-level urls[] array, which lists the latest release's own
    // distribution files). A release is yanked if any of its distribution files has yanked=true;
    // we map yanked releases to a deprecation message (yanked_reason or a default).
    //
    // The upstream sources are resolved once by the caller (ProcessGroupAsync) through
    // UpstreamRegistryResolver — the same DB-backed, priority-ordered source the hosted proxy
    // handlers and UpstreamLatestVersionResolver use — so a private mirror and the
    // empty=disabled contract are honoured identically here rather than a hardcoded
    // public-registry default bypassing both, without a second decrypt pass over the same rows.
    private async Task<(Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest)> FetchPyPiMetadataAsync(
        IReadOnlyList<UpstreamSource> sources, string purlName, CancellationToken ct)
    {
        foreach (var source in sources)
        {
            var response = await _upstream.GetOrFetchMetadataAsync($"{source.Url}/pypi/{purlName}/json", source.AuthorizationHeader, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("PyPI project JSON fetch returned {StatusCode} for {Package}.", response.StatusCode, purlName);
                continue;
            }

            if (response.IsStale)
            {
                LogStaleAnswer("pypi", purlName);
                continue;
            }

            using var doc = JsonDocument.Parse(response.Body);
            var parsed = ParsePyPiProject(doc.RootElement);
            if (parsed.Deprecated is null)
            {
                LogUnusableDocument("pypi", purlName);
                continue;
            }

            return parsed;
        }

        // No configured source gave a live 2xx answer, so there is no verdict: the null map makes
        // the caller record nothing. Never fall back to a hardcoded public registry. (Zero
        // configured sources is filtered out by the caller before this method is ever invoked.)
        return (null, UpstreamLatestVersion.None);
    }

    // Reads one already-fetched npm packument: per-version "deprecated" strings, dist-tags.latest,
    // and that version's publish time from the time[] map. An abbreviated packument carries no
    // time[] map, which only nulls publishedAt.
    // A document with no object-valued "versions", or an empty one, yields a null map: no answer.
    // An empty version list cannot be a verdict on versions this registry holds, so it must not
    // clear their recorded deprecations.
    internal static (Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest) ParseNpmPackument(
        JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("versions", out var versionsEl)
            || versionsEl.ValueKind != JsonValueKind.Object)
        {
            return (null, UpstreamLatestVersion.None);
        }

        string? latest = ReadNonEmptyString(root, "dist-tags", "latest");
        var publishedAt = ReadNpmPublishTime(root, latest);
        var result = new Dictionary<string, string?>(VersionIdentity.Comparer("npm"));

        foreach (var entry in versionsEl.EnumerateObject())
        {
            result[entry.Name] = ReadNonEmptyString(entry.Value, "deprecated");
        }

        if (result.Count == 0)
        {
            return (null, UpstreamLatestVersion.None);
        }

        var stableVersions = EcosystemVersionOrdering.OrderStableDescending("npm", result.Keys);
        return (result, new UpstreamLatestVersion(latest, publishedAt, stableVersions));
    }

    // Reads one already-fetched PyPI project document: per-release yank status, info.version, and
    // the latest release's publish time from the top-level urls[] array.
    // A document with no object-valued "releases", or an empty one, yields a null map: no answer.
    // An empty release list cannot be a verdict on releases this registry holds, so it must not
    // clear their recorded yanks.
    internal static (Dictionary<string, string?>? Deprecated, UpstreamLatestVersion Latest) ParsePyPiProject(
        JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("releases", out var releasesEl)
            || releasesEl.ValueKind != JsonValueKind.Object)
        {
            return (null, UpstreamLatestVersion.None);
        }

        string? latest = ReadNonEmptyString(root, "info", "version");
        var publishedAt = ReadPyPiUploadTime(root);
        var result = new Dictionary<string, string?>(VersionIdentity.Comparer("pypi"));

        foreach (var release in releasesEl.EnumerateObject())
        {
            result[release.Name] = ExtractYankedDeprecation(release.Value);
        }

        if (result.Count == 0)
        {
            return (null, UpstreamLatestVersion.None);
        }

        var stableVersions = EcosystemVersionOrdering.OrderStableDescending("pypi", result.Keys);
        return (result, new UpstreamLatestVersion(latest, publishedAt, stableVersions));
    }

    // The publish time of the packument's dist-tags.latest, read from the time[] map. Null when
    // there is no latest tag, no time[] map, no entry for that version, or an unparseable stamp.
    private static DateTimeOffset? ReadNpmPublishTime(JsonElement root, string? latest)
    {
        return latest is not null
            && root.TryGetProperty("time", out var time)
            && time.ValueKind == JsonValueKind.Object
            && time.TryGetProperty(latest, out var timeEl)
            && timeEl.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(timeEl.GetString(), CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var ts)
            ? ts
            : null;
    }

    // The first parseable upload_time_iso_8601 in the project document's top-level urls[] array,
    // which lists the latest release's own distribution files.
    private static DateTimeOffset? ReadPyPiUploadTime(JsonElement root)
    {
        if (!root.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var file in urls.EnumerateArray())
        {
            if (file.TryGetProperty("upload_time_iso_8601", out var uploadEl)
                && uploadEl.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(uploadEl.GetString(), CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var ts))
            {
                return ts;
            }
        }

        return null;
    }

    // Reads a JSON string property, collapsing absent/wrong-kind/blank to null so a whitespace-only
    // upstream value never reads as a real version or deprecation message. The object-kind guard is
    // what keeps a malformed upstream document from throwing out of TryGetProperty.
    private static string? ReadNonEmptyString(JsonElement owner, string name)
    {
        if (owner.ValueKind != JsonValueKind.Object
            || !owner.TryGetProperty(name, out var element)
            || element.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? value = element.GetString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    // The nested form: owner.parent.name, with the same absent/wrong-kind/blank collapse.
    private static string? ReadNonEmptyString(JsonElement owner, string parent, string name)
    {
        return owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(parent, out var element)
            ? ReadNonEmptyString(element, name)
            : null;
    }

    // A release is yanked if any of its distribution files has yanked=true; maps to the
    // yanked_reason or a default "yanked" marker. Returns null when no file is yanked.
    private static string? ExtractYankedDeprecation(JsonElement releaseFiles)
    {
        foreach (var file in releaseFiles.EnumerateArray())
        {
            if (!file.TryGetProperty("yanked", out var yankedEl) || !yankedEl.GetBoolean())
            {
                continue;
            }

            string? reason = file.TryGetProperty("yanked_reason", out var reasonEl)
                ? reasonEl.GetString()
                : null;
            return string.IsNullOrWhiteSpace(reason) ? "yanked" : reason;
        }
        return null;
    }
}
