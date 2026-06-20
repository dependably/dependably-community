using System.Text.Json;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that refreshes upstream metadata for proxy-cached package versions. Runs on
/// a cron schedule (<c>DEPRECATION_REFRESH_SCHEDULE</c> env var, default daily at 5am UTC).
///
/// Deprecation is refreshed for npm and PyPI only — they expose a per-version deprecation/yank
/// signal in a single metadata endpoint; NuGet, Maven, RPM, and OCI do not. For each stale
/// npm/PyPI package, fetches the upstream packument (npm) or project JSON (PyPI) and updates
/// <c>deprecated</c>/<c>deprecation_checked_at</c> for every version row under that package.
///
/// Upstream-latest is refreshed for npm, PyPI, NuGet, and Maven: the same npm/PyPI fetch yields
/// <c>dist-tags.latest</c>/<c>info.version</c>, while NuGet/Maven resolve their latest-stable
/// release via <see cref="Protocol.IUpstreamLatestVersionResolver"/>. The result is written to
/// <c>packages.upstream_latest_version</c>, which drives the packages-list "Latest" indicator and
/// the package-detail "behind upstream" banner. Newly-proxied packages get their baseline
/// immediately from the first-fetch recorder, so this pass keeps the baseline current rather than
/// establishing it.
/// </summary>
public sealed class DeprecationRefreshService : ScheduledBackgroundService
{
    private readonly PackageRepository _packages;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly AuditRepository _audit;
    private readonly UpstreamClient _upstream;
    private readonly IUpstreamLatestVersionResolver _latestResolver;
    private readonly IAirGapMode _airGap;
    private readonly IConfiguration _config;
    private readonly ILogger<DeprecationRefreshService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "DEPRECATION_REFRESH_SCHEDULE";
    protected override string DefaultCron => "0 5 * * *";
    protected override string? JitterEnvKey => "DEPRECATION_REFRESH_JITTER_SECONDS";
    protected override bool RunOnStartup => true;
    protected override bool ContinueOnTickError => false;

    public DeprecationRefreshService(
        PackageRepository packages,
        CacheArtifactRepository cacheArtifacts,
        AuditRepository audit,
        UpstreamClient upstream,
        IUpstreamLatestVersionResolver latestResolver,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<DeprecationRefreshService> logger,
        TimeProvider time)
        : base(config, logger, time)
    {
        _packages = packages;
        _cacheArtifacts = cacheArtifacts;
        _audit = audit;
        _upstream = upstream;
        _latestResolver = latestResolver;
        _airGap = airGap;
        _config = config;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunRefreshPassAsync(ct);

    internal async Task RunRefreshPassAsync(CancellationToken ct)
    {
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
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var groups = await _cacheArtifacts.ListGroupsNeedingDeprecationRefreshAsync(ageHours, batchSize, _time, ct);
        int totalChecked = 0;
        int totalUpdated = 0;

        foreach (var group in groups)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var (checked_, updated) = await ProcessCacheGroupAsync(group, ct);
            totalChecked += checked_;
            totalUpdated += updated;

            if (batchDelayMs > 0 && !ct.IsCancellationRequested)
            {
                try { await Task.Delay(batchDelayMs, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        sw.Stop();
        _logger.LogInformation(
            "Deprecation refresh pass complete. Checked {Checked} versions across {Groups} packages, {Updated} updated, took {ElapsedMs}ms.",
            totalChecked, groups.Count, totalUpdated, sw.ElapsedMilliseconds);
    }

    /// <summary>
    /// Processes one (ecosystem, name, orgId) group: fetches upstream metadata and writes
    /// <c>deprecated</c>/<c>deprecation_checked_at</c> to each <c>cache_artifact</c> row for
    /// that package name. One upstream fetch covers all version rows for the name.
    /// </summary>
    private async Task<(int Checked, int Updated)> ProcessCacheGroupAsync(
        (string Ecosystem, string Name, string OrgId) group,
        CancellationToken ct)
    {
        var (ecosystem, name, orgId) = group;

        if (!IsSupportedEcosystem(ecosystem))
        {
            return (0, 0);
        }

        Dictionary<string, string?> upstreamDeprecated;
        string? upstreamLatest;
        try
        {
            (upstreamDeprecated, upstreamLatest) = await FetchUpstreamMetadataAsync(ecosystem, orgId, name, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to fetch upstream deprecation metadata for {Ecosystem}/{Package}: {ExceptionType}",
                ecosystem, name, ex.GetType().Name);
            return (0, 0);
        }

        // Record upstream's declared latest version on the packages row if one exists for this org.
        // The packages table may not have a row when the artifact was only ever accessed via the
        // global plane; skip silently in that case.
        var pkg = await _packages.GetByPurlNameAsync(orgId, ecosystem, name, ct);
        if (pkg is not null)
        {
            await _packages.UpdateUpstreamLatestAsync(pkg.Id, upstreamLatest, ct);
        }

        var versions = await _cacheArtifacts.ListVersionsForNameAsync(ecosystem, name, ct);
        int checked_ = 0;
        int updated = 0;

        foreach (var ver in versions)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            // Look up the upstream deprecated value for this version.
            // If the version key isn't present in upstream metadata, treat as not deprecated.
            upstreamDeprecated.TryGetValue(ver.Version, out string? upstreamValue);

            checked_++;
            DependablyMeter.DeprecationRefreshChecked.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem));

            if (upstreamValue != ver.Deprecated)
            {
                await _cacheArtifacts.UpdateDeprecationAsync(ver.Id, upstreamValue, _time, ct);
                updated++;
                DependablyMeter.DeprecationRefreshUpdated.Add(1,
                    new KeyValuePair<string, object?>("ecosystem", ecosystem));
            }
            else
            {
                await _cacheArtifacts.TouchDeprecationCheckedAtAsync(ver.Id, _time, ct);
            }
        }

        if (checked_ > 0)
        {
            try
            {
                await _audit.LogActivityAsync(
                    orgId,
                    ecosystem: ecosystem,
                    purl: null,
                    eventType: "deprecation_refresh",
                    actorId: null,
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

        return (checked_, updated);
    }

    private static bool IsSupportedEcosystem(string ecosystem) =>
        ecosystem is "npm" or "pypi" or "nuget" or "maven";

    // Per-version deprecation map plus upstream's declared latest version (null when absent).
    // npm/PyPI carry a per-version deprecation signal AND a latest tag in one document. NuGet and
    // Maven have no deprecation signal, so the deprecation map is empty (their cache_artifact
    // rows never set deprecated, so the empty map clears nothing) and only the latest is resolved.
    private async Task<(Dictionary<string, string?> Deprecated, string? Latest)> FetchUpstreamMetadataAsync(
        string ecosystem, string orgId, string purlName, CancellationToken ct)
    {
        return ecosystem switch
        {
            "npm" => await FetchNpmMetadataAsync(purlName, ct),
            "pypi" => await FetchPyPiMetadataAsync(purlName, ct),
            "nuget" or "maven" =>
                (new Dictionary<string, string?>(), await _latestResolver.ResolveAsync(ecosystem, orgId, purlName, ct)),
            _ => (new Dictionary<string, string?>(), null)
        };
    }

    // Fetches the npm packument and extracts deprecated per version plus dist-tags.latest.
    // The packument is a JSON object with a "versions" property mapping version string → metadata.
    // Within each version object, "deprecated" is a string (or absent) per npm spec; the package's
    // newest published version is "dist-tags".latest.
    private async Task<(Dictionary<string, string?> Deprecated, string? Latest)> FetchNpmMetadataAsync(string purlName, CancellationToken ct)
    {
        string upstream = _config["Npm:Upstream"] ?? "https://registry.npmjs.org";
        // npm scoped packages have purlName encoded as %40scope%2Fpkg; the packument URL uses @scope/pkg.
        string packageName = Uri.UnescapeDataString(purlName).Replace("%40", "@").Replace("%2F", "/");
        string url = $"{upstream.TrimEnd('/')}/{packageName}";

        var response = await _upstream.GetOrFetchMetadataAsync(url, ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("npm packument fetch returned {StatusCode} for {Package}.", response.StatusCode, packageName);
            return (new Dictionary<string, string?>(), null);
        }

        using var doc = JsonDocument.Parse(response.Body);
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        string? latest = null;
        if (doc.RootElement.TryGetProperty("dist-tags", out var distTags)
            && distTags.TryGetProperty("latest", out var latestEl)
            && latestEl.ValueKind == JsonValueKind.String)
        {
            latest = latestEl.GetString();
            if (string.IsNullOrWhiteSpace(latest))
            {
                latest = null;
            }
        }

        if (!doc.RootElement.TryGetProperty("versions", out var versionsEl))
        {
            return (result, latest);
        }

        foreach (var entry in versionsEl.EnumerateObject())
        {
            string? deprecated = null;
            if (entry.Value.TryGetProperty("deprecated", out var depEl)
                && depEl.ValueKind == JsonValueKind.String)
            {
                deprecated = depEl.GetString();
                if (string.IsNullOrWhiteSpace(deprecated))
                {
                    deprecated = null;
                }
            }
            result[entry.Name] = deprecated;
        }
        return (result, latest);
    }

    // Fetches the PyPI project JSON and extracts yanked status per release plus info.version.
    // A release is yanked if any of its distribution files has yanked=true; we map yanked releases
    // to a deprecation message (yanked_reason or a default). info.version is PyPI's latest release.
    private async Task<(Dictionary<string, string?> Deprecated, string? Latest)> FetchPyPiMetadataAsync(string purlName, CancellationToken ct)
    {
        string upstream = _config["PyPI:Upstream"] ?? "https://pypi.org";
        string url = $"{upstream.TrimEnd('/')}/pypi/{purlName}/json";

        var response = await _upstream.GetOrFetchMetadataAsync(url, ct);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("PyPI project JSON fetch returned {StatusCode} for {Package}.", response.StatusCode, purlName);
            return (new Dictionary<string, string?>(), null);
        }

        using var doc = JsonDocument.Parse(response.Body);
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        string? latest = null;
        if (doc.RootElement.TryGetProperty("info", out var info)
            && info.TryGetProperty("version", out var versionEl)
            && versionEl.ValueKind == JsonValueKind.String)
        {
            latest = versionEl.GetString();
            if (string.IsNullOrWhiteSpace(latest))
            {
                latest = null;
            }
        }

        if (!doc.RootElement.TryGetProperty("releases", out var releasesEl))
        {
            return (result, latest);
        }

        foreach (var release in releasesEl.EnumerateObject())
        {
            result[release.Name] = ExtractYankedDeprecation(release.Value);
        }

        return (result, latest);
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
