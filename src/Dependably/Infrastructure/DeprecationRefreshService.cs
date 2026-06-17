using System.Text.Json;
using Cronos;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Background service that refreshes upstream deprecation metadata for proxy-cached package
/// versions. Runs on a cron schedule (<c>DEPRECATION_REFRESH_SCHEDULE</c> env var, default
/// daily at 5am UTC). Supports npm and PyPI; NuGet, Maven, RPM, and OCI are skipped (no
/// reliable upstream deprecation signal in a single metadata endpoint).
///
/// For each stale package, fetches the upstream packument (npm) or project JSON (PyPI) and
/// updates <c>package_versions.deprecated</c> and <c>package_versions.deprecation_checked_at</c>
/// for every version row under that package. The same fetch also records upstream's declared
/// latest version (npm <c>dist-tags.latest</c> / PyPI <c>info.version</c>) on
/// <c>packages.upstream_latest_version</c>, which drives the packages-list "Latest" indicator.
/// </summary>
public sealed class DeprecationRefreshService : BackgroundService
{
    private readonly PackageRepository _packages;
    private readonly AuditRepository _audit;
    private readonly UpstreamClient _upstream;
    private readonly IAirGapMode _airGap;
    private readonly IConfiguration _config;
    private readonly ILogger<DeprecationRefreshService> _logger;
    private readonly TimeProvider _time;

    public DeprecationRefreshService(
        PackageRepository packages,
        AuditRepository audit,
        UpstreamClient upstream,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<DeprecationRefreshService> logger,
        TimeProvider time)
    {
        _packages = packages;
        _audit = audit;
        _upstream = upstream;
        _airGap = airGap;
        _config = config;
        _logger = logger;
        _time = time;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RunRefreshPassAsync(stoppingToken);

        var schedule = CronExpression.Parse(
            _config["DEPRECATION_REFRESH_SCHEDULE"] ?? "0 5 * * *",
            CronFormat.Standard);

        while (!stoppingToken.IsCancellationRequested)
        {
            var next = schedule.GetNextOccurrence(_time.GetUtcNow(), TimeZoneInfo.Utc);
            if (next is null)
            {
                break;
            }

            int jitterMaxSeconds = int.TryParse(_config["DEPRECATION_REFRESH_JITTER_SECONDS"], out int j) && j >= 0 ? j : 3600;
            // SCS0005: load-spreading jitter, not a security boundary — weak RNG is intentional.
#pragma warning disable SCS0005
            var jitter = jitterMaxSeconds > 0
                ? TimeSpan.FromSeconds(Random.Shared.Next(0, jitterMaxSeconds + 1))
                : TimeSpan.Zero;
#pragma warning restore SCS0005
            var delay = (next.Value - _time.GetUtcNow()) + jitter;
            if (delay > TimeSpan.Zero)
            {
                try { await Task.Delay(delay, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }

            if (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            await RunRefreshPassAsync(stoppingToken);
        }
    }

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
        if (_airGap.IsEnabled)
        {
            _logger.LogInformation("Deprecation refresh skipped: air-gap mode is enabled.");
            return;
        }

        int ageHours = int.TryParse(_config["DEPRECATION_REFRESH_AGE_HOURS"], out int h) && h > 0 ? h : 24;
        int batchSize = int.TryParse(_config["DEPRECATION_REFRESH_BATCH_SIZE"], out int bs) && bs > 0 ? bs : 500;
        int batchDelayMs = int.TryParse(_config["DEPRECATION_REFRESH_BATCH_DELAY_MS"], out int d) ? d : 500;

        _logger.LogInformation(
            "Deprecation refresh pass starting (ageHours={AgeHours}, batchSize={BatchSize}).",
            ageHours, batchSize);
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var packages = await _packages.ListPackagesNeedingDeprecationRefreshAsync(ageHours, batchSize, ct);
        int totalChecked = 0;
        int totalUpdated = 0;

        foreach (var pkg in packages)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var (checked_, updated) = await ProcessPackageAsync(pkg, ct);
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
            "Deprecation refresh pass complete. Checked {Checked} versions across {Packages} packages, {Updated} updated, took {ElapsedMs}ms.",
            totalChecked, packages.Count, totalUpdated, sw.ElapsedMilliseconds);
    }

    private async Task<(int Checked, int Updated)> ProcessPackageAsync(
        (string PackageId, string Ecosystem, string PurlName, string OrgId) pkg,
        CancellationToken ct)
    {
        var (packageId, ecosystem, purlName, orgId) = pkg;

        if (!IsSupportedEcosystem(ecosystem))
        {
            return (0, 0);
        }

        Dictionary<string, string?> upstreamDeprecated;
        string? upstreamLatest;
        try
        {
            (upstreamDeprecated, upstreamLatest) = await FetchUpstreamMetadataAsync(ecosystem, purlName, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to fetch upstream deprecation metadata for {Ecosystem}/{Package}: {ExceptionType}",
                ecosystem, purlName, ex.GetType().Name);
            return (0, 0);
        }

        // Record upstream's declared latest version for the packages-list "Latest" indicator.
        // Null clears any stale baseline (upstream had no latest claim).
        await _packages.UpdateUpstreamLatestAsync(packageId, upstreamLatest, ct);

        var versions = await _packages.GetVersionsAsync(packageId, ct);
        int checked_ = 0;
        int updated = 0;

        foreach (var ver in versions)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            if (ver.Origin != "proxy")
            {
                continue;
            }

            // Look up the upstream deprecated value for this version.
            // If the version key isn't present in upstream metadata, treat as not deprecated.
            upstreamDeprecated.TryGetValue(ver.Version, out string? upstreamValue);

            checked_++;
            DependablyMeter.DeprecationRefreshChecked.Add(1,
                new KeyValuePair<string, object?>("ecosystem", ecosystem));

            if (upstreamValue != ver.Deprecated)
            {
                await _packages.UpdateDeprecatedAndCheckedAsync(ver.Id, upstreamValue, ct);
                updated++;
                DependablyMeter.DeprecationRefreshUpdated.Add(1,
                    new KeyValuePair<string, object?>("ecosystem", ecosystem));
            }
            else
            {
                await _packages.UpdateDeprecationCheckedAtAsync(ver.Id, ct);
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
                    detail: $"Checked {checked_} version(s) for {purlName}, {updated} updated",
                    ct: ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to log deprecation_refresh activity for {OrgId}/{Package}: {ExceptionType}",
                    orgId, purlName, ex.GetType().Name);
            }
        }

        return (checked_, updated);
    }

    private static bool IsSupportedEcosystem(string ecosystem) =>
        ecosystem is "npm" or "pypi";

    // Per-version deprecation map plus upstream's declared latest version (null when absent).
    private async Task<(Dictionary<string, string?> Deprecated, string? Latest)> FetchUpstreamMetadataAsync(
        string ecosystem, string purlName, CancellationToken ct)
    {
        return ecosystem switch
        {
            "npm" => await FetchNpmMetadataAsync(purlName, ct),
            "pypi" => await FetchPyPiMetadataAsync(purlName, ct),
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
