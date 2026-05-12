using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// Offline <see cref="IOsvSource"/> for air-gapped deployments (#41). Reads OSV JSON dumps
/// from a sideloaded directory at <c>OSV_LOCAL_PATH</c> and answers queries from an
/// in-memory index. The operator's out-of-band process refreshes the directory; this source
/// re-loads on a configurable interval (<c>OSV_LOCAL_REFRESH_MINUTES</c>, default 60).
///
/// Dump shape: any directory tree of <c>.json</c> files in OSV schema format
/// (<see href="https://ossf.github.io/osv-schema/"/>). The bgzipped per-ecosystem dumps
/// from osv.dev are the canonical source — the operator unzips them under
/// <c>OSV_LOCAL_PATH</c> on a refresh cycle.
///
/// Severity: prefers the dump's <c>severity[].score</c> CVSS vector (computed via the same
/// helper used by the remote client) and falls back to <c>database_specific.severity</c>.
/// CVSS computation for offline mode delegates to <see cref="OsvScoring"/>.
/// </summary>
public sealed class LocalOsvSource : IOsvSource, IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    private readonly string _path;
    private readonly ILogger<LocalOsvSource> _logger;
    private readonly Lazy<Task> _initialLoad;
    private readonly System.Threading.Timer? _refreshTimer;

    // Index by (ecosystem-lowercase, name-lowercase) → list of advisories.
    // Replaced atomically on each reload; reads can run lock-free.
    private volatile Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>> _index =
        new(EcosystemNameComparer.Instance);

    public LocalOsvSource(IConfiguration config, ILogger<LocalOsvSource> logger)
    {
        _logger = logger;
        _path = config["OSV_LOCAL_PATH"]
            ?? throw new InvalidOperationException(
                "OSV_LOCAL_PATH is required when OSV_MODE=local.");
        var minutes = int.TryParse(config["OSV_LOCAL_REFRESH_MINUTES"], out var m) && m > 0 ? m : 60;
        var refreshInterval = TimeSpan.FromMinutes(minutes);

        _initialLoad = new Lazy<Task>(() => Task.Run(() => ReloadAsync(default)));
        _refreshTimer = new System.Threading.Timer(OnRefreshTick, null, refreshInterval, refreshInterval);
    }

    /// <summary>Test-only constructor: fixed path, no refresh timer.</summary>
    internal LocalOsvSource(string path, ILogger<LocalOsvSource> logger)
    {
        _logger = logger;
        _path = path;
        _initialLoad = new Lazy<Task>(() => Task.Run(() => ReloadAsync(default)));
    }

    /// <summary>
    /// Timer callback. Discards the task return because the timer can't observe completion
    /// anyway — exceptions surface in <see cref="ReloadAsync"/>'s own try/catch around the
    /// per-file parse. Extracted to a named method so Sonar S1854 doesn't trip on the inline
    /// discard pattern in the constructor.
    /// </summary>
    private void OnRefreshTick(object? state) => _ = ReloadAsync(default);

    public async Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
    {
        await _initialLoad.Value;
        var parsed = ParsePurl(purl);
        if (parsed is null) return [];
        var (ecosystem, name, version) = parsed.Value;

        if (!_index.TryGetValue((ecosystem, name), out var list)) return [];

        // Match version against each advisory's affected versions. An advisory with no
        // version list (range-only) is reported — the scan service's downstream handling
        // decides what to do with range advisories.
        return list
            .Where(a => a.AffectedPackages.Any(ap =>
                MatchesEcosystemAndName(ap, ecosystem, name) &&
                (ap.Versions.Length == 0 || ap.Versions.Any(v =>
                    v.Equals(version, StringComparison.OrdinalIgnoreCase)))))
            .ToList();
    }

    public async Task<List<List<OsvAdvisory>>> QueryBatchAsync(
        IReadOnlyList<string> purls, CancellationToken ct = default)
    {
        await _initialLoad.Value;
        var result = new List<List<OsvAdvisory>>(purls.Count);
        foreach (var p in purls)
        {
            if (ct.IsCancellationRequested) break;
            result.Add(await QueryAsync(p, ct));
        }
        return result;
    }

    /// <summary>
    /// Re-reads the dump directory and rebuilds the index. Public so operators can trigger a
    /// reload via an admin endpoint (e.g. after sideloading new dumps without restarting).
    /// </summary>
    public async Task ReloadAsync(CancellationToken ct)
    {
        if (!Directory.Exists(_path))
        {
            _logger.LogWarning("OSV local path not found: {Path}", _path);
            _index = new Dictionary<(string, string), List<OsvAdvisory>>(EcosystemNameComparer.Instance);
            return;
        }

        var newIndex = new Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>>(EcosystemNameComparer.Instance);
        var loaded = 0;
        var errors = 0;

        foreach (var file in Directory.EnumerateFiles(_path, "*.json", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) break;
            if (await TryIndexFileAsync(file, newIndex, ct)) loaded++;
            else errors++;
        }

        _index = newIndex;
        _logger.LogInformation(
            "OSV local index reloaded: {Loaded} advisories, {Keys} keys, {Errors} parse errors.",
            loaded, newIndex.Count, errors);
    }

    /// <summary>
    /// Reads one OSV JSON file and merges its advisories into the building index. Returns
    /// true on success, false if parsing failed or the file was empty (cancellations
    /// propagate). Extracted so <see cref="ReloadAsync"/> stays a thin loop and the parse
    /// error path lives in one place.
    /// </summary>
    private async Task<bool> TryIndexFileAsync(
        string file,
        Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>> index,
        CancellationToken ct)
    {
        try
        {
            using var stream = File.OpenRead(file);
            var raw = await JsonSerializer.DeserializeAsync<RawOsvDump>(stream, JsonOpts, ct);
            if (raw is null) return false;

            var advisory = BuildAdvisory(raw);
            foreach (var pkg in advisory.AffectedPackages)
            {
                if (pkg.Ecosystem is null || pkg.Name is null) continue;
                var key = (pkg.Ecosystem.ToLowerInvariant(), pkg.Name.ToLowerInvariant());
                if (!index.TryGetValue(key, out var list))
                {
                    list = new List<OsvAdvisory>();
                    index[key] = list;
                }
                list.Add(advisory);
            }
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Failed to parse OSV dump: {Path}", file);
            return false;
        }
    }

    private static (string Ecosystem, string Name, string Version)? ParsePurl(string purl)
    {
        // pkg:{ecosystem}/{name}@{version}
        if (!purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return null;
        var rest = purl["pkg:".Length..];
        var slash = rest.IndexOf('/');
        if (slash < 0) return null;
        var ecosystem = rest[..slash];
        var nameAndVersion = rest[(slash + 1)..];
        var at = nameAndVersion.LastIndexOf('@');
        if (at < 0) return null;
        var name = nameAndVersion[..at];
        var version = nameAndVersion[(at + 1)..];
        return (NormalizeEcosystem(ecosystem), name.ToLowerInvariant(), version);
    }

    private static string NormalizeEcosystem(string ecosystem) => ecosystem.ToLowerInvariant() switch
    {
        // Map purl ecosystem names to OSV ecosystem names where they differ.
        "pypi" => "pypi",
        "npm" => "npm",
        "nuget" => "nuget",
        var other => other
    };

    private static bool MatchesEcosystemAndName(OsvAffectedPackage ap, string ecosystem, string name)
    {
        var apEco = ap.Ecosystem?.ToLowerInvariant();
        var apName = ap.Name?.ToLowerInvariant();
        // OSV uses "PyPI", "npm", "NuGet" (case sensitive in the schema). Match case-insensitively.
        return apEco is not null
            && apName is not null
            && string.Equals(apEco, ecosystem, StringComparison.OrdinalIgnoreCase)
            && string.Equals(apName, name, StringComparison.OrdinalIgnoreCase);
    }

    private static OsvAdvisory BuildAdvisory(RawOsvDump raw)
    {
        var affected = raw.Affected?
            .Where(a => a.Package is not null)
            .Select(a => new OsvAffectedPackage(
                Purl: a.Package!.Purl,
                Ecosystem: a.Package.Ecosystem,
                Name: a.Package.Name,
                Versions: a.Versions?.Distinct().ToArray() ?? []))
            .ToArray() ?? [];

        string? severity = null;
        double? cvssScore = null;

        var cvss = raw.Severity?.FirstOrDefault(s =>
            s.Type?.StartsWith("CVSS", StringComparison.OrdinalIgnoreCase) == true);
        if (cvss?.Score is not null)
            cvssScore = OsvScoring.ParseCvssBaseScore(cvss.Score, out severity);

        if (severity is null && raw.DatabaseSpecific is not null
            && raw.DatabaseSpecific.TryGetValue("severity", out var dbSev))
        {
            severity = dbSev?.ToString();
        }

        return new OsvAdvisory(
            Id: raw.Id ?? "",
            Aliases: raw.Aliases?.ToArray() ?? [],
            Summary: raw.Summary,
            Severity: OsvScoring.NormalizeSeverity(severity),
            CvssScore: cvssScore,
            AffectedPackages: affected,
            Published: raw.Published,
            Modified: raw.Modified,
            IsHydrated: true);
    }

    public void Dispose() => _refreshTimer?.Dispose();

    // Minimal subset of the OSV schema needed to populate OsvAdvisory.
    private sealed record RawOsvDump(
        string? Id,
        List<string>? Aliases,
        string? Summary,
        List<RawSeverity>? Severity,
        List<RawAffected>? Affected,
        string? Published,
        string? Modified,
        [property: JsonPropertyName("database_specific")] Dictionary<string, object?>? DatabaseSpecific);

    private sealed record RawSeverity(string? Type, string? Score);
    private sealed record RawAffected(RawPackage? Package, List<string>? Versions);
    private sealed record RawPackage(string? Ecosystem, string? Name, string? Purl);

    private sealed class EcosystemNameComparer : IEqualityComparer<(string, string)>
    {
        public static readonly EcosystemNameComparer Instance = new();
        public bool Equals((string, string) x, (string, string) y) =>
            string.Equals(x.Item1, y.Item1, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Item2, y.Item2, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string, string) obj) =>
            HashCode.Combine(obj.Item1.ToLowerInvariant(), obj.Item2.ToLowerInvariant());
    }
}
