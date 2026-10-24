using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// Offline <see cref="IOsvSource"/> for air-gapped deployments. Reads OSV JSON dumps
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
    private readonly ITimer? _refreshTimer;

    // Index by (ecosystem-lowercase, name-lowercase) → list of advisories.
    // Replaced atomically on each reload; reads can run lock-free.
    private volatile Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>> _index =
        new(EcosystemNameComparer.Instance);

    // Index by advisory id, for TryGetAdvisoryAsync. Replaced with _index on every reload.
    private volatile Dictionary<string, OsvAdvisory> _byId = new(StringComparer.OrdinalIgnoreCase);

    // Reachability signal for TryQueryAsync: true once a reload has successfully consulted
    // OSV_LOCAL_PATH (even if the resulting index is empty or individual files failed to
    // parse); false only when the configured directory itself does not exist — the
    // "air-gapped source is unavailable/misconfigured" case, distinct from a genuinely
    // empty or malware-free dump set.
    private volatile bool _sourceReachable;

    // Dynamic coverage signal for HasCoverageFor("rpm"): true once the current reload indexed
    // at least one advisory under a known RPM-distro ecosystem (see KnownRpmDistroEcosystems).
    // RPM has no single OSV ecosystem of its own — distro feeds are what a pkg:rpm query can
    // ever match — so unlike every other ecosystem, "the dump loaded fine" does not imply
    // "this dump could ever answer an RPM query". Set on every reload, including the
    // no-directory early return, so a dump that stops carrying distro feeds is reflected here
    // rather than sticking at whatever the previous reload found.
    private volatile bool _rpmDistroCoverageLoaded;

    // The distinct affected-package ecosystems the current index holds, so a release-scoped query
    // and HasCoverageFor can tell "this dump has no feed for that release or ecosystem" from "this
    // dump has the feed and found nothing". Replaced with the index on every reload.
    private volatile HashSet<string> _loadedEcosystems = new(StringComparer.OrdinalIgnoreCase);

    public LocalOsvSource(IConfiguration config, ILogger<LocalOsvSource> logger, TimeProvider time)
    {
        _logger = logger;
        _path = config["OSV_LOCAL_PATH"]
            ?? throw new InvalidOperationException(
                "OSV_LOCAL_PATH is required when OSV_MODE=local.");
        int minutes = int.TryParse(config["OSV_LOCAL_REFRESH_MINUTES"], out int m) && m > 0 ? m : 60;
        var refreshInterval = TimeSpan.FromMinutes(minutes);

        _initialLoad = new Lazy<Task>(() => Task.Run(() => ReloadAsync(default)));
        _refreshTimer = time.CreateTimer(OnRefreshTick, null, refreshInterval, refreshInterval);
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
        if (parsed is null)
        {
            return [];
        }

        var (ecosystem, name, version) = parsed.Value;

        if (!_index.TryGetValue((ecosystem, name), out var list))
        {
            return [];
        }

        // ParsePurl has already stripped the Go "v" prefix from the queried version; strip it from
        // the advisory side too so a dump using the prefixed form still matches.
        bool isGo = string.Equals(ecosystem, "Go", StringComparison.OrdinalIgnoreCase);

        // Match version against each advisory's affected versions. An advisory with no
        // version list (range-only) is reported — the scan service's downstream handling
        // decides what to do with range advisories.
        return list
            .Where(a => a.AffectedPackages.Any(ap =>
                MatchesEcosystemAndName(ap, ecosystem, name) &&
                (ap.Versions.Length == 0 || ap.Versions.Any(v =>
                    (isGo ? StripGoVersionPrefix(v) : v)
                        .Equals(version, StringComparison.OrdinalIgnoreCase)))))
            .ToList();
    }

    /// <summary>
    /// Same query as <see cref="QueryAsync"/>, but reports whether the local dump directory
    /// was actually consulted. Reached is true whenever the last reload found
    /// <c>OSV_LOCAL_PATH</c> present — a genuinely empty or malware-free index still counts as
    /// reached. Reached is false only when the directory itself is missing (unavailable or
    /// misconfigured), matching <see cref="ReloadAsync"/>'s early-return branch.
    /// </summary>
    public async Task<OsvQueryResult> TryQueryAsync(string purl, CancellationToken ct = default)
    {
        var advisories = await QueryAsync(purl, ct);
        return new OsvQueryResult(advisories, Reached: _sourceReachable);
    }

    /// <summary>
    /// One advisory by id from the loaded dumps. Reached follows <see cref="TryQueryAsync"/>: false
    /// only when the dump directory itself is missing.
    /// </summary>
    public async Task<OsvIdLookupResult> TryGetAdvisoryAsync(string id, CancellationToken ct = default)
    {
        await _initialLoad.Value;
        return new OsvIdLookupResult(
            _byId.TryGetValue(id, out var advisory) ? advisory : null, Reached: _sourceReachable);
    }

    public async Task<List<List<OsvAdvisory>>> QueryBatchAsync(
        IReadOnlyList<string> purls, CancellationToken ct = default)
    {
        await _initialLoad.Value;
        var result = new List<List<OsvAdvisory>>(purls.Count);
        foreach (string p in purls)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            result.Add(await QueryAsync(p, ct));
        }
        return result;
    }

    /// <summary>
    /// Release-scoped query answered from the dump: the advisories under the scope's feed whose
    /// enumerated versions or ECOSYSTEM ranges include the version, evaluated with the distro's
    /// own ordering. <see cref="OsvScopedQueryResult.Covered"/> is false when no loaded advisory
    /// is filed under the release, so a dump that never carried that feed cannot read as clean.
    /// </summary>
    public async Task<OsvScopedQueryResult> TryQueryDistroPackageAsync(
        DistroScope scope, string name, string version, CancellationToken ct = default)
    {
        await _initialLoad.Value;
        if (!_sourceReachable)
        {
            return new OsvScopedQueryResult([], Reached: false, Covered: false);
        }

        if (!_loadedEcosystems.Any(e => DistroScopes.Covers(scope.OsvEcosystem, e)))
        {
            return new OsvScopedQueryResult([], Reached: true, Covered: false);
        }

        var bucket = (scope.IsApk ? "alpine" : "rpm", name.ToLowerInvariant());
        return new OsvScopedQueryResult(
            _index.TryGetValue(bucket, out var list)
                ? list.Where(a => DistroScopes.IsAffected(a, scope, name, version)).ToList()
                : [],
            Reached: true);
    }

    /// <summary>
    /// Same batch query as <see cref="QueryBatchAsync"/>, but reports whether the local dump
    /// directory was actually consulted — mirroring <see cref="TryQueryAsync"/>. Reached is false
    /// only when <c>OSV_LOCAL_PATH</c> itself is missing (unavailable or misconfigured), which
    /// otherwise answers every purl empty and is indistinguishable from a clean batch.
    /// </summary>
    public async Task<OsvBatchQueryResult> TryQueryBatchAsync(
        IReadOnlyList<string> purls, CancellationToken ct = default)
    {
        var results = await QueryBatchAsync(purls, ct);
        return new OsvBatchQueryResult(results, Reached: _sourceReachable);
    }

    /// <summary>
    /// Defers to the static <see cref="OsvFeedCoverage.HasAdvisoryFeed"/> gate first — an
    /// ecosystem it already excludes (OCI, Terraform) stays excluded here regardless of what is
    /// loaded. Past that, coverage is what the current dump actually holds: a sideloaded dump may
    /// carry only some ecosystems' feeds, and a query against a missing feed answers empty, which
    /// cannot be told from a clean result. A PURL ecosystem is covered when the index holds an
    /// advisory under its OSV ecosystem name (any <c>Alpine:*</c> release for apk); RPM, which has
    /// no OSV ecosystem of its own, is covered when a known distro feed is loaded (see
    /// <see cref="_rpmDistroCoverageLoaded"/>). An absent ecosystem keeps the static answer.
    /// </summary>
    public async Task<bool> HasCoverageFor(string? ecosystem)
    {
        await _initialLoad.Value;

        if (!OsvFeedCoverage.HasAdvisoryFeed(ecosystem))
        {
            return false;
        }

        if (string.IsNullOrEmpty(ecosystem))
        {
            return true;
        }

        if (string.Equals(ecosystem, "rpm", StringComparison.OrdinalIgnoreCase))
        {
            return _rpmDistroCoverageLoaded;
        }

        // Stored rows name Go "go" while its purl type is "golang"; both map to OSV's "Go".
        string osvEcosystem = NormalizeEcosystem(
            string.Equals(ecosystem, "go", StringComparison.OrdinalIgnoreCase) ? "golang" : ecosystem);
        var loaded = _loadedEcosystems;
        return string.Equals(osvEcosystem, "Alpine", StringComparison.OrdinalIgnoreCase)
            ? loaded.Any(e => e.StartsWith("alpine", StringComparison.OrdinalIgnoreCase))
            : loaded.Contains(osvEcosystem);
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
            _byId = new Dictionary<string, OsvAdvisory>(StringComparer.OrdinalIgnoreCase);
            _sourceReachable = false;
            _rpmDistroCoverageLoaded = false;
            _loadedEcosystems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return;
        }

        var newIndex = new Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>>(EcosystemNameComparer.Instance);
        var newById = new Dictionary<string, OsvAdvisory>(StringComparer.OrdinalIgnoreCase);
        int loaded = 0;
        int errors = 0;
        bool rpmDistroCoverageFound = false;

        foreach (string file in Directory.EnumerateFiles(_path, "*.json", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var result = await TryIndexFileAsync(file, newIndex, newById, ct);
            if (result.Success)
            {
                loaded++;
                rpmDistroCoverageFound |= result.FoundRpmDistroCoverage;
            }
            else
            {
                errors++;
            }
        }

        _index = newIndex;
        _byId = newById;
        _loadedEcosystems = newIndex.Keys.Select(k => k.Ecosystem).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _sourceReachable = true;
        _rpmDistroCoverageLoaded = rpmDistroCoverageFound;
        _logger.LogInformation(
            "OSV local index reloaded: {Loaded} advisories, {Keys} keys, {Errors} parse errors, RPM distro coverage: {RpmCoverage}.",
            loaded, newIndex.Count, errors, rpmDistroCoverageFound);
    }

    /// <summary>Outcome of indexing one dump file — see <see cref="TryIndexFileAsync"/>.</summary>
    private readonly record struct FileIndexResult(bool Success, bool FoundRpmDistroCoverage);

    /// <summary>
    /// Reads one OSV JSON file and merges its advisories into the building index. Returns
    /// <see cref="FileIndexResult.Success"/> false if parsing failed or the file was empty
    /// (cancellations propagate). Extracted so <see cref="ReloadAsync"/> stays a thin loop and
    /// the parse error path lives in one place.
    /// </summary>
    private async Task<FileIndexResult> TryIndexFileAsync(
        string file,
        Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>> index,
        Dictionary<string, OsvAdvisory> byId,
        CancellationToken ct)
    {
        try
        {
            // Read the file as a string (each dump file is a single advisory) so the raw OSV
            // JSON can be carried on the advisory for persistence, mirroring the remote client.
            string content = await File.ReadAllTextAsync(file, ct);
            var raw = JsonSerializer.Deserialize<RawOsvDump>(content, JsonOpts);
            if (raw is null)
            {
                return new FileIndexResult(false, false);
            }

            var advisory = BuildAdvisory(raw, content);
            if (advisory.Id.Length > 0)
            {
                byId.TryAdd(advisory.Id, advisory);
            }

            bool foundRpmDistroCoverage = false;
            foreach (var pkg in advisory.AffectedPackages)
            {
                if (pkg.Ecosystem is null || pkg.Name is null)
                {
                    continue;
                }

                var key = (pkg.Ecosystem.ToLowerInvariant(), pkg.Name.ToLowerInvariant());
                AddToIndex(index, key, advisory);

                // Alpine (apk) advisories are release-qualified in OSV ("Alpine:v3.18",
                // "Alpine:v3.19", …) — one advisory feed per Alpine release. apk purls carry no
                // release qualifier (ParsePurl/NormalizeEcosystem produce the bare "Alpine"), so
                // also index every release-qualified entry under the bare "alpine" bucket. That
                // lets QueryAsync's single exact-key lookup find every release's advisories for
                // the name; MatchesEcosystemAndName then narrows the affected-package match with
                // a prefix check against the release-qualified ecosystem string.
                if (key.Item1.StartsWith("alpine", StringComparison.OrdinalIgnoreCase) && key.Item1 != "alpine")
                {
                    AddToIndex(index, ("alpine", key.Item2), advisory);
                }

                // RPM has no single OSV ecosystem of its own — advisories live under
                // distro-specific, release-qualified names ("Rocky Linux:9", "Red Hat:…", …),
                // never under a bare "rpm" key. Mirror the Alpine dual-bucket mechanism: also
                // index every advisory affecting a known RPM-distro ecosystem under the bare
                // "rpm" bucket, so QueryAsync's pkg:rpm lookup (which normalises to the bare
                // "rpm" key) finds it. MatchesEcosystemAndName then narrows against
                // KnownRpmDistroEcosystems rather than a single fixed prefix, because — unlike
                // "alpine" — "rpm" itself is not a prefix any distro's ecosystem string carries.
                if (IsKnownRpmDistroEcosystem(pkg.Ecosystem))
                {
                    AddToIndex(index, ("rpm", key.Item2), advisory);
                    foundRpmDistroCoverage = true;
                }
            }
            return new FileIndexResult(true, foundRpmDistroCoverage);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Failed to parse OSV dump: {Path}", file);
            return new FileIndexResult(false, false);
        }
    }

    // Adds an advisory under the given (ecosystem, name) bucket, creating the bucket on first
    // insert. Shared by the primary per-file index pass and the Alpine dual-bucket indexing.
    private static void AddToIndex(
        Dictionary<(string Ecosystem, string Name), List<OsvAdvisory>> index,
        (string Ecosystem, string Name) key,
        OsvAdvisory advisory)
    {
        if (!index.TryGetValue(key, out var list))
        {
            list = new List<OsvAdvisory>();
            index[key] = list;
        }
        list.Add(advisory);
    }

    // Deliberately distinct from PurlParser.TryParse: this index key is matched case-insensitively
    // against OSV dump data (whose ecosystem/name casing conventions differ from purl-spec), so the
    // "pkg:" prefix check and the extracted name are case-insensitive here, and the ecosystem is
    // re-mapped to OSV's own ecosystem vocabulary by NormalizeEcosystem below.
    private static (string Ecosystem, string Name, string Version)? ParsePurl(string purl)
    {
        // pkg:{ecosystem}/{name}@{version}
        if (!purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string rest = purl["pkg:".Length..];
        int slash = rest.IndexOf('/');
        if (slash < 0)
        {
            return null;
        }

        string ecosystem = rest[..slash];
        string nameAndVersion = rest[(slash + 1)..];
        int at = nameAndVersion.LastIndexOf('@');
        if (at < 0)
        {
            return null;
        }

        string name = nameAndVersion[..at];
        string version = nameAndVersion[(at + 1)..];

        // Strip purl-spec qualifiers (everything from '?' onward) from the version — apk purls
        // carry an arch qualifier (?arch=...) that is never part of the version an OSV advisory
        // lists.
        int qmark = version.IndexOf('?');
        if (qmark >= 0)
        {
            version = version[..qmark];
        }

        // apk purls carry an explicit "alpine" namespace segment
        // (pkg:apk/alpine/{name}@{version}) that OSV's own affected[].package.name field does
        // not include — strip it so the extracted name matches what TryIndexFileAsync indexed
        // from the OSV dump.
        if (string.Equals(ecosystem, "apk", StringComparison.OrdinalIgnoreCase)
            && name.StartsWith("alpine/", StringComparison.OrdinalIgnoreCase))
        {
            name = name["alpine/".Length..];
        }

        // Maven purls carry the coordinate as pkg:maven/{groupId}/{artifactId}@{version}, but OSV's
        // affected[].package.name field mandates "groupId:artifactId" — convert the separator so the
        // extracted name matches what TryIndexFileAsync indexed from the OSV dump. The final path
        // segment is always the artifactId (everything before it is the namespace/groupId), so the
        // last '/' is the boundary to replace. A name already in colon form, or one carrying no
        // separator at all, is left untouched and simply finds no match.
        if (string.Equals(ecosystem, "maven", StringComparison.OrdinalIgnoreCase))
        {
            int groupArtifactBoundary = name.LastIndexOf('/');
            if (groupArtifactBoundary >= 0)
            {
                name = string.Concat(
                    name[..groupArtifactBoundary],
                    ":",
                    name[(groupArtifactBoundary + 1)..]);
            }
        }

        // Go module versions carry a leading "v" on the wire (v1.2.3) and PurlNormalizer.Golang
        // preserves it, while OSV's Go entries express versions bare (1.2.3). Strip it so an
        // advisory that enumerates affected[].versions matches. Range-only advisories are
        // unaffected either way — QueryAsync short-circuits on an empty version list.
        if (string.Equals(ecosystem, "golang", StringComparison.OrdinalIgnoreCase))
        {
            version = StripGoVersionPrefix(version);
        }

        return (NormalizeEcosystem(ecosystem), name.ToLowerInvariant(), version);
    }

    /// <summary>
    /// Strips the leading <c>v</c> from a Go module version. Applied to both sides of the version
    /// comparison: purls carry the prefix and OSV's Go entries do not, so normalising only the
    /// purl would leave a dump that does use the prefixed form silently unmatched. Go's module
    /// spec mandates the lower-case <c>v</c>, so the check is ordinal.
    /// </summary>
    private static string StripGoVersionPrefix(string version) =>
        version.StartsWith('v') ? version[1..] : version;

    private static string NormalizeEcosystem(string ecosystem) => ecosystem.ToLowerInvariant() switch
    {
        // Map purl ecosystem names to OSV ecosystem names where they differ.
        "pypi" => "pypi",
        "npm" => "npm",
        "nuget" => "nuget",
        // OSV uses capitalised "Maven"; case-insensitive matching in MatchesEcosystemAndName.
        "maven" => "Maven",
        // OSV uses "Go" (capitalised); case-insensitive matching handles both.
        "golang" => "Go",
        // Cargo maps to the "crates.io" ecosystem in OSV, which is the canonical name for
        // Rust crate advisories in the RustSec and GitHub Advisory databases.
        "cargo" => "crates.io",
        // OSV publishes a dedicated "Hex" ecosystem (the Erlang Ecosystem Foundation runs its own
        // CNA); case-insensitive matching handles the capital.
        "hex" => "Hex",
        // apk maps to OSV's "Alpine" ecosystem. OSV publishes release-qualified Alpine feeds
        // ("Alpine:v3.18", "Alpine:v3.19", …); apk purls carry no release qualifier, so this
        // normalises to the bare "Alpine" and MatchesEcosystemAndName does a release-qualified
        // prefix match against the indexed advisories (see the dual-bucket indexing above).
        "apk" => "Alpine",
        // RPM falls through to the bare lower-cased "rpm" key deliberately: OSV has no single
        // "RPM" ecosystem of its own (vulnerabilities live under distro-specific, release-
        // qualified names — "Rocky Linux:9", "AlmaLinux:9", "Red Hat:…", …), so a pkg:rpm query
        // normalises to "rpm" and is answered from the dual-bucket "rpm" index that
        // TryIndexFileAsync builds from every known-RPM-distro advisory, mirroring how the
        // "alpine" bucket is built. OCI and Terraform are not normalised for a different reason:
        // OCI image vulns are image-scan territory (Trivy), not OSV, and OSV publishes no
        // Terraform provider ecosystem at all, so falling through with the lower-cased key
        // correctly yields no matches — the honest outcome, since neither has any feed to
        // consult, while the rest of the block gate (operator blocks, revocation, source
        // pinning) still applies.
        var other => other
    };

    // OSV.dev's own ecosystem-list documentation
    // (https://ossf.github.io/osv-schema/#defined-ecosystems) names these as RPM-packaged
    // distro ecosystems — either explicitly ("the name is the name of the source RPM" / "RPM
    // package" / "binary or source RPM": openEuler, openSUSE, Photon OS, Red Hat, SUSE) or, for
    // AlmaLinux, Azure Linux, Mageia, and Rocky Linux (whose OSV description says only "source
    // package"), because the distro itself is independently and unambiguously documented as
    // RPM-based (AlmaLinux and Rocky Linux are RHEL clones; Azure Linux/CBL-Mariner packages
    // with rpm/tdnf; Mageia — a Mandriva Linux fork — packages with DNF/urpmi over RPM). Each
    // publishes advisories release- or product-qualified with a ":<RELEASE>" suffix on the
    // ecosystem string, mirroring Alpine's "Alpine:v3.18" convention, so membership is matched
    // by prefix rather than exact equality (see IsKnownRpmDistroEcosystem).
    private static readonly string[] KnownRpmDistroEcosystems =
    [
        "AlmaLinux",
        "Azure Linux",
        "Mageia",
        "openEuler",
        "openSUSE",
        "Photon OS",
        "Red Hat",
        "Rocky Linux",
        "SUSE",
    ];

    private static bool IsKnownRpmDistroEcosystem(string? ecosystem) =>
        ecosystem is not null
        && KnownRpmDistroEcosystems.Any(d => ecosystem.StartsWith(d, StringComparison.OrdinalIgnoreCase));

    private static bool MatchesEcosystemAndName(OsvAffectedPackage ap, string ecosystem, string name)
    {
        string? apEco = ap.Ecosystem?.ToLowerInvariant();
        string? apName = ap.Name?.ToLowerInvariant();
        // OSV uses "PyPI", "npm", "NuGet" (case sensitive in the schema). Match case-insensitively.
        if (apEco is null || apName is null || !string.Equals(apName, name, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Alpine (apk) advisories are release-qualified ("Alpine:v3.18"); the query ecosystem is
        // the bare "Alpine" (apk purls carry no OS-release qualifier), so match any release via a
        // prefix check instead of exact equality.
        if (string.Equals(ecosystem, "Alpine", StringComparison.OrdinalIgnoreCase))
        {
            return apEco.StartsWith("alpine", StringComparison.OrdinalIgnoreCase);
        }

        // RPM (query ecosystem "rpm") has no fixed prefix the way "alpine" does — no distro's
        // ecosystem string starts with "rpm" itself. The advisories reachable from the "rpm"
        // bucket were added there only when the affected package's own ecosystem matched a known
        // RPM-distro name (TryIndexFileAsync), but an advisory can carry affected packages across
        // several ecosystems at once, so this still narrows against the same known-distro set at
        // match time rather than trusting bucket membership alone.
        return string.Equals(ecosystem, "rpm", StringComparison.OrdinalIgnoreCase)
            ? IsKnownRpmDistroEcosystem(ap.Ecosystem)
            : string.Equals(apEco, ecosystem, StringComparison.OrdinalIgnoreCase);
    }

    private static OsvAdvisory BuildAdvisory(RawOsvDump raw, string rawJson)
    {
        var affected = raw.Affected?
            .Where(a => a.Package is not null)
            .Select(a => new OsvAffectedPackage(
                Purl: a.Package!.Purl,
                Ecosystem: a.Package.Ecosystem,
                Name: a.Package.Name,
                Versions: a.Versions?.Distinct().ToArray() ?? []))
            .ToArray() ?? [];

        // Prefers whichever severity entry actually parses, highest CVSS version first, over
        // the array's listing order — kept identical to OsvClient.ParseAdvisory so the same
        // advisory scores the same online and offline.
        string? severity;
        double? cvssScore;
        (cvssScore, severity) = OsvScoring.SelectCvssBaseScore(
            raw.Severity?.Select(s => (s.Type, s.Score)));

        if (severity is null && raw.DatabaseSpecific is not null
            && raw.DatabaseSpecific.TryGetValue("severity", out object? dbSev))
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
            IsHydrated: true,
            RawJson: rawJson);
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
