using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Per-ecosystem upstream metadata fetch for <see cref="PackageLookupService"/>: one
/// Fetch&lt;Ecosystem&gt;Async / TryFetch&lt;Ecosystem&gt;FromSourceAsync / Resolve&lt;Ecosystem&gt;VersionAsync
/// trio per supported ecosystem (npm, PyPI, NuGet, Maven, Cargo, Go), dispatched from
/// <c>FetchFactsAsync</c> in the main file. Split from the lookup orchestration purely to stay
/// under the file-length compliance gate — both halves are one service.
/// </summary>
public sealed partial class PackageLookupService
{
    private async Task<FactsOutcome> FetchNpmAsync(
        string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        var sources = await _registries.ResolveAsync(orgId, "npm", ct);
        if (sources.Count == 0)
        {
            return FactsOutcome.NotConfigured;
        }

        bool sawDefinitiveMiss = false;
        foreach (var source in sources)
        {
            var attempt = await TryFetchNpmFromSourceAsync(source, orgId, name, requestedVersion, ct);
            sawDefinitiveMiss |= attempt.DefinitiveMiss;
            if (attempt.Result is not null)
            {
                return attempt.Result;
            }
        }

        return sawDefinitiveMiss ? FactsOutcome.NotFound : FactsOutcome.Unavailable;
    }

    private async Task<SourceAttempt> TryFetchNpmFromSourceAsync(
        UpstreamSource source, string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        UpstreamMetadataResponse resp;
        try
        {
            // Abbreviated-document fallback for packuments past the metadata byte cap; the
            // abbreviated document has no time[] map or per-version license, which the
            // extraction below already tolerates (published date and license stay null).
            resp = await NpmPackumentFetcher.FetchAsync(
                _upstream, $"{source.Url}/{name}", source.AuthorizationHeader, logger: null, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex)) { return SourceAttempt.Continue; }

        // Only an explicit 404 from a reachable source counts as a "definitively not found"
        // signal; a 5xx (or other non-2xx) means that source is unhealthy, not authoritative —
        // it must not be conflated with a genuine miss (matches the transient-exception path
        // just above, which also continues without touching that flag).
        if (resp.StatusCode == 404)
        {
            return SourceAttempt.Miss;
        }

        if (!resp.IsSuccessStatusCode)
        {
            return SourceAttempt.Continue;
        }

        JsonObject? doc;
        try { doc = JsonNode.Parse(resp.Body) as JsonObject; }
        catch (JsonException) { return SourceAttempt.Continue; }
        return doc is null
            ? SourceAttempt.Continue
            : SourceAttempt.Done(await ResolveNpmVersionAsync(doc, orgId, name, requestedVersion, ct));
    }

    private async Task<FactsOutcome> ResolveNpmVersionAsync(
        JsonObject doc, string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        string? version = requestedVersion;
        if (version is null)
        {
            var (resolved, transient) = await TryResolveLatestAsync("npm", orgId, name, ct);
            if (transient)
            {
                return FactsOutcome.Unavailable;
            }

            if (resolved is null)
            {
                return FactsOutcome.NotFound;
            }

            version = resolved;
        }

        var versionNode = doc["versions"]?[version];
        if (versionNode is null)
        {
            return FactsOutcome.NotFound;
        }

        var extracted = LicenseExtractor.FromNpmPackumentVersion(versionNode);
        string? publishedRaw = null;
        try { publishedRaw = doc["time"]?[version]?.GetValue<string>(); }
        catch (Exception ex) when (ex is InvalidOperationException or FormatException) { /* not a string node — no published date */ }
        var publishedAt = TryParseDate(publishedRaw);
        return FactsOutcome.Ok(version, new VersionMetadataFacts(publishedAt, extracted.Deprecated, extracted.Spdx));
    }

    private async Task<FactsOutcome> FetchPyPiAsync(
        string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        string normalizedName = PurlNormalizer.PyPiName(name);
        var sources = await _registries.ResolveAsync(orgId, "pypi", ct);
        if (sources.Count == 0)
        {
            return FactsOutcome.NotConfigured;
        }

        bool sawDefinitiveMiss = false;
        foreach (var source in sources)
        {
            var attempt = await TryFetchPyPiFromSourceAsync(source, orgId, normalizedName, name, requestedVersion, ct);
            sawDefinitiveMiss |= attempt.DefinitiveMiss;
            if (attempt.Result is not null)
            {
                return attempt.Result;
            }
        }

        return sawDefinitiveMiss ? FactsOutcome.NotFound : FactsOutcome.Unavailable;
    }

    private async Task<SourceAttempt> TryFetchPyPiFromSourceAsync(
        UpstreamSource source, string orgId, string normalizedName, string name, string? requestedVersion, CancellationToken ct)
    {
        UpstreamMetadataResponse resp;
        try
        {
            resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/pypi/{normalizedName}/json", source.AuthorizationHeader, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex)) { return SourceAttempt.Continue; }

        // Only an explicit 404 from a reachable source counts as a "definitively not found"
        // signal; a 5xx (or other non-2xx) means that source is unhealthy, not authoritative —
        // it must not be conflated with a genuine miss (matches the transient-exception path
        // just above, which also continues without touching that flag).
        if (resp.StatusCode == 404)
        {
            return SourceAttempt.Miss;
        }

        if (!resp.IsSuccessStatusCode)
        {
            return SourceAttempt.Continue;
        }

        JsonDocument doc;
        try { doc = JsonDocument.Parse(resp.Body); }
        catch (JsonException) { return SourceAttempt.Continue; }
        using (doc)
        {
            return SourceAttempt.Done(await ResolvePyPiVersionAsync(doc.RootElement, orgId, name, requestedVersion, ct));
        }
    }

    private async Task<FactsOutcome> ResolvePyPiVersionAsync(
        JsonElement root, string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        bool hasInfo = root.TryGetProperty("info", out var info) && info.ValueKind == JsonValueKind.Object;
        string? latestVersion = hasInfo && info.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;

        string? version = requestedVersion;
        if (version is null)
        {
            var (resolved, transient) = await TryResolveLatestAsync("pypi", orgId, name, ct);
            if (transient)
            {
                return FactsOutcome.Unavailable;
            }

            // The resolver's own algorithm agrees with PyPI's own "latest" pointer for
            // every real deployment; falling back to the value already in hand avoids a
            // spurious not-found if the two ever momentarily disagree (e.g. resolver
            // cache staleness) — the document we just fetched is the source of truth.
            version = resolved ?? latestVersion;
            if (version is null)
            {
                return FactsOutcome.NotFound;
            }
        }

        if (!root.TryGetProperty("releases", out var releases) || releases.ValueKind != JsonValueKind.Object
            || !releases.TryGetProperty(version, out var releaseFiles) || releaseFiles.ValueKind != JsonValueKind.Array
            || releaseFiles.GetArrayLength() == 0)
        {
            return FactsOutcome.NotFound;
        }

        var firstFile = releaseFiles.EnumerateArray().First();
        var deprecatedMeta = LicenseExtractor.FromPyPiJsonFile(firstFile);
        var publishedAt = TryParsePyPiUploadTime(firstFile);

        IReadOnlyList<string> spdx = Array.Empty<string>();
        if (hasInfo && string.Equals(version, latestVersion, StringComparison.Ordinal))
        {
            spdx = LicenseExtractor.FromPyPiJsonInfo(info).Spdx;
        }

        return FactsOutcome.Ok(version, new VersionMetadataFacts(publishedAt, deprecatedMeta.Deprecated, spdx));
    }

    private async Task<FactsOutcome> FetchNuGetAsync(
        string orgId, string id, string? requestedVersion, CancellationToken ct)
    {
        var sources = await _registries.ResolveAsync(orgId, "nuget", ct);
        if (sources.Count == 0)
        {
            return FactsOutcome.NotConfigured;
        }

        string lowerId = id.ToLowerInvariant();
        bool sawDefinitiveMiss = false;
        foreach (var source in sources)
        {
            var attempt = await TryFetchNuGetFromSourceAsync(source, orgId, id, lowerId, requestedVersion, ct);
            sawDefinitiveMiss |= attempt.DefinitiveMiss;
            if (attempt.Result is not null)
            {
                return attempt.Result;
            }
        }

        return sawDefinitiveMiss ? FactsOutcome.NotFound : FactsOutcome.Unavailable;
    }

    private async Task<SourceAttempt> TryFetchNuGetFromSourceAsync(
        UpstreamSource source, string orgId, string id, string lowerId, string? requestedVersion, CancellationToken ct)
    {
        UpstreamMetadataResponse resp;
        try
        {
            resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/flatcontainer/{lowerId}/index.json", source.AuthorizationHeader, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex)) { return SourceAttempt.Continue; }

        // Only an explicit 404 from a reachable source counts as a "definitively not found"
        // signal; a 5xx (or other non-2xx) means that source is unhealthy, not authoritative —
        // it must not be conflated with a genuine miss (matches the transient-exception path
        // just above, which also continues without touching that flag).
        if (resp.StatusCode == 404)
        {
            return SourceAttempt.Miss;
        }

        if (!resp.IsSuccessStatusCode)
        {
            return SourceAttempt.Continue;
        }

        JsonDocument doc;
        try { doc = JsonDocument.Parse(resp.Body); }
        catch (JsonException) { return SourceAttempt.Continue; }
        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("versions", out var versionsEl) || versionsEl.ValueKind != JsonValueKind.Array)
            {
                return SourceAttempt.Continue;
            }

            var versions = versionsEl.EnumerateArray()
                .Select(v => v.GetString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!)
                .ToList();

            return SourceAttempt.Done(await ResolveNuGetVersionAsync(source, orgId, id, lowerId, versions, requestedVersion, ct));
        }
    }

    private async Task<FactsOutcome> ResolveNuGetVersionAsync(
        UpstreamSource source, string orgId, string id, string lowerId, List<string> versions, string? requestedVersion, CancellationToken ct)
    {
        string? version = requestedVersion;
        if (version is null)
        {
            var (resolved, transient) = await TryResolveLatestAsync("nuget", orgId, id, ct);
            if (transient)
            {
                return FactsOutcome.Unavailable;
            }

            if (resolved is null)
            {
                return FactsOutcome.NotFound;
            }

            version = resolved;
        }

        string normalizedRequested = PurlNormalizer.NormalizeNuGetVersionString(version);
        bool exists = versions.Any(v =>
            string.Equals(PurlNormalizer.NormalizeNuGetVersionString(v), normalizedRequested, StringComparison.OrdinalIgnoreCase));
        if (!exists)
        {
            return FactsOutcome.NotFound;
        }

        var spdx = await TryFetchNuGetLicenseAsync(source, lowerId, normalizedRequested, ct);
        return FactsOutcome.Ok(version, new VersionMetadataFacts(
            null, null, spdx, DeprecationResolved: false));
    }

    // Best-effort .nuspec fetch for the license expression. The flat-container nuspec endpoint
    // is a NuGet v3 convenience file (not every mirror serves it); a failure here degrades to an
    // empty SPDX list rather than failing the whole lookup — version existence was already
    // confirmed against the index.json versions array.
    private async Task<IReadOnlyList<string>> TryFetchNuGetLicenseAsync(
        UpstreamSource source, string lowerId, string lowerVersion, CancellationToken ct)
    {
        try
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/flatcontainer/{lowerId}/{lowerVersion.ToLowerInvariant()}/{lowerId}.nuspec",
                source.AuthorizationHeader, ct);
            return resp.IsSuccessStatusCode
                ? LicenseExtractor.FromNuspecXml(resp.BodyAsString()).Spdx
                : Array.Empty<string>();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    private async Task<FactsOutcome> FetchMavenAsync(
        string orgId, string coordinate, string? requestedVersion, CancellationToken ct)
    {
        int sep = coordinate.IndexOf(':');
        string groupId = coordinate[..sep];
        string artifact = coordinate[(sep + 1)..];
        string groupPath = groupId.Replace('.', '/');

        var sources = await _registries.ResolveAsync(orgId, "maven", ct);
        if (sources.Count == 0)
        {
            return FactsOutcome.NotConfigured;
        }

        bool sawDefinitiveMiss = false;
        foreach (var source in sources)
        {
            var attempt = await TryFetchMavenFromSourceAsync(source, orgId, coordinate, groupPath, artifact, requestedVersion, ct);
            sawDefinitiveMiss |= attempt.DefinitiveMiss;
            if (attempt.Result is not null)
            {
                return attempt.Result;
            }
        }

        return sawDefinitiveMiss ? FactsOutcome.NotFound : FactsOutcome.Unavailable;
    }

    private async Task<SourceAttempt> TryFetchMavenFromSourceAsync(
        UpstreamSource source, string orgId, string coordinate, string groupPath, string artifact,
        string? requestedVersion, CancellationToken ct)
    {
        UpstreamMetadataResponse resp;
        try
        {
            resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/{groupPath}/{artifact}/maven-metadata.xml", source.AuthorizationHeader, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex)) { return SourceAttempt.Continue; }

        // Only an explicit 404 from a reachable source counts as a "definitively not found"
        // signal; a 5xx (or other non-2xx) means that source is unhealthy, not authoritative —
        // it must not be conflated with a genuine miss (matches the transient-exception path
        // just above, which also continues without touching that flag).
        if (resp.StatusCode == 404)
        {
            return SourceAttempt.Miss;
        }

        if (!resp.IsSuccessStatusCode)
        {
            return SourceAttempt.Continue;
        }

        XDocument xdoc;
        try { xdoc = XDocument.Parse(resp.BodyAsString()); }
        catch (Exception ex) when (ex is System.Xml.XmlException or FormatException) { return SourceAttempt.Continue; }

        var versioning = xdoc.Root?.Element("versioning");
        var versions = versioning?.Element("versions")?.Elements("version")
            .Select(e => e.Value).ToList() ?? [];

        return SourceAttempt.Done(await ResolveMavenVersionAsync(orgId, coordinate, versions, requestedVersion, ct));
    }

    private async Task<FactsOutcome> ResolveMavenVersionAsync(
        string orgId, string coordinate, List<string> versions, string? requestedVersion, CancellationToken ct)
    {
        string? version = requestedVersion;
        if (version is null)
        {
            var (resolved, transient) = await TryResolveLatestAsync("maven", orgId, coordinate, ct);
            if (transient)
            {
                return FactsOutcome.Unavailable;
            }

            if (resolved is null)
            {
                return FactsOutcome.NotFound;
            }

            version = resolved;
        }

        return versions.Contains(version, StringComparer.Ordinal)
            ? FactsOutcome.Ok(version, new VersionMetadataFacts(
                null, null, Array.Empty<string>(), DeprecationResolved: false))
            : FactsOutcome.NotFound;
    }

    // ── Cargo ───────────────────────────────────────────────────────────────────

    private async Task<FactsOutcome> FetchCargoAsync(
        string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        var sources = await _registries.ResolveAsync(orgId, "cargo", ct);
        if (sources.Count == 0)
        {
            return FactsOutcome.NotConfigured;
        }

        bool sawDefinitiveMiss = false;
        foreach (var source in sources)
        {
            var attempt = await TryFetchCargoFromSourceAsync(source, orgId, name, requestedVersion, ct);
            sawDefinitiveMiss |= attempt.DefinitiveMiss;
            if (attempt.Result is not null)
            {
                return attempt.Result;
            }
        }

        return sawDefinitiveMiss ? FactsOutcome.NotFound : FactsOutcome.Unavailable;
    }

    private async Task<SourceAttempt> TryFetchCargoFromSourceAsync(
        UpstreamSource source, string orgId, string name, string? requestedVersion, CancellationToken ct)
    {
        UpstreamMetadataResponse resp;
        try
        {
            resp = await _upstream.GetOrFetchMetadataAsync(
                $"{source.Url}/{CargoController.IndexPath(name)}", source.AuthorizationHeader, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex)) { return SourceAttempt.Continue; }

        // Only an explicit 404 from a reachable source is authoritative; a 5xx means that source
        // is unhealthy and the next one in priority order still gets a chance.
        if (resp.StatusCode == 404)
        {
            return SourceAttempt.Miss;
        }

        if (!resp.IsSuccessStatusCode)
        {
            return SourceAttempt.Continue;
        }

        var entries = CargoLookupMetadata.ParseIndex(resp.BodyAsString());
        return entries.Count == 0
            ? SourceAttempt.Miss
            : SourceAttempt.Done(await ResolveCargoVersionAsync(source, orgId, name, entries, requestedVersion, ct));
    }

    private async Task<FactsOutcome> ResolveCargoVersionAsync(
        UpstreamSource source, string orgId, string name,
        IReadOnlyList<CargoLookupMetadata.CargoIndexEntry> entries, string? requestedVersion, CancellationToken ct)
    {
        string? version = requestedVersion;
        if (version is null)
        {
            var (resolved, transient) = await TryResolveLatestAsync("cargo", orgId, name, ct);
            if (transient)
            {
                return FactsOutcome.Unavailable;
            }

            // Same belt-and-braces as PyPI: fall back to the highest stable non-yanked entry in
            // the document already in hand if the resolver and this index momentarily disagree.
            var stableDescending = EcosystemVersionOrdering.OrderStableDescending(
                "cargo", entries.Where(e => !e.Yanked).Select(e => e.Version));
            version = resolved ?? (stableDescending.Count > 0 ? stableDescending[0] : null);
            if (version is null)
            {
                return FactsOutcome.NotFound;
            }
        }

        var entry = entries.FirstOrDefault(e => string.Equals(e.Version, version, StringComparison.Ordinal));
        if (entry is null)
        {
            return FactsOutcome.NotFound;
        }

        // A yanked crate is Cargo's deprecation signal. The index always carries it, so cargo
        // resolves a deprecation state even when the crates.io API leg below is unavailable.
        string? deprecated = entry.Yanked ? "yanked" : null;

        var apiFacts = await TryFetchCratesIoFactsAsync(source, name, version, ct);
        return FactsOutcome.Ok(version, new VersionMetadataFacts(
            apiFacts?.PublishedAt, deprecated, apiFacts?.Spdx ?? Array.Empty<string>()));
    }

    /// <summary>
    /// Best-effort license and publish date from the crates.io JSON API, which only crates.io
    /// serves. Returns null — never a source failure — on any non-2xx (including a 429 from the
    /// API's tighter rate limit), throw, or parse failure, so a healthy sparse index is never
    /// abandoned over this leg. Skipped entirely unless the configured upstream IS crates.io's
    /// index: a private mirror's operator has not authorized an egress call to crates.io.
    /// </summary>
    private async Task<CargoLookupMetadata.CargoApiFacts?> TryFetchCratesIoFactsAsync(
        UpstreamSource source, string name, string version, CancellationToken ct)
    {
        if (!CargoLookupMetadata.IsCratesIoIndexHost(source.Url))
        {
            return null;
        }

        string apiUrl = CargoLookupMetadata.CratesIoApiUrl(name);

        // The API lives on crates.io while the configured index is index.crates.io, so the
        // host-pin drops the credential — expressed through the shared helper rather than a
        // hardcoded null so the invariant stays testable and survives a same-host registry.
        string? authorizationHeader = UpstreamHostPin.IsSameHost(source.Url, apiUrl)
            ? source.AuthorizationHeader
            : null;

        try
        {
            var resp = await _upstream.GetOrFetchMetadataAsync(apiUrl, authorizationHeader, ct);
            return resp.IsSuccessStatusCode ? CargoLookupMetadata.ParseCratesIoCrate(resp.BodyAsString(), version) : null;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { return null; }
    }

    // ── Go ──────────────────────────────────────────────────────────────────────

    private async Task<FactsOutcome> FetchGoAsync(
        string orgId, string module, string? requestedVersion, CancellationToken ct)
    {
        var sources = await _registries.ResolveAsync(orgId, "golang", ct);
        if (sources.Count == 0)
        {
            return FactsOutcome.NotConfigured;
        }

        bool sawDefinitiveMiss = false;
        foreach (var source in sources)
        {
            var attempt = await TryFetchGoFromSourceAsync(source, module, requestedVersion, ct);
            sawDefinitiveMiss |= attempt.DefinitiveMiss;
            if (attempt.Result is not null)
            {
                return attempt.Result;
            }
        }

        return sawDefinitiveMiss ? FactsOutcome.NotFound : FactsOutcome.Unavailable;
    }

    /// <summary>
    /// Resolves a Go module version and its publish date. Both <c>@latest</c> (no version given)
    /// and <c>@v/{version}.info</c> answer with the same <c>{Version, Time}</c> shape, so one
    /// parse covers both. A Go module carries no license or deprecation signal outside its zip —
    /// which lookup must never download, that being the ingest this feature exists to avoid — so
    /// both stay unresolved and are reported in UnavailableChecks.
    /// </summary>
    private async Task<SourceAttempt> TryFetchGoFromSourceAsync(
        UpstreamSource source, string module, string? requestedVersion, CancellationToken ct)
    {
        string encodedModule = GoController.EncodeBangEncoding(module);
        string url = requestedVersion is null
            ? $"{source.Url}/{encodedModule}/@latest"
            : $"{source.Url}/{encodedModule}/@v/{GoController.EncodeBangEncoding(requestedVersion)}.info";

        UpstreamMetadataResponse resp;
        try
        {
            resp = await _upstream.GetOrFetchMetadataAsync(url, source.AuthorizationHeader, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (IsTransientUpstreamFailure(ex)) { return SourceAttempt.Continue; }

        // The Go module proxy answers an unknown module or version with 404 or 410 (gone).
        if (resp.StatusCode is 404 or 410)
        {
            return SourceAttempt.Miss;
        }

        if (!resp.IsSuccessStatusCode)
        {
            return SourceAttempt.Continue;
        }

        JsonDocument doc;
        try { doc = JsonDocument.Parse(resp.Body); }
        catch (JsonException) { return SourceAttempt.Continue; }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return SourceAttempt.Continue;
            }

            string? version = requestedVersion
                ?? (root.TryGetProperty("Version", out var vEl) && vEl.ValueKind == JsonValueKind.String
                    ? vEl.GetString() : null);
            if (string.IsNullOrWhiteSpace(version))
            {
                return SourceAttempt.Continue;
            }

            var publishedAt = root.TryGetProperty("Time", out var tEl) && tEl.ValueKind == JsonValueKind.String
                ? TryParseDate(tEl.GetString())
                : null;

            return SourceAttempt.Done(FactsOutcome.Ok(version, new VersionMetadataFacts(
                publishedAt, null, Array.Empty<string>(), DeprecationResolved: false)));
        }
    }

    private static DateTimeOffset? TryParseDate(string? raw) =>
        !string.IsNullOrEmpty(raw) && DateTimeOffset.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var dt) ? dt : null;

    private static DateTimeOffset? TryParsePyPiUploadTime(JsonElement fileEntry) =>
        fileEntry.ValueKind == JsonValueKind.Object
            && fileEntry.TryGetProperty("upload_time_iso_8601", out var el)
            && el.ValueKind == JsonValueKind.String
            ? TryParseDate(el.GetString())
            : null;
}
