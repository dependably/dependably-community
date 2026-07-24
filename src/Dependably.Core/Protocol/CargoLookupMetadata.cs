using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// Pure parsing and host-classification helpers for the Cargo lookup metadata path. No HTTP and
/// no DI: <see cref="PackageLookupService"/> owns the fetching and passes the response bodies here.
///
/// Cargo lookup draws on two upstream documents. The sparse index is served by every cargo
/// registry and carries version existence and <c>yanked</c>, but no license and no publish date.
/// The crates.io JSON API carries both, but only crates.io serves it — so it is consulted only
/// when the operator-configured upstream is crates.io's own index, and a lookup against a private
/// mirror degrades to index-only facts rather than reaching a host the operator never configured.
/// </summary>
internal static class CargoLookupMetadata
{
    private const string CratesIoIndexHost = "index.crates.io";
    private const string CratesIoHost = "crates.io";

    /// <summary>
    /// One sparse-index line's lookup-relevant fields. The index carries more (deps, features,
    /// cksum, rust_version); only the version and its yank state bear on a lookup verdict.
    /// </summary>
    internal sealed record CargoIndexEntry(string Version, bool Yanked);

    /// <summary>Facts only the crates.io JSON API supplies for a specific version.</summary>
    internal sealed record CargoApiFacts(DateTimeOffset? PublishedAt, IReadOnlyList<string> Spdx);

    /// <summary>
    /// Parses a Cargo sparse-index document — newline-delimited JSON, one object per published
    /// version. A blank or unparsable line is skipped rather than failing the document: the index
    /// is upstream-controlled and one malformed line must not cost the caller every other version.
    /// </summary>
    internal static IReadOnlyList<CargoIndexEntry> ParseIndex(string indexText)
    {
        var entries = new List<CargoIndexEntry>();
        if (string.IsNullOrWhiteSpace(indexText))
        {
            return entries;
        }

        foreach (string rawLine in indexText.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            JsonDocument doc;
            try { doc = JsonDocument.Parse(line); }
            catch (JsonException) { continue; }

            using (doc)
            {
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("vers", out var versEl)
                    || versEl.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                string? vers = versEl.GetString();
                if (string.IsNullOrWhiteSpace(vers))
                {
                    continue;
                }

                bool yanked = root.TryGetProperty("yanked", out var yankedEl)
                    && yankedEl.ValueKind == JsonValueKind.True;

                entries.Add(new CargoIndexEntry(vers, yanked));
            }
        }

        return entries;
    }

    /// <summary>
    /// Pulls the license and publish date for <paramref name="version"/> out of a crates.io
    /// <c>/api/v1/crates/{name}</c> response. Returns null when the document is unparsable or
    /// names no such version — the caller degrades to index-only facts rather than failing.
    /// The raw <c>license</c> string is validated through
    /// <see cref="LicenseExtractor.FromCargoPublishLicense"/> so a free-text or absent value
    /// yields no SPDX rather than reaching the license policy check as garbage.
    /// </summary>
    internal static CargoApiFacts? ParseCratesIoCrate(string json, string version)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException) { return null; }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object
                || !doc.RootElement.TryGetProperty("versions", out var versions)
                || versions.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var entry in versions.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object
                    || !entry.TryGetProperty("num", out var numEl)
                    || numEl.ValueKind != JsonValueKind.String
                    || !string.Equals(numEl.GetString(), version, StringComparison.Ordinal))
                {
                    continue;
                }

                string? license = entry.TryGetProperty("license", out var licenseEl)
                    && licenseEl.ValueKind == JsonValueKind.String
                    ? licenseEl.GetString()
                    : null;

                var publishedAt = entry.TryGetProperty("created_at", out var createdEl)
                    && createdEl.ValueKind == JsonValueKind.String
                    ? TryParseTimestamp(createdEl.GetString())
                    : null;

                return new CargoApiFacts(publishedAt, LicenseExtractor.FromCargoPublishLicense(license).Spdx);
            }

            return null;
        }
    }

    /// <summary>
    /// True when <paramref name="upstreamUrl"/> is crates.io's own sparse index, the only upstream
    /// whose operator has implicitly authorized the crates.io JSON API fetch. Compares parsed
    /// <see cref="Uri.Host"/> values, never a substring of the URL: a host-shaped substring can
    /// appear in any part of an arbitrary URL, so <c>https://evil-index.crates.io.example/</c>
    /// and <c>https://attacker.example/?x=index.crates.io</c> must both be false.
    /// </summary>
    internal static bool IsCratesIoIndexHost(string upstreamUrl)
    {
        return Uri.TryCreate(upstreamUrl, UriKind.Absolute, out var uri)
            && (string.Equals(uri.Host, CratesIoIndexHost, StringComparison.OrdinalIgnoreCase)
                || string.Equals(uri.Host, CratesIoHost, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The crates.io JSON API URL for a crate's full version list.</summary>
    internal static string CratesIoApiUrl(string name) => $"https://{CratesIoHost}/api/v1/crates/{name}";

    private static DateTimeOffset? TryParseTimestamp(string? raw) =>
        !string.IsNullOrEmpty(raw) && DateTimeOffset.TryParse(
            raw, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : null;
}
