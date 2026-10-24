using System.Text.Json;
using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>
/// The OSV ecosystem a release-scoped lookup (apk, rpm) queries: <c>Alpine:v3.20</c>,
/// <c>Rocky Linux:9</c>, <c>AlmaLinux:9</c>, <c>Red Hat:enterprise_linux:9::baseos</c>. OSV files distro
/// advisories under one ecosystem per release, so a package name and version alone cannot be
/// matched against them — the release is part of the question.
/// </summary>
public sealed record DistroScope(string OsvEcosystem, string Family)
{
    /// <summary>True for the Alpine (apk) feeds; every other family is RPM-packaged.</summary>
    public bool IsApk => Family == "Alpine";
}

/// <summary>
/// Parses, derives and matches <see cref="DistroScope"/> values. The accepted families are the ones
/// whose release grammar and feed were checked against OSV itself: Alpine, Rocky Linux, AlmaLinux
/// and Red Hat. OSV answers an unknown release of a known family with an empty 200, which is
/// indistinguishable from "no advisories", so a release is only ever queried remotely once it is in
/// the embedded known-release set (<see cref="IsKnownRelease"/>).
/// </summary>
public static partial class DistroScopes
{
    // Canonical OSV family name, the PURL namespace segment OSV registers for it (null when OSV
    // registers none), and the lower-case aliases accepted on input.
    private static readonly (string Family, string? PurlNamespace, string[] Aliases)[] RpmFamilies =
    [
        ("AlmaLinux", "almalinux", ["almalinux", "alma"]),
        ("Red Hat", "redhat", ["red hat", "redhat"]),
        ("Rocky Linux", "rocky-linux", ["rocky linux", "rocky-linux", "rocky"]),
    ];

    // The releases OSV publishes a feed for, as of the last time they were checked against
    // api.osv.dev. A release outside the set is reported as having no coverage rather than
    // queried, because OSV answers it with an empty 200. Extending the set is an edit here, after
    // confirming the release returns advisories for a package known to have them. Alpine keeps one
    // minor-version range; the RPM families list every ecosystem string.
    private const int AlpineMinMinor = 2;
    private const int AlpineMaxMinor = 24;

    private static readonly HashSet<string> KnownRpmReleases = new(StringComparer.OrdinalIgnoreCase)
    {
        "Rocky Linux:8", "Rocky Linux:9", "Rocky Linux:10",
        "AlmaLinux:8", "AlmaLinux:9", "AlmaLinux:10",
        "Red Hat:enterprise_linux:8::baseos", "Red Hat:enterprise_linux:8::appstream",
        "Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream",
    };

    /// <summary>
    /// True when OSV is known to publish a feed for <paramref name="scope"/>'s release. False means
    /// an empty answer for it proves nothing and must not be reported as checked.
    /// </summary>
    public static bool IsKnownRelease(DistroScope scope)
    {
        if (scope.IsApk)
        {
            var m = AlpineRelease().Match(scope.OsvEcosystem);
            return m.Success && m.Groups[1].Value == "3"
                && int.TryParse(m.Groups[2].Value, out int minor)
                && minor is >= AlpineMinMinor and <= AlpineMaxMinor;
        }

        return KnownRpmReleases.Contains(scope.OsvEcosystem);
    }

    private const int MaxDistroLength = 80;

    /// <summary>
    /// Normalises a caller-supplied release for <paramref name="ecosystem"/> (<c>apk</c> or
    /// <c>rpm</c>). Returns false when the value is present but is not a release OSV could carry a
    /// feed for. apk accepts <c>v3.20</c>, <c>3.20</c> or <c>Alpine:v3.20</c>; rpm takes
    /// <c>&lt;family&gt;:&lt;release&gt;</c> with the family matched case-insensitively and the release
    /// held to its family's grammar: a major number for Rocky Linux and AlmaLinux (<c>9</c>, never
    /// <c>9.4</c>), and <c>enterprise_linux:N::baseos|appstream</c> for Red Hat.
    /// </summary>
    public static bool TryParse(string ecosystem, string raw, out DistroScope? scope)
    {
        scope = null;
        string value = raw.Trim();
        if (value.Length == 0 || value.Length > MaxDistroLength || value.Any(char.IsControl))
        {
            return false;
        }

        if (ecosystem == "apk")
        {
            var m = AlpineRelease().Match(value);
            if (!m.Success)
            {
                return false;
            }

            scope = new DistroScope($"Alpine:v{m.Groups[1].Value}.{m.Groups[2].Value}", "Alpine");
            return true;
        }

        int colon = value.IndexOf(':');
        if (colon <= 0 || colon == value.Length - 1)
        {
            return false;
        }

        string family = value[..colon].Trim().ToLowerInvariant();
        string release = value[(colon + 1)..].Trim();
        var (knownFamily, _, _) = RpmFamilies.FirstOrDefault(f => f.Aliases.Contains(family));
        bool grammarOk = knownFamily switch
        {
            "Red Hat" => RedHatRelease().IsMatch(release),
            null => false,
            _ => MajorRelease().IsMatch(release),
        };
        if (!grammarOk)
        {
            return false;
        }

        scope = new DistroScope($"{knownFamily}:{(knownFamily == "Red Hat" ? release.ToLowerInvariant() : release)}", knownFamily!);
        return true;
    }

    /// <summary>
    /// The scope implied by the org's configured upstream URLs, or null when they do not agree on
    /// one. Every URL must name the same release: a mixed or opaque mirror list is ambiguous, and
    /// guessing a branch would query the wrong feed and read its silence as a clean answer.
    /// </summary>
    public static DistroScope? Derive(string ecosystem, IReadOnlyList<string> upstreamUrls)
    {
        if (upstreamUrls.Count == 0)
        {
            return null;
        }

        var scopes = upstreamUrls.Select(u => DeriveOne(ecosystem, u)).ToList();
        return scopes.Any(s => s is null) || scopes.Select(s => s!.OsvEcosystem).Distinct(StringComparer.Ordinal).Count() != 1
            ? null
            : scopes[0];
    }

    private static DistroScope? DeriveOne(string ecosystem, string url)
    {
        if (ecosystem == "apk")
        {
            var m = AlpineUrlBranch().Match(url);
            return m.Success ? new DistroScope($"Alpine:v{m.Groups[1].Value}.{m.Groups[2].Value}", "Alpine") : null;
        }

        var rocky = RockyUrlRelease().Match(url);
        if (rocky.Success)
        {
            return new DistroScope($"Rocky Linux:{rocky.Groups[1].Value}", "Rocky Linux");
        }

        var alma = AlmaUrlRelease().Match(url);
        return alma.Success ? new DistroScope($"AlmaLinux:{alma.Groups[1].Value}", "AlmaLinux") : null;
    }

    /// <summary>The PURL namespace segment OSV registers for the scope's RPM family, or null.</summary>
    public static string? PurlNamespace(DistroScope? scope) =>
        scope is null ? null : RpmFamilies.FirstOrDefault(f => f.Family == scope.Family).PurlNamespace;

    /// <summary>
    /// True when an advisory's affected-package ecosystem is the scope's feed: an exact match, or
    /// the scope followed by further <c>:</c>-separated qualifiers (Red Hat adds a product stream
    /// after the release).
    /// </summary>
    public static bool Covers(string scopeEcosystem, string? advisoryEcosystem) =>
        advisoryEcosystem is not null
        && (advisoryEcosystem.Equals(scopeEcosystem, StringComparison.OrdinalIgnoreCase)
            || advisoryEcosystem.StartsWith(scopeEcosystem + ":", StringComparison.OrdinalIgnoreCase));

    /// <summary>The ordering that applies to <paramref name="scope"/>'s version scheme.</summary>
    public static Comparison<string> ComparerFor(DistroScope scope) =>
        scope.IsApk ? DistroVersionComparer.CompareApk : DistroVersionComparer.CompareRpm;

    /// <summary>
    /// Whether <paramref name="version"/> of <paramref name="name"/> is affected per the OSV
    /// record's <c>affected[]</c> entries for the scope's feed. An entry matches on an enumerated
    /// version (by the scheme's own equality, so <c>0:2.0-1</c> equals <c>2.0-1</c> while <c>1:2.0-1</c> is newer) or on an
    /// ECOSYSTEM range evaluated with the scheme's ordering. An entry that carries neither is
    /// reported, the conservative reading a bare package entry is given elsewhere.
    /// </summary>
    public static bool IsAffected(OsvAdvisory advisory, DistroScope scope, string name, string version)
    {
        var compare = ComparerFor(scope);
        if (advisory.RawJson is null)
        {
            return advisory.AffectedPackages.Any(ap =>
                Covers(scope.OsvEcosystem, ap.Ecosystem)
                && string.Equals(ap.Name, name, StringComparison.OrdinalIgnoreCase)
                && (ap.Versions.Length == 0 || ap.Versions.Any(v => compare(v, version) == 0)));
        }

        try
        {
            using var doc = JsonDocument.Parse(advisory.RawJson);
            return doc.RootElement.TryGetProperty("affected", out var affected)
                && affected.ValueKind == JsonValueKind.Array
                && affected.EnumerateArray().Any(entry => EntryAffects(entry, scope, name, version, compare));
        }
        catch (JsonException)
        {
            // An unreadable record cannot be shown to exclude the version, so it is reported.
            return true;
        }
    }

    private static bool EntryAffects(JsonElement entry, DistroScope scope, string name, string version, Comparison<string> compare)
    {
        return entry.TryGetProperty("package", out var pkg)
            && string.Equals(Str(pkg, "name"), name, StringComparison.OrdinalIgnoreCase)
            && Covers(scope.OsvEcosystem, Str(pkg, "ecosystem"))
            && (ListsVersion(entry, version, compare, out bool anyVersions)
                || InEcosystemRange(entry, version, compare, out bool anyRanges)
                || (!anyVersions && !anyRanges));
    }

    // Whether the entry enumerates the version; anyVersions is whether it enumerates any at all.
    private static bool ListsVersion(JsonElement entry, string version, Comparison<string> compare, out bool anyVersions)
    {
        anyVersions = false;
        if (entry.TryGetProperty("versions", out var versions) && versions.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in versions.EnumerateArray())
            {
                anyVersions = true;
                if (v.ValueKind == JsonValueKind.String && compare(v.GetString()!, version) == 0)
                {
                    return true;
                }
            }
        }

        return false;
    }

    // Whether an ECOSYSTEM range of the entry contains the version; anyRanges is whether it has any.
    private static bool InEcosystemRange(JsonElement entry, string version, Comparison<string> compare, out bool anyRanges)
    {
        anyRanges = false;
        if (entry.TryGetProperty("ranges", out var ranges) && ranges.ValueKind == JsonValueKind.Array)
        {
            foreach (var range in ranges.EnumerateArray())
            {
                if (!string.Equals(Str(range, "type"), "ECOSYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                anyRanges = true;
                if (RangeContains(range, version, compare))
                {
                    return true;
                }
            }
        }

        return false;
    }

    // Events are applied in version order (OSV leaves their listing order to the producer): an
    // introduced event at or below the version opens the range, a fixed event at or below it
    // closes the range, and last_affected closes it only once the version is past it.
    private static bool RangeContains(JsonElement range, string version, Comparison<string> compare)
    {
        if (!range.TryGetProperty("events", out var eventsEl) || eventsEl.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var events = new List<(string Kind, string Version)>();
        foreach (var ev in eventsEl.EnumerateArray())
        {
            foreach (string kind in new[] { "introduced", "fixed", "last_affected" })
            {
                string? v = Str(ev, kind);
                if (v is not null)
                {
                    events.Add((kind, v));
                }
            }
        }

        bool affected = false;
        foreach (var (kind, eventVersion) in events
            .Select((e, i) => (Event: e, Index: i))
            .OrderBy(x => x.Event.Version == "0" ? 0 : 1)
            .ThenBy(x => x.Event.Version, Comparer<string>.Create(compare))
            .ThenBy(x => x.Index)
            .Select(x => x.Event))
        {
            int cmp = eventVersion == "0" ? 1 : compare(version, eventVersion);
            affected = kind switch
            {
                "introduced" => cmp >= 0 || affected,
                "fixed" => cmp < 0 && affected,
                _ => cmp <= 0 && affected,
            };
        }

        return affected;
    }

    private static string? Str(JsonElement el, string property) =>
        el.ValueKind == JsonValueKind.Object && el.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    [GeneratedRegex(@"^(?:alpine\s*[:\-]\s*)?v?(\d{1,3})\.(\d{1,3})\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AlpineRelease();

    [GeneratedRegex(@"^\d{1,2}\z", RegexOptions.CultureInvariant)]
    private static partial Regex MajorRelease();

    [GeneratedRegex(@"^enterprise_linux:\d{1,2}::(?:baseos|appstream)\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RedHatRelease();

    [GeneratedRegex(@"/alpine/v(\d{1,3})\.(\d{1,3})(?:/|\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AlpineUrlBranch();

    [GeneratedRegex(@"/rocky/(\d{1,2})(?:[./]|\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RockyUrlRelease();

    [GeneratedRegex(@"/almalinux/(\d{1,2})(?:[./]|\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AlmaUrlRelease();
}
