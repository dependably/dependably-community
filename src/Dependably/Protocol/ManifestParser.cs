using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// Parses ecosystem lockfile / requirements formats into a normalised list of
/// <see cref="ManifestEntry"/> records for the manifest-driven import path.
///
/// Supported:
/// <list type="bullet">
///   <item>npm <c>package-lock.json</c> v1 (top-level <c>dependencies</c> tree) and v2/v3
///   (top-level <c>packages</c> map). The lockfile-version field selects which walk to use.</item>
///   <item>pip <c>requirements.txt</c> with pinned <c>name==version</c> lines and optional
///   <c>--hash=sha256:...</c> continuations.</item>
///   <item>NuGet <c>packages.lock.json</c> — central transitive lock with one entry per
///   resolved (id, version) across all target frameworks.</item>
/// </list>
///
/// Names are normalised to the same form the per-ecosystem validator emits, so manifest
/// entries can match against parsed artefacts without ecosystem-specific reconciliation:
/// pip uses PEP 503, nuget uses lowercase, npm uses raw scope/name.
/// </summary>
public static class ManifestParser
{
    public enum ManifestType { Unknown, NpmPackageLock, PipRequirements, NuGetPackagesLock }

    /// <summary>
    /// Detects manifest type from a filename (preferred) and a peek at the content.
    /// Filename takes precedence — operators name these files conventionally.
    /// </summary>
    public static ManifestType Detect(string filename, string content)
    {
        var lower = filename.ToLowerInvariant();
        if (lower.EndsWith("package-lock.json", StringComparison.Ordinal)) return ManifestType.NpmPackageLock;
        if (lower.EndsWith("packages.lock.json", StringComparison.Ordinal)) return ManifestType.NuGetPackagesLock;
        if (lower.EndsWith("requirements.txt", StringComparison.Ordinal)) return ManifestType.PipRequirements;

        // Content sniff fallback. JSON content gets disambiguated by top-level keys.
        var trimmed = content.TrimStart();
        if (trimmed.StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;
                if (root.TryGetProperty("lockfileVersion", out _)) return ManifestType.NpmPackageLock;
                if (root.TryGetProperty("dependencies", out var deps) && deps.ValueKind == JsonValueKind.Object
                    && root.TryGetProperty("version", out _)) return ManifestType.NuGetPackagesLock;
            }
            catch (JsonException) { /* fall through */ }
        }
        else if (trimmed.Length > 0)
        {
            // requirements.txt is the only plain-text manifest we accept.
            return ManifestType.PipRequirements;
        }
        return ManifestType.Unknown;
    }

    public static IReadOnlyList<ManifestEntry> Parse(ManifestType type, string content) => type switch
    {
        ManifestType.NpmPackageLock => ParseNpmPackageLock(content),
        ManifestType.PipRequirements => ParseRequirementsTxt(content),
        ManifestType.NuGetPackagesLock => ParseNuGetPackagesLock(content),
        _ => []
    };

    private static List<ManifestEntry> ParseNpmPackageLock(string json)
    {
        var entries = new List<ManifestEntry>();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (LockfileVersion(root) >= 2
            && root.TryGetProperty("packages", out var packages)
            && packages.ValueKind == JsonValueKind.Object)
        {
            // v2/v3: each key is a node_modules path; the empty-string key is the root project.
            foreach (var prop in packages.EnumerateObject())
            {
                var entry = TryReadNpmPackagesEntry(prop);
                if (entry is not null) entries.Add(entry);
            }
        }
        else if (root.TryGetProperty("dependencies", out var deps)
            && deps.ValueKind == JsonValueKind.Object)
        {
            // v1: depth-first walk through the nested dependency tree.
            WalkV1(deps, entries);
        }

        // Dedup: the same (name, version) shows up under multiple paths in v2/v3 and across
        // transitive trees in v1. Keep one entry per coordinate.
        return entries
            .GroupBy(e => (e.Ecosystem, e.Name, e.Version))
            .Select(g => g.First())
            .ToList();
    }

    private static int LockfileVersion(JsonElement root) =>
        root.TryGetProperty("lockfileVersion", out var lv) && lv.ValueKind == JsonValueKind.Number
            ? lv.GetInt32()
            : 1;

    /// <summary>
    /// Reads one entry from the v2/v3 <c>packages</c> map. Returns null when the entry
    /// is the root project (empty key), a non-package path, or is missing a version
    /// (every required field is a "skip on absent" rather than a hard error — partial
    /// lockfiles in the wild stay tolerable).
    /// </summary>
    private static ManifestEntry? TryReadNpmPackagesEntry(JsonProperty prop)
    {
        if (string.IsNullOrEmpty(prop.Name)) return null;
        var pkgName = ExtractNpmNameFromPath(prop.Name);
        if (pkgName is null) return null;
        if (!prop.Value.TryGetProperty("version", out var ver) || ver.ValueKind != JsonValueKind.String) return null;

        var integrity = prop.Value.TryGetProperty("integrity", out var ig) && ig.ValueKind == JsonValueKind.String
            ? ig.GetString() : null;
        return new ManifestEntry("npm", pkgName, ver.GetString()!, ParseIntegrity(integrity));
    }

    private static void WalkV1(JsonElement deps, List<ManifestEntry> entries)
    {
        foreach (var prop in deps.EnumerateObject())
        {
            if (!prop.Value.TryGetProperty("version", out var ver) || ver.ValueKind != JsonValueKind.String) continue;
            var version = ver.GetString()!;
            var integrity = prop.Value.TryGetProperty("integrity", out var ig) && ig.ValueKind == JsonValueKind.String
                ? ig.GetString() : null;
            entries.Add(new ManifestEntry("npm", prop.Name, version, ParseIntegrity(integrity)));
            if (prop.Value.TryGetProperty("dependencies", out var nested) && nested.ValueKind == JsonValueKind.Object)
                WalkV1(nested, entries);
        }
    }

    /// <summary>
    /// "node_modules/lodash" → "lodash". "node_modules/@scope/name" → "@scope/name".
    /// Skips entries that don't start with node_modules/ (e.g. workspaces, root references).
    /// </summary>
    private static string? ExtractNpmNameFromPath(string path)
    {
        const string prefix = "node_modules/";
        if (!path.StartsWith(prefix, StringComparison.Ordinal)) return null;
        var rest = path[prefix.Length..];
        // Pick the last occurrence so nested dependencies (node_modules/a/node_modules/b) still
        // resolve to the leaf package name.
        var idx = rest.LastIndexOf(prefix, StringComparison.Ordinal);
        if (idx >= 0) rest = rest[(idx + prefix.Length)..];
        return rest.Length == 0 ? null : rest;
    }

    private static List<ManifestEntry> ParseRequirementsTxt(string content)
    {
        var entries = new List<ManifestEntry>();
        // Stitch line continuations: requirements.txt allows trailing backslash to extend a
        // line, particularly for hash continuations (--hash=sha256:...). Normalise first.
        var stitched = content.Replace("\\\r\n", " ").Replace("\\\n", " ");
        foreach (var rawLine in stitched.Split('\n'))
        {
            var entry = TryParseRequirementLine(rawLine);
            if (entry is not null) entries.Add(entry);
        }
        return entries;
    }

    /// <summary>
    /// Parses one requirements.txt line, returning null for blank/comment/option lines or
    /// any pinning shape we don't recognise (e.g. <c>~=</c>, <c>&gt;=</c>; we only match
    /// strict <c>==</c> pins because looser specifiers can't be matched to a single
    /// uploaded artefact). Strips trailing comments and PEP 508 environment markers.
    /// </summary>
    private static ManifestEntry? TryParseRequirementLine(string rawLine)
    {
        var line = rawLine.Trim();
        if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('-')) return null;

        var hashIdx = line.IndexOf('#');
        if (hashIdx > 0) line = line[..hashIdx].Trim();

        var semiIdx = line.IndexOf(';');
        if (semiIdx >= 0) line = line[..semiIdx].Trim();

        var parts = line.Split("==", 2, StringSplitOptions.None);
        if (parts.Length != 2) return null;

        var name = parts[0].Trim();
        var rhs = parts[1].Trim();
        var ws = rhs.IndexOfAny([' ', '\t']);
        var version = ws < 0 ? rhs : rhs[..ws].Trim();
        var hashes = ws < 0 ? "" : rhs[ws..];

        return new ManifestEntry(
            "pypi", PyPiArtifactValidator.Normalize(name), version, ExtractFirstSha256Hash(hashes));
    }

    /// <summary>
    /// Pulls the first <c>--hash=sha256:&lt;hex&gt;</c> token out of a requirements.txt line's
    /// trailing hash clauses. Returns null if no sha256 hash is present (md5/sha1 are not
    /// recorded — we hash uploads with sha256 and don't try to match other algorithms).
    /// </summary>
    private static string? ExtractFirstSha256Hash(string hashes)
    {
        const string hashPrefix = "--hash=sha256:";
        var hashStart = hashes.IndexOf(hashPrefix, StringComparison.Ordinal);
        if (hashStart < 0) return null;

        var hashRest = hashes[(hashStart + hashPrefix.Length)..];
        var hashEnd = hashRest.IndexOfAny([' ', '\t', '-']);
        return hashEnd < 0 ? hashRest.Trim() : hashRest[..hashEnd].Trim();
    }

    private static List<ManifestEntry> ParseNuGetPackagesLock(string json)
    {
        var entries = new List<ManifestEntry>();
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("dependencies", out var byFramework)
            || byFramework.ValueKind != JsonValueKind.Object) return entries;

        foreach (var fwValue in byFramework.EnumerateObject()
                                            .Where(fw => fw.Value.ValueKind == JsonValueKind.Object)
                                            .Select(fw => fw.Value))
        {
            foreach (var pkg in fwValue.EnumerateObject())
            {
                var entry = TryReadNuGetPackageEntry(pkg);
                if (entry is not null) entries.Add(entry);
            }
        }
        return entries
            .GroupBy(e => (e.Ecosystem, e.Name, e.Version))
            .Select(g => g.First())
            .ToList();
    }

    /// <summary>
    /// Reads one entry from a <c>packages.lock.json</c> framework block. Returns null if
    /// the entry is not a project dependency (e.g. <c>type:Project</c>) or is missing
    /// the <c>resolved</c> version we need to match an uploaded artefact.
    /// </summary>
    private static ManifestEntry? TryReadNuGetPackageEntry(JsonProperty pkg)
    {
        if (pkg.Value.ValueKind != JsonValueKind.Object) return null;
        if (!pkg.Value.TryGetProperty("resolved", out var ver) || ver.ValueKind != JsonValueKind.String) return null;

        var sha = pkg.Value.TryGetProperty("contentHash", out var ch) && ch.ValueKind == JsonValueKind.String
            ? ch.GetString() : null;
        return new ManifestEntry("nuget", pkg.Name.ToLowerInvariant(), ver.GetString()!, sha);
    }

    /// <summary>
    /// npm integrity strings are in subresource-integrity format ("sha512-..." / "sha256-...").
    /// We only record sha256 since that's what we hash uploads with; everything else is null.
    /// </summary>
    private static string? ParseIntegrity(string? integrity)
    {
        if (string.IsNullOrEmpty(integrity)) return null;
        const string prefix = "sha256-";
        if (!integrity.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        var b64 = integrity[prefix.Length..];
        try { return Convert.ToHexString(Convert.FromBase64String(b64)).ToLowerInvariant(); }
        catch { return null; }
    }
}

/// <summary>One package coordinate from a manifest. Matched against an uploaded artefact.</summary>
public sealed record ManifestEntry(string Ecosystem, string Name, string Version, string? Sha256);
