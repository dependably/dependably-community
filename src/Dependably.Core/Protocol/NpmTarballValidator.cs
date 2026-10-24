using System.Text.Json.Nodes;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Decodes an npm tarball, finds the top-level <c>package.json</c>, and extracts the package
/// name and version. Used by both the npm publish controller and the bulk-import
/// controller so the validation rules stay aligned.
///
/// <para>Accepts <c>package.json</c> either at the root or inside a single wrapper directory
/// of any name (<c>npm pack</c> always writes <c>package/</c>, but tarballs from
/// <c>git archive</c>, GitHub release assets, or hand-rolled <c>tar</c> commands often use the
/// <c>{name}-{version}/</c> shape or no wrapper at all — npm itself strips one leading
/// directory on install, so the wrapper name is not significant).</para>
/// </summary>
/// <summary>
/// Combines the validation outcome with the extracted package name and version so
/// callers receive all three values in a single return without out-parameters.
/// <see cref="Manifest"/> is the parsed <c>package.json</c> object on success — the
/// artefact-authoritative source for the install-relevant manifest subset persisted at
/// publish (see <see cref="NpmInstallManifest"/>) — and null on validation failure.
/// </summary>
public sealed record NpmTarballParsed(
    ValidationResult Validation, string? Name, string? Version, JsonObject? Manifest = null);

public static class NpmTarballValidator
{
    private static readonly char[] PathSeparators = ['/', '\\'];

    public static NpmTarballParsed Validate(byte[] bytes) => Validate(new MemoryStream(bytes));

    /// <summary>
    /// Streaming overload: reads the gzipped tar directly from <paramref name="gzipSource"/> (a
    /// staged file on the publish path) so the artifact is never materialised in a byte[]. The
    /// same zip-bomb guards apply. The source stream is left open for the caller to dispose.
    /// </summary>
    public static NpmTarballParsed Validate(Stream gzipSource)
    {
        try
        {
            // Zip-bomb guards and manifest selection live in the shared scanner: it caps total
            // decompressed bytes, entry count, and the manifest size, and rejects an archive with
            // more than one top-level manifest because npm would install a different one than a
            // first-match reader inspects.
            var scan = NpmTarballManifestScanner.Scan(gzipSource, leaveOpen: true);
            return scan.Outcome switch
            {
                NpmManifestScanOutcome.Found => ParseManifest(scan.EntryName!, scan.Bytes!),
                NpmManifestScanOutcome.Ambiguous => new NpmTarballParsed(
                    ValidationResult.Fail("content",
                        "Tarball contains more than one top-level package.json; the installed manifest would be ambiguous."),
                    null, null),
                NpmManifestScanOutcome.TooManyEntries => new NpmTarballParsed(
                    ValidationResult.Fail("content", $"Tarball exceeds the {TarScanLimits.MaxEntries}-entry limit."),
                    null, null),
                NpmManifestScanOutcome.Missing => new NpmTarballParsed(
                    ValidationResult.Fail("content", "Tarball is missing a top-level package.json"),
                    null, null),
                _ => new NpmTarballParsed(
                    ValidationResult.Fail("content",
                        "Tarball could not be scanned: the archive is malformed or read differently by npm, or its package.json is not valid JSON with unique keys."),
                    null, null),
            };
        }
        catch (Exception ex)
        {
            return new NpmTarballParsed(
                ValidationResult.Fail("content", $"Invalid gzip tar: {ex.Message}"),
                null, null);
        }
    }

    // Parses the package.json bytes, validates the name and version fields, and applies the
    // outer-label override for GitHub-style source archives.
    private static NpmTarballParsed ParseManifest(string entryName, byte[] manifestBytes)
    {
        var json = JsonNode.Parse(manifestBytes);
        var manifest = json as JsonObject;
        string? name = json?["name"]?.GetValue<string>();
        string? version = json?["version"]?.GetValue<string>();

        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(version))
        {
            // Return partially-extracted values so callers can observe what was present.
            return new NpmTarballParsed(
                ValidationResult.Fail("content", "package.json missing name or version"),
                name, version);
        }

        // Name shape gate (same rules as the npm publish controller). The import
        // path takes this name verbatim into blob-key construction, so slash-laden
        // manifest names other than a single @scope/ prefix must be rejected here.
        if (!NpmNameValidator.IsValidFullName(name))
        {
            return new NpmTarballParsed(
                ValidationResult.Fail("content", $"Invalid npm package name: {name}"),
                null, null);
        }

        // Outer-label override: when the wrapper directory looks like
        // {anything}-{semver}/ (typical of GitHub source archives whose root
        // package.json may be stale across release tags), the wrapper's semver
        // is authoritative for the version. `npm pack`'s `package/` wrapper
        // carries no version, so this is a no-op for canonical npm publish.
        string wrapper = WrapperOf(entryName);
        if (OuterVersionLabel.TryFromNpmWrapper(wrapper, out string? labelled))
        {
            version = labelled;
        }

        return new NpmTarballParsed(ValidationResult.Ok(), name, version, manifest);
    }

    /// <summary>How an archive entry name relates to the manifest npm installs.</summary>
    internal enum ManifestEntryKind
    {
        /// <summary>Not a top-level manifest (including nested <c>package.json</c> files).</summary>
        None,

        /// <summary>The top-level manifest: root, or exactly one wrapper component.</summary>
        TopLevel,

        /// <summary>A <c>package.json</c> whose path climbs with <c>..</c>; its extracted location is unknowable.</summary>
        Traversal,
    }

    // Classifies an entry name the way node-tar's `strip: 1` extraction sees it, under both of the
    // readings npm applies depending on the host. On posix a `\` is an ordinary filename character:
    // node-tar splits on `/` only, so `x\y/package.json` strips the wrapper `x\y` and lands on the
    // manifest. On win32 it first turns every `\` into `/` (normalize-windows-path), so the same
    // name is the nested `y/package.json`. An entry is the manifest if either reading installs it
    // there, and a traversal if either reading climbs with `..`.
    //
    // In each reading the first component is the stripped wrapper, so a leading `./` is itself the
    // wrapper (`./package.json` is the manifest, `./x/package.json` a nested file) and a leading `/`
    // makes an empty wrapper (`/package/package.json` extracts as the nested `package/package.json`).
    // The remainder then goes through StripAbsolutePath, which mirrors node-tar's
    // `stripAbsolutePath` and reads `\` as a separator on every platform, so `package/C:package.json`
    // and, even on posix, `package/\\server\share\package.json` land on `package.json`. Empty and `.`
    // components after that are no-ops (`package//package.json`, `package/./package.json`). The `..`
    // check runs on the stripped remainder with `\` read as `/`, as node-tar does on every platform.
    // A bare `package.json` at the archive root is also accepted. Matching is case-insensitive,
    // which is wider than npm on a case-sensitive filesystem: a case variant is rejected as
    // ambiguous rather than guessed at.
    internal static ManifestEntryKind ClassifyEntry(string entryName)
    {
        var posix = ClassifyReading(entryName);
        var win32 = ClassifyReading(entryName.Replace('\\', '/'));
        return posix == ManifestEntryKind.Traversal || win32 == ManifestEntryKind.Traversal
            ? ManifestEntryKind.Traversal
            : posix == ManifestEntryKind.TopLevel || win32 == ManifestEntryKind.TopLevel
                ? ManifestEntryKind.TopLevel
                : ManifestEntryKind.None;
    }

    // One reading, splitting on `/` only: the win32 reading converts backslashes before calling.
    private static ManifestEntryKind ClassifyReading(string name)
    {
        if (name.EndsWith('/'))
        {
            return ManifestEntryKind.None;
        }

        string[] parts = name.Split('/');
        if (parts.Length == 1)
        {
            return IsManifestName(parts[0]) ? ManifestEntryKind.TopLevel : ManifestEntryKind.None;
        }

        string remainder = StripAbsolutePath(string.Join('/', parts.Skip(1)));
        if (remainder.Replace('\\', '/').Split('/').Contains(".."))
        {
            string last = remainder.Split(PathSeparators).LastOrDefault(p => p.Length > 0 && p != ".") ?? string.Empty;
            return IsManifestName(last) ? ManifestEntryKind.Traversal : ManifestEntryKind.None;
        }

        string[] rest = remainder.Split('/').Where(p => p.Length > 0 && p != ".").ToArray();
        return rest.Length == 1 && IsManifestName(rest[0]) ? ManifestEntryKind.TopLevel : ManifestEntryKind.None;
    }

    // Mirrors node-tar's `stripAbsolutePath` (src/strip-absolute-path.ts): while the path has a
    // root, remove it. The root is a single leading `/` unless the path starts `//?/`, and
    // otherwise whatever `path.win32.parse` reports, which treats `\` and `/` alike: a drive prefix
    // `X:` with an optional following separator, a lone leading separator, or a UNC root
    // `\\server\share\` (which also covers the `\\?\C:\` and `\\.\pipe\` device forms).
    internal static string StripAbsolutePath(string path)
    {
        while (true)
        {
            int root = path.StartsWith('/') && !path.StartsWith("//?/", StringComparison.Ordinal)
                ? 1
                : Win32RootLength(path);
            if (root == 0)
            {
                return path;
            }

            path = path[root..];
        }
    }

    // The length of `path.win32.parse(path).root`, as Node's lib/path.js computes it.
    private static int Win32RootLength(string path)
    {
        int len = path.Length;
        if (len == 0)
        {
            return 0;
        }

        if (IsSeparator(path[0]))
        {
            return len > 1 && IsSeparator(path[1]) ? UncRootLength(path) : 1;
        }

        bool drive = len >= 2 && char.IsAsciiLetter(path[0]) && path[1] == ':';
        return !drive ? 0 : len > 2 && IsSeparator(path[2]) ? 3 : 2;
    }

    // `\\server\share` (whole path) or `\\server\share\`; anything shorter is just a leading separator.
    private static int UncRootLength(string path)
    {
        int len = path.Length;
        int j = 2;
        while (j < len && !IsSeparator(path[j]))
        {
            j++;
        }

        if (j == len || j == 2)
        {
            return 1;
        }

        int last = j;
        while (j < len && IsSeparator(path[j]))
        {
            j++;
        }

        if (j == len || j == last)
        {
            return 1;
        }

        last = j;
        while (j < len && !IsSeparator(path[j]))
        {
            j++;
        }

        return j == len ? j : j != last ? j + 1 : 1;
    }

    private static bool IsSeparator(char c) => c is '/' or '\\';

    // Also matches the names a Windows npm host resolves to the same file: Win32 drops trailing
    // dots and spaces (`package.json.`, `package.json `), and `PACKAG~<n>.JSO` is the 8.3 short
    // name of `package.json`. Either one, extracted after the manifest, overwrites it.
    private static bool IsManifestName(string component)
    {
        string name = component.TrimEnd('.', ' ');
        return name.Equals("package.json", StringComparison.OrdinalIgnoreCase) || IsShortManifestName(name);
    }

    private static bool IsShortManifestName(string name)
    {
        const string Stem = "PACKAG~";
        const string Extension = ".JSO";
        if (!name.StartsWith(Stem, StringComparison.OrdinalIgnoreCase)
            || !name.EndsWith(Extension, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var digits = name.AsSpan(Stem.Length, Math.Max(0, name.Length - Stem.Length - Extension.Length));
        return digits.Length > 0 && !digits.ContainsAnyExceptInRange('0', '9');
    }

    internal static bool IsTopLevelPackageJson(string entryName) =>
        ClassifyEntry(entryName) == ManifestEntryKind.TopLevel;

    // Returns the wrapper-dir segment of a top-level entry name, or empty when the entry sits at
    // the archive root (no wrapper). The wrapper is the first `/` component when the posix reading
    // finds the manifest, otherwise the first component with `\` read as a separator.
    private static string WrapperOf(string entryName)
    {
        string name = ClassifyReading(entryName) == ManifestEntryKind.TopLevel
            ? entryName
            : entryName.Replace('\\', '/');
        string[] parts = name.Split('/');
        return parts.Length < 2 ? string.Empty : parts[0];
    }
}
