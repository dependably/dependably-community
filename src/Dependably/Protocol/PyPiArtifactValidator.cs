using System.Formats.Tar;
using System.IO.Compression;
using System.Text.RegularExpressions;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Extracts package name and version from a PyPI artefact for the bulk-import path.
/// Supported formats:
/// <list type="bullet">
///   <item>Wheel (<c>.whl</c>): zip with metadata at <c>{name}-{version}.dist-info/METADATA</c>.
///   The filename itself encodes <c>{name}-{version}-...</c> per PEP 427.</item>
///   <item>Sdist (<c>.tar.gz</c> or <c>.tgz</c>): gzipped tar with PEP 314
///   <c>{name}-{version}/PKG-INFO</c> at the top level.</item>
///   <item>Egg (<c>.egg</c>): legacy setuptools zip with metadata at <c>EGG-INFO/PKG-INFO</c>.
///   Supported for proxying and importing existing artefacts; PyPI no longer accepts egg uploads.</item>
/// </list>
/// Names are normalised per PEP 503 (lowercase, runs of <c>_</c>, <c>.</c>, or <c>-</c>
/// collapse to a single <c>-</c>) before comparison.
/// </summary>
public static partial class PyPiArtifactValidator
{
    [GeneratedRegex(@"^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?$")]
    private static partial Regex Pep508NameRegex();

    [GeneratedRegex(@"^\d[\w\.\!\+\-]*$")]
    private static partial Regex Pep440VersionRegex();

    /// <summary>
    /// Extension-based dispatch. Kept for protocol callers (twine upload) where the server
    /// authoritatively knows the filename and wants the strict filename↔METADATA cross-check.
    /// The content-based EcosystemDetector calls <see cref="ValidateWheel(byte[],out string?,out string?)"/>
    /// and <see cref="ValidateSdist"/> directly so a renamed file can't lie about its format.
    /// </summary>
    public static ValidationResult Validate(string filename, byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;
        string lowered = filename.ToLowerInvariant();
        try
        {
            return lowered.EndsWith(".whl", StringComparison.Ordinal)
                ? ValidateWheelStrict(filename, bytes, out name, out version)
                : lowered.EndsWith(".tar.gz", StringComparison.Ordinal)
                || lowered.EndsWith(".tgz", StringComparison.Ordinal)
                ? ValidateSdist(bytes, out name, out version)
                : lowered.EndsWith(".egg", StringComparison.Ordinal)
                ? ValidateEggStrict(filename, bytes, out name, out version)
                : ValidationResult.Fail("filename",
                "Unrecognised PyPI artefact extension; expected .whl, .tar.gz/.tgz, or .egg.");
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Failed to parse PyPI artefact: {ex.Message}");
        }
    }

    /// <summary>
    /// Content-only wheel validation. Derives name+version from <c>{name}-{version}.dist-info/METADATA</c>
    /// inside the archive — no filename involved. Called by EcosystemDetector when the filename
    /// is untrusted.
    /// </summary>
    public static ValidationResult ValidateWheel(byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            var metaEntry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
            if (metaEntry is null)
            {
                return ValidationResult.Fail("content", "Wheel is missing dist-info/METADATA.");
            }

            using var stream = metaEntry.Open();
            using var reader = new StreamReader(stream);
            var (metaName, metaVersion) = ReadHeaders(reader, "Name", "Version");

            if (!ValidateNameVersion(metaName, metaVersion, out string? error))
            {
                return ValidationResult.Fail("content", error);
            }

            name = Normalize(metaName!);
            version = metaVersion;
            return ValidationResult.Ok();
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Failed to parse wheel: {ex.Message}");
        }
    }

    /// <summary>
    /// Strict wheel validation used by the protocol push path: cross-checks the filename-derived
    /// (name, version) against METADATA so a renamed wheel pushed by twine is rejected.
    /// </summary>
    private static ValidationResult ValidateWheelStrict(string filename, byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;

        // Filename per PEP 427: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
        string stem = filename[..^4];
        string[] parts = stem.Split('-');
        if (parts.Length < 5)
        {
            return ValidationResult.Fail("filename", "Wheel filename must have at least 5 dash-separated segments.");
        }

        string fileName = parts[0];
        string fileVersion = parts[1];

        var inner = ValidateWheel(bytes, out string? metaNameNormalized, out string? metaVersion);
        if (!inner.IsValid)
        {
            return inner;
        }

        if (!Normalize(fileName).Equals(metaNameNormalized!, StringComparison.Ordinal))
        {
            return ValidationResult.Fail("content",
                $"Wheel filename name '{fileName}' does not match METADATA Name.");
        }

        if (fileVersion != metaVersion)
        {
            return ValidationResult.Fail("content",
                $"Wheel filename version '{fileVersion}' does not match METADATA Version '{metaVersion}'.");
        }

        name = metaNameNormalized;
        version = metaVersion;
        return ValidationResult.Ok();
    }

    /// <summary>
    /// Content-only egg validation. Derives name+version from <c>EGG-INFO/PKG-INFO</c> inside
    /// the zip — no filename involved. Eggs are a legacy setuptools format supported for
    /// proxying and importing existing artefacts; PyPI no longer accepts egg uploads.
    /// </summary>
    public static ValidationResult ValidateEgg(byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            var metaEntry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
            if (metaEntry is null)
            {
                return ValidationResult.Fail("content", "Egg is missing EGG-INFO/PKG-INFO.");
            }

            using var stream = metaEntry.Open();
            using var reader = new StreamReader(stream);
            var (metaName, metaVersion) = ReadHeaders(reader, "Name", "Version");

            if (!ValidateNameVersion(metaName, metaVersion, out string? error))
            {
                return ValidationResult.Fail("content", error);
            }

            name = Normalize(metaName!);
            version = metaVersion;
            return ValidationResult.Ok();
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Failed to parse egg: {ex.Message}");
        }
    }

    /// <summary>
    /// Strict egg validation for the protocol push path: cross-checks the filename-derived name
    /// against <c>EGG-INFO/PKG-INFO</c>. The setuptools egg filename mangles <c>-</c> to <c>_</c>
    /// in both name and version, so only the PEP 503-normalised name is cross-checked; the
    /// version is taken from PKG-INFO, which is authoritative.
    /// </summary>
    private static ValidationResult ValidateEggStrict(string filename, byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;

        // Filename per setuptools: {name}-{version}(-py{X.Y})?(-{platform})?.egg
        string stem = filename[..^4];
        string[] parts = stem.Split('-');
        if (parts.Length < 2)
        {
            return ValidationResult.Fail("filename", "Egg filename must have at least 2 dash-separated segments.");
        }

        var inner = ValidateEgg(bytes, out string? metaNameNormalized, out string? metaVersion);
        if (!inner.IsValid)
        {
            return inner;
        }

        if (!Normalize(parts[0]).Equals(metaNameNormalized!, StringComparison.Ordinal))
        {
            return ValidationResult.Fail("content",
                $"Egg filename name '{parts[0]}' does not match EGG-INFO/PKG-INFO Name.");
        }

        name = metaNameNormalized;
        version = metaVersion;
        return ValidationResult.Ok();
    }

    /// <summary>
    /// Content-only sdist validation. Looks for <c>{name}-{version}/PKG-INFO</c> at the top
    /// level of the gzipped tarball and parses the RFC 822 headers there. Used by both the
    /// extension-dispatch wrapper and the content-based EcosystemDetector.
    /// </summary>
    public static ValidationResult ValidateSdist(byte[] bytes, out string? name, out string? version)
    {
        name = null;
        version = null;
        try
        {
            using var gzip = new LimitedReadStream(
                new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress),
                ArchiveDecompressLimits.MaxDecompressedBytes, "Sdist");
            using var tar = new TarReader(gzip, leaveOpen: false);

            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.Name.EndsWith("/PKG-INFO", StringComparison.OrdinalIgnoreCase)
                    && entry.Name.Count(c => c == '/') == 1)
                {
                    using var stream = entry.DataStream!;
                    using var reader = new StreamReader(stream);
                    var (pkgName, pkgVersion) = ReadHeaders(reader, "Name", "Version");
                    if (!ValidateNameVersion(pkgName, pkgVersion, out string? error))
                    {
                        return ValidationResult.Fail("content", error);
                    }

                    name = Normalize(pkgName!);
                    version = pkgVersion;

                    // Outer-label override: PEP 314 sdists wrap as {name}-{version}/, so when
                    // the wrapper carries a PEP 440-shaped suffix it is authoritative for the
                    // version. For canonical sdists the wrapper matches PKG-INFO; for source
                    // archives whose PKG-INFO is stale across tags, the wrapper disambiguates.
                    string wrapper = entry.Name[..entry.Name.IndexOf('/')];
                    if (OuterVersionLabel.TryFromPyPiSdistWrapper(wrapper, out string? labelled))
                    {
                        version = labelled;
                    }

                    return ValidationResult.Ok();
                }
            }

            return ValidationResult.Fail("content", "Sdist is missing top-level {name}-{version}/PKG-INFO.");
        }
        catch (Exception ex)
        {
            return ValidationResult.Fail("content", $"Failed to parse sdist: {ex.Message}");
        }
    }

    private static (string? Name, string? Version) ReadHeaders(StreamReader reader, string nameHeader, string versionHeader)
    {
        // RFC 822-style headers — first blank line ends the section.
        string? name = null;
        string? version = null;
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0)
            {
                break;
            }

            int colon = line.IndexOf(':');
            if (colon < 0)
            {
                continue;
            }

            string key = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();
            if (key.Equals(nameHeader, StringComparison.OrdinalIgnoreCase))
            {
                name = value;
            }
            else if (key.Equals(versionHeader, StringComparison.OrdinalIgnoreCase))
            {
                version = value;
            }

            if (name is not null && version is not null)
            {
                break;
            }
        }
        return (name, version);
    }

    private static bool ValidateNameVersion(string? name, string? version, out string error)
    {
        if (string.IsNullOrEmpty(name)) { error = "Name header missing or empty."; return false; }
        if (string.IsNullOrEmpty(version)) { error = "Version header missing or empty."; return false; }
        if (!Pep508NameRegex().IsMatch(name)) { error = $"Invalid PEP 508 name: {name}"; return false; }
        if (!Pep440VersionRegex().IsMatch(version)) { error = $"Invalid PEP 440 version: {version}"; return false; }
        error = "";
        return true;
    }

    /// <summary>PEP 503 canonicalisation. Public so the import path can use the same normaliser as the publish path.</summary>
    public static string Normalize(string name) =>
        Pep503Replace().Replace(name.ToLowerInvariant(), "-");

    /// <summary>True when <paramref name="version"/> is PEP 440-shaped (digit-leading). Public so
    /// manifest parsers can skip non-version entries (e.g. poetry vcs/path source deps).</summary>
    public static bool IsPep440Version(string version) => Pep440VersionRegex().IsMatch(version);

    [GeneratedRegex(@"[-_.]+")]
    private static partial Regex Pep503Replace();

    /// <summary>
    /// Filename-only parser used by the proxy <c>/packages/{file}</c> path, where the
    /// archive bytes aren't in hand yet. Wheels and eggs follow a strict dash-split (name and
    /// version are the first two segments); sdists need a right-to-left PEP 440 scan because the
    /// distribution segment can contain hyphens
    /// (e.g. <c>psycopg2-binary-2.9.10.tar.gz</c> → <c>psycopg2-binary</c> + <c>2.9.10</c>).
    /// Returned <paramref name="purlName"/> is PEP 503 normalised.
    /// </summary>
    public static bool TryParseFilename(string filename, out string? purlName, out string? version)
    {
        purlName = null;
        version = null;
        if (string.IsNullOrEmpty(filename))
        {
            return false;
        }

        string lowered = filename.ToLowerInvariant();

        return lowered.EndsWith(".egg", StringComparison.Ordinal)
            ? TryParseEggFilename(filename, out purlName, out version)
            : TryStripArchiveExtension(filename, lowered, out string? stem, out bool isWheel) && (isWheel
            ? TryParseWheelStem(stem, out purlName, out version)
            : TryParseSdistStem(stem, out purlName, out version));
    }

    // setuptools egg: {name}-{version}(-py{X.Y})?(-{platform})?.egg. '-' inside the name/version
    // is mangled to '_', so the first two dash segments are name + version.
    private static bool TryParseEggFilename(string filename, out string? purlName, out string? version)
    {
        purlName = null;
        version = null;
        string[] eggParts = filename[..^4].Split('-');
        if (eggParts.Length < 2 || !Pep440VersionRegex().IsMatch(eggParts[1]))
        {
            return false;
        }

        purlName = Normalize(eggParts[0]);
        version = eggParts[1];
        return true;
    }

    // Strips the sdist/wheel archive extension, yielding the stem and whether it's a wheel.
    private static bool TryStripArchiveExtension(string filename, string lowered, out string stem, out bool isWheel)
    {
        isWheel = false;
        if (lowered.EndsWith(".whl", StringComparison.Ordinal)) { stem = filename[..^4]; isWheel = true; return true; }
        if (lowered.EndsWith(".tar.gz", StringComparison.Ordinal)) { stem = filename[..^7]; return true; }
        if (lowered.EndsWith(".tar.bz2", StringComparison.Ordinal)) { stem = filename[..^8]; return true; }
        // .zip is legacy PEP 314 sdist; PyPI still serves them. Same 4-char strip as .tgz.
        if (lowered.EndsWith(".tgz", StringComparison.Ordinal)
            || lowered.EndsWith(".zip", StringComparison.Ordinal)) { stem = filename[..^4]; return true; }
        stem = "";
        return false;
    }

    // PEP 427: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}. Distribution is
    // mandated to use underscores, so split-on-dash is safe here.
    private static bool TryParseWheelStem(string stem, out string? purlName, out string? version)
    {
        purlName = null;
        version = null;
        string[] parts = stem.Split('-');
        if (parts.Length < 5)
        {
            return false;
        }

        if (!Pep440VersionRegex().IsMatch(parts[1]))
        {
            return false;
        }

        purlName = Normalize(parts[0]);
        version = parts[1];
        return true;
    }

    // Sdist: scan right-to-left for the first split where the right side is PEP 440-shaped. This
    // is how pip disambiguates names like "psycopg2-binary" from version suffixes.
    private static bool TryParseSdistStem(string stem, out string? purlName, out string? version)
    {
        purlName = null;
        version = null;
        for (int i = stem.LastIndexOf('-'); i > 0; i = stem.LastIndexOf('-', i - 1))
        {
            string candidate = stem[(i + 1)..];
            if (Pep440VersionRegex().IsMatch(candidate))
            {
                purlName = Normalize(stem[..i]);
                version = candidate;
                return true;
            }
        }
        return false;
    }
}
