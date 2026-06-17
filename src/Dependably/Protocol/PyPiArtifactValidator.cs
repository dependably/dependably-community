using System.Formats.Tar;
using System.IO.Compression;
using System.Text.RegularExpressions;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Combines the validation outcome with the extracted package name and version so callers
/// receive all three values without out-parameters.
/// </summary>
public sealed record PyPiArtifactParsed(ValidationResult Validation, string? Name, string? Version);

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
    // Archive extension character lengths (for slicing off the extension from filenames).
    private const int WhlExtLen = 4;     // ".whl"
    private const int TarGzExtLen = 7;   // ".tar.gz"
    private const int TarBz2ExtLen = 8;  // ".tar.bz2"
    private const int TgzExtLen = 4;     // ".tgz"
    // Minimum wheel filename segment count per PEP 427.
    private const int WheelMinSegments = 5;

    // Minimum egg filename segment count (name + version).
    private const int EggMinSegments = 2;

    [GeneratedRegex(@"^[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?$")]
    private static partial Regex Pep508NameRegex();

    [GeneratedRegex(@"^\d[\w\.\!\+\-]*$")]
    private static partial Regex Pep440VersionRegex();

    /// <summary>
    /// Extension-based dispatch. Kept for protocol callers (twine upload) where the server
    /// authoritatively knows the filename and wants the strict filename&lt;→&gt;METADATA cross-check.
    /// The content-based EcosystemDetector calls <see cref="ValidateWheel(byte[])"/>
    /// and <see cref="ValidateSdist"/> directly so a renamed file can't lie about its format.
    /// </summary>
    public static PyPiArtifactParsed Validate(string filename, byte[] bytes)
    {
        string lowered = filename.ToLowerInvariant();
        try
        {
            return lowered.EndsWith(".whl", StringComparison.Ordinal)
                ? ValidateWheelStrict(filename, bytes)
                : lowered.EndsWith(".tar.gz", StringComparison.Ordinal)
                || lowered.EndsWith(".tgz", StringComparison.Ordinal)
                ? ValidateSdist(bytes)
                : lowered.EndsWith(".egg", StringComparison.Ordinal)
                ? ValidateEggStrict(filename, bytes)
                : new PyPiArtifactParsed(
                    ValidationResult.Fail("filename",
                        "Unrecognised PyPI artefact extension; expected .whl, .tar.gz/.tgz, or .egg."),
                    null, null);
        }
        catch (Exception ex)
        {
            return new PyPiArtifactParsed(
                ValidationResult.Fail("content", $"Failed to parse PyPI artefact: {ex.Message}"),
                null, null);
        }
    }

    /// <summary>
    /// Content-only wheel validation. Derives name+version from <c>{name}-{version}.dist-info/METADATA</c>
    /// inside the archive — no filename involved. Called by EcosystemDetector when the filename
    /// is untrusted.
    /// </summary>
    public static PyPiArtifactParsed ValidateWheel(byte[] bytes)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            var metaEntry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
            if (metaEntry is null)
            {
                return new PyPiArtifactParsed(
                    ValidationResult.Fail("content", "Wheel is missing dist-info/METADATA."),
                    null, null);
            }

            using var stream = new LimitedReadStream(
                metaEntry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "Wheel METADATA");
            using var reader = new StreamReader(stream);
            var (metaName, metaVersion) = ReadHeaders(reader, "Name", "Version");

            string? validationError = ValidateNameVersion(metaName, metaVersion);
            return validationError is not null
                ? new PyPiArtifactParsed(ValidationResult.Fail("content", validationError), null, null)
                : new PyPiArtifactParsed(ValidationResult.Ok(), Normalize(metaName!), metaVersion);
        }
        catch (Exception ex)
        {
            return new PyPiArtifactParsed(
                ValidationResult.Fail("content", $"Failed to parse wheel: {ex.Message}"),
                null, null);
        }
    }

    /// <summary>
    /// Strict wheel validation used by the protocol push path: cross-checks the filename-derived
    /// (name, version) against METADATA so a renamed wheel pushed by twine is rejected.
    /// </summary>
    private static PyPiArtifactParsed ValidateWheelStrict(string filename, byte[] bytes)
    {
        // Filename per PEP 427: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
        string stem = filename[..^WhlExtLen];
        string[] parts = stem.Split('-');
        if (parts.Length < WheelMinSegments)
        {
            return new PyPiArtifactParsed(
                ValidationResult.Fail("filename", "Wheel filename must have at least 5 dash-separated segments."),
                null, null);
        }

        string fileName = parts[0];
        string fileVersion = parts[1];

        var inner = ValidateWheel(bytes);
        return !inner.Validation.IsValid
            ? inner
            : !Normalize(fileName).Equals(inner.Name!, StringComparison.Ordinal)
                ? new PyPiArtifactParsed(
                    ValidationResult.Fail("content",
                        $"Wheel filename name '{fileName}' does not match METADATA Name."),
                    null, null)
                : fileVersion != inner.Version
                    ? new PyPiArtifactParsed(
                        ValidationResult.Fail("content",
                            $"Wheel filename version '{fileVersion}' does not match METADATA Version '{inner.Version}'."),
                        null, null)
                    : inner;
    }

    /// <summary>
    /// Content-only egg validation. Derives name+version from <c>EGG-INFO/PKG-INFO</c> inside
    /// the zip — no filename involved. Eggs are a legacy setuptools format supported for
    /// proxying and importing existing artefacts; PyPI no longer accepts egg uploads.
    /// </summary>
    public static PyPiArtifactParsed ValidateEgg(byte[] bytes)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            var metaEntry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
            if (metaEntry is null)
            {
                return new PyPiArtifactParsed(
                    ValidationResult.Fail("content", "Egg is missing EGG-INFO/PKG-INFO."),
                    null, null);
            }

            using var stream = new LimitedReadStream(
                metaEntry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "Egg PKG-INFO");
            using var reader = new StreamReader(stream);
            var (metaName, metaVersion) = ReadHeaders(reader, "Name", "Version");

            string? validationError = ValidateNameVersion(metaName, metaVersion);
            return validationError is not null
                ? new PyPiArtifactParsed(ValidationResult.Fail("content", validationError), null, null)
                : new PyPiArtifactParsed(ValidationResult.Ok(), Normalize(metaName!), metaVersion);
        }
        catch (Exception ex)
        {
            return new PyPiArtifactParsed(
                ValidationResult.Fail("content", $"Failed to parse egg: {ex.Message}"),
                null, null);
        }
    }

    /// <summary>
    /// Strict egg validation for the protocol push path: cross-checks the filename-derived name
    /// against <c>EGG-INFO/PKG-INFO</c>. The setuptools egg filename mangles <c>-</c> to <c>_</c>
    /// in both name and version, so only the PEP 503-normalised name is cross-checked; the
    /// version is taken from PKG-INFO, which is authoritative.
    /// </summary>
    private static PyPiArtifactParsed ValidateEggStrict(string filename, byte[] bytes)
    {
        // Filename per setuptools: {name}-{version}(-py{X.Y})?(-{platform})?.egg
        string stem = filename[..^WhlExtLen];
        string[] parts = stem.Split('-');
        if (parts.Length < EggMinSegments)
        {
            return new PyPiArtifactParsed(
                ValidationResult.Fail("filename", "Egg filename must have at least 2 dash-separated segments."),
                null, null);
        }

        var inner = ValidateEgg(bytes);
        return !inner.Validation.IsValid
            ? inner
            : !Normalize(parts[0]).Equals(inner.Name!, StringComparison.Ordinal)
                ? new PyPiArtifactParsed(
                    ValidationResult.Fail("content",
                        $"Egg filename name '{parts[0]}' does not match EGG-INFO/PKG-INFO Name."),
                    null, null)
                : inner;
    }

    /// <summary>
    /// Content-only sdist validation. Looks for <c>{name}-{version}/PKG-INFO</c> at the top
    /// level of the gzipped tarball and parses the RFC 822 headers there. Used by both the
    /// extension-dispatch wrapper and the content-based EcosystemDetector.
    /// </summary>
    public static PyPiArtifactParsed ValidateSdist(byte[] bytes)
    {
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
                    return ParseSdistPkgInfoEntry(entry);
                }
            }

            return new PyPiArtifactParsed(
                ValidationResult.Fail("content", "Sdist is missing top-level {name}-{version}/PKG-INFO."),
                null, null);
        }
        catch (Exception ex)
        {
            return new PyPiArtifactParsed(
                ValidationResult.Fail("content", $"Failed to parse sdist: {ex.Message}"),
                null, null);
        }
    }

    // Parses the PKG-INFO TarEntry found inside a sdist tarball, extracting name and version.
    // Applies the outer-label version override: PEP 314 sdists wrap as {name}-{version}/, and
    // when that wrapper carries a PEP 440-shaped suffix it is authoritative for the version.
    private static PyPiArtifactParsed ParseSdistPkgInfoEntry(TarEntry entry)
    {
        using var stream = entry.DataStream!;
        using var reader = new StreamReader(stream);
        var (pkgName, pkgVersion) = ReadHeaders(reader, "Name", "Version");
        string? validationError = ValidateNameVersion(pkgName, pkgVersion);
        if (validationError is not null)
        {
            return new PyPiArtifactParsed(ValidationResult.Fail("content", validationError), null, null);
        }

        string name = Normalize(pkgName!);
        string version = pkgVersion!;
        string wrapper = entry.Name[..entry.Name.IndexOf('/')];
        if (OuterVersionLabel.TryFromPyPiSdistWrapper(wrapper, out string? labelled))
        {
            version = labelled!;
        }

        return new PyPiArtifactParsed(ValidationResult.Ok(), name, version);
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

    // Returns null when name and version are valid; returns an error message otherwise.
    private static string? ValidateNameVersion(string? name, string? version) =>
        string.IsNullOrEmpty(name) ? "Name header missing or empty." :
        string.IsNullOrEmpty(version) ? "Version header missing or empty." :
        !Pep508NameRegex().IsMatch(name) ? $"Invalid PEP 508 name: {name}" :
        !Pep440VersionRegex().IsMatch(version) ? $"Invalid PEP 440 version: {version}" : null;

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
    /// Returns (success, purlName, version) — purlName is PEP 503 normalised on success.
    /// </summary>
    public static (bool Success, string? PurlName, string? Version) TryParseFilename(string filename)
    {
        if (string.IsNullOrEmpty(filename))
        {
            return (false, null, null);
        }

        string lowered = filename.ToLowerInvariant();

        if (lowered.EndsWith(".egg", StringComparison.Ordinal))
        {
            return TryParseEggFilename(filename);
        }

        var (stripped, stem, isWheel) = TryStripArchiveExtension(filename, lowered);
        return !stripped
            ? (false, null, null)
            : isWheel ? TryParseWheelStem(stem) : TryParseSdistStem(stem);
    }

    // setuptools egg: {name}-{version}(-py{X.Y})?(-{platform})?.egg. '-' inside the name/version
    // is mangled to '_', so the first two dash segments are name + version.
    private static (bool Success, string? PurlName, string? Version) TryParseEggFilename(string filename)
    {
        string[] eggParts = filename[..^WhlExtLen].Split('-');
        if (eggParts.Length < EggMinSegments || !Pep440VersionRegex().IsMatch(eggParts[1]))
        {
            return (false, null, null);
        }

        return (true, Normalize(eggParts[0]), eggParts[1]);
    }

    // Strips the sdist/wheel archive extension, yielding the stem and whether it's a wheel.
    private static (bool Stripped, string Stem, bool IsWheel) TryStripArchiveExtension(string filename, string lowered)
    {
        if (lowered.EndsWith(".whl", StringComparison.Ordinal)) { return (true, filename[..^WhlExtLen], true); }
        if (lowered.EndsWith(".tar.gz", StringComparison.Ordinal)) { return (true, filename[..^TarGzExtLen], false); }
        if (lowered.EndsWith(".tar.bz2", StringComparison.Ordinal)) { return (true, filename[..^TarBz2ExtLen], false); }
        // .zip is legacy PEP 314 sdist; PyPI still serves them. Same length as .tgz.
        if (lowered.EndsWith(".tgz", StringComparison.Ordinal)
            || lowered.EndsWith(".zip", StringComparison.Ordinal)) { return (true, filename[..^TgzExtLen], false); }
        return (false, "", false);
    }

    // PEP 427: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}. Distribution is
    // mandated to use underscores, so split-on-dash is safe here.
    private static (bool Success, string? PurlName, string? Version) TryParseWheelStem(string stem)
    {
        string[] parts = stem.Split('-');
        if (parts.Length < WheelMinSegments || !Pep440VersionRegex().IsMatch(parts[1]))
        {
            return (false, null, null);
        }

        return (true, Normalize(parts[0]), parts[1]);
    }

    // Sdist: scan right-to-left for the first split where the right side is PEP 440-shaped. This
    // is how pip disambiguates names like "psycopg2-binary" from version suffixes.
    private static (bool Success, string? PurlName, string? Version) TryParseSdistStem(string stem)
    {
        for (int i = stem.LastIndexOf('-'); i > 0; i = stem.LastIndexOf('-', i - 1))
        {
            string candidate = stem[(i + 1)..];
            if (Pep440VersionRegex().IsMatch(candidate))
            {
                return (true, Normalize(stem[..i]), candidate);
            }
        }
        return (false, null, null);
    }
}
