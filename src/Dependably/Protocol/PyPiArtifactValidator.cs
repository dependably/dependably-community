using System.Formats.Tar;
using System.IO.Compression;
using System.Text.RegularExpressions;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Extracts package name and version from a PyPI artefact for the bulk-import path (#46).
/// Two formats are supported:
/// <list type="bullet">
///   <item>Wheel (<c>.whl</c>): zip with metadata at <c>{name}-{version}.dist-info/METADATA</c>.
///   The filename itself encodes <c>{name}-{version}-...</c> per PEP 427.</item>
///   <item>Sdist (<c>.tar.gz</c> or <c>.tgz</c>): gzipped tar with PEP 314
///   <c>{name}-{version}/PKG-INFO</c> at the top level.</item>
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
        var lowered = filename.ToLowerInvariant();
        try
        {
            if (lowered.EndsWith(".whl", StringComparison.Ordinal))
                return ValidateWheelStrict(filename, bytes, out name, out version);

            if (lowered.EndsWith(".tar.gz", StringComparison.Ordinal)
                || lowered.EndsWith(".tgz", StringComparison.Ordinal))
                return ValidateSdist(bytes, out name, out version);

            return ValidationResult.Fail("filename",
                "Unrecognised PyPI artefact extension; expected .whl or .tar.gz/.tgz.");
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
                return ValidationResult.Fail("content", "Wheel is missing dist-info/METADATA.");

            using var stream = metaEntry.Open();
            using var reader = new StreamReader(stream);
            var (metaName, metaVersion) = ReadHeaders(reader, "Name", "Version");

            if (!ValidateNameVersion(metaName, metaVersion, out var error))
                return ValidationResult.Fail("content", error);

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
        var stem = filename[..^4];
        var parts = stem.Split('-');
        if (parts.Length < 5)
            return ValidationResult.Fail("filename", "Wheel filename must have at least 5 dash-separated segments.");

        var fileName = parts[0];
        var fileVersion = parts[1];

        var inner = ValidateWheel(bytes, out var metaNameNormalized, out var metaVersion);
        if (!inner.IsValid) return inner;

        if (!Normalize(fileName).Equals(metaNameNormalized!, StringComparison.Ordinal))
            return ValidationResult.Fail("content",
                $"Wheel filename name '{fileName}' does not match METADATA Name.");
        if (fileVersion != metaVersion)
            return ValidationResult.Fail("content",
                $"Wheel filename version '{fileVersion}' does not match METADATA Version '{metaVersion}'.");

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
            using var gzip = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var tar = new TarReader(gzip, leaveOpen: false);

            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.Name.EndsWith("/PKG-INFO", StringComparison.OrdinalIgnoreCase)
                    && entry.Name.Count(c => c == '/') == 1)
                {
                    using var stream = entry.DataStream!;
                    using var reader = new StreamReader(stream);
                    var (pkgName, pkgVersion) = ReadHeaders(reader, "Name", "Version");
                    if (!ValidateNameVersion(pkgName, pkgVersion, out var error))
                        return ValidationResult.Fail("content", error);
                    name = Normalize(pkgName!);
                    version = pkgVersion;

                    // Outer-label override: PEP 314 sdists wrap as {name}-{version}/, so when
                    // the wrapper carries a PEP 440-shaped suffix it is authoritative for the
                    // version. For canonical sdists the wrapper matches PKG-INFO; for source
                    // archives whose PKG-INFO is stale across tags, the wrapper disambiguates.
                    var wrapper = entry.Name[..entry.Name.IndexOf('/')];
                    if (OuterVersionLabel.TryFromPyPiSdistWrapper(wrapper, out var labelled))
                        version = labelled;

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
            if (line.Length == 0) break;
            var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (key.Equals(nameHeader, StringComparison.OrdinalIgnoreCase)) name = value;
            else if (key.Equals(versionHeader, StringComparison.OrdinalIgnoreCase)) version = value;
            if (name is not null && version is not null) break;
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

    [GeneratedRegex(@"[-_.]+")]
    private static partial Regex Pep503Replace();
}
