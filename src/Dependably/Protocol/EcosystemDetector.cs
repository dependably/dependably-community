using System.Formats.Tar;
using System.IO.Compression;

namespace Dependably.Protocol;

/// <summary>
/// Content-based ecosystem detection for the unified upload endpoint. Reads magic bytes to
/// pick the archive format (ZIP vs gzipped tar), then peeks at entries to identify the
/// ecosystem from required manifest files — <c>.nuspec</c> for NuGet, <c>.dist-info/METADATA</c>
/// for PyPI wheels, <c>EGG-INFO/PKG-INFO</c> for legacy PyPI eggs, <c>package/package.json</c>
/// for npm, top-level <c>PKG-INFO</c> / <c>pyproject.toml</c> for PyPI sdists. Never trusts the
/// filename extension: a renamed <c>.nupkg</c> saved as <c>.tgz</c> is still detected as NuGet.
///
/// Returns (name, version) extracted via the ecosystem's existing validator
/// (<see cref="NuGetNupkgValidator"/>, <see cref="PyPiArtifactValidator"/>,
/// <see cref="NpmTarballValidator"/>) so all detection paths agree with the protocol path.
/// </summary>
public static class EcosystemDetector
{
    public sealed record DetectionResult(
        string Ecosystem, string Name, string PurlName, string Version);

    public sealed record DetectionFailure(string Code, string Message);

    public static (DetectionResult? Ok, DetectionFailure? Err) Detect(string filename, byte[] bytes)
    {
        var format = ArchiveExtractor.Detect(bytes);
        try
        {
            return format switch
            {
                ArchiveExtractor.ArchiveFormat.Zip => DetectZip(filename, bytes),
                ArchiveExtractor.ArchiveFormat.GzippedTar => DetectGzippedTar(bytes),
                _ => Fail("unrecognised_format",
                    "File is neither a ZIP (PK header) nor a gzipped tar (1F 8B header)."),
            };
        }
        catch (Exception ex)
        {
            return Fail("unrecognised_format", $"Failed to inspect archive: {ex.Message}");
        }
    }

    private static (DetectionResult?, DetectionFailure?) DetectZip(string filename, byte[] bytes)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);

        bool hasRootNuspec = zip.Entries.Any(e =>
            e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)
            && !e.FullName.Contains('/'));
        if (hasRootNuspec)
        {
            var (parseResult, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
            if (!parseResult.IsValid)
            {
                return Fail("nupkg_invalid", parseResult.Message ?? "Invalid .nupkg.");
            }
            // Outer-label override: when the filename follows the `{Id}.{Version}.nupkg`
            // convention with a parseable trailing version, use that as the version. Lets
            // two distinct uploads with the same .nuspec but different filenames land
            // separately; canonical `dotnet pack` output is unaffected because filename
            // and nuspec already agree.
            if (OuterVersionLabel.TryFromNupkgFilename(filename, out string? labelled))
            {
                version = labelled;
            }

            string purlName = id!.ToLowerInvariant();
            string normalizedVersion = PurlNormalizer.NormalizeNuGetVersionString(version!);
            return Ok("nuget", id, purlName, normalizedVersion);
        }

        bool hasDistInfo = zip.Entries.Any(e =>
            e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
        if (hasDistInfo)
        {
            var wheel = PyPiArtifactValidator.ValidateWheel(bytes);
            if (!wheel.Validation.IsValid)
            {
                return Fail("artifact_invalid", wheel.Validation.Message ?? "Invalid PyPI wheel.");
            }
            // Outer-label override: PEP 427 wheel filenames carry the version in segment 2
            // of `{dist}-{version}-{python}-{abi}-{platform}.whl`. Use it when present so
            // a renamed/relabelled wheel can land under its outer label.
            string? version = wheel.Version;
            if (OuterVersionLabel.TryFromWheelFilename(filename, out string? labelled))
            {
                version = labelled;
            }

            return Ok("pypi", wheel.Name!, wheel.Name!, version!);
        }

        bool hasEggInfo = zip.Entries.Any(e =>
            e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
        if (hasEggInfo)
        {
            var egg = PyPiArtifactValidator.ValidateEgg(bytes);
            return !egg.Validation.IsValid
                ? Fail("artifact_invalid", egg.Validation.Message ?? "Invalid PyPI egg.")
                : Ok("pypi", egg.Name!, egg.Name!, egg.Version!);
        }

        return Fail("unrecognised_format",
            "ZIP archive contains no root .nuspec, *.dist-info/METADATA, or EGG-INFO/PKG-INFO — not a NuGet or PyPI package.");
    }

    private static (DetectionResult?, DetectionFailure?) DetectGzippedTar(byte[] bytes)
    {
        var marker = ScanGzippedTar(bytes);
        switch (marker)
        {
            case TarMarker.NpmPackageJson:
                {
                    var npm = NpmTarballValidator.Validate(bytes);
                    return !npm.Validation.IsValid
                        ? Fail("tarball_invalid", npm.Validation.Message ?? "Invalid npm tarball.")
                        : Ok("npm", npm.Name!, npm.Name!, npm.Version!);
                }
            case TarMarker.PyPiSdist:
                {
                    var sdist = PyPiArtifactValidator.ValidateSdist(bytes);
                    return !sdist.Validation.IsValid
                        ? Fail("artifact_invalid", sdist.Validation.Message ?? "Invalid PyPI sdist.")
                        : Ok("pypi", sdist.Name!, sdist.Name!, sdist.Version!);
                }
            default:
                return Fail("unrecognised_format",
                    "Gzipped tar contains neither a top-level package.json nor a top-level PKG-INFO/pyproject.toml.");
        }
    }

    private enum TarMarker { None, NpmPackageJson, PyPiSdist }

    private static TarMarker ScanGzippedTar(byte[] bytes)
    {
        // Zip-bomb guard: cap total decompressed bytes and entry count. Skipping past
        // entries still decompresses their payloads, so an uncapped scan over a crafted
        // high-ratio gzip would burn unbounded CPU before any marker match.
        using var gzip = new LimitedReadStream(
            new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress),
            TarScanLimits.MaxTotalDecompressedBytes, "Archive");
        using var tar = new TarReader(gzip, leaveOpen: false);
        int entryCount = 0;
        while (tar.GetNextEntry() is { } entry)
        {
            if (++entryCount > TarScanLimits.MaxEntries)
            {
                throw new InvalidDataException(
                    $"Archive exceeds the {TarScanLimits.MaxEntries}-entry limit.");
            }

            // `npm pack` writes package/package.json, but git-archive and hand-rolled tarballs
            // commonly use {name}-{version}/package.json or no wrapper at all. NpmTarballValidator
            // accepts the same set so detection and validation stay in lockstep.
            if (NpmTarballValidator.IsTopLevelPackageJson(entry.Name))
            {
                return TarMarker.NpmPackageJson;
            }
            // PyPI sdists per PEP 314 use top-level {name}-{version}/PKG-INFO; some legacy
            // sdists carry pyproject.toml at the same depth without PKG-INFO.
            int slashCount = entry.Name.Count(c => c == '/');
            if (slashCount == 1
                && (entry.Name.EndsWith("/PKG-INFO", StringComparison.OrdinalIgnoreCase)
                    || entry.Name.EndsWith("/pyproject.toml", StringComparison.OrdinalIgnoreCase)))
            {
                return TarMarker.PyPiSdist;
            }
        }
        return TarMarker.None;
    }

    private static (DetectionResult?, DetectionFailure?) Ok(
        string ecosystem, string name, string purlName, string version) =>
        (new DetectionResult(ecosystem, name, purlName, version), null);

    private static (DetectionResult?, DetectionFailure?) Fail(string code, string message) =>
        (null, new DetectionFailure(code, message));
}
