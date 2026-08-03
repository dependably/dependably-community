using System.Formats.Tar;
using System.IO.Compression;
using Dependably.Api.NuGetProtocol;

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
    /// <summary>
    /// <paramref name="NpmManifestJson"/> is the install-relevant manifest subset
    /// (see <see cref="NpmInstallManifest"/>) extracted from an npm tarball's package.json
    /// during detection; null for every other ecosystem.
    /// </summary>
    public sealed record DetectionResult(
        string Ecosystem, string Name, string PurlName, string Version,
        string? NpmManifestJson = null);

    public sealed record DetectionFailure(string Code, string Message);

    /// <summary>Extension of a NuGet symbol package, validated under the reduced-manifest rules.</summary>
    private const string NuGetSymbolPackageExtension = ".snupkg";

    public static (DetectionResult? Ok, DetectionFailure? Err) Detect(string filename, byte[] bytes)
    {
        using var stream = new MemoryStream(bytes, writable: false);
        return Detect(filename, stream);
    }

    /// <summary>
    /// Streaming overload: sniffs the archive format and inspects entries directly from
    /// <paramref name="stream"/> (a staged file on the bulk-import path) so the artifact is
    /// never materialised in a byte[]. Requires a seekable stream — the header peek and each
    /// format-specific pass rewind to the start. The source stream is left open for the
    /// caller to dispose.
    /// </summary>
    public static (DetectionResult? Ok, DetectionFailure? Err) Detect(string filename, Stream stream)
    {
        try
        {
            byte[] header = new byte[ArchiveExtractor.HeaderPeekLength];
            int read = ReadFully(stream, header);
            stream.Seek(0, SeekOrigin.Begin);
            var format = ArchiveExtractor.Detect(read == header.Length ? header : header[..read]);

            return format switch
            {
                ArchiveExtractor.ArchiveFormat.Zip => DetectZip(filename, stream),
                ArchiveExtractor.ArchiveFormat.GzippedTar => DetectGzippedTar(stream),
                _ => Fail("unrecognised_format",
                    "File is neither a ZIP (PK header) nor a gzipped tar (1F 8B header)."),
            };
        }
        catch (Exception ex)
        {
            return Fail("unrecognised_format", $"Failed to inspect archive: {ex.Message}");
        }
    }

    // Reads up to buffer.Length bytes, looping over short reads (a single Stream.Read call
    // is not guaranteed to fill the buffer even when more data is available). Returns the
    // number of bytes actually read, which is less than buffer.Length only at end of stream.
    private static int ReadFully(Stream stream, byte[] buffer)
    {
        int total = 0;
        int read;
        while (total < buffer.Length && (read = stream.Read(buffer, total, buffer.Length - total)) > 0)
        {
            total += read;
        }
        return total;
    }

    private static (DetectionResult?, DetectionFailure?) DetectZip(string filename, Stream stream)
    {
        bool hasRootNuspec;
        bool hasDistInfo;
        bool hasEggInfo;
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true))
        {
            hasRootNuspec = zip.Entries.Any(e =>
                e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)
                && !e.FullName.Contains('/'));
            hasDistInfo = zip.Entries.Any(e =>
                e.FullName.EndsWith(".dist-info/METADATA", StringComparison.OrdinalIgnoreCase));
            hasEggInfo = zip.Entries.Any(e =>
                e.FullName.EndsWith("EGG-INFO/PKG-INFO", StringComparison.OrdinalIgnoreCase));
        }

        if (hasRootNuspec)
        {
            stream.Seek(0, SeekOrigin.Begin);
            // A .snupkg is validated as a SYMBOL package: `dotnet pack` emits a reduced manifest
            // for one and strips <authors>, so validating it as a package rejects every real
            // symbol archive with "authors is required". The upload surfaces (drag-and-drop,
            // bulk import) carry the filename, which is the only signal available before the
            // nuspec is parsed — and it is the same signal `dotnet nuget push` routes on.
            bool isSymbol = filename.EndsWith(NuGetSymbolPackageExtension, StringComparison.OrdinalIgnoreCase);
            var (parseResult, id, version) = NuGetNupkgValidator.ParseFromStream(stream, isSymbol);
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
            // Lowercased canonical form — matches the form every NuGet read path
            // (flatcontainer/registration/symbols) resolves against. Detection is one of the
            // hosted-write surfaces (alongside NuGetPublishHandler), so it must store under the
            // same form or an imported mixed-case prerelease becomes undownloadable.
            string normalizedVersion = NuGetNormalization.NormalizeVersion(version!);
            return Ok("nuget", id, purlName, normalizedVersion);
        }

        if (hasDistInfo)
        {
            stream.Seek(0, SeekOrigin.Begin);
            var wheel = PyPiArtifactValidator.ValidateWheel(stream);
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

        if (hasEggInfo)
        {
            stream.Seek(0, SeekOrigin.Begin);
            var egg = PyPiArtifactValidator.ValidateEgg(stream);
            return !egg.Validation.IsValid
                ? Fail("artifact_invalid", egg.Validation.Message ?? "Invalid PyPI egg.")
                : Ok("pypi", egg.Name!, egg.Name!, egg.Version!);
        }

        return Fail("unrecognised_format",
            "ZIP archive contains no root .nuspec, *.dist-info/METADATA, or EGG-INFO/PKG-INFO — not a NuGet or PyPI package.");
    }

    private static (DetectionResult?, DetectionFailure?) DetectGzippedTar(Stream stream)
    {
        var marker = ScanGzippedTar(stream);
        stream.Seek(0, SeekOrigin.Begin);
        switch (marker)
        {
            case TarMarker.NpmPackageJson:
                {
                    var npm = NpmTarballValidator.Validate(stream);
                    return !npm.Validation.IsValid
                        ? Fail("tarball_invalid", npm.Validation.Message ?? "Invalid npm tarball.")
                        : (new DetectionResult("npm", npm.Name!, npm.Name!, npm.Version!,
                            NpmInstallManifest.BuildJson(npm.Manifest, publishBodyVersion: null, npm.Name!)), null);
                }
            case TarMarker.PyPiSdist:
                {
                    var sdist = PyPiArtifactValidator.ValidateSdist(stream);
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

    private static TarMarker ScanGzippedTar(Stream stream)
    {
        // Zip-bomb guard: cap total decompressed bytes and entry count. Skipping past
        // entries still decompresses their payloads, so an uncapped scan over a crafted
        // high-ratio gzip would burn unbounded CPU before any marker match.
        using var gzip = new LimitedReadStream(
            new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true),
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
