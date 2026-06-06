using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Coverage-extension tests for <see cref="EcosystemDetector"/> focused on the failure
/// branches the happy-path tests don't reach: corrupt archives that throw mid-inspection,
/// magic-bytes-match-but-validator-rejects pairs (nuspec/wheel/tarball/sdist), the
/// pyproject-only sdist branch, and the empty-payload fall-through to Unknown format.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EcosystemDetectorExtendedTests
{
    // ── Empty / truncated payloads ──────────────────────────────────────────────

    [Fact]
    public void Empty_Payload_Returns_UnrecognisedFormat()
    {
        // Zero bytes: ArchiveExtractor.Detect short-circuits to Unknown via the
        // length check, hitting the `_ =>` arm of the switch.
        var (ok, err) = EcosystemDetector.Detect("empty.bin", []);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
    }

    [Fact]
    public void Single_Byte_Payload_Returns_UnrecognisedFormat()
    {
        // One byte can't satisfy either magic-byte prefix; ArchiveFormat is Unknown.
        var (ok, err) = EcosystemDetector.Detect("trunc.bin", [0x1F]);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
    }

    // ── Corrupt-after-magic-bytes (catch block) ─────────────────────────────────

    [Fact]
    public void Corrupt_Zip_After_PK_Magic_Hits_Catch_Block()
    {
        // PK\x03\x04 satisfies ArchiveExtractor.Detect -> Zip, then ZipArchive ctor blows
        // up on the truncated central directory. Exercises the try/catch fallback in Detect.
        var bytes = new byte[] { (byte)'P', (byte)'K', 0x03, 0x04, 0x00, 0x00, 0x00 };
        var (ok, err) = EcosystemDetector.Detect("corrupt.zip", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
        Assert.Contains("Failed to inspect archive", err.Message);
    }

    [Fact]
    public void Corrupt_Gzip_After_1F8B_Magic_Hits_Catch_Block()
    {
        // 1F 8B satisfies the gzip magic-byte check, but the body is junk so GZipStream
        // throws when the TarReader tries to advance. Catch block converts that into
        // unrecognised_format with the "Failed to inspect archive" prefix.
        var bytes = new byte[] { 0x1F, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var (ok, err) = EcosystemDetector.Detect("corrupt.tgz", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
        Assert.Contains("Failed to inspect archive", err.Message);
    }

    // ── ZIP-with-nuspec but nuspec invalid ──────────────────────────────────────

    [Fact]
    public void Zip_With_RootNuspec_But_Invalid_Returns_NupkgInvalid()
    {
        // Root .nuspec gates into the NuGet branch, but the nuspec uses an unrecognised
        // XML namespace so NuGetNupkgValidator.Parse rejects it. Detector must surface
        // nupkg_invalid, not unrecognised_format, so the operator sees the real cause.
        var bytes = BuildZipWithEntry("evil.nuspec", "<package xmlns=\"urn:bogus\"><metadata/></package>");
        var (ok, err) = EcosystemDetector.Detect("evil.nupkg", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("nupkg_invalid", err!.Code);
    }

    [Fact]
    public void Zip_With_NestedNuspec_Only_Is_Not_NuGet()
    {
        // .nuspec nested under a directory must NOT trigger the NuGet branch — detector
        // checks `!FullName.Contains('/')`. With no root nuspec, no dist-info METADATA, and no
        // EGG-INFO/PKG-INFO, we fall through to the ZIP "contains no ..." message.
        var bytes = BuildZipWithEntry("subdir/inner.nuspec", "<package/>");
        var (ok, err) = EcosystemDetector.Detect("nested.nupkg", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
        Assert.Contains("ZIP archive contains no root .nuspec", err.Message);
    }

    // ── ZIP-with-dist-info but wheel invalid ────────────────────────────────────

    [Fact]
    public void Zip_With_DistInfo_But_Missing_Name_Returns_ArtifactInvalid()
    {
        // dist-info/METADATA present but the METADATA body has no Name/Version headers.
        // ValidateWheel fails -> detector surfaces artifact_invalid.
        var bytes = BuildZipWithEntry("pkg-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nSummary: empty\n");
        var (ok, err) = EcosystemDetector.Detect("pkg-1.0.0-py3-none-any.whl", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("artifact_invalid", err!.Code);
    }

    // ── Gzipped-tar with package.json but invalid ───────────────────────────────

    [Fact]
    public void Tarball_With_PackageJson_But_Missing_Version_Returns_TarballInvalid()
    {
        // Top-level package/package.json gates into the npm branch, but the JSON omits
        // "version" so NpmTarballValidator.Validate fails. Detector surfaces tarball_invalid.
        var bytes = BuildGzippedTar(("package/package.json", "{\"name\":\"orphan\"}"));
        var (ok, err) = EcosystemDetector.Detect("orphan-1.0.0.tgz", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("tarball_invalid", err!.Code);
    }

    // ── Gzipped-tar with PyPI markers but invalid ───────────────────────────────

    [Fact]
    public void Sdist_With_PkgInfo_But_Missing_Headers_Returns_ArtifactInvalid()
    {
        // Top-level {wrapper}/PKG-INFO gates into the sdist branch, but PKG-INFO lacks
        // Name and Version headers so ValidateSdist fails. Detector surfaces artifact_invalid.
        var bytes = BuildGzippedTar(("badpkg-1.0.0/PKG-INFO", "Metadata-Version: 2.1\nSummary: nothing\n"));
        var (ok, err) = EcosystemDetector.Detect("badpkg-1.0.0.tar.gz", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("artifact_invalid", err!.Code);
    }

    [Fact]
    public void Sdist_With_Only_PyprojectToml_Is_Detected_As_PyPi()
    {
        // Legacy sdist shape: no PKG-INFO, only {wrapper}/pyproject.toml at depth 1.
        // Exercises the pyproject.toml arm of the slashCount==1 condition in ScanGzippedTar.
        // ValidateSdist will fail (no PKG-INFO), but we expect artifact_invalid (the PyPI branch)
        // rather than unrecognised_format — proving the pyproject branch was taken.
        var bytes = BuildGzippedTar(("legacy-0.1.0/pyproject.toml", "[project]\nname = \"legacy\"\nversion = \"0.1.0\"\n"));
        var (ok, err) = EcosystemDetector.Detect("legacy-0.1.0.tar.gz", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("artifact_invalid", err!.Code);
    }

    [Fact]
    public void Sdist_With_DeepPkgInfo_Is_Not_Detected()
    {
        // PKG-INFO at slashCount>1 must NOT trigger the sdist branch — the depth check
        // requires exactly one slash. Falls through to the gzipped-tar "neither ... nor ..."
        // message.
        var bytes = BuildGzippedTar(("a/b/PKG-INFO", "Metadata-Version: 2.1\nName: deep\nVersion: 1.0.0\n"));
        var (ok, err) = EcosystemDetector.Detect("mystery.tar.gz", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
        Assert.Contains("Gzipped tar contains neither", err.Message);
    }

    // ── Content-trumps-filename (the inverse direction) ─────────────────────────

    [Fact]
    public void Content_Trumps_Extension_Wheel_Renamed_As_Nupkg()
    {
        // .nupkg-named file whose bytes are actually a wheel. Magic bytes say ZIP; ZIP
        // contains dist-info/METADATA (no root nuspec) so it's pypi, not nuget.
        var (bytes, _) = PyPiFixtures.BuildWheel("renamed_wheel", "0.1.0");
        var (ok, err) = EcosystemDetector.Detect("Pretender.0.1.0.nupkg", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("pypi", ok!.Ecosystem);
        Assert.Equal("renamed-wheel", ok.Name);
    }

    [Fact]
    public void Content_Trumps_Extension_Sdist_Renamed_As_Nupkg()
    {
        // .nupkg-named file whose bytes are an sdist (gzip+tar). Magic bytes route to the
        // gzip branch; PKG-INFO at depth 1 yields pypi.
        var (bytes, _) = PyPiFixtures.BuildSdist("renamed-sdist", "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("Pretender.1.0.0.nupkg", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("pypi", ok!.Ecosystem);
        Assert.Equal("renamed-sdist", ok.Name);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private static byte[] BuildZipWithEntry(string entryName, string content)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry(entryName);
            using var w = new StreamWriter(entry.Open());
            w.Write(content);
        }
        return ms.ToArray();
    }

    private static byte[] BuildGzippedTar(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, n)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(c))
                };
                tw.WriteEntry(entry);
            }
        }
        return ms.ToArray();
    }
}
