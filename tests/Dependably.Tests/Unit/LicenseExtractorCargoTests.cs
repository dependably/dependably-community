using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Coverage for the Cargo license sources added to <see cref="LicenseExtractor"/>: the
/// crates.io publish-envelope <c>license</c> field, and the <c>.crate</c> tarball's
/// <c>[package].license</c> key for the proxy path (the sparse index carries no license
/// field at all).
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseExtractorCargoTests
{
    // ── FromCargoPublishLicense (publish envelope) ────────────────────────────

    [Fact]
    public void FromCargoPublishLicense_PlausibleValue_ExtractedAndTrimmed()
    {
        var result = LicenseExtractor.FromCargoPublishLicense("  MIT OR Apache-2.0  ");
        Assert.Equal(new[] { "MIT OR Apache-2.0" }, result.Spdx);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void FromCargoPublishLicense_Null_ReturnsEmpty()
    {
        var result = LicenseExtractor.FromCargoPublishLicense(null);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCargoPublishLicense_Whitespace_ReturnsEmpty()
    {
        var result = LicenseExtractor.FromCargoPublishLicense("   ");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCargoPublishLicense_ImplausibleShape_ReturnsEmpty()
    {
        // '/' is not an SPDX-friendly character.
        var result = LicenseExtractor.FromCargoPublishLicense("MIT/Custom");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── FromCrateTarball (.crate tarball, proxy path) ─────────────────────────

    [Fact]
    public void FromCrateTarball_PackageSectionLicense_Extracted()
    {
        byte[] bytes = BuildCrateTarGz("demo-crate", "1.2.3", """
            [package]
            name = "demo-crate"
            version = "1.2.3"
            edition = "2021"
            license = "MIT"

            [dependencies]
            """);
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(bytes));
        Assert.Equal(new[] { "MIT" }, result.Spdx);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void FromCrateTarball_LicenseFileOnly_NoSpdxSignal_ReturnsEmpty()
    {
        // license-file points at a bundled file, not an SPDX expression — never modelled.
        byte[] bytes = BuildCrateTarGz("filecrate", "0.1.0", """
            [package]
            name = "filecrate"
            version = "0.1.0"
            license-file = "LICENSE"
            """);
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCrateTarball_LicenseKeyOutsidePackageSection_NotMatched()
    {
        // A "license" key that appears under an unrelated table (e.g. a dependency table)
        // must never be attributed to the crate's own license. [package] itself carries
        // no license key here.
        byte[] bytes = BuildCrateTarGz("depcrate", "0.2.0", """
            [package]
            name = "depcrate"
            version = "0.2.0"

            [dependencies.something]
            license = "GPL-3.0-only"
            version = "1.0"
            """);
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCrateTarball_NestedCargoTomlBeyondRootDepth_NotMatched()
    {
        // Only "<root-dir>/Cargo.toml" (depth 1) is the crate's own manifest; a Cargo.toml
        // bundled in a subdirectory (e.g. a vendored dependency) must not be picked up.
        byte[] contentBytes = Encoding.UTF8.GetBytes("""
            [package]
            name = "nested"
            version = "9.9.9"
            license = "MIT"
            """);
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, "nested-9.9.9/vendor/sub/Cargo.toml")
            {
                DataStream = new MemoryStream(contentBytes),
            };
            tw.WriteEntry(entry);
        }
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(ms.ToArray()));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCrateTarball_NoCargoTomlAtAll_ReturnsEmpty()
    {
        byte[] bytes = BuildCrateTarball("nomanifest-1.0.0/src/lib.rs", "pub fn f() {}");
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCrateTarball_ImplausibleSpdxValue_ReturnsEmpty()
    {
        byte[] bytes = BuildCrateTarGz("badspdx", "1.0.0", """
            [package]
            name = "badspdx"
            version = "1.0.0"
            license = "MIT/Custom"
            """);
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void FromCrateTarball_MalformedGzip_ReturnsEmpty()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("not a gzipped tarball");
        var result = LicenseExtractor.FromCrateTarball(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    // Builds a gzip-tar with a single "{name}-{version}/Cargo.toml" entry, mirroring the
    // shape a crates.io publish/download produces.
    private static byte[] BuildCrateTarGz(string name, string version, string cargoTomlBody)
        => BuildCrateTarball($"{name}-{version}/Cargo.toml", cargoTomlBody);

    private static byte[] BuildCrateTarball(string entryName, string content)
    {
        byte[] contentBytes = Encoding.UTF8.GetBytes(content);
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(contentBytes),
            };
            tw.WriteEntry(entry);
        }
        return ms.ToArray();
    }
}
