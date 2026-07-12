using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class LicenseExtractorGoTests
{
    private const string Module = "example.com/foo/bar";
    private const string Version = "v1.0.0";

    [Fact]
    public void RootLicenseFile_RealMitText_ExtractsMit()
    {
        byte[] zip = BuildGoZip(("LICENSE", SpdxTextFixtures.Text("MIT")));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(new[] { "MIT" }, result.Spdx);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void OnlyNestedVendorLicense_ReturnsEmpty()
    {
        byte[] zip = BuildGoZip(("vendor/x/LICENSE", SpdxTextFixtures.Text("MIT")));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NoLicenseFile_ReturnsEmpty()
    {
        byte[] zip = BuildGoZip(("go.mod", "module example.com/foo/bar\n\ngo 1.21\n"));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void GarbageBytes_NotAZip_ReturnsEmpty()
    {
        byte[] garbage = Encoding.UTF8.GetBytes("this is not a zip file at all");
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(garbage), Module, Version);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void LicenceVariant_ExtractsLicense()
    {
        byte[] zip = BuildGoZip(("LICENCE", SpdxTextFixtures.Text("Apache-2.0")));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(new[] { "Apache-2.0" }, result.Spdx);
    }

    [Fact]
    public void CopyingVariant_ExtractsLicense()
    {
        byte[] zip = BuildGoZip(("COPYING", SpdxTextFixtures.Text("MIT")));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void LicenseAndCopyingBothPresent_LicenseWinsPriority()
    {
        byte[] zip = BuildGoZip(
            ("LICENSE", SpdxTextFixtures.Text("MIT")),
            ("COPYING", SpdxTextFixtures.Text("Apache-2.0")));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void OversizedLicenseEntry_ReturnsEmpty()
    {
        // A single repeated character compresses extremely well, so the zip on disk stays small
        // while the decompressed entry exceeds the 32 MiB metadata-entry cap enforced by
        // LimitedReadStream — the extractor must fail closed to Empty rather than buffering an
        // unbounded string.
        string oversized = new('A', 33 * 1024 * 1024);
        byte[] zip = BuildGoZip(("LICENSE", oversized));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NoMatchingLicenseText_ReturnsEmpty()
    {
        byte[] zip = BuildGoZip(("LICENSE", "This module has a bespoke internal usage policy, not an open license."));
        var result = LicenseExtractor.FromGoModuleZip(new MemoryStream(zip), Module, Version);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] BuildGoZip(params (string RelativePath, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (relativePath, content) in entries)
            {
                var entry = zip.CreateEntry($"{Module}@{Version}/{relativePath}");
                using var s = entry.Open();
                using var w = new StreamWriter(s, new UTF8Encoding(false));
                w.Write(content);
            }
        }
        return ms.ToArray();
    }
}
