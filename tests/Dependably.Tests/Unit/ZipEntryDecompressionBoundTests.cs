using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Verifies that ZIP-format entry reads are capped via <see cref="LimitedReadStream"/> in
/// every validator and extractor that opens a ZIP entry for metadata. Each test constructs
/// a crafted .zip whose target entry stores highly-compressible data that expands well beyond
/// <see cref="ZipEntryLimits.MaxMetadataEntryBytes"/>.
///
/// <para>The bombs are designed so that the decompressed content is structurally valid and
/// would be accepted without the cap. Only the <see cref="LimitedReadStream"/> guard
/// prevents the unbounded allocation and causes rejection.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ZipEntryDecompressionBoundTests
{
    // ── Helpers ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a wheel zip whose METADATA entry begins with enough non-Name/non-Version
    /// RFC 822 lines to exceed <see cref="ZipEntryLimits.MaxMetadataEntryBytes"/> of
    /// decompressed data, followed by valid Name and Version headers.
    ///
    /// <para>Without the <see cref="LimitedReadStream"/> guard:
    /// <see cref="StreamReader.ReadLine"/> iterates through all the filler lines and
    /// eventually finds Name + Version, returning <c>IsValid=true</c>.</para>
    /// <para>With the guard: the cap fires during the filler section and
    /// <see cref="InvalidDataException"/> propagates to the outer catch, returning
    /// <c>IsValid=false</c>.</para>
    /// </summary>
    private static byte[] BuildWheelZipBomb()
    {
        using var ms = new MemoryStream();
        using var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true);
        var entry = zip.CreateEntry("mybomb-1.0.0.dist-info/METADATA", CompressionLevel.SmallestSize);
        using (var entryStream = entry.Open())
        using (var writer = new StreamWriter(entryStream, Encoding.UTF8, leaveOpen: true))
        {
            // Emit lines that the RFC 822 header parser ignores (not Name or Version),
            // accumulating decompressed bytes past the cap. The repetitive content
            // compresses at >1000:1, keeping the compressed artifact tiny.
            const string fillerLine = "X-Filler: A\n";
            long reps = ZipEntryLimits.MaxMetadataEntryBytes / fillerLine.Length + 1;
            for (long i = 0; i < reps; i++)
            {
                writer.Write(fillerLine);
            }
            // Valid headers come after the over-limit filler.
            writer.WriteLine("Name: mybomb");
            writer.WriteLine("Version: 1.0.0");
        }
        zip.Dispose();
        return ms.ToArray();
    }

    /// <summary>
    /// Egg ZIP bomb — EGG-INFO/PKG-INFO with over-limit filler before valid headers.
    /// Same structural reasoning as the wheel bomb.
    /// </summary>
    private static byte[] BuildEggZipBomb()
    {
        using var ms = new MemoryStream();
        using var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true);
        var entry = zip.CreateEntry("EGG-INFO/PKG-INFO", CompressionLevel.SmallestSize);
        using (var entryStream = entry.Open())
        using (var writer = new StreamWriter(entryStream, Encoding.UTF8, leaveOpen: true))
        {
            const string fillerLine = "X-Filler: A\n";
            long reps = ZipEntryLimits.MaxMetadataEntryBytes / fillerLine.Length + 1;
            for (long i = 0; i < reps; i++)
            {
                writer.Write(fillerLine);
            }
            writer.WriteLine("Name: mybomb");
            writer.WriteLine("Version: 1.0.0");
        }
        zip.Dispose();
        return ms.ToArray();
    }

    /// <summary>
    /// Nupkg ZIP bomb — .nuspec wraps a valid nuspec in a large XML comment before the
    /// root element. <see cref="System.Xml.Linq.XDocument.Load"/> buffers the whole
    /// document; the comment body causes the cap to fire before parsing completes.
    ///
    /// <para>Without the cap: full valid XML is parsed, id/version/description/authors
    /// all present, returns <c>IsValid=true</c>.</para>
    /// <para>With the cap: fires during the large comment, <see cref="XDocument.Load"/>
    /// throws, outer catch returns <c>IsValid=false</c>.</para>
    /// </summary>
    private static byte[] BuildNupkgZipBomb()
    {
        // Padding must exceed MaxMetadataEntryBytes to trigger the cap once wrapped in the
        // XML comment. We use MaxMetadataEntryBytes + 1 chars of 'A' so the decompressed
        // size of the comment alone exceeds the limit, regardless of surrounding XML overhead.
        string padding = new('A', (int)ZipEntryLimits.MaxMetadataEntryBytes + 1);
        string nuspec = $"""
            <?xml version="1.0"?>
            <!--{padding}-->
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Acme</id><version>1.0.0</version>
                <description>desc</description><authors>x</authors>
              </metadata>
            </package>
            """;

        using var ms = new MemoryStream();
        using var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true);
        var entry = zip.CreateEntry("mybomb.nuspec", CompressionLevel.SmallestSize);
        using (var entryStream = entry.Open())
        using (var writer = new StreamWriter(entryStream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(nuspec);
        }
        zip.Dispose();
        return ms.ToArray();
    }

    // ── LimitedReadStream over a real ZipEntry.Open() ─────────────────────────

    [Fact]
    public void LimitedReadStream_OverZipEntry_ThrowsWhenEntryExceedsCap()
    {
        // Direct unit test: wrapping ZipEntry.Open() in LimitedReadStream limits
        // how many decompressed bytes can be read from a compressed ZIP entry.
        const long cap = 1024;
        const long bombSize = cap + 1;

        using var ms = new MemoryStream();
        using var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true);
        var entry = zip.CreateEntry("data.txt", CompressionLevel.SmallestSize);
        using (var es = entry.Open())
        {
            byte[] chunk = new byte[(int)bombSize];
            es.Write(chunk, 0, chunk.Length);
        }
        zip.Dispose();

        using var readZip = new ZipArchive(new MemoryStream(ms.ToArray()), ZipArchiveMode.Read);
        var readEntry = readZip.Entries.First();
        using var limited = new LimitedReadStream(readEntry.Open(), cap, "test-entry");

        Assert.Throws<InvalidDataException>(() =>
        {
            using var buf = new MemoryStream();
            limited.CopyTo(buf);
        });
    }

    [Fact]
    public void LimitedReadStream_OverZipEntry_AllowsEntryUnderCap()
    {
        string content = "Name: pkg\nVersion: 1.0.0\n";
        byte[] contentBytes = Encoding.UTF8.GetBytes(content);

        using var ms = new MemoryStream();
        using var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true);
        var entry = zip.CreateEntry("METADATA");
        using (var es = entry.Open())
        {
            es.Write(contentBytes, 0, contentBytes.Length);
        }
        zip.Dispose();

        using var readZip = new ZipArchive(new MemoryStream(ms.ToArray()), ZipArchiveMode.Read);
        var readEntry = readZip.Entries.First();
        using var limited = new LimitedReadStream(
            readEntry.Open(), ZipEntryLimits.MaxMetadataEntryBytes, "test-entry");

        using var buf = new MemoryStream();
        limited.CopyTo(buf);
        Assert.Equal(content, Encoding.UTF8.GetString(buf.ToArray()));
    }

    // ── PyPiArtifactValidator.ValidateWheel ────────────────────────────────────

    /// <summary>
    /// Regression test for the ZIP entry decompression cap in ValidateWheel.
    /// The bomb METADATA contains over-limit filler lines before valid Name/Version headers.
    /// Without the LimitedReadStream guard the validator reads all filler and finds the
    /// valid headers, returning IsValid=true. With the guard the cap fires during the filler
    /// section (before Name/Version are reached) and returns IsValid=false.
    /// </summary>
    [Fact]
    public void ValidateWheel_ZipBombMetadataEntry_ReturnsFailResult()
    {
        byte[] bomb = BuildWheelZipBomb();

        var parsed = PyPiArtifactValidator.ValidateWheel(bomb);

        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
        Assert.Null(parsed.Name);
        Assert.Null(parsed.Version);
    }

    [Fact]
    public void ValidateWheel_LegitimateInput_StillSucceeds()
    {
        var (bytes, _) = PyPiFixtures.BuildWheel("acme", "1.0.0");
        var parsed = PyPiArtifactValidator.ValidateWheel(bytes);

        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("acme", parsed.Name);
        Assert.Equal("1.0.0", parsed.Version);
    }

    // ── PyPiArtifactValidator.ValidateEgg ──────────────────────────────────────

    /// <summary>
    /// Regression test for the ZIP entry decompression cap in ValidateEgg.
    /// Same pattern as wheel: over-limit filler before valid Name/Version in PKG-INFO.
    /// </summary>
    [Fact]
    public void ValidateEgg_ZipBombPkgInfoEntry_ReturnsFailResult()
    {
        byte[] bomb = BuildEggZipBomb();

        var parsed = PyPiArtifactValidator.ValidateEgg(bomb);

        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
        Assert.Null(parsed.Name);
        Assert.Null(parsed.Version);
    }

    [Fact]
    public void ValidateEgg_LegitimateInput_StillSucceeds()
    {
        var (bytes, _) = PyPiFixtures.BuildEgg("acme", "1.0.0");
        var parsed = PyPiArtifactValidator.ValidateEgg(bytes);

        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("acme", parsed.Name);
        Assert.Equal("1.0.0", parsed.Version);
    }

    // ── NuGetNupkgValidator.Parse ──────────────────────────────────────────────

    /// <summary>
    /// Regression test for the ZIP entry decompression cap in NuGetNupkgValidator.Parse.
    /// The bomb nuspec is structurally valid XML with a large comment before the root element.
    /// Without the cap XDocument.Load reads the entire document and returns IsValid=true.
    /// With the cap it fires during the comment body and XDocument.Load throws, caught by
    /// the outer handler returning IsValid=false.
    /// </summary>
    [Fact]
    public void NuGetNupkgValidator_ZipBombNuspecEntry_ReturnsFailResult()
    {
        byte[] bomb = BuildNupkgZipBomb();

        var (result, id, version) = NuGetNupkgValidator.Parse(bomb, isSymbol: false);

        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Null(id);
        Assert.Null(version);
    }

    [Fact]
    public void NuGetNupkgValidator_LegitimateInput_StillSucceeds()
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg("Acme.Lib", "1.2.3");
        var (result, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);

        Assert.True(result.IsValid);
        Assert.Equal("Acme.Lib", id);
        Assert.Equal("1.2.3", version);
    }

    // ── LicenseExtractor wheel and nuspec paths ────────────────────────────────

    [Fact]
    public void LicenseExtractor_WheelZipBombMetadataEntry_ReturnsEmpty()
    {
        // LicenseExtractor.ReadWheelMetadata calls reader.ReadToEnd(), which reads
        // the entire entry. The bomb's filler exceeds the cap; LimitedReadStream fires,
        // the exception propagates through ReadWheelMetadata to the outer catch in
        // FromPyPiPackageBytes, returning Empty.
        byte[] bomb = BuildWheelZipBomb();
        var result = LicenseExtractor.FromPyPiPackageBytes(
            new MemoryStream(bomb), "mybomb-1.0.0-py3-none-any.whl");

        Assert.Same(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void LicenseExtractor_NupkgZipBombNuspecEntry_ReturnsEmpty()
    {
        // FromNuspec wraps the entry in a LimitedReadStream; the large comment fires
        // the cap during XDocument.Load, caught by the outer catch returning Empty.
        byte[] bomb = BuildNupkgZipBomb();
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bomb));

        Assert.Same(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── Mixed partial-failure scenario ─────────────────────────────────────────

    /// <summary>
    /// Validates behaviour across a batch where some inputs are legitimate and some are
    /// ZIP bombs. Each call is independent — legitimate packages succeed, bombs fail —
    /// with no cross-call contamination and no unhandled exception escaping.
    /// </summary>
    [Fact]
    public void ValidateWheel_MixedBatch_BombsFailLegitimateSucceed()
    {
        var (legitWheel1, _) = PyPiFixtures.BuildWheel("pkg-a", "1.0.0");
        var (legitWheel2, _) = PyPiFixtures.BuildWheel("pkg-b", "2.0.0");
        byte[] bomb = BuildWheelZipBomb();

        var inputs = new[]
        {
            (bytes: legitWheel1, expectValid: true),
            (bytes: bomb,        expectValid: false),
            (bytes: legitWheel2, expectValid: true),
            (bytes: bomb,        expectValid: false),
        };

        foreach (var (bytes, expectValid) in inputs)
        {
            var parsed = PyPiArtifactValidator.ValidateWheel(bytes);
            Assert.Equal(expectValid, parsed.Validation.IsValid);
        }
    }

    [Fact]
    public void NuGetNupkgValidator_MixedBatch_BombsFailLegitimateSucceed()
    {
        var (legit1, _) = NuGetFixtures.BuildNupkg("Acme.Lib", "1.0.0");
        var (legit2, _) = NuGetFixtures.BuildNupkg("Other.Pkg", "2.5.0");
        byte[] bomb = BuildNupkgZipBomb();

        var inputs = new[]
        {
            (bytes: legit1, expectValid: true),
            (bytes: bomb,   expectValid: false),
            (bytes: legit2, expectValid: true),
            (bytes: bomb,   expectValid: false),
        };

        foreach (var (bytes, expectValid) in inputs)
        {
            var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
            Assert.Equal(expectValid, result.IsValid);
        }
    }
}
