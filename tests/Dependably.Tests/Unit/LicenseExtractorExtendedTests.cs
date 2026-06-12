using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Extends LicenseExtractorTests with coverage for ecosystem-specific edge cases
/// (missing entries, fallback paths, RFC 822 continuation/no-colon lines, atypical
/// npm JsonNode shapes, NuGet license-type variants) and the IsPlausibleSpdx
/// shape gate — the remaining uncovered branches in LicenseExtractor.cs.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseExtractorExtendedTests
{
    // ── PyPI: wheel structure edges ──────────────────────────────────────────

    [Fact]
    public void PyPi_Wheel_NoMetadataEntry_ReturnsEmpty()
    {
        // Wheel zip with no .dist-info/METADATA entry — ReadWheelMetadata returns null
        // and FromPyPiPackageBytes short-circuits to Empty.
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo-1.0.dist-info/RECORD"] = "garbage",
            ["foo/__init__.py"] = "",
        });
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0-py3-none-any.whl");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── PyPI: sdist (tar.gz + zip fallback) ──────────────────────────────────

    [Fact]
    public void PyPi_Sdist_TarGz_ExtractsLicenseFromPkgInfo()
    {
        byte[] bytes = BuildTarGz("foo-1.0/PKG-INFO", """
            Metadata-Version: 2.1
            Name: foo
            Version: 1.0
            License: Apache-2.0

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0.tar.gz");
        Assert.Equal(new[] { "Apache-2.0" }, result.Spdx);
    }

    [Fact]
    public void PyPi_Sdist_TarGz_NoPkgInfo_FallsThroughAndReturnsEmpty()
    {
        // Valid tar.gz, but no */PKG-INFO entry — tar walk exhausts, zip-fallback
        // sees the same bytes as not-a-zip, and ReadSdistPkgInfo returns null.
        byte[] bytes = BuildTarGz("foo-1.0/setup.py", "x = 1");
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0.tar.gz");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void PyPi_Sdist_ZipFallback_ExtractsLicenseFromPkgInfo()
    {
        // Filename doesn't end in .whl, so we go through ReadSdistPkgInfo. Bytes are
        // not gzip, so the tar try-catch falls through; the zip path picks up PKG-INFO.
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo-1.0/PKG-INFO"] = """
                Metadata-Version: 2.1
                Name: foo
                Version: 1.0
                License: BSD-2-Clause

                body
                """,
        });
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0.zip");
        Assert.Equal(new[] { "BSD-2-Clause" }, result.Spdx);
    }

    [Fact]
    public void PyPi_Sdist_ZipFallback_NoPkgInfoEntry_ReturnsEmpty()
    {
        // Valid zip, but no PKG-INFO entry — ReadSdistPkgInfo returns null.
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo-1.0/setup.py"] = "x = 1",
        });
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0.zip");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void PyPi_Sdist_GarbageBytes_ReturnsEmpty()
    {
        // Neither gzip nor zip — both branches throw and the outer catch returns Empty.
        byte[] bytes = Encoding.UTF8.GetBytes("absolutely not a package");
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0.tar.gz");
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── PyPI: RFC 822 header parser edge cases ───────────────────────────────

    [Fact]
    public void PyPi_Headers_ContinuationLine_AppendedToPriorValue()
    {
        // The continuation extends the License-Expression value, which then contains
        // a newline and is rejected by IsPlausibleSpdx — so no SPDX is emitted.
        byte[] bytes = BuildWheel("""
            Metadata-Version: 2.3
            Name: foo
            Version: 1.0
            License-Expression: MIT
             continued-on-next-line

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0-py3-none-any.whl");
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void PyPi_Headers_LineWithNoColon_SkippedAndDoesNotBreakParse()
    {
        // The 'orphan' line (no colon) resets currentKey to null; the subsequent
        // License-Expression must still be picked up.
        byte[] bytes = BuildWheel("""
            Metadata-Version: 2.3
            Name: foo
            orphan line with no colon
            License-Expression: MIT
            Version: 1.0

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0-py3-none-any.whl");
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void PyPi_Headers_ColonAtStartOfLine_TreatedAsOrphan()
    {
        // idx == 0 → currentKey reset, line skipped. Following License is still parsed.
        byte[] bytes = BuildWheel("""
            Metadata-Version: 2.1
            : nothing
            Name: foo
            Version: 1.0
            License: MIT

            body
            """);
        var result = LicenseExtractor.FromPyPiPackageBytes(new MemoryStream(bytes), "foo-1.0-py3-none-any.whl");
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    // ── npm: JsonNode shape edges ────────────────────────────────────────────

    [Fact]
    public void Npm_NullVersionNode_ReturnsEmpty()
    {
        var result = LicenseExtractor.FromNpmPackumentVersion(null);
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void Npm_LicenseAsArray_NotAStringOrObject_Ignored()
    {
        // The single "license" field is an array (not a JsonValue or JsonObject) —
        // falls into the `_` switch arm in AddNpmSingleLicense. legacy "licenses"
        // is absent, so the result is empty.
        var node = JsonNode.Parse("""{"license":["MIT","Apache-2.0"]}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Npm_LicenseObjectWithMissingType_Skipped()
    {
        // Object without "type" — SafeReadString(null) returns null, AddIfPlausibleSpdx skips.
        var node = JsonNode.Parse("""{"license":{"url":"https://example.com/LICENSE"}}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Npm_LicenseAsNonStringValue_Skipped()
    {
        // license: 42 — JsonValue.GetValue<string>() throws in SafeReadString.
        var node = JsonNode.Parse("""{"license":42}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Npm_LegacyLicenses_NotAnArray_Ignored()
    {
        // "licenses" is a string (not an array) — AddNpmLegacyLicensesArray returns early.
        var node = JsonNode.Parse("""{"licenses":"MIT"}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Npm_LegacyLicenses_ArrayWithStringElement_Extracted()
    {
        // Array items can themselves be JsonValue strings — covers the JsonValue arm
        // inside AddNpmLegacyLicensesArray's switch.
        var node = JsonNode.Parse("""{"licenses":["MIT","ISC"]}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Equal(new[] { "MIT", "ISC" }, result.Spdx);
    }

    [Fact]
    public void Npm_LegacyLicenses_ArrayWithNestedArray_Ignored()
    {
        // Nested array item — falls into the `_` arm of the inner switch.
        var node = JsonNode.Parse("""{"licenses":[["MIT"]]}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Npm_DuplicateLicensesAcrossFields_DeduplicatedCaseInsensitively()
    {
        // "license": "MIT" plus "licenses": [{"type":"mit"}] — second is the same SPDX
        // ignoring case, must not be added twice.
        var node = JsonNode.Parse("""
            {"license":"MIT","licenses":[{"type":"mit"}]}
            """);
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void Npm_ImplausibleSpdx_Rejected()
    {
        // Newline in the value — rejected by IsPlausibleSpdx.
        var node = JsonNode.Parse("""{"license":"MIT\nlicense text"}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void Npm_DeprecatedWhitespaceOnly_NormalizedToNull()
    {
        var node = JsonNode.Parse("""{"license":"MIT","deprecated":"   "}""");
        var result = LicenseExtractor.FromNpmPackumentVersion(node);
        Assert.Null(result.Deprecated);
    }

    // ── npm: tarball walker ──────────────────────────────────────────────────

    [Fact]
    public void NpmTarball_NoPackageJson_ReturnsEmpty()
    {
        byte[] bytes = BuildTarGz("package/index.js", "module.exports = {};");
        var result = LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NpmTarball_MalformedPackageJson_ReturnsEmpty()
    {
        // Tar.gz reads fine, but JsonNode.Parse throws — outer catch returns Empty.
        byte[] bytes = BuildTarGz("package/package.json", "{ not valid json");
        var result = LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NpmTarball_MalformedGzip_ReturnsEmpty()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("not a gzipped tarball");
        var result = LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── NuGet: nuspec location and license-element variants ──────────────────

    [Fact]
    public void NuGet_NuspecInSubfolder_Ignored_ReturnsEmpty()
    {
        // Only root .nuspec is considered. A nested one must be skipped.
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["_rels/foo.nuspec"] = """
                <?xml version="1.0"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Foo</id>
                    <version>1.0.0</version>
                    <license type="expression">MIT</license>
                  </metadata>
                </package>
                """,
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NuGet_LicenseExpressionType_Extracted()
    {
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo.nuspec"] = """
                <?xml version="1.0"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Foo</id>
                    <version>1.0.0</version>
                    <license type="expression">MIT OR Apache-2.0</license>
                  </metadata>
                </package>
                """,
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(new[] { "MIT OR Apache-2.0" }, result.Spdx);
        Assert.Null(result.Deprecated);
    }

    [Fact]
    public void NuGet_LicenseWithoutTypeAttribute_Ignored()
    {
        // No `type` attribute — first branch rejects (type != "expression").
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo.nuspec"] = """
                <?xml version="1.0"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Foo</id>
                    <version>1.0.0</version>
                    <license>MIT</license>
                  </metadata>
                </package>
                """,
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NuGet_LicenseExpressionEmpty_ReturnsEmpty()
    {
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo.nuspec"] = """
                <?xml version="1.0"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Foo</id>
                    <version>1.0.0</version>
                    <license type="expression">   </license>
                  </metadata>
                </package>
                """,
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NuGet_LicenseExpressionImplausibleSpdx_ReturnsEmpty()
    {
        // type="expression" but the value contains invalid SPDX characters.
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo.nuspec"] = """
                <?xml version="1.0"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Foo</id>
                    <version>1.0.0</version>
                    <license type="expression">MIT/Custom/Thing</license>
                  </metadata>
                </package>
                """,
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NuGet_NoNuspecAtAll_ReturnsEmpty()
    {
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["lib/netstandard2.0/_._"] = "",
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NuGet_MalformedZipBytes_ReturnsEmpty()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("not a zip at all");
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void NuGet_NuspecWithoutMetadataElement_ReturnsEmpty()
    {
        // Root has no <metadata> child — metadata is null, licenseEl is null → Empty.
        byte[] bytes = BuildZip(new Dictionary<string, string>
        {
            ["foo.nuspec"] = """
                <?xml version="1.0"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <other />
                </package>
                """,
        });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    // ── IsPlausibleSpdx shape gate (exercised indirectly via NuGet) ──────────

    [Theory]
    [InlineData("MIT\rblah")]               // CR rejected
    [InlineData("MIT\nblah")]               // LF rejected (rare via XML but still)
    [InlineData("MIT/Apache")]              // invalid char '/'
    [InlineData("MIT@2.0")]                 // invalid char '@'
    public void IsPlausibleSpdx_RejectsImplausibleShapes_ViaNuspec(string value)
    {
        string xml = $"""
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Foo</id>
                <version>1.0.0</version>
                <license type="expression">{System.Security.SecurityElement.Escape(value)}</license>
              </metadata>
            </package>
            """;
        byte[] bytes = BuildZip(new Dictionary<string, string> { ["foo.nuspec"] = xml });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void IsPlausibleSpdx_RejectsOverlyLongValue_ViaNuspec()
    {
        // 101-char value — IsPlausibleSpdx caps at 100.
        string longSpdx = new('A', 101);
        string xml = $"""
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Foo</id>
                <version>1.0.0</version>
                <license type="expression">{longSpdx}</license>
              </metadata>
            </package>
            """;
        byte[] bytes = BuildZip(new Dictionary<string, string> { ["foo.nuspec"] = xml });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(LicenseExtractor.ExtractedMetadata.Empty, result);
    }

    [Fact]
    public void IsPlausibleSpdx_AcceptsExpressionWithParensAndPlus_ViaNuspec()
    {
        // Exercises the '(', ')', '+' branches of the char filter.
        string xml = """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Foo</id>
                <version>1.0.0</version>
                <license type="expression">(MIT OR GPL-2.0+)</license>
              </metadata>
            </package>
            """;
        byte[] bytes = BuildZip(new Dictionary<string, string> { ["foo.nuspec"] = xml });
        var result = LicenseExtractor.FromNuspec(new MemoryStream(bytes));
        Assert.Equal(new[] { "(MIT OR GPL-2.0+)" }, result.Spdx);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] BuildWheel(string metadata)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("foo-1.0.dist-info/METADATA");
            using var s = entry.Open();
            using var w = new StreamWriter(s, new UTF8Encoding(false));
            w.Write(metadata);
        }
        return ms.ToArray();
    }

    private static byte[] BuildZip(IDictionary<string, string> entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (path, content) in entries)
            {
                var entry = zip.CreateEntry(path);
                using var s = entry.Open();
                using var w = new StreamWriter(s, new UTF8Encoding(false));
                w.Write(content);
            }
        }
        return ms.ToArray();
    }

    private static byte[] BuildTarGz(string entryName, string content)
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
