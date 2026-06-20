using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class NuGetNupkgValidatorTests
{
    [Fact]
    public void Parse_RealFixture_Succeeds()
    {
        var (bytes, _) = NuGetFixtures.RealNupkg();
        var (result, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("Newtonsoft.Json", id);
        Assert.Equal("13.0.3", version);
    }

    [Fact]
    public void Parse_SyntheticNupkg_Succeeds()
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg("Acme.Lib", "1.2.3");
        var (result, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("Acme.Lib", id);
        Assert.Equal("1.2.3", version);
    }

    [Fact]
    public void Parse_NotAZip_FailsContent()
    {
        var (result, id, version) = NuGetNupkgValidator.Parse(
            "garbage"u8.ToArray(), isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Null(id);
        Assert.Null(version);
    }

    [Fact]
    public void Parse_NoNuspec_FailsContent()
    {
        byte[] bytes = BuildZip(("readme.md", "no nuspec"));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void Parse_NuspecInSubfolder_NotRoot_Rejected()
    {
        // Only root-level .nuspec counts; nested ones are noise.
        string nuspec = BuildNuspec("Acme", "1.0.0", "desc", "authors");
        byte[] bytes = BuildZip(("lib/acme.nuspec", nuspec));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void Parse_UnknownNamespace_FailsContent()
    {
        byte[] bytes = BuildZip(("acme.nuspec",
            """
            <?xml version="1.0"?>
            <package xmlns="https://attacker.example/nuspec.xsd">
              <metadata>
                <id>Acme</id><version>1.0.0</version>
                <description>desc</description><authors>x</authors>
              </metadata>
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains("namespace", result.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("name with spaces")]
    [InlineData("name/with/slashes")]
    public void Parse_InvalidId_Fails(string badId)
    {
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec(badId, "1.0.0", "desc", "authors")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("id", result.FieldName);
    }

    [Fact]
    public void Parse_TooLongId_Fails()
    {
        string longId = new('a', 101);
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec(longId, "1.0.0", "desc", "authors")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("id", result.FieldName);
    }

    [Fact]
    public void Parse_InvalidVersion_Fails()
    {
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "not.a.version!!!", "desc", "authors")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("version", result.FieldName);
    }

    [Fact]
    public void Parse_MissingDescription_Fails()
    {
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "1.0.0", description: "", authors: "x")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("description", result.FieldName);
    }

    [Fact]
    public void Parse_MissingAuthors_Fails()
    {
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "1.0.0", description: "desc", authors: "")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("authors", result.FieldName);
    }

    [Fact]
    public void Parse_Symbol_WithoutPdb_FailsContent()
    {
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "1.0.0", "desc", "x")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: true);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains(".pdb", result.Message);
    }

    [Fact]
    public void Parse_Symbol_WithPdb_Succeeds()
    {
        byte[] bytes = BuildZip(
            ("a.nuspec", BuildNuspec("Acme", "1.0.0", "desc", "x")),
            ("lib/Acme.pdb", "synthetic pdb"));
        var (result, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: true);
        Assert.True(result.IsValid);
        Assert.Equal("Acme", id);
        Assert.Equal("1.0.0", version);
    }

    [Theory]
    [InlineData("http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd")]
    public void Parse_AcceptsAllKnownNamespaces(string ns)
    {
        string nuspec = $"""
            <?xml version="1.0"?>
            <package xmlns="{ns}">
              <metadata>
                <id>Acme</id><version>1.0.0</version>
                <description>desc</description><authors>x</authors>
              </metadata>
            </package>
            """;
        byte[] bytes = BuildZip(("a.nuspec", nuspec));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
    }

    // ── ParseFromStream — stream overload parity ──────────────────────────────

    [Fact]
    public void ParseFromStream_ValidNupkg_ReturnsIdAndVersion()
    {
        // Regression: ParseFromStream is the path used by the publish handler.
        // Verifies the stream overload returns the same successful result as Parse(byte[]).
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme.Lib", "2.0.0", "desc", "x")));
        using var ms = new MemoryStream(bytes);
        var (result, id, version) = NuGetNupkgValidator.ParseFromStream(ms, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("Acme.Lib", id);
        Assert.Equal("2.0.0", version);
    }

    [Fact]
    public void ParseFromStream_InvalidZip_FailsContent()
    {
        // Regression: ParseFromStream must surface the same error as Parse(byte[]) on bad input.
        using var ms = new MemoryStream("garbage"u8.ToArray());
        var (result, id, version) = NuGetNupkgValidator.ParseFromStream(ms, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains("Invalid .nupkg", result.Message);
        Assert.Null(id);
        Assert.Null(version);
    }

    [Fact]
    public void ParseFromStream_And_ParseBytes_ProduceSameResult_ForSameInput()
    {
        // Regression pin: the publish handler (stream) and import controller (bytes) must
        // produce identical outcomes for the same nupkg content. A future tightening of
        // one path would not silently miss the other. Covers both the success and a
        // validation-failure case (bad id) to confirm shared ParseZip logic runs on both.
        byte[] validBytes = BuildZip(("a.nuspec", BuildNuspec("My.Pkg", "3.1.4", "desc", "auth")));
        byte[] badIdBytes = BuildZip(("a.nuspec", BuildNuspec("invalid id!", "1.0.0", "desc", "x")));

        // Success path
        var (r1, id1, v1) = NuGetNupkgValidator.Parse(validBytes, isSymbol: false);
        using var ms1 = new MemoryStream(validBytes);
        var (r2, id2, v2) = NuGetNupkgValidator.ParseFromStream(ms1, isSymbol: false);
        Assert.Equal(r1.IsValid, r2.IsValid);
        Assert.Equal(id1, id2);
        Assert.Equal(v1, v2);

        // Failure path — bad id character set
        var (rf1, _, _) = NuGetNupkgValidator.Parse(badIdBytes, isSymbol: false);
        using var ms2 = new MemoryStream(badIdBytes);
        var (rf2, _, _) = NuGetNupkgValidator.ParseFromStream(ms2, isSymbol: false);
        Assert.False(rf1.IsValid);
        Assert.False(rf2.IsValid);
        Assert.Equal(rf1.FieldName, rf2.FieldName);
        Assert.Equal(rf1.Message, rf2.Message);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string BuildNuspec(string id, string version, string description, string authors) => $"""
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
          <metadata>
            <id>{id}</id>
            <version>{version}</version>
            <description>{description}</description>
            <authors>{authors}</authors>
          </metadata>
        </package>
        """;

    private static byte[] BuildZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                var entry = zip.CreateEntry(n);
                using var w = new StreamWriter(entry.Open(), Encoding.UTF8);
                w.Write(c);
            }
        }
        return ms.ToArray();
    }
}
