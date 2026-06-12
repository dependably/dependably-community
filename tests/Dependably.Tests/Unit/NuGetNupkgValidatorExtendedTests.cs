using System.IO.Compression;
using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Branch-coverage extensions for <see cref="NuGetNupkgValidator"/>.
/// Focuses on the conditional decisions in <c>Parse</c>: null-vs-empty metadata fields,
/// case-insensitivity on entry name matching, missing <c>metadata</c> wrapper, malformed XML
/// (caught by the try/catch), and the symbol-package <c>.pdb</c> casing branch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetNupkgValidatorExtendedTests
{
    [Fact]
    public void Parse_MalformedXml_FailsWithCatchPath()
    {
        // Hits the catch block: XDocument.Load throws on truncated XML.
        byte[] bytes = BuildZip(("a.nuspec", "<package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\"><metadata"));
        var (result, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains("Invalid .nupkg", result.Message);
        Assert.Null(id);
        Assert.Null(version);
    }

    [Fact]
    public void Parse_NuspecWithNoNamespace_FailsContent()
    {
        // doc.Root?.Name.NamespaceName returns "" when no xmlns is declared.
        // Empty namespace is not in the known set -> fail.
        byte[] bytes = BuildZip(("a.nuspec", """
            <?xml version="1.0"?>
            <package>
              <metadata>
                <id>Acme</id><version>1.0.0</version>
                <description>desc</description><authors>x</authors>
              </metadata>
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains("Unknown nuspec namespace", result.Message);
    }

    [Fact]
    public void Parse_MissingMetadataElement_FailsOnNullId()
    {
        // No <metadata> wrapper -> id, version, description, authors are all null.
        // string.IsNullOrEmpty(id) short-circuits on the null path (not the empty-string path).
        byte[] bytes = BuildZip(("a.nuspec", """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("id", result.FieldName);
    }

    [Fact]
    public void Parse_MissingVersionTag_FailsOnNullVersion()
    {
        // <version> element absent -> version is null -> NuGetVersion.TryParse returns false.
        byte[] bytes = BuildZip(("a.nuspec", """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Acme</id>
                <description>desc</description>
                <authors>x</authors>
              </metadata>
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("version", result.FieldName);
    }

    [Fact]
    public void Parse_MissingDescriptionTag_FailsOnNullDescription()
    {
        // No <description> element at all -> description is null (vs empty-string covered in base tests).
        byte[] bytes = BuildZip(("a.nuspec", """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Acme</id>
                <version>1.0.0</version>
                <authors>x</authors>
              </metadata>
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("description", result.FieldName);
    }

    [Fact]
    public void Parse_MissingAuthorsTag_FailsOnNullAuthors()
    {
        // No <authors> element at all -> authors is null.
        byte[] bytes = BuildZip(("a.nuspec", """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Acme</id>
                <version>1.0.0</version>
                <description>desc</description>
              </metadata>
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("authors", result.FieldName);
    }

    [Fact]
    public void Parse_NuspecEntryNameMatchedCaseInsensitively()
    {
        // .NUSPEC (upper case) must still match via OrdinalIgnoreCase.
        byte[] bytes = BuildZip(("PACKAGE.NUSPEC", BuildNuspec("Acme", "1.0.0", "desc", "x")));
        var (result, id, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("Acme", id);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void Parse_Symbol_PdbCaseInsensitive_Succeeds()
    {
        // Upper-case .PDB extension must still satisfy the "has any .pdb" branch.
        byte[] bytes = BuildZip(
            ("a.nuspec", BuildNuspec("Acme", "1.0.0", "desc", "x")),
            ("lib/Acme.PDB", "synthetic pdb"));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: true);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Parse_Symbol_EmptyZip_FailsContent()
    {
        // No entries at all -> hasPdb false; symbol branch returns the .pdb failure
        // before the nuspec lookup runs.
        byte[] bytes = BuildZip();
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: true);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Contains(".pdb", result.Message);
    }

    [Fact]
    public void Parse_IdAtBoundary_100Chars_Succeeds()
    {
        // id.Length == 100 must NOT trip the > 100 guard (off-by-one boundary).
        string boundaryId = new('a', 100);
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec(boundaryId, "1.0.0", "desc", "x")));
        var (result, id, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal(boundaryId, id);
    }

    [Fact]
    public void Parse_IdWithUnderscoresAndDots_Succeeds()
    {
        // Exercise IdRegex's full allowed character class: A-Z, a-z, 0-9, _, -, .
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("My_Cool-Pkg.v2", "1.0.0", "desc", "x")));
        var (result, id, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("My_Cool-Pkg.v2", id);
    }

    [Fact]
    public void Parse_PrereleaseVersion_NormalizedAndAccepted()
    {
        // NuGet.Versioning treats SemVer prerelease + build metadata as parseable.
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "1.0.0-beta.1+build.42", "desc", "x")));
        var (result, _, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("1.0.0-beta.1+build.42", version);
    }

    [Fact]
    public void Parse_VersionWithSurroundingWhitespace_TrimmedAndAccepted()
    {
        // Whitespace inside the <version> element is trimmed before TryParse.
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "  2.5.0  ", "desc", "x")));
        var (result, _, version) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
        Assert.Equal("2.5.0", version);
    }

    [Fact]
    public void Parse_EmptyVersionTag_FailsVersion()
    {
        // <version></version> -> empty after Trim -> TryParse("") returns false.
        byte[] bytes = BuildZip(("a.nuspec", """
            <?xml version="1.0"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>Acme</id>
                <version></version>
                <description>desc</description>
                <authors>x</authors>
              </metadata>
            </package>
            """));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("version", result.FieldName);
    }

    [Fact]
    public void Parse_NuspecFullNameWithSlash_Rejected_EvenWithRootMatchingName()
    {
        // FullName "deep/nested/x.nuspec" has Name "x.nuspec" but FullName contains '/'.
        // Tests the !FullName.Contains('/') half of the predicate alongside an entry-name match.
        byte[] bytes = BuildZip(("deep/nested/x.nuspec", BuildNuspec("Acme", "1.0.0", "desc", "x")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void Parse_NonSymbol_WithoutPdb_StillEvaluatesNuspec()
    {
        // isSymbol=false skips the pdb gate entirely; a package with no pdb is fine.
        byte[] bytes = BuildZip(("a.nuspec", BuildNuspec("Acme", "1.0.0", "desc", "x")));
        var (result, _, _) = NuGetNupkgValidator.Parse(bytes, isSymbol: false);
        Assert.True(result.IsValid);
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
