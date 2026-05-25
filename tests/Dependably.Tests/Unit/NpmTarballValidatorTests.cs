using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class NpmTarballValidatorTests
{
    [Fact]
    public void Validate_RealFixture_Succeeds()
    {
        var (bytes, _) = NpmFixtures.RealTarball();
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("is-odd", name);
        Assert.Equal("3.0.1", version);
    }

    [Fact]
    public void Validate_SyntheticPackageDirWrapper_Succeeds()
    {
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme", "1.0.0");
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("acme", name);
        Assert.Equal("1.0.0", version);
    }

    [Fact]
    public void Validate_PackageJsonAtRoot_NoWrapper_Succeeds()
    {
        var bytes = BuildTarballWithEntries(
            ("package.json", """{"name":"rooted","version":"2.0.0"}"""));
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("rooted", name);
        Assert.Equal("2.0.0", version);
    }

    [Fact]
    public void Validate_SemverWrapper_OverridesPackageJsonVersion()
    {
        // GitHub source archive shape: wrapper "{name}-{semver}/" disambiguates stale manifests.
        // Wrapper version 2.5.0 wins over the package.json's 1.0.0.
        var bytes = BuildTarballWithEntries(
            ("foo-2.5.0/package.json", """{"name":"foo","version":"1.0.0"}"""));
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("foo", name);
        Assert.Equal("2.5.0", version);
    }

    [Fact]
    public void Validate_NoPackageJson_Fails()
    {
        var bytes = BuildTarballWithEntries(("package/README.md", "just a readme"));
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Null(name);
        Assert.Null(version);
    }

    [Fact]
    public void Validate_DeeplyNestedPackageJson_Ignored()
    {
        // package.json buried under multiple directories must NOT be picked up; the validator
        // only considers root or single-wrapper entries.
        var bytes = BuildTarballWithEntries(
            ("a/b/package.json", """{"name":"nested","version":"1.0.0"}"""));
        var result = NpmTarballValidator.Validate(bytes, out _, out _);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_MissingNameOrVersionInPackageJson_Fails()
    {
        var bytes = BuildTarballWithEntries(("package/package.json", """{"name":"only"}"""));
        var result = NpmTarballValidator.Validate(bytes, out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    [Fact]
    public void Validate_MissingNameInPackageJson_Fails()
    {
        // Exercises the left-hand side of the `IsNullOrEmpty(name) || IsNullOrEmpty(version)`
        // short-circuit: name absent, version present.
        var bytes = BuildTarballWithEntries(("package/package.json", """{"version":"1.2.3"}"""));
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Null(name);
        Assert.Equal("1.2.3", version);
    }

    [Fact]
    public void Validate_NullJsonInPackageJson_Fails()
    {
        // The `json?["name"]` chain short-circuits to null when the root JSON itself parses
        // to a JSON null literal. Both name and version end up null, triggering the
        // missing-name-or-version failure path.
        var bytes = BuildTarballWithEntries(("package/package.json", "null"));
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
        Assert.Null(name);
        Assert.Null(version);
    }

    [Fact]
    public void Validate_SkipsNonPackageJsonEntriesBeforeMatch()
    {
        // Forces the GetNextEntry loop to iterate past unrelated entries (false branch of
        // IsTopLevelPackageJson) before landing on the real package.json.
        var bytes = BuildTarballWithEntries(
            ("package/README.md", "readme"),
            ("package/lib/index.js", "console.log('hi');"),
            ("package/package.json", """{"name":"late","version":"4.5.6"}"""));
        var result = NpmTarballValidator.Validate(bytes, out var name, out var version);
        Assert.True(result.IsValid);
        Assert.Equal("late", name);
        Assert.Equal("4.5.6", version);
    }

    [Fact]
    public void Validate_InvalidGzip_FailsGracefully()
    {
        var result = NpmTarballValidator.Validate("not gzip"u8.ToArray(), out _, out _);
        Assert.False(result.IsValid);
        Assert.Equal("content", result.FieldName);
    }

    // ── IsTopLevelPackageJson (internal helper) ──────────────────────────────

    [Theory]
    [InlineData("package.json", true)]
    [InlineData("PACKAGE.JSON", true)]
    [InlineData("package/package.json", true)]
    [InlineData("anything-1.0.0/package.json", true)]
    [InlineData("a/b/package.json", false)]
    [InlineData("subdir/inner/package.json", false)]
    [InlineData("not-package.json", false)]
    public void IsTopLevelPackageJson_MatchesRootOrSingleWrapper(string entryName, bool expected)
    {
        Assert.Equal(expected, NpmTarballValidator.IsTopLevelPackageJson(entryName));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] BuildTarballWithEntries(params (string Name, string Content)[] entries)
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
