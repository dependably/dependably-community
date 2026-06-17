using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class NpmTarballValidatorTests
{
    [Fact]
    public void Validate_RealFixture_Succeeds()
    {
        var (bytes, _) = NpmFixtures.RealTarball();
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("is-odd", parsed.Name);
        Assert.Equal("3.0.1", parsed.Version);
    }

    [Fact]
    public void Validate_SyntheticPackageDirWrapper_Succeeds()
    {
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme", "1.0.0");
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("acme", parsed.Name);
        Assert.Equal("1.0.0", parsed.Version);
    }

    [Fact]
    public void Validate_PackageJsonAtRoot_NoWrapper_Succeeds()
    {
        byte[] bytes = BuildTarballWithEntries(
            ("package.json", """{"name":"rooted","version":"2.0.0"}"""));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("rooted", parsed.Name);
        Assert.Equal("2.0.0", parsed.Version);
    }

    [Fact]
    public void Validate_SemverWrapper_OverridesPackageJsonVersion()
    {
        // GitHub source archive shape: wrapper "{name}-{semver}/" disambiguates stale manifests.
        // Wrapper version 2.5.0 wins over the package.json's 1.0.0.
        byte[] bytes = BuildTarballWithEntries(
            ("foo-2.5.0/package.json", """{"name":"foo","version":"1.0.0"}"""));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("foo", parsed.Name);
        Assert.Equal("2.5.0", parsed.Version);
    }

    [Fact]
    public void Validate_NoPackageJson_Fails()
    {
        byte[] bytes = BuildTarballWithEntries(("package/README.md", "just a readme"));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
        Assert.Null(parsed.Name);
        Assert.Null(parsed.Version);
    }

    [Fact]
    public void Validate_DeeplyNestedPackageJson_Ignored()
    {
        // package.json buried under multiple directories must NOT be picked up; the validator
        // only considers root or single-wrapper entries.
        byte[] bytes = BuildTarballWithEntries(
            ("a/b/package.json", """{"name":"nested","version":"1.0.0"}"""));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.False(parsed.Validation.IsValid);
    }

    [Fact]
    public void Validate_MissingNameOrVersionInPackageJson_Fails()
    {
        byte[] bytes = BuildTarballWithEntries(("package/package.json", """{"name":"only"}"""));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
    }

    [Fact]
    public void Validate_MissingNameInPackageJson_Fails()
    {
        // Exercises the left-hand side of the `IsNullOrEmpty(name) || IsNullOrEmpty(version)`
        // short-circuit: name absent, version present.
        byte[] bytes = BuildTarballWithEntries(("package/package.json", """{"version":"1.2.3"}"""));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
        Assert.Null(parsed.Name);
        Assert.Equal("1.2.3", parsed.Version);
    }

    [Fact]
    public void Validate_NullJsonInPackageJson_Fails()
    {
        // The `json?["name"]` chain short-circuits to null when the root JSON itself parses
        // to a JSON null literal. Both name and version end up null, triggering the
        // missing-name-or-version failure path.
        byte[] bytes = BuildTarballWithEntries(("package/package.json", "null"));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
        Assert.Null(parsed.Name);
        Assert.Null(parsed.Version);
    }

    [Fact]
    public void Validate_SkipsNonPackageJsonEntriesBeforeMatch()
    {
        // Forces the GetNextEntry loop to iterate past unrelated entries (false branch of
        // IsTopLevelPackageJson) before landing on the real package.json.
        byte[] bytes = BuildTarballWithEntries(
            ("package/README.md", "readme"),
            ("package/lib/index.js", "console.log('hi');"),
            ("package/package.json", """{"name":"late","version":"4.5.6"}"""));
        var parsed = NpmTarballValidator.Validate(bytes);
        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("late", parsed.Name);
        Assert.Equal("4.5.6", parsed.Version);
    }

    [Fact]
    public void Validate_InvalidGzip_FailsGracefully()
    {
        var parsed = NpmTarballValidator.Validate("not gzip"u8.ToArray());
        Assert.False(parsed.Validation.IsValid);
        Assert.Equal("content", parsed.Validation.FieldName);
    }

    // ── Zip-bomb caps ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_OversizedPackageJsonEntry_Fails()
    {
        // package.json larger than the manifest cap must be rejected before JsonNode.Parse
        // materialises it in memory. 5 MiB of padding > the 4 MiB cap, but gzip keeps the
        // fixture tiny on the wire (high compression ratio — the bomb shape).
        string json = $$"""{"name":"big","version":"1.0.0","padding":"{{new string('a', 5 * 1024 * 1024)}}"}""";
        byte[] bytes = BuildTarballWithEntries(("package/package.json", json));

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.False(parsed.Validation.IsValid);
        Assert.Contains("decompression limit", parsed.Validation.Message);
    }

    [Fact]
    public void Validate_TotalDecompressedBytesOverCap_Fails()
    {
        // A single entry decompressing past the total budget — even though it is not the
        // package.json we parse — must abort the scan (skipping an entry still decompresses it).
        byte[] bytes = NpmFixtures.BuildBombTarball(
            "package/blob.bin", TarScanLimits.MaxTotalDecompressedBytes + 1024 * 1024);

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.False(parsed.Validation.IsValid);
        Assert.Contains("decompression limit", parsed.Validation.Message);
    }

    [Fact]
    public void Validate_EntryCountOverCap_Fails()
    {
        byte[] bytes = NpmFixtures.BuildManyEntryTarball(TarScanLimits.MaxEntries + 1);

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.False(parsed.Validation.IsValid);
        Assert.Contains("entry limit", parsed.Validation.Message);
    }

    [Fact]
    public void Validate_PackageJsonJustUnderManifestCap_StillParses()
    {
        // Mixed-boundary control: a large-but-legal package.json must keep working — the cap
        // rejects bombs, not big-but-real manifests.
        string json = $$"""{"name":"big-legal","version":"1.0.0","padding":"{{new string('a', 1024 * 1024)}}"}""";
        byte[] bytes = BuildTarballWithEntries(("package/package.json", json));

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("big-legal", parsed.Name);
        Assert.Equal("1.0.0", parsed.Version);
    }

    // ── Name shape (shared with the npm publish controller) ──────────────────

    [Theory]
    [InlineData("a/b")]
    [InlineData("evil/../name")]
    [InlineData("@scope/a/b")]
    [InlineData("@/name")]
    [InlineData("@scope/")]
    [InlineData("UPPER")]
    public void Validate_SlashLadenOrMalformedName_Fails(string badName)
    {
        byte[] bytes = BuildTarballWithEntries(
            ("package/package.json", $$"""{"name":"{{badName}}","version":"1.0.0"}"""));

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.False(parsed.Validation.IsValid);
        Assert.Contains("Invalid npm package name", parsed.Validation.Message);
    }

    [Fact]
    public void Validate_ScopedName_StillAccepted()
    {
        byte[] bytes = BuildTarballWithEntries(
            ("package/package.json", """{"name":"@scope/name","version":"1.0.0"}"""));

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("@scope/name", parsed.Name);
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
