using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// The npm licence extractor selects the same top-level manifest as the tarball validator:
/// <c>package.json</c> at the root or under exactly one wrapper directory of any name, so
/// DefinitelyTyped tarballs (<c>json5/</c>, <c>react v18.3/</c>) are read like <c>package/</c> ones.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseExtractorNpmWrapperTests
{
    [Theory]
    [InlineData("package/package.json")]
    [InlineData("json5/package.json")]
    [InlineData("react v18.3/package.json")]
    [InlineData("package.json")]
    [InlineData("./package.json")]
    public void TopLevelManifest_AnyWrapperShape_LicenceExtracted(string manifestPath)
    {
        var result = LicenseExtractor.FromNpmTarballPackageJson(
            Tarball((manifestPath, Manifest("MIT"))));

        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Theory]
    [InlineData("package/node_modules/x/package/package.json")]
    [InlineData("package/node_modules/x/package.json")]
    [InlineData("package/sub/package.json")]
    public void NestedManifestBeforeTopLevel_TopLevelWins(string nestedPath)
    {
        var result = LicenseExtractor.FromNpmTarballPackageJson(Tarball(
            (nestedPath, Manifest("GPL-3.0-only")),
            ("react v18.3/package.json", Manifest("MIT"))));

        Assert.Equal(new[] { "MIT" }, result.Spdx);
    }

    [Fact]
    public void DotSlashPackageDir_IsNestedUnderTheDotWrapper_NotTheManifest()
    {
        var result = LicenseExtractor.FromNpmTarballPackageJson(
            Tarball(("./package/package.json", Manifest("MIT"))));

        Assert.Empty(result.Spdx);
    }

    // npm strips the first path component without normalizing it, so "./" is the wrapper:
    // ./x/package.json installs as a nested file and ./package.json is the manifest.
    private const string Real =
        """{"name":"real","version":"1.0.0","license":"GPL-3.0-only","scripts":{"postinstall":"echo pwn"}}""";
    private const string Decoy = """{"name":"decoy","version":"1.0.0","license":"MIT"}""";

    [Fact]
    public void DotSlashDecoyBeforeDotSlashManifest_AllReadersPickTheDotSlashManifest()
    {
        byte[] tgz = Tarball(("./x/package.json", Decoy), ("./package.json", Real)).ToArray();

        Assert.Equal("real", NpmTarballValidator.Validate(tgz).Name);
        Assert.Equal(new[] { "GPL-3.0-only" }, LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(tgz)).Spdx);
        Assert.True(ScriptDetectionService.Detect("npm", "real-1.0.0.tgz", tgz).HasScript);
    }

    [Fact]
    public void OnlyNestedManifest_NoLicence()
    {
        var result = LicenseExtractor.FromNpmTarballPackageJson(Tarball(
            ("package/node_modules/x/package/package.json", Manifest("GPL-3.0-only"))));

        Assert.Empty(result.Spdx);
    }

    private static string Manifest(string license) =>
        $$"""{"name":"x","version":"1.0.0","license":"{{license}}"}""";

    private static MemoryStream Tarball(params (string Path, string Json)[] entries)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            foreach (var (path, json) in entries)
            {
                tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, path)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(json)),
                });
            }
        }
        return new MemoryStream(ms.ToArray());
    }
}
