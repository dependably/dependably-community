using System.IO.Compression;
using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// EcosystemDetector trust contract: detection comes from <em>content</em> (magic bytes plus
/// the required manifest entry), never the filename extension. These tests therefore include
/// "lying extension" cases where the filename advertises one ecosystem and the bytes are
/// another — content always wins.
/// </summary>
public sealed class EcosystemDetectorTests
{
    [Fact]
    public void Detects_Npm_From_Tarball_With_PackageJson()
    {
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-detect-npm", "1.2.3");
        var (ok, err) = EcosystemDetector.Detect("acme-detect-npm-1.2.3.tgz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("npm", ok!.Ecosystem);
        Assert.Equal("acme-detect-npm", ok.Name);
        Assert.Equal("1.2.3", ok.Version);
    }

    [Fact]
    public void Detects_PyPi_Wheel_From_Zip_With_DistInfo_Metadata()
    {
        var (bytes, _) = PyPiFixtures.BuildWheel("acme_detect_wheel", "0.5.0");
        var (ok, err) = EcosystemDetector.Detect("acme_detect_wheel-0.5.0-py3-none-any.whl", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("pypi", ok!.Ecosystem);
        Assert.Equal("acme-detect-wheel", ok.Name);
        Assert.Equal("0.5.0", ok.Version);
    }

    [Fact]
    public void Detects_PyPi_Sdist_From_Tar_With_PkgInfo()
    {
        var (bytes, _) = PyPiFixtures.BuildSdist("acme-detect-sdist", "2.0.0");
        var (ok, err) = EcosystemDetector.Detect("acme-detect-sdist-2.0.0.tar.gz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("pypi", ok!.Ecosystem);
        Assert.Equal("acme-detect-sdist", ok.Name);
        Assert.Equal("2.0.0", ok.Version);
    }

    [Fact]
    public void Detects_NuGet_From_Zip_With_Nuspec()
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg("Acme.Detect.NuGet", "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("Acme.Detect.NuGet.1.0.0.nupkg", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("nuget", ok!.Ecosystem);
        Assert.Equal("Acme.Detect.NuGet", ok.Name);
        Assert.Equal("acme.detect.nuget", ok.PurlName);
        Assert.Equal("1.0.0", ok.Version);
    }

    [Fact]
    public void Content_Trumps_Extension_NuPkg_Renamed_As_Tgz()
    {
        // File named .tgz but the bytes are a .nupkg (ZIP with a .nuspec). The detector must
        // not be fooled by the extension — magic bytes (PK header) say ZIP, the ZIP contains
        // a .nuspec, so the verdict is "nuget".
        var (bytes, _) = NuGetFixtures.BuildNupkg("Lying.Extension", "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("evil.tgz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("nuget", ok!.Ecosystem);
    }

    [Fact]
    public void Content_Trumps_Extension_Tarball_Renamed_As_Whl()
    {
        // File named .whl but the bytes are an npm tarball. Magic bytes (1F 8B) say gzip,
        // tar contains package/package.json, so it's npm — not a wheel.
        var (bytes, _, _) = NpmFixtures.BuildTarball("npm-disguised-as-whl", "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("evil.whl", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("npm", ok!.Ecosystem);
    }

    [Fact]
    public void Detects_Npm_From_Tarball_With_Custom_Wrapper_Directory()
    {
        // Some npm tarballs (git-archive, GitHub release assets) wrap files in {name}-{version}/
        // rather than package/. npm itself strips one leading dir on install, so the wrapper
        // name isn't significant — the detector must accept this shape.
        var bytes = BuildGzippedTarWithPackageJson("acme-pkg-1.2.3/package.json", "acme-pkg", "1.2.3");
        var (ok, err) = EcosystemDetector.Detect("acme-pkg-1.2.3.tgz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("npm", ok!.Ecosystem);
        Assert.Equal("acme-pkg", ok.Name);
        Assert.Equal("1.2.3", ok.Version);
    }

    [Fact]
    public void Detects_Npm_From_Tarball_With_PackageJson_At_Root()
    {
        // Hand-rolled `tar -czf` from a project directory may put package.json at the archive
        // root with no wrapper directory. Accept this shape too.
        var bytes = BuildGzippedTarWithPackageJson("package.json", "root-pkg", "0.1.0");
        var (ok, err) = EcosystemDetector.Detect("root-pkg-0.1.0.tgz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("npm", ok!.Ecosystem);
        Assert.Equal("root-pkg", ok.Name);
        Assert.Equal("0.1.0", ok.Version);
    }

    // ── Outer-label version override (per-ecosystem) ─────────────────────────
    //
    // Two distinct uploads that share the same embedded manifest version but carry
    // different outer labels (wrapper-dir for tarballs, filename for ZIPs) should land
    // as distinct (name, version) coordinates. The motivating case: GitHub source archives
    // of a monorepo at different release tags ship the same workspace package.json across
    // tags — without the override, dependably conflates them as `version_exists`.

    [Fact]
    public void Npm_Wrapper_Dir_Overrides_Stale_Embedded_Version()
    {
        // mermaid-style monorepo: workspace package.json claims 10.2.4 but the source archive
        // for tag v11.13.0 wraps everything in `<repo>-11.13.0/`. Use the wrapper version.
        var bytes = BuildGzippedTarWithPackageJson("mermaid-mermaid-11.13.0/package.json",
            name: "mermaid-monorepo", version: "10.2.4");
        var (ok, err) = EcosystemDetector.Detect("mermaid-mermaid-11.13.0.tar.gz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("npm", ok!.Ecosystem);
        Assert.Equal("mermaid-monorepo", ok.Name);
        Assert.Equal("11.13.0", ok.Version);
    }

    [Fact]
    public void Npm_Canonical_Wrapper_Keeps_Embedded_Version()
    {
        // Regression: `npm pack`'s canonical `package/` wrapper has no version suffix, so the
        // override must be silent — embedded version stays authoritative.
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-canonical", "1.2.3");
        var (ok, err) = EcosystemDetector.Detect("acme-canonical-1.2.3.tgz", bytes);

        Assert.Null(err);
        Assert.Equal("1.2.3", ok!.Version);
    }

    [Fact]
    public void PyPi_Sdist_Wrapper_Dir_Overrides_Stale_PkgInfo_Version()
    {
        // Wrapper-dir says 2.0.0 but PKG-INFO inside says 1.0.0 (stale across release tags).
        var bytes = BuildGzippedTarWithPkgInfo("myproj-2.0.0/PKG-INFO", name: "myproj", version: "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("myproj-2.0.0.tar.gz", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("pypi", ok!.Ecosystem);
        Assert.Equal("myproj", ok.Name);
        Assert.Equal("2.0.0", ok.Version);
    }

    [Fact]
    public void PyPi_Wheel_Filename_Overrides_Stale_Metadata_Version()
    {
        // Embedded METADATA version 1.0.0; wheel filename advertises 2.0.0. PEP 427's
        // segment-2 is authoritative per the override rule.
        var (bytes, _) = PyPiFixtures.BuildWheel("acme_wheel", "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("acme_wheel-2.0.0-py3-none-any.whl", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("pypi", ok!.Ecosystem);
        Assert.Equal("2.0.0", ok.Version);
    }

    [Fact]
    public void NuGet_Nupkg_Filename_Overrides_Stale_Nuspec_Version()
    {
        // Embedded .nuspec version 1.0.0; filename says 2.0.0. Use filename.
        var (bytes, _) = NuGetFixtures.BuildNupkg("Acme.Override", "1.0.0");
        var (ok, err) = EcosystemDetector.Detect("Acme.Override.2.0.0.nupkg", bytes);

        Assert.Null(err);
        Assert.NotNull(ok);
        Assert.Equal("nuget", ok!.Ecosystem);
        Assert.Equal("2.0.0", ok.Version);
    }

    [Fact]
    public void Rejects_Zip_With_No_Recognised_Manifest()
    {
        // ZIP that's neither a wheel nor a .nupkg — just a random ZIP. Detector should fail
        // cleanly rather than misclassify.
        var bytes = BuildEmptyishZip();
        var (ok, err) = EcosystemDetector.Detect("mystery.zip", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
    }

    [Fact]
    public void Rejects_GzippedTar_With_No_Recognised_Manifest()
    {
        // gzip+tar with neither package/package.json nor */PKG-INFO at top level.
        var bytes = BuildGzippedTarWithEntry("random/data.txt", "hello");
        var (ok, err) = EcosystemDetector.Detect("mystery.tar.gz", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
    }

    [Fact]
    public void Rejects_Random_Non_Archive_Bytes()
    {
        var bytes = Encoding.UTF8.GetBytes("not an archive, just text");
        var (ok, err) = EcosystemDetector.Detect("readme.txt", bytes);

        Assert.Null(ok);
        Assert.NotNull(err);
        Assert.Equal("unrecognised_format", err!.Code);
    }

    private static byte[] BuildEmptyishZip()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var e = zip.CreateEntry("README.md");
            using var w = new StreamWriter(e.Open());
            w.Write("not a package");
        }
        return ms.ToArray();
    }

    private static byte[] BuildGzippedTarWithPackageJson(string entryPath, string name, string version)
    {
        var json = $"{{\"name\":\"{name}\",\"version\":\"{version}\"}}";
        return BuildGzippedTarWithEntry(entryPath, json);
    }

    private static byte[] BuildGzippedTarWithPkgInfo(string entryPath, string name, string version)
    {
        var pkgInfo = $"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: synthetic\n";
        return BuildGzippedTarWithEntry(entryPath, pkgInfo);
    }

    private static byte[] BuildGzippedTarWithEntry(string entryName, string content)
    {
        var contentBytes = Encoding.UTF8.GetBytes(content);
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new System.Formats.Tar.TarWriter(gz, leaveOpen: true))
        {
            var entry = new System.Formats.Tar.PaxTarEntry(
                System.Formats.Tar.TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(contentBytes)
            };
            tw.WriteEntry(entry);
        }
        return ms.ToArray();
    }
}
