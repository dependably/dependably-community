using Dependably.Api;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for the apk filename parser: <c>{pkgname}-{pkgver}-r{pkgrel}.apk</c> parsed
/// from the right, since Alpine forbids <c>-</c> in <c>pkgver</c>.
/// </summary>
[Trait("Category", "Unit")]
public class ApkControllerTests
{
    [Theory]
    [InlineData("curl-8.9.0-r0.apk", "curl", "8.9.0", "0")]
    [InlineData("busybox-static-1.36.1-r2.apk", "busybox-static", "1.36.1", "2")]
    [InlineData("py3-pip-24.0-r2.apk", "py3-pip", "24.0", "2")]
    [InlineData("a-1-r0.apk", "a", "1", "0")]
    [InlineData("libssl3-3.3.1-r1.apk", "libssl3", "3.3.1", "1")]
    public void ParseApkFilename_WellFormed_ExtractsNameVersionRelease(
        string filename, string expectedName, string expectedVer, string expectedRel)
    {
        var parsed = ApkController.ParseApkFilename(filename);
        Assert.NotNull(parsed);
        Assert.Equal(expectedName, parsed!.Value.PkgName);
        Assert.Equal(expectedVer, parsed.Value.PkgVer);
        Assert.Equal(expectedRel, parsed.Value.PkgRel);
    }

    [Theory]
    [InlineData("APKINDEX.tar.gz")]              // not a .apk file at all
    [InlineData("curl.apk")]                     // no version/release segments
    [InlineData("curl-8.9.0.apk")]                // missing the r{pkgrel} segment
    [InlineData("curl-8.9.0-rX.apk")]             // release is not numeric
    [InlineData("curl-8.9.0-r.apk")]              // release has no digits
    [InlineData("-8.9.0-r0.apk")]                 // empty pkgname
    [InlineData("curl-r0.apk")]                   // missing pkgver segment (single dash before r0)
    [InlineData("not-an-apk-file.txt")]           // wrong extension
    [InlineData("")]                              // empty string
    public void ParseApkFilename_MalformedOrNonMatching_ReturnsNull(string filename)
    {
        Assert.Null(ApkController.ParseApkFilename(filename));
    }

    [Fact]
    public void ParseApkFilename_IsCaseInsensitiveOnExtension()
    {
        // apk clients always request lowercase .apk, but the parser itself only checks the
        // extension case-insensitively — mirrors RpmController.ParseNevra's .rpm handling.
        var parsed = ApkController.ParseApkFilename("curl-8.9.0-r0.APK");
        Assert.NotNull(parsed);
        Assert.Equal("curl", parsed!.Value.PkgName);
    }

    [Fact]
    public void ParseApkFilename_PkgverWithDotsAndUnderscores_ParsesAsSingleSegment()
    {
        // pkgver never contains '-' (Alpine forbids it), but dots/underscores/tildes are legal.
        var parsed = ApkController.ParseApkFilename("libfoo-1.2.3_alpha~rc1-r5.apk");
        Assert.NotNull(parsed);
        Assert.Equal("libfoo", parsed!.Value.PkgName);
        Assert.Equal("1.2.3_alpha~rc1", parsed.Value.PkgVer);
        Assert.Equal("5", parsed.Value.PkgRel);
    }
}
