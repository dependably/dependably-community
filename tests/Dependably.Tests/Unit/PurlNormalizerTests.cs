using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class PurlNormalizerTests
{
    // PyPI name normalization (PEP 503) — PyPiName is the shared normalizer used by cache
    // keys and PURL construction; all equivalent name forms must produce the same output.
    [Theory]
    [InlineData("my-package", "my-package")]
    [InlineData("my_package", "my-package")]
    [InlineData("my.package", "my-package")]
    [InlineData("My_Package", "my-package")]
    [InlineData("MY-PACKAGE", "my-package")]
    [InlineData("my__package", "my-package")]
    [InlineData("my-.package", "my-package")]
    public void PyPiName_EquivalentForms_ProduceSameKey(string input, string expected)
        => Assert.Equal(expected, PurlNormalizer.PyPiName(input));

    // Cache key equivalence: eviction by one PEP 503-equivalent form invalidates lookups
    // by any other form (they all resolve to the same normalized cache key).
    [Fact]
    public void PyPiName_DashUnderscoreDot_ProduceIdenticalCacheKey()
    {
        string dashForm = PurlNormalizer.PyPiName("my-package");
        string underscoreForm = PurlNormalizer.PyPiName("my_package");
        string dotForm = PurlNormalizer.PyPiName("my.package");

        Assert.Equal(dashForm, underscoreForm);
        Assert.Equal(dashForm, dotForm);
    }

    // PyPI PURL normalization (PEP 503)
    [Theory]
    [InlineData("requests", "2.28.0", "pkg:pypi/requests@2.28.0")]
    [InlineData("My_Package", "1.0.0", "pkg:pypi/my-package@1.0.0")]
    [InlineData("my.package", "1.0.0", "pkg:pypi/my-package@1.0.0")]
    [InlineData("my-package", "1.0.0", "pkg:pypi/my-package@1.0.0")]
    [InlineData("My__Double__Under", "0.1", "pkg:pypi/my-double-under@0.1")]
    [InlineData("Flask", "2.3.0", "pkg:pypi/flask@2.3.0")]
    public void PyPi_NormalizesCorrectly(string name, string version, string expected)
        => Assert.Equal(expected, PurlNormalizer.PyPi(name, version));

    // NuGet — unparseable version falls through the false branch of TryParse and returns original
    [Fact]
    public void NuGet_UnparseableVersion_ReturnsOriginalString()
    {
        string purl = PurlNormalizer.NuGet("SomeLib", "not-a-version!!");
        Assert.Equal("pkg:nuget/SomeLib@not-a-version!!", purl);
    }

    // NormalizeNuGetVersionString — exercises the standalone entry point on both branches
    [Theory]
    [InlineData("1.0.0.0", "1.0.0")]        // 4-part zero revision collapses
    [InlineData("1.0.0.4", "1.0.0.4")]      // non-zero revision preserved
    [InlineData("2.1.0-beta.1", "2.1.0-beta.1")] // prerelease preserved
    [InlineData("garbage", "garbage")]      // unparseable returns original
    [InlineData("", "")]                    // empty unparseable returns original
    public void NormalizeNuGetVersionString_HandlesParseableAndUnparseable(string input, string expected)
        => Assert.Equal(expected, PurlNormalizer.NormalizeNuGetVersionString(input));

    // npm — unscoped
    [Theory]
    [InlineData("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")]
    [InlineData("is-odd", "3.0.1", "pkg:npm/is-odd@3.0.1")]
    public void Npm_Unscoped_NormalizesCorrectly(string name, string version, string expected)
        => Assert.Equal(expected, PurlNormalizer.Npm(name, version));

    // npm — scoped (@scope/name) — @ is NOT percent-encoded in the PURL
    [Theory]
    [InlineData("@angular/core", "15.0.0", "pkg:npm/@angular/core@15.0.0")]
    [InlineData("@types/node", "18.0.0", "pkg:npm/@types/node@18.0.0")]
    public void Npm_Scoped_NormalizesCorrectly(string name, string version, string expected)
        => Assert.Equal(expected, PurlNormalizer.Npm(name, version));

    // NuGet version normalization
    [Theory]
    [InlineData("Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3")]
    [InlineData("Newtonsoft.Json", "1.0.0.0", "pkg:nuget/Newtonsoft.Json@1.0.0")]   // 4-part zero revision → 3-part
    [InlineData("Newtonsoft.Json", "1.0.0.4", "pkg:nuget/Newtonsoft.Json@1.0.0.4")] // non-zero revision preserved
    [InlineData("SomeLib", "2.1.0-beta.1", "pkg:nuget/SomeLib@2.1.0-beta.1")]       // prerelease preserved
    public void NuGet_NormalizesVersionCorrectly(string id, string version, string expected)
        => Assert.Equal(expected, PurlNormalizer.NuGet(id, version));

    [Fact]
    public void NuGet_PreservesIdCasing()
    {
        string purl = PurlNormalizer.NuGet("Newtonsoft.Json", "13.0.3");
        Assert.Contains("Newtonsoft.Json", purl);
    }
}

[Trait("Category", "Unit")]
public class NpmRouteHelperTests
{
    [Theory]
    [InlineData("lodash", "lodash")]       // unscoped — unchanged
    [InlineData("@scope%2Fpkg", "@scope/pkg")]   // %2F decoded
    [InlineData("%40scope%2Fpkg", "@scope/pkg")]   // %40 + %2F both decoded
    [InlineData("@scope%2fpkg", "@scope/pkg")]   // lowercase %2f
    [InlineData("@scope/pkg", "@scope/pkg")]   // already clean
    public void DecodeRouteName_NormalizesEncodedChars(string input, string expected)
        => Assert.Equal(expected, NpmRouteHelper.DecodeRouteName(input));

    [Theory]
    [InlineData("npm", "@babel%2Fcore", "@babel/core")]  // npm: decode
    [InlineData("npm", "%40babel%2Fcore", "@babel/core")]  // npm: decode %40 too
    [InlineData("pypi", "my%2Fpkg", "my%2Fpkg")]     // non-npm: pass through
    [InlineData("nuget", "Some%2FPkg", "Some%2FPkg")]   // non-npm: pass through
    public void AsPurlName_OnlyDecodesNpm(string ecosystem, string input, string expected)
    {
        string result = ecosystem == "npm" ? NpmRouteHelper.DecodeRouteName(input) : input;
        Assert.Equal(expected, result);
    }
}

[Trait("Category", "Unit")]
public class PurlParserTests
{
    [Theory]
    [InlineData("pkg:pypi/requests@2.28.0", "pypi", "requests", "2.28.0")]
    [InlineData("pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21")]
    [InlineData("pkg:npm/@angular/core@15.0.0", "npm", "@angular/core", "15.0.0")]
    [InlineData("pkg:npm/%40angular/core@15.0.0", "npm", "@angular/core", "15.0.0")] // old %40 format still parses
    [InlineData("pkg:nuget/Newtonsoft.Json@13.0.3", "nuget", "Newtonsoft.Json", "13.0.3")]
    public void TryParse_ValidPurl_ReturnsComponents(string purl, string eco, string name, string version)
    {
        var result = PurlParser.TryParse(purl);
        Assert.NotNull(result);
        Assert.Equal(eco, result.Ecosystem);
        Assert.Equal(name, result.Name);
        Assert.Equal(version, result.Version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("notapurl")]
    [InlineData("pkg:pypi/requests")]         // missing version
    [InlineData("pkg:/requests@1.0")]         // missing ecosystem
    [InlineData("pkg:npmlodash@4.17.21")]     // no slash after scheme — covers slashIdx < 0
    [InlineData("pkg:")]                       // scheme only, no body — slashIdx < 0
    [InlineData("pkg:pypi")]                   // scheme + ecosystem but no slash — slashIdx < 0
    public void TryParse_InvalidPurl_ReturnsNull(string purl)
        => Assert.Null(PurlParser.TryParse(purl));

    [Fact]
    public void RoundTrip_PyPi()
    {
        string original = PurlNormalizer.PyPi("My_Package", "1.0.0");
        var parsed = PurlParser.TryParse(original);
        Assert.NotNull(parsed);
        Assert.Equal("pypi", parsed.Ecosystem);
        Assert.Equal("my-package", parsed.Name);
        Assert.Equal("1.0.0", parsed.Version);
    }

    [Fact]
    public void RoundTrip_Npm_Scoped()
    {
        string original = PurlNormalizer.Npm("@angular/core", "15.0.0");
        var parsed = PurlParser.TryParse(original);
        Assert.NotNull(parsed);
        Assert.Equal("npm", parsed.Ecosystem);
        Assert.Equal("@angular/core", parsed.Name);
        Assert.Equal("15.0.0", parsed.Version);
    }
}
