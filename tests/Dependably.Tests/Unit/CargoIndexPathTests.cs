using Dependably.Api;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class CargoIndexPathTests
{
    [Theory]
    [InlineData("a", "1/a")]
    [InlineData("z", "1/z")]
    [InlineData("ab", "2/ab")]
    [InlineData("io", "2/io")]
    [InlineData("abc", "3/a/abc")]
    [InlineData("nom", "3/n/nom")]
    [InlineData("serde", "se/rd/serde")]
    [InlineData("tokio", "to/ki/tokio")]
    [InlineData("rand", "ra/nd/rand")]
    [InlineData("serde_json", "se/rd/serde_json")]
    [InlineData("my-crate", "my/-c/my-crate")]
    public void IndexPath_ReturnsCorrectLayout(string name, string expected)
        => Assert.Equal(expected, CargoController.IndexPath(name));

    [Fact]
    public void IndexPath_FourCharName_UsesFirstAndSecondPairs()
    {
        // 4-char: chars[0..1] / chars[2..3] / name
        Assert.Equal("ab/cd/abcd", CargoController.IndexPath("abcd"));
    }
}

[Trait("Category", "Unit")]
public class CargoPurlNormalizerTests
{
    [Theory]
    [InlineData("serde", "1.0.193", "pkg:cargo/serde@1.0.193")]
    [InlineData("tokio", "1.35.1", "pkg:cargo/tokio@1.35.1")]
    [InlineData("serde_json", "1.0.108", "pkg:cargo/serde_json@1.0.108")]
    [InlineData("my-crate", "0.1.0", "pkg:cargo/my-crate@0.1.0")]
    public void Cargo_ProducesCanonicalPurl(string name, string version, string expected)
        => Assert.Equal(expected, PurlNormalizer.Cargo(name, version));
}

[Trait("Category", "Unit")]
public class CargoPurlParserTests
{
    [Theory]
    [InlineData("pkg:cargo/serde@1.0.193", "cargo", "serde", "1.0.193")]
    [InlineData("pkg:cargo/tokio@1.35.1", "cargo", "tokio", "1.35.1")]
    [InlineData("pkg:cargo/serde_json@1.0.108", "cargo", "serde_json", "1.0.108")]
    [InlineData("pkg:cargo/my-crate@0.1.0", "cargo", "my-crate", "0.1.0")]
    public void TryParse_CargoPurl_ReturnsComponents(string purl, string eco, string name, string version)
    {
        var result = PurlParser.TryParse(purl);
        Assert.NotNull(result);
        Assert.Equal(eco, result.Ecosystem);
        Assert.Equal(name, result.Name);
        Assert.Equal(version, result.Version);
    }

    [Fact]
    public void RoundTrip_Cargo()
    {
        string original = PurlNormalizer.Cargo("serde", "1.0.193");
        var parsed = PurlParser.TryParse(original);
        Assert.NotNull(parsed);
        Assert.Equal("cargo", parsed.Ecosystem);
        Assert.Equal("serde", parsed.Name);
        Assert.Equal("1.0.193", parsed.Version);
    }
}

[Trait("Category", "Unit")]
public class CargoBlobKeysTests
{
    [Fact]
    public void Cargo_ProducesOrgScopedKey()
    {
        string key = BlobKeys.Cargo("org1", "serde", "1.0.193");
        Assert.Equal("cargo/org1/serde/1.0.193.crate", key);
    }

    [Theory]
    [InlineData("myorg", "tokio", "1.35.1", "cargo/myorg/tokio/1.35.1.crate")]
    [InlineData("org2", "serde_json", "1.0.0", "cargo/org2/serde_json/1.0.0.crate")]
    public void Cargo_IncludesCrateSuffix(string orgId, string name, string version, string expected)
        => Assert.Equal(expected, BlobKeys.Cargo(orgId, name, version));
}
