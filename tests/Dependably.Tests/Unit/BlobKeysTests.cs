using Dependably.Storage;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class BlobKeysTests
{
    // ---- Proxy ----
    [Fact]
    public void Proxy_Golden_ReturnsProxyPrefixedKey()
    {
        var key = BlobKeys.Proxy("abc123");
        Assert.Equal("proxy/abc123", key);
    }

    [Fact]
    public void Proxy_EmptySha_StillBuildsKey()
    {
        // BlobKeys is a pure string-builder; it does not validate input.
        Assert.Equal("proxy/", BlobKeys.Proxy(""));
    }

    [Theory]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")] // sha256 hex
    [InlineData("UPPERCASEHEX0123")]
    [InlineData("with-dashes_and.dots")]
    public void Proxy_PreservesShaVerbatim(string sha)
    {
        Assert.Equal($"proxy/{sha}", BlobKeys.Proxy(sha));
    }

    // ---- Hosted ----
    [Fact]
    public void Hosted_Golden_BuildsFiveSegmentKey()
    {
        var key = BlobKeys.Hosted("acme", "npm", "lodash", "4.17.21", "lodash-4.17.21.tgz");
        Assert.Equal("hosted/acme/npm/lodash/4.17.21/lodash-4.17.21.tgz", key);
    }

    [Theory]
    [InlineData("org", "pypi", "requests", "2.28.0", "requests-2.28.0.tar.gz")]
    [InlineData("o", "nuget", "Newtonsoft.Json", "13.0.1", "newtonsoft.json.13.0.1.nupkg")]
    [InlineData("ACME-Co", "npm", "@scope/pkg", "1.0.0-beta.1+build.7", "pkg-1.0.0-beta.1+build.7.tgz")]
    public void Hosted_PreservesAllSegmentsVerbatim(
        string orgId, string ecosystem, string purlName, string version, string filename)
    {
        var key = BlobKeys.Hosted(orgId, ecosystem, purlName, version, filename);
        Assert.Equal($"hosted/{orgId}/{ecosystem}/{purlName}/{version}/{filename}", key);
    }

    [Fact]
    public void Hosted_UnicodeAndSpecialCharsArePassthrough()
    {
        // Pure string composition — no sanitization happens here.
        var key = BlobKeys.Hosted("orñ", "npm", "pâckage", "1.0.0+ünicode", "f%20.tgz");
        Assert.Equal("hosted/orñ/npm/pâckage/1.0.0+ünicode/f%20.tgz", key);
    }

    [Fact]
    public void Hosted_VeryLongName_BuildsExpectedKey()
    {
        var longName = new string('a', 512);
        var key = BlobKeys.Hosted("org", "npm", longName, "1.0.0", "file.tgz");
        Assert.Equal($"hosted/org/npm/{longName}/1.0.0/file.tgz", key);
    }

    [Fact]
    public void Hosted_EmptySegments_StillBuildsKey()
    {
        // No validation — empty pieces produce consecutive slashes.
        var key = BlobKeys.Hosted("", "", "", "", "");
        Assert.Equal("hosted/////", key);
    }

    // ---- StoreKey ----
    // Covers both branches of the compound condition: parts.Length == 3 && parts[0] == "proxy"

    [Fact]
    public void StoreKey_ProxyDbKeyWithFilename_StripsSuffix()
    {
        // 3 parts AND first segment is "proxy" → both conditions true → strip filename.
        var store = BlobKeys.StoreKey("proxy/abc123/lodash-4.17.21.tgz");
        Assert.Equal("proxy/abc123", store);
    }

    [Fact]
    public void StoreKey_ProxyKeyWithoutFilename_ReturnedUnchanged()
    {
        // 2 parts → Length == 3 is false → return unchanged.
        var store = BlobKeys.StoreKey("proxy/abc123");
        Assert.Equal("proxy/abc123", store);
    }

    [Fact]
    public void StoreKey_ThreePartKeyButNotProxy_ReturnedUnchanged()
    {
        // 3 parts but first segment != "proxy" → second condition false → return unchanged.
        // This is the critical branch that exercises the right-hand side of the && short-circuit.
        var store = BlobKeys.StoreKey("hosted/org/file");
        Assert.Equal("hosted/org/file", store);
    }

    [Fact]
    public void StoreKey_HostedKey_ReturnedUnchanged()
    {
        // 6 parts — Length != 3 → return unchanged.
        var input = "hosted/acme/npm/lodash/4.17.21/lodash-4.17.21.tgz";
        Assert.Equal(input, BlobKeys.StoreKey(input));
    }

    [Fact]
    public void StoreKey_SingleSegment_ReturnedUnchanged()
    {
        // 1 part → Length != 3 → return unchanged.
        Assert.Equal("loose", BlobKeys.StoreKey("loose"));
    }

    [Fact]
    public void StoreKey_EmptyString_ReturnedUnchanged()
    {
        // Split("") → ["" ] (length 1) → return unchanged.
        Assert.Equal("", BlobKeys.StoreKey(""));
    }

    [Fact]
    public void StoreKey_ProxyCaseSensitive_NonLowercaseNotStripped()
    {
        // 3 parts but first segment is "Proxy" (capital) — string compare is case-sensitive.
        var store = BlobKeys.StoreKey("Proxy/abc123/file.tgz");
        Assert.Equal("Proxy/abc123/file.tgz", store);
    }

    [Fact]
    public void StoreKey_FourPartProxyKey_ReturnedUnchanged()
    {
        // Length == 4 → first condition false → return unchanged even though it starts with proxy.
        var input = "proxy/abc123/sub/file.tgz";
        Assert.Equal(input, BlobKeys.StoreKey(input));
    }

    [Fact]
    public void Proxy_RoundTripsThroughStoreKey()
    {
        // The output of Proxy() has only 2 segments, so StoreKey leaves it untouched.
        var k = BlobKeys.Proxy("deadbeef");
        Assert.Equal(k, BlobKeys.StoreKey(k));
    }
}
