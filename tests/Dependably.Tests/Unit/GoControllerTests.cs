using Dependably.Api;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for Go module proxy helpers: bang-encoding, PURL construction, and
/// route-suffix parsing logic that lives in static helpers.
/// </summary>
[Trait("Category", "Unit")]
public class GoControllerTests
{
    // ── DecodeBangEncoding ────────────────────────────────────────────────────

    [Theory]
    [InlineData("github.com/azure/sdk-for-go", "github.com/azure/sdk-for-go")]      // no bang
    [InlineData("github.com/!azure/sdk-for-go", "github.com/Azure/sdk-for-go")]     // single bang
    [InlineData("github.com/!a!bc/pkg", "github.com/ABc/pkg")]                      // two bangs
    [InlineData("github.com/!a!b!c/pkg", "github.com/ABC/pkg")]                     // three bangs
    [InlineData("!", "!")]                                                            // trailing bang alone
    [InlineData("!!", "!!")]                                                          // double bang, no lowercase follows
    [InlineData("!a", "A")]                                                           // single-char uppercase
    [InlineData("v!a1.2.3", "vA1.2.3")]                                              // bang in version
    [InlineData("lowercase", "lowercase")]                                            // no change needed
    public void DecodeBangEncoding_TranslatesCorrectly(string encoded, string expected)
        => Assert.Equal(expected, GoController.DecodeBangEncoding(encoded));

    [Theory]
    [InlineData("!9", "!9")]    // bang + digit — not a letter, pass through unchanged
    [InlineData("!Z", "!Z")]    // bang + uppercase — uppercase not in a-z range, pass through
    [InlineData("", "")]        // empty string
    public void DecodeBangEncoding_EdgeCases(string encoded, string expected)
        => Assert.Equal(expected, GoController.DecodeBangEncoding(encoded));

    // ── EncodeBangEncoding ────────────────────────────────────────────────────

    [Theory]
    [InlineData("github.com/azure/sdk-for-go", "github.com/azure/sdk-for-go")]      // no uppercase
    [InlineData("github.com/Azure/sdk-for-go", "github.com/!azure/sdk-for-go")]     // single uppercase
    [InlineData("github.com/ABc/pkg", "github.com/!a!bc/pkg")]                      // two uppercase
    [InlineData("ABC", "!a!b!c")]                                                    // all uppercase
    [InlineData("", "")]                                                              // empty
    public void EncodeBangEncoding_TranslatesCorrectly(string decoded, string expected)
        => Assert.Equal(expected, GoController.EncodeBangEncoding(decoded));

    // ── Round-trip ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("github.com/Azure/azure-sdk-for-go")]
    [InlineData("github.com/BurntSushi/toml")]
    [InlineData("github.com/lowercase/only")]
    [InlineData("golang.org/x/net")]
    public void BangEncoding_RoundTrip_IsIdempotent(string original)
    {
        string encoded = GoController.EncodeBangEncoding(original);
        string decoded = GoController.DecodeBangEncoding(encoded);
        Assert.Equal(original, decoded);
    }

    // ── PurlNormalizer.Golang ─────────────────────────────────────────────────

    [Theory]
    [InlineData("golang.org/x/net", "v0.10.0", "pkg:golang/golang.org/x/net@v0.10.0")]
    [InlineData("github.com/stretchr/testify", "v1.8.4", "pkg:golang/github.com/stretchr/testify@v1.8.4")]
    [InlineData("github.com/Azure/azure-sdk-for-go", "v1.0.0", "pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0")]
    [InlineData("example.com/simple", "v2.0.0+incompatible", "pkg:golang/example.com/simple@v2.0.0+incompatible")]
    public void Golang_BuildsCanonicalPurl(string module, string version, string expected)
        => Assert.Equal(expected, PurlNormalizer.Golang(module, version));

    // ── PurlParser round-trip ─────────────────────────────────────────────────

    [Theory]
    [InlineData("golang.org/x/net", "v0.10.0")]
    [InlineData("github.com/stretchr/testify", "v1.8.4")]
    public void PurlParser_RoundTrips_GolangPurl(string module, string version)
    {
        string purl = PurlNormalizer.Golang(module, version);
        var parsed = PurlParser.TryParse(purl);
        Assert.NotNull(parsed);
        Assert.Equal("golang", parsed!.Ecosystem);
        Assert.Equal(module, parsed.Name);
        Assert.Equal(version, parsed.Version);
    }

    // ── Upstream-path-segment safety (percent-encoded traversal defence) ───────

    // The module/version are composed into the upstream proxy URL via EncodeBangEncoding, which
    // passes '%' through untouched, and the /go/{**path} catch-all leaves %2F/%2E undecoded — so
    // a percent-encoded traversal would otherwise reach the upstream and be decoded to '../'
    // there. ValidateModulePath must reject any segment carrying '%' (or a raw traversal /
    // control char) before the URL is composed.
    [Theory]
    [InlineData("example.com/%2e%2e%2f%2e%2e/etc")]  // '%' in an interior segment
    [InlineData("example.com%2f..%2f..%2fetc")]      // single-segment %2f traversal
    [InlineData("github.com/a%2fb/mod")]             // '%' anywhere in the path
    [InlineData("github.com/../../etc")]             // raw traversal segment
    [InlineData("github.com/foo\u0000bar/mod")]      // null byte
    public void ValidateModulePath_RejectsUnsafeSegment(string module)
    {
        Assert.NotNull(GoController.ValidateModulePath(module));
    }

    [Theory]
    [InlineData("golang.org/x/net")]
    [InlineData("github.com/stretchr/testify")]
    [InlineData("github.com/foo/bar")]
    [InlineData("example.com/simple")]
    public void ValidateModulePath_AcceptsWellFormedModule(string module)
    {
        Assert.Null(GoController.ValidateModulePath(module));
    }

    [Theory]
    [InlineData("v1.0.0%2f%2e%2e")]  // '%' traversal smuggled into the version
    [InlineData("v1.0.0/../etc")]    // raw separator + traversal
    [InlineData("v1.0\u0000")]       // null byte
    public void UpstreamSegmentError_RejectsUnsafeVersion(string version)
    {
        Assert.NotNull(GoController.UpstreamSegmentError(version));
    }

    [Theory]
    [InlineData("v0.10.0")]
    [InlineData("v0.0.0-20231201123456-abcdef123456")]  // pseudo-version
    [InlineData("v2.0.0+incompatible")]
    public void UpstreamSegmentError_AcceptsWellFormedVersion(string version)
    {
        Assert.Null(GoController.UpstreamSegmentError(version));
    }
}
