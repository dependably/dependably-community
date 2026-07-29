using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Security")]
public class PathSafeValidatorTests
{
    [Theory]
    [InlineData("../etc/passwd")]
    [InlineData("foo/../bar")]
    [InlineData("../../etc")]
    public void Validate_PathTraversal_Fails(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("foo/bar")]
    [InlineData("foo\\bar")]
    public void Validate_PathSeparator_Fails(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_NullByte_Fails()
    {
        var result = PathSafeValidator.Validate("foo\0bar", "field");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_Empty_Fails()
    {
        var result = PathSafeValidator.Validate("", "field");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_TooLong_Fails()
    {
        var result = PathSafeValidator.Validate(new string('a', 201), "field");
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("requests")]
    [InlineData("my-package")]
    [InlineData("lodash")]
    [InlineData("Newtonsoft.Json")]
    [InlineData("1.0.0")]
    [InlineData("2.1.0-beta.1")]
    public void Validate_ValidInputs_Passes(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");
        Assert.True(result.IsValid);
    }
}

[Trait("Category", "Security")]
public class HeaderInjectionTests
{
    [Fact]
    public void SanitizeHeader_StripsCRLF()
    {
        const string purl = "pkg:pypi/requests@2.28.0\r\nX-Injected: evil";
        string sanitized = SanitizeHeader(purl);
        // CRLF stripped — injection cannot create a separate HTTP header
        Assert.DoesNotContain('\r', sanitized);
        Assert.DoesNotContain('\n', sanitized);
    }

    [Fact]
    public void SanitizeHeader_StripsNullByte()
    {
        const string purl = "pkg:pypi/requests@2.28.0\0extra";
        string sanitized = SanitizeHeader(purl);
        Assert.DoesNotContain('\0', sanitized);
    }

    [Fact]
    public void SanitizeHeader_LeavesValidPurlUnchanged()
    {
        const string purl = "pkg:npm/%40angular/core@15.0.0";
        Assert.Equal(purl, SanitizeHeader(purl));
    }

    // Replicates the SanitizeHeader method from controllers
    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

[Trait("Category", "Security")]
public class UpstreamUrlValidatorTests
{
    [Theory]
    [InlineData("http://127.0.0.1/packages")]
    [InlineData("http://127.0.0.100/packages")]
    [InlineData("http://10.0.0.1/packages")]
    [InlineData("http://172.16.0.1/packages")]
    [InlineData("http://172.31.255.255/packages")]
    [InlineData("http://192.168.1.1/packages")]
    [InlineData("http://169.254.169.254/metadata")]  // AWS metadata endpoint
    [InlineData("http://100.64.0.1/packages")]
    public void ValidateUrl_BlockedIp_ReturnsError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("ftp://pypi.org/packages")]
    [InlineData("file:///etc/passwd")]
    [InlineData("not-a-url")]
    public void ValidateUrl_InvalidSchemeOrFormat_ReturnsError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("https://pypi.org")]
    [InlineData("https://registry.npmjs.org")]
    [InlineData("https://api.nuget.org/v3")]
    [InlineData("http://my-private-registry.example.com")]
    public void ValidateUrl_PublicUrl_ReturnsNull(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.Null(error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void ValidateUrl_NullOrWhitespace_ReturnsEmptyError(string? url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.Equal("Upstream URL must not be empty.", error);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/plain,hello")]
    [InlineData("gopher://example.com")]
    [InlineData("ws://example.com")]
    public void ValidateUrl_NonHttpScheme_ReturnsSchemeError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.Equal("Only http:// and https:// schemes are accepted.", error);
    }

    [Theory]
    [InlineData("relative/path")]
    [InlineData("http://")]
    [InlineData(":::not a uri:::")]
    public void ValidateUrl_MalformedUri_ReturnsFormatError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.Equal("Invalid URL format.", error);
    }

    // #437 item 2: an upstream URL embedding user:pass@ credentials must be rejected at save
    // time. Storing it plaintext in upstream_registry.url leaks the credential to any
    // read:packages caller through the per-version projection (unlike the encrypted secret column).
    [Theory]
    [InlineData("https://svc:s3cr3t@nexus.corp.example/repository/npm/")]
    [InlineData("https://user@nexus.corp.example/repository/npm/")]
    [InlineData("http://svc:pw@mirror.example.com/pypi/simple/")]
    public void ValidateUrl_EmbeddedCredentials_ReturnsError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
        Assert.Contains("must not embed credentials", error);
    }

    // #437 item 2: legacy rows written before the save-time gate can still hold userinfo, so the
    // projection strips it. Adversarial twins: a credential-free URL and a non-URL pass through
    // unchanged so the redaction never mangles a legitimate value.
    [Fact]
    public void StripCredentials_RemovesUserInfo_PreservesCleanValues()
    {
        Assert.Equal(
            "https://nexus.corp.example/repository/npm/",
            UpstreamUrlValidator.StripCredentials("https://svc:s3cr3t@nexus.corp.example/repository/npm/"));

        // No userinfo — returned verbatim.
        Assert.Equal(
            "https://registry.npmjs.org/left-pad",
            UpstreamUrlValidator.StripCredentials("https://registry.npmjs.org/left-pad"));

        // Not parseable as absolute — returned verbatim, never crashes.
        Assert.Equal("not-a-url", UpstreamUrlValidator.StripCredentials("not-a-url"));
        Assert.Null(UpstreamUrlValidator.StripCredentials(null));
    }

    [Theory]
    [InlineData("http://[::1]/packages")]            // IPv6 loopback
    [InlineData("http://[fc00::1]/packages")]        // IPv6 unique-local
    [InlineData("http://[fe80::1]/packages")]        // IPv6 link-local
    public void ValidateUrl_BlockedIpv6_ReturnsBlockedError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
        Assert.StartsWith("Upstream URL resolves to a blocked IP range", error);
    }

    [Theory]
    [InlineData("http://[2606:4700:4700::1111]/packages")]   // Cloudflare DNS — public IPv6
    [InlineData("http://8.8.8.8/packages")]                  // Public IPv4 literal
    public void ValidateUrl_PublicIpLiteral_ReturnsNull(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.Null(error);
    }

    // Reserved / special-use ranges beyond the basic RFC 1918 set — all must be blocked
    // at save time when supplied as IP literals so that a tenant cannot register an upstream
    // pointing at a documentation test-net, Class E, or broadcast address.
    [Theory]
    [InlineData("http://0.0.0.1/packages")]             // 0/8 "this host" — kernel routes to loopback
    [InlineData("http://0.255.255.255/packages")]        // 0/8 upper bound
    [InlineData("http://192.0.0.1/packages")]            // 192.0.0.0/24 IETF protocol assignments
    [InlineData("http://192.0.2.100/packages")]          // 192.0.2.0/24 TEST-NET-1 (documentation)
    [InlineData("http://198.18.0.1/packages")]           // 198.18.0.0/15 benchmarking
    [InlineData("http://198.51.100.1/packages")]         // 198.51.100.0/24 TEST-NET-2 (documentation)
    [InlineData("http://203.0.113.1/packages")]          // 203.0.113.0/24 TEST-NET-3 (documentation)
    [InlineData("http://240.0.0.1/packages")]            // 240.0.0.0/4 reserved / Class E
    [InlineData("http://255.255.255.255/packages")]      // limited broadcast
    public void ValidateUrl_ReservedRange_ReturnsBlockedError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
        Assert.StartsWith("Upstream URL resolves to a blocked IP range", error);
    }

    // IPv4-mapped IPv6 forms must not bypass the block — ::ffff:a.b.c.d collapses to the
    // underlying IPv4 address before the range check, so a mapped loopback or RFC 1918
    // address is indistinguishable from its plain IPv4 form.
    [Theory]
    [InlineData("http://[::ffff:127.0.0.1]/packages")]      // IPv4-mapped loopback
    [InlineData("http://[::ffff:169.254.169.254]/packages")] // IPv4-mapped cloud metadata
    [InlineData("http://[::ffff:10.0.0.1]/packages")]        // IPv4-mapped RFC 1918
    [InlineData("http://[::ffff:192.168.1.1]/packages")]     // IPv4-mapped RFC 1918
    [InlineData("http://[::ffff:0.0.0.1]/packages")]         // IPv4-mapped "this host" range
    public void ValidateUrl_Ipv4MappedBlockedIpv6_ReturnsBlockedError(string url)
    {
        string? error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
        Assert.StartsWith("Upstream URL resolves to a blocked IP range", error);
    }

    // Mixed partial-failure scenario: a batch of upstream URL candidates where some are
    // valid and some are blocked — each is validated independently and the outcome for one
    // must not affect the outcome for another.
    [Fact]
    public void ValidateUrl_MixedBatch_BlockedAndAllowedUrlsBehaveCorrectly()
    {
        var cases = new (string Url, bool ShouldBlock)[]
        {
            ("https://pypi.org",                                false),
            ("http://10.0.0.1/packages",                        true),
            ("https://registry.npmjs.org",                      false),
            ("http://169.254.169.254/metadata",                 true),
            ("http://[::ffff:127.0.0.1]/packages",              true),
            ("https://api.nuget.org/v3",                        false),
            ("http://240.0.0.1/packages",                       true),
            ("http://[2606:4700:4700::1111]/packages",          false),
        };

        var failures = cases
            .Select(c => (c.Url, c.ShouldBlock, Error: UpstreamUrlValidator.ValidateUrl(c.Url)))
            .Where(r => r.ShouldBlock != (r.Error is not null))
            .Select(r => $"{r.Url}: expected blocked={r.ShouldBlock}, got error={(r.Error ?? "null")}")
            .ToList();

        Assert.Empty(failures);
    }
}
