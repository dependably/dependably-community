using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="BaseUrlHostHelper"/> — the single source of truth for deriving
/// the apex hostname from <c>BASE_URL</c>. Covers absolute URIs, port stripping,
/// localhost detection, and the predicate used by host-header filtering and startup warnings.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BaseUrlHostHelperTests
{
    // ── ExtractHost ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://localhost", "localhost")]
    [InlineData("http://localhost:8080", "localhost")]
    [InlineData("https://dependably.example.com", "dependably.example.com")]
    [InlineData("https://repo.example.test:8443/", "repo.example.test")]
    [InlineData("https://REPO.Example.TEST", "repo.example.test")]
    [InlineData("https://repo.example.test:8443/some/path", "repo.example.test")]
    public void ExtractHost_AbsoluteUri_ReturnsHostLowercase(string baseUrl, string expectedHost)
    {
        Assert.Equal(expectedHost, BaseUrlHostHelper.ExtractHost(baseUrl));
    }

    [Theory]
    [InlineData("example.com:8080", "example.com")]
    [InlineData("dependably.example.com", "dependably.example.com")]
    [InlineData("repo.example.test:8443/some/path", "repo.example.test")]
    [InlineData("http://[::1]:8080", "[::1]")]
    [InlineData("[::1]:8080", "[::1]")]
    public void ExtractHost_SchemeLessOrIpv6_ReturnsHost(string baseUrl, string expectedHost)
    {
        Assert.Equal(expectedHost, BaseUrlHostHelper.ExtractHost(baseUrl));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExtractHost_NullOrEmpty_ReturnsNull(string? baseUrl)
    {
        Assert.Null(BaseUrlHostHelper.ExtractHost(baseUrl));
    }

    // ── IsUsableApexHost ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://repo.example.com")]
    [InlineData("https://dependably.northwardlabs.ca")]
    [InlineData("https://repo.example.test:8443/")]
    [InlineData("dependably.example.com")]
    [InlineData("repo.example.test:8443")]
    public void IsUsableApexHost_NonLocalhostHost_ReturnsTrue(string baseUrl)
    {
        Assert.True(BaseUrlHostHelper.IsUsableApexHost(baseUrl));
    }

    [Theory]
    [InlineData("http://localhost")]
    [InlineData("http://localhost:8080")]
    [InlineData("http://127.0.0.1")]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("http://[::1]")]
    [InlineData("localhost:8080")]
    [InlineData("[::1]:8080")]
    public void IsUsableApexHost_LocalhostVariants_ReturnsFalse(string baseUrl)
    {
        Assert.False(BaseUrlHostHelper.IsUsableApexHost(baseUrl));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsUsableApexHost_NullOrEmpty_ReturnsFalse(string? baseUrl)
    {
        Assert.False(BaseUrlHostHelper.IsUsableApexHost(baseUrl));
    }

    // ── Mixed partial-failure: batch of inputs, some yield a host, some do not ──

    [Fact]
    public void ExtractHost_MixedInputs_ProducesCorrectHostsPerInput()
    {
        // Exercises all main parsing branches in a single table-driven pass: absolute URIs,
        // scheme-less host:port, bare hostname, IPv6 literal, and null/empty inputs.
        var cases = new (string? input, string? expected)[]
        {
            ("https://apex.example.com", "apex.example.com"),
            ("https://apex.example.com:8443/", "apex.example.com"),
            ("http://localhost:8080", "localhost"),
            ("example.com:8080", "example.com"),
            ("dependably.example.com", "dependably.example.com"),
            ("http://[::1]:8080", "[::1]"),
            (null, null),
            ("", null),
            ("   ", null),
        };

        var failures = new List<string>();
        foreach (var (input, expected) in cases)
        {
            string? actual = BaseUrlHostHelper.ExtractHost(input);
            if (actual != expected)
            {
                failures.Add($"input='{input}' expected='{expected}' actual='{actual}'");
            }
        }

        Assert.Empty(failures);
    }
}
