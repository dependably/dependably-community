using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

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

    [Theory]
    [InlineData("/tenants")]
    [InlineData("?x")]
    [InlineData("#frag")]
    [InlineData("https://")]
    [InlineData(":8080")]
    [InlineData("user@")]
    [InlineData(".")]
    public void ExtractHost_NoHostPortion_ReturnsNullWithoutThrowing(string value)
    {
        Assert.Null(BaseUrlHostHelper.ExtractHost(value));
    }

    [Theory]
    [InlineData("example.com.", "example.com")]
    [InlineData("https://Example.com.:8443/path", "example.com")]
    public void ExtractHost_DropsATrailingDot(string value, string expected)
    {
        Assert.Equal(expected, BaseUrlHostHelper.ExtractHost(value));
    }

    private static Microsoft.Extensions.Configuration.IConfiguration TenantDomainCfg(string? value) =>
        new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["BASE_URL"] = "https://mydomain.com",
                ["TENANT_DOMAIN"] = value,
            })
            .Build();

    [Theory]
    [InlineData(null, true)]
    [InlineData("   ", true)]
    [InlineData("example.org", true)]
    [InlineData("example.org.", true)]
    [InlineData("https://", false)]
    [InlineData(":8080", false)]
    [InlineData("?x", false)]
    [InlineData("user@", false)]
    [InlineData("/tenants", false)]
    [InlineData("localhost", false)]
    public void IsTenantDomainValueUsable_ValidatesTheExplicitValueNotTheApexFallback(string? value, bool expected)
    {
        Assert.Equal(expected, BaseUrlHostHelper.IsTenantDomainValueUsable(TenantDomainCfg(value)));
    }

    [Fact]
    public void ResolveTenantDomain_TrailingDotIsNormalizedAway()
    {
        Assert.Equal("example.org", BaseUrlHostHelper.ResolveTenantDomain(TenantDomainCfg("example.org.")));
        Assert.Equal("example.org", BaseUrlHostHelper.ResolveUsableTenantDomain(TenantDomainCfg("example.org.")));
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

    // ── ResolveApexHost / ResolveUsableApexHost: APEX_HOST overrides, BASE_URL is the default ──

    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    [Theory]
    [InlineData(null, "https://repo.example.com", "repo.example.com")]
    [InlineData("", "https://repo.example.com", "repo.example.com")]
    [InlineData("tenants.example.com", "https://repo.example.com", "tenants.example.com")]
    [InlineData("https://Tenants.Example.com:8443/", "https://repo.example.com", "tenants.example.com")]
    [InlineData("tenants.example.com", null, "tenants.example.com")]
    [InlineData(null, null, null)]
    public void ResolveApexHost_PrefersApexHostOverBaseUrl(string? apexHost, string? baseUrl, string? expected)
    {
        Assert.Equal(expected, BaseUrlHostHelper.ResolveApexHost(Cfg(("APEX_HOST", apexHost), ("BASE_URL", baseUrl))));
    }

    [Fact]
    public void ResolveUsableApexHost_LocalhostBaseUrl_ApexHostSet_ReturnsApexHost()
    {
        Assert.Equal("tenants.example.com", BaseUrlHostHelper.ResolveUsableApexHost(Cfg(
            ("APEX_HOST", "tenants.example.com"),
            ("BASE_URL", "http://localhost:8080"))));
    }

    [Fact]
    public void ResolveUsableApexHost_LocalhostApexHost_ReturnsNull()
    {
        // An explicit override wins even when it names loopback, and loopback is not an apex.
        Assert.Null(BaseUrlHostHelper.ResolveUsableApexHost(Cfg(
            ("APEX_HOST", "localhost"),
            ("BASE_URL", "https://repo.example.com"))));
    }

    // ── TENANT_DOMAIN ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("mydomain.com", "https://repo.example.com", "mydomain.com")]
    [InlineData("https://MyDomain.com:8443/", "https://repo.example.com", "mydomain.com")]
    [InlineData(null, "https://repo.example.com", "repo.example.com")]
    [InlineData("", "https://repo.example.com", "repo.example.com")]
    [InlineData("   ", "https://repo.example.com", "repo.example.com")]
    [InlineData(null, null, null)]
    public void ResolveTenantDomain_PrefersTenantDomainElseApex(string? tenantDomain, string? baseUrl, string? expected)
    {
        Assert.Equal(expected, BaseUrlHostHelper.ResolveTenantDomain(Cfg(("TENANT_DOMAIN", tenantDomain), ("BASE_URL", baseUrl))));
    }

    [Fact]
    public void ResolveTenantDomain_FallsBackToApexHostOverride_NotBaseUrl()
    {
        Assert.Equal("tenants.example.com", BaseUrlHostHelper.ResolveTenantDomain(Cfg(
            ("APEX_HOST", "tenants.example.com"), ("BASE_URL", "https://repo.example.com"))));
    }

    [Fact]
    public void ResolveUsableTenantDomain_Loopback_ReturnsNull_RealHostIsKept()
    {
        Assert.Null(BaseUrlHostHelper.ResolveUsableTenantDomain(Cfg(
            ("TENANT_DOMAIN", "localhost"), ("BASE_URL", "https://repo.example.com"))));
        Assert.Equal("mydomain.com", BaseUrlHostHelper.ResolveUsableTenantDomain(Cfg(
            ("TENANT_DOMAIN", "mydomain.com"), ("BASE_URL", "http://localhost"))));
    }

    [Theory]
    [InlineData("mydomain.com", true)]
    [InlineData("localhost", true)]
    [InlineData("", false)]
    [InlineData("  ", false)]
    [InlineData(null, false)]
    public void IsTenantDomainConfigured_TrueOnlyForNonBlank(string? value, bool expected)
    {
        Assert.Equal(expected, BaseUrlHostHelper.IsTenantDomainConfigured(Cfg(("TENANT_DOMAIN", value))));
    }

    [Theory]
    [InlineData("master.mydomain.com", "mydomain.com", "master")]
    [InlineData("a.b.mydomain.com", "mydomain.com", "b")]
    [InlineData("MASTER.MyDomain.com.", "mydomain.com", "master")]
    [InlineData("mydomain.com", "mydomain.com", null)]
    [InlineData("mydomain.com", "t.mydomain.com", null)]
    [InlineData("master.other.com", "mydomain.com", null)]
    [InlineData("xmydomain.com", "mydomain.com", null)]
    [InlineData(null, "mydomain.com", null)]
    [InlineData("master.mydomain.com", null, null)]
    public void ApexReservedLabel_IsTheLabelDirectlyBelowTheTenantDomain(string? apex, string? tenantDomain, string? expected)
    {
        Assert.Equal(expected, BaseUrlHostHelper.ApexReservedLabel(apex, tenantDomain));
    }
}
