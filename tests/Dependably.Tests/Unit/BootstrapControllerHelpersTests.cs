using Dependably.Api;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class BootstrapControllerHelpersTests
{
    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    // ── ResolveMode ───────────────────────────────────────────────────────────

    [Fact]
    public void ResolveMode_Missing_DefaultsToSingle()
    {
        Assert.Equal("single", BootstrapController.ResolveMode(Cfg()));
    }

    [Theory]
    [InlineData("multi", "multi")]
    [InlineData("MULTI", "multi")]
    [InlineData(" multi ", "multi")]
    [InlineData("header", "multi")]
    [InlineData("HEADER", "multi")]
    [InlineData(" header ", "multi")]
    [InlineData("single", "single")]
    [InlineData("anything-else", "single")]
    [InlineData("", "single")]
    public void ResolveMode_NormalizesAndDefaultsConservatively(string input, string expected)
    {
        Assert.Equal(expected, BootstrapController.ResolveMode(Cfg(("DEPLOYMENT_MODE", input))));
    }

    // ── ResolveApexHost ───────────────────────────────────────────────────────
    // The apex hostname is derived solely from BASE_URL (host portion only).
    // APEX_HOST is no longer read; these tests cover the BASE_URL derivation paths.

    [Fact]
    public void ResolveApexHost_DerivesHostFromFullBaseUrl()
    {
        string? apex = BootstrapController.ResolveApexHost(Cfg(
            ("BASE_URL", "https://apex.example.com")));
        Assert.Equal("apex.example.com", apex);
    }

    [Fact]
    public void ResolveApexHost_StripsPortFromBaseUrl()
    {
        string? apex = BootstrapController.ResolveApexHost(Cfg(("BASE_URL", "https://APEX.example.com:8443/")));
        Assert.Equal("apex.example.com", apex);
    }

    [Fact]
    public void ResolveApexHost_Missing_ReturnsNull()
    {
        Assert.Null(BootstrapController.ResolveApexHost(Cfg()));
    }

    [Fact]
    public void ResolveApexHost_SchemeOnlyBaseUrl_ReturnsNull()
    {
        // No host component to extract once the scheme is stripped.
        Assert.Null(BootstrapController.ResolveApexHost(Cfg(("BASE_URL", "http://"))));
    }

    [Fact]
    public void ResolveApexHost_BareHostname_IsPreserved()
    {
        // A scheme-less single-label host is legitimate (e.g. a Docker service name);
        // BASE_URL host extraction preserves it rather than rejecting it.
        string? apex = BootstrapController.ResolveApexHost(Cfg(("BASE_URL", "dependably")));
        Assert.Equal("dependably", apex);
    }

    [Fact]
    public void ResolveApexHost_BaseUrlOnly_NoApexHostKey()
    {
        // BASE_URL is the single source of truth; APEX_HOST is not consulted.
        string? apex = BootstrapController.ResolveApexHost(Cfg(
            ("BASE_URL", "https://real.example.com")));
        Assert.Equal("real.example.com", apex);
    }
}
