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

    [Fact]
    public void ResolveApexHost_PrefersApexHostOverBaseUrl()
    {
        string? apex = BootstrapController.ResolveApexHost(Cfg(
            ("APEX_HOST", "Apex.Example.Com"),
            ("BASE_URL", "https://other.example.com")));
        Assert.Equal("apex.example.com", apex);
    }

    [Fact]
    public void ResolveApexHost_FallsBackToBaseUrlHost()
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
    public void ResolveApexHost_MalformedBaseUrl_ReturnsNull()
    {
        Assert.Null(BootstrapController.ResolveApexHost(Cfg(("BASE_URL", "not-a-url"))));
    }

    [Fact]
    public void ResolveApexHost_BlankApexHost_FallsThroughToBaseUrl()
    {
        string? apex = BootstrapController.ResolveApexHost(Cfg(
            ("APEX_HOST", "   "),
            ("BASE_URL", "https://fallback.example.com")));
        Assert.Equal("fallback.example.com", apex);
    }
}
