using Dependably.Infrastructure.Startup;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="InfrastructureStartupExtensions.ResolveCorsOrigin"/> — the helper
/// that resolves the management API's CORS origin from <c>BASE_URL</c> and reports whether the
/// value was missing/blank and the local dev default was substituted. The fallback flag is what
/// lets <c>AddDependablyCors</c> warn instead of silently shipping a CORS allowlist that trusts
/// <c>http://localhost:8080</c> in a deployment that simply forgot to set <c>BASE_URL</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InfrastructureStartupExtensionsCorsTests
{
    private static IConfiguration Config(string? baseUrl) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["BASE_URL"] = baseUrl })
            .Build();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ResolveCorsOrigin_MissingOrBlankBaseUrl_FallsBackAndReportsFallback(string? configured)
    {
        var (origin, isFallback) = InfrastructureStartupExtensions.ResolveCorsOrigin(Config(configured));

        // Pins the actual fix: the old code (`PublicBaseUrl() ?? DefaultBaseUrl`) had no way to
        // distinguish "operator configured localhost" from "operator forgot BASE_URL entirely" —
        // both silently produced the same origin with no signal. IsFallback restores that signal.
        Assert.Equal("http://localhost:8080", origin);
        Assert.True(isFallback);
    }

    [Theory]
    [InlineData("https://repo.example.com", "https://repo.example.com")]
    [InlineData("https://repo.example.com/", "https://repo.example.com")]
    [InlineData("http://localhost:8080", "http://localhost:8080")]
    public void ResolveCorsOrigin_ConfiguredBaseUrl_UsesItAndReportsNoFallback(string configured, string expectedOrigin)
    {
        var (origin, isFallback) = InfrastructureStartupExtensions.ResolveCorsOrigin(Config(configured));

        Assert.Equal(expectedOrigin, origin);
        Assert.False(isFallback);
    }
}
