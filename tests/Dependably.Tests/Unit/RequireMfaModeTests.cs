using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class RequireMfaModeTests
{
    private static RequireMfaMode Build(string? value)
    {
        var dict = new Dictionary<string, string?> { ["REQUIRE_MFA"] = value };
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
        return new RequireMfaMode(cfg);
    }

    // ── IsEnabled ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("true")]
    [InlineData("True")]
    [InlineData("TRUE")]
    [InlineData("1")]
    public void TrueValues_Enabled(string v) => Assert.True(Build(v).IsEnabled);

    [Theory]
    [InlineData("false")]
    [InlineData("0")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("yes")]
    [InlineData("on")]
    public void FalseOrUnknownValues_NotEnabled(string? v) => Assert.False(Build(v).IsEnabled);
}
