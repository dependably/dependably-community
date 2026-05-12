using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class AirGapModeTests
{
    private static AirGapMode Build(string? value)
    {
        var dict = new Dictionary<string, string?> { ["AIR_GAPPED"] = value };
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
        return new AirGapMode(cfg);
    }

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
    [InlineData("yes")]      // only the documented values count as on
    [InlineData("on")]
    public void FalseOrUnknownValues_NotEnabled(string? v) => Assert.False(Build(v).IsEnabled);
}
