using Dependably.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class OciOptionsValidatorTests
{
    private static readonly OciOptionsValidator Validator = new();

    private static OciOptions ValidOptions() => new()
    {
        ManifestTagTtl = TimeSpan.FromMinutes(5),
        TokenCacheDuration = TimeSpan.FromMinutes(55),
        UpstreamHttpTimeout = TimeSpan.FromMinutes(30),
    };

    [Fact]
    public void Validate_DefaultValidConfig_Succeeds()
    {
        var result = Validator.Validate(null, ValidOptions());
        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_NonPositiveTimeSpans_Fail(int seconds)
    {
        var span = TimeSpan.FromSeconds(seconds);
        var opts = ValidOptions();
        opts.ManifestTagTtl = span;
        opts.TokenCacheDuration = span;
        opts.UpstreamHttpTimeout = span;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:ManifestTagTtl must be positive.", result.Failures!);
        Assert.Contains("Oci:TokenCacheDuration must be positive.", result.Failures!);
        Assert.Contains("Oci:UpstreamHttpTimeout must be positive.", result.Failures!);
    }
}
