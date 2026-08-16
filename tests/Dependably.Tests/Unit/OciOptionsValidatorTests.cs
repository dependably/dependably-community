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
        opts.ManifestTagStaleGrace = span;
        opts.TokenCacheDuration = span;
        opts.UpstreamHttpTimeout = span;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:ManifestTagTtl must be positive.", result.Failures!);
        Assert.Contains("Oci:ManifestTagStaleGrace must be positive.", result.Failures!);
        Assert.Contains("Oci:TokenCacheDuration must be positive.", result.Failures!);
        Assert.Contains("Oci:UpstreamHttpTimeout must be positive.", result.Failures!);
    }

    [Fact]
    public void Defaults_TtlIsOneHour_StaleGraceIsTwentyFourHours()
    {
        // The three-policy model's instance-level halves: hourly revalidation cadence and a
        // 24-hour bounded stale-serving window. Promotion age (min_release_age_hours) is
        // per-org and deliberately absent from this options object.
        var opts = new OciOptions();
        Assert.Equal(TimeSpan.FromHours(1), opts.ManifestTagTtl);
        Assert.Equal(TimeSpan.FromHours(24), opts.ManifestTagStaleGrace);
    }
}
