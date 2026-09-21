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

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(1024)]
    public void Validate_BlobProxyCapBelowTheFloor_Fails(long bytes)
    {
        // A floor rather than a positivity check: a cap below one layer's worth of bytes is a
        // blob proxy that refuses every real image, and without this it fails at pull time on
        // the operator's users instead of at startup. 1024 covers the likeliest typo — a value
        // meant as MiB or GiB written as bytes.
        var opts = ValidOptions();
        opts.MaxBlobProxyBytes = bytes;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("Oci:MaxBlobProxyBytes", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_BlobProxyCapAtTheFloor_Succeeds()
    {
        // The twin for the theory above: without it, a validator that rejected every value
        // would pass the failure cases and still be wrong.
        var opts = ValidOptions();
        opts.MaxBlobProxyBytes = 1024L * 1024;

        Assert.True(Validator.Validate(null, opts).Succeeded);
    }

    [Fact]
    public void Defaults_BlobProxyCapClearsTypicalMlImageLayers()
    {
        // The default has to clear the layer sizes that motivated making it configurable at all:
        // a CUDA/ML base image ships single layers several GB wide, which the shared 600 MB
        // upstream constant refused outright. Asserted as a floor, not an equality, so the
        // number can be tuned without a test edit — what must not regress is that the default
        // is in the right order of magnitude.
        var opts = new OciOptions();
        Assert.True(opts.MaxBlobProxyBytes >= 8L * 1024 * 1024 * 1024,
            $"default MaxBlobProxyBytes {opts.MaxBlobProxyBytes} is too small for real image layers");
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
