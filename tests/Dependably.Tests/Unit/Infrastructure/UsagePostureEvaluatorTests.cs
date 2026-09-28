using Dependably.Infrastructure.Usage;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="UsagePostureEvaluator"/>'s thresholds, each pinned at its exact boundary: 100 % of any
/// capped meter refuses uploads, 110 % of a capped egress meter throttles downloads, and an org
/// with no caps is never enforced however much it uses.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsagePostureEvaluatorTests
{
    private static Dictionary<string, long> Caps(params (string Meter, long Cap)[] caps) =>
        caps.ToDictionary(c => c.Meter, c => c.Cap, StringComparer.Ordinal);

    private static UsageMeasurements Usage(string meter, long quantity) => meter switch
    {
        UsageCapMeters.EgressBytes => UsageMeasurements.None with { EgressBytes = quantity },
        UsageCapMeters.EgressMetadataBytes => UsageMeasurements.None with { EgressMetadataBytes = quantity },
        UsageCapMeters.StorageBytes => UsageMeasurements.None with { StorageBytes = quantity },
        UsageCapMeters.ArtifactCount => UsageMeasurements.None with { ArtifactCount = quantity },
        _ => throw new ArgumentOutOfRangeException(nameof(meter)),
    };

    [Fact]
    public void No_caps_is_normal_however_much_is_used()
    {
        var heavy = new UsageMeasurements(long.MaxValue, long.MaxValue, long.MaxValue, long.MaxValue);

        Assert.Equal(UsagePostures.Normal, UsagePostureEvaluator.Evaluate(Caps(), heavy));
    }

    [Theory]
    [InlineData(UsageCapMeters.EgressBytes)]
    [InlineData(UsageCapMeters.EgressMetadataBytes)]
    [InlineData(UsageCapMeters.StorageBytes)]
    [InlineData(UsageCapMeters.ArtifactCount)]
    public void One_below_the_cap_is_normal(string meter)
    {
        Assert.Equal(UsagePostures.Normal, UsagePostureEvaluator.Evaluate(Caps((meter, 1000)), Usage(meter, 999)));
    }

    [Theory]
    [InlineData(UsageCapMeters.EgressBytes)]
    [InlineData(UsageCapMeters.EgressMetadataBytes)]
    [InlineData(UsageCapMeters.StorageBytes)]
    [InlineData(UsageCapMeters.ArtifactCount)]
    public void Exactly_the_cap_refuses_uploads(string meter)
    {
        Assert.Equal(UsagePostures.UploadsRefused, UsagePostureEvaluator.Evaluate(Caps((meter, 1000)), Usage(meter, 1000)));
    }

    [Theory]
    [InlineData(UsageCapMeters.EgressBytes)]
    [InlineData(UsageCapMeters.EgressMetadataBytes)]
    public void One_below_110_percent_of_an_egress_cap_refuses_uploads_only(string meter)
    {
        Assert.Equal(UsagePostures.UploadsRefused, UsagePostureEvaluator.Evaluate(Caps((meter, 1000)), Usage(meter, 1099)));
    }

    [Theory]
    [InlineData(UsageCapMeters.EgressBytes)]
    [InlineData(UsageCapMeters.EgressMetadataBytes)]
    public void Exactly_110_percent_of_an_egress_cap_throttles_downloads(string meter)
    {
        Assert.Equal(UsagePostures.DownloadsThrottled, UsagePostureEvaluator.Evaluate(Caps((meter, 1000)), Usage(meter, 1100)));
    }

    [Fact]
    public void The_110_percent_boundary_is_exact_for_a_cap_that_does_not_divide_by_ten()
    {
        // 110 % of 7 is 7.7, so 7 is under it and 8 is over it. Integer division would read both as 7.
        Assert.Equal(UsagePostures.UploadsRefused, UsagePostureEvaluator.Evaluate(Caps((UsageCapMeters.EgressBytes, 7)), Usage(UsageCapMeters.EgressBytes, 7)));
        Assert.Equal(UsagePostures.DownloadsThrottled, UsagePostureEvaluator.Evaluate(Caps((UsageCapMeters.EgressBytes, 7)), Usage(UsageCapMeters.EgressBytes, 8)));
    }

    [Theory]
    [InlineData(UsageCapMeters.StorageBytes)]
    [InlineData(UsageCapMeters.ArtifactCount)]
    public void Storage_and_artifact_overage_never_throttles(string meter)
    {
        Assert.Equal(UsagePostures.UploadsRefused, UsagePostureEvaluator.Evaluate(Caps((meter, 1000)), Usage(meter, 5000)));
    }

    [Fact]
    public void Any_capped_meter_over_its_cap_decides_even_when_the_others_are_under()
    {
        var caps = Caps(
            (UsageCapMeters.EgressBytes, 1000),
            (UsageCapMeters.StorageBytes, 1000),
            (UsageCapMeters.ArtifactCount, 10));
        var usage = new UsageMeasurements(EgressBytes: 10, EgressMetadataBytes: 0, StorageBytes: 10, ArtifactCount: 10);

        Assert.Equal(UsagePostures.UploadsRefused, UsagePostureEvaluator.Evaluate(caps, usage));
    }

    [Fact]
    public void Throttling_wins_over_an_upload_refusal_on_another_meter()
    {
        var caps = Caps((UsageCapMeters.StorageBytes, 1000), (UsageCapMeters.EgressMetadataBytes, 1000));
        var usage = new UsageMeasurements(EgressBytes: 0, EgressMetadataBytes: 2000, StorageBytes: 1000, ArtifactCount: 0);

        Assert.Equal(UsagePostures.DownloadsThrottled, UsagePostureEvaluator.Evaluate(caps, usage));
    }

    [Fact]
    public void An_uncapped_meter_is_ignored_however_much_it_is_used()
    {
        var caps = Caps((UsageCapMeters.StorageBytes, 1000));
        var usage = new UsageMeasurements(EgressBytes: long.MaxValue, EgressMetadataBytes: 0, StorageBytes: 1, ArtifactCount: 0);

        Assert.Equal(UsagePostures.Normal, UsagePostureEvaluator.Evaluate(caps, usage));
    }

    [Fact]
    public void A_cap_near_the_long_limit_does_not_overflow()
    {
        long cap = long.MaxValue - 1;

        Assert.Equal(UsagePostures.Normal, UsagePostureEvaluator.Evaluate(Caps((UsageCapMeters.EgressBytes, cap)), Usage(UsageCapMeters.EgressBytes, cap - 1)));
        Assert.Equal(UsagePostures.UploadsRefused, UsagePostureEvaluator.Evaluate(Caps((UsageCapMeters.EgressBytes, cap)), Usage(UsageCapMeters.EgressBytes, long.MaxValue)));
    }

    [Fact]
    public void An_unknown_meter_or_a_non_positive_cap_is_ignored()
    {
        var caps = Caps(("requests", 1), (UsageCapMeters.EgressBytes, 0));

        Assert.Equal(UsagePostures.Normal, UsagePostureEvaluator.Evaluate(caps, Usage(UsageCapMeters.EgressBytes, 50)));
    }

    [Theory]
    [InlineData(UsagePostures.Normal, false)]
    [InlineData(UsagePostures.UploadsRefused, true)]
    [InlineData(UsagePostures.DownloadsThrottled, true)]
    [InlineData(null, false)]
    public void Both_enforced_postures_refuse_uploads(string? posture, bool refused)
    {
        Assert.Equal(refused, UsagePostures.RefusesUploads(posture));
    }
}
