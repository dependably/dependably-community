using Dependably.Infrastructure.Usage;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="DefaultUsageCaps"/>: parsing <c>DEFAULT_USAGE_CAPS</c> (every malformed shape fails
/// rather than running uncapped), its multi-tenant-only scope, and the merge of an org's explicit
/// caps over the defaults.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DefaultUsageCapsTests
{
    private static IConfiguration Config(string? mode, string? defaults)
    {
        var values = new Dictionary<string, string?>();
        if (mode is not null)
        {
            values["DEPLOYMENT_MODE"] = mode;
        }

        if (defaults is not null)
        {
            values[DefaultUsageCaps.ConfigKey] = defaults;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static Dictionary<string, long> Caps(params (string Meter, long Cap)[] caps) =>
        caps.ToDictionary(c => c.Meter, c => c.Cap, StringComparer.Ordinal);

    // ── Parsing ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Parses_every_meter_with_surrounding_whitespace()
    {
        var parsed = DefaultUsageCaps.Parse(
            " egress_bytes=500000000000 , egress_metadata_bytes = 1000,storage_bytes=2000,artifact_count=9223372036854775807 ");

        Assert.True(parsed.Any);
        Assert.Equal(4, parsed.Caps.Count);
        Assert.Equal(500_000_000_000, parsed.Caps[UsageCapMeters.EgressBytes]);
        Assert.Equal(1000, parsed.Caps[UsageCapMeters.EgressMetadataBytes]);
        Assert.Equal(2000, parsed.Caps[UsageCapMeters.StorageBytes]);
        Assert.Equal(long.MaxValue, parsed.Caps[UsageCapMeters.ArtifactCount]);
    }

    [Fact]
    public void Parses_a_subset_of_meters()
    {
        var parsed = DefaultUsageCaps.Parse("artifact_count=10");

        Assert.Equal(10, Assert.Single(parsed.Caps, c => c.Key == UsageCapMeters.ArtifactCount).Value);
        Assert.Single(parsed.Caps);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Unset_or_empty_is_no_defaults(string? raw)
    {
        var parsed = DefaultUsageCaps.Parse(raw);

        Assert.False(parsed.Any);
        Assert.Empty(parsed.Caps);
    }

    [Theory]
    [InlineData("requests=10", "requests=10")]
    [InlineData("cache_storage_bytes=10", "cache_storage_bytes=10")]
    [InlineData("EGRESS_BYTES=10", "EGRESS_BYTES=10")]
    [InlineData("egress_bytes=0", "egress_bytes=0")]
    [InlineData("egress_bytes=-5", "egress_bytes=-5")]
    [InlineData("egress_bytes=1.5", "egress_bytes=1.5")]
    [InlineData("egress_bytes=1e9", "egress_bytes=1e9")]
    [InlineData("egress_bytes=+10", "egress_bytes=+10")]
    [InlineData("egress_bytes=1_000", "egress_bytes=1_000")]
    [InlineData("egress_bytes=abc", "egress_bytes=abc")]
    [InlineData("egress_bytes=", "egress_bytes=")]
    [InlineData("egress_bytes=9223372036854775808", "egress_bytes=9223372036854775808")]
    [InlineData("egress_bytes", "egress_bytes")]
    [InlineData("=10", "=10")]
    [InlineData("egress_bytes=10,storage_bytes=20,egress_bytes=30", "egress_bytes=30")]
    [InlineData("egress_bytes=10,,storage_bytes=20", "")]
    [InlineData("egress_bytes=10,", "")]
    [InlineData("egress_bytes=10;storage_bytes=20", "egress_bytes=10;storage_bytes=20")]
    public void Each_invalid_shape_fails_naming_the_token_and_the_valid_meters(string raw, string badToken)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => DefaultUsageCaps.Parse(raw));

        Assert.Contains(DefaultUsageCaps.ConfigKey, ex.Message);
        Assert.Contains($"token '{badToken}'", ex.Message);
        foreach (string meter in UsageCapMeters.All)
        {
            Assert.Contains(meter, ex.Message);
        }
    }

    // ── Scope ────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("multi")]
    [InlineData("header")]
    [InlineData(" Multi ")]
    public void Multi_tenant_modes_read_the_setting(string mode)
    {
        var parsed = DefaultUsageCaps.FromConfiguration(Config(mode, "storage_bytes=100"));

        Assert.Equal(100, parsed.Caps[UsageCapMeters.StorageBytes]);
    }

    [Fact]
    public void Multi_tenant_mode_with_the_setting_unset_has_no_defaults()
    {
        Assert.Same(DefaultUsageCaps.None, DefaultUsageCaps.FromConfiguration(Config("multi", null)));
    }

    [Fact]
    public void Multi_tenant_mode_with_a_malformed_setting_fails()
    {
        Assert.Throws<InvalidOperationException>(
            () => DefaultUsageCaps.FromConfiguration(Config("multi", "storage_bytes=lots")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("single")]
    [InlineData("edge")]
    public void Other_modes_ignore_the_setting(string? mode)
    {
        Assert.Same(DefaultUsageCaps.None, DefaultUsageCaps.FromConfiguration(Config(mode, "storage_bytes=100")));
    }

    // ── Effective caps ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void An_org_with_no_explicit_caps_inherits_every_default()
    {
        var defaults = DefaultUsageCaps.Parse("egress_bytes=1000,artifact_count=10");

        var effective = defaults.Effective(Caps());

        Assert.Equal(2, effective.Count);
        Assert.Equal(1000, effective[UsageCapMeters.EgressBytes]);
        Assert.Equal(10, effective[UsageCapMeters.ArtifactCount]);
    }

    [Fact]
    public void An_explicit_cap_wins_over_the_default_whether_lower_or_higher()
    {
        var defaults = DefaultUsageCaps.Parse("egress_bytes=1000,storage_bytes=5000,artifact_count=10");

        var effective = defaults.Effective(Caps(
            (UsageCapMeters.EgressBytes, 10),
            (UsageCapMeters.StorageBytes, long.MaxValue)));

        Assert.Equal(3, effective.Count);
        Assert.Equal(10, effective[UsageCapMeters.EgressBytes]);
        Assert.Equal(long.MaxValue, effective[UsageCapMeters.StorageBytes]);
        Assert.Equal(10, effective[UsageCapMeters.ArtifactCount]);
    }

    [Fact]
    public void An_explicit_cap_on_a_meter_without_a_default_is_kept()
    {
        var defaults = DefaultUsageCaps.Parse("egress_bytes=1000");

        var effective = defaults.Effective(Caps((UsageCapMeters.EgressMetadataBytes, 7)));

        Assert.Equal(1000, effective[UsageCapMeters.EgressBytes]);
        Assert.Equal(7, effective[UsageCapMeters.EgressMetadataBytes]);
    }

    [Fact]
    public void No_defaults_leaves_the_explicit_caps_as_they_are()
    {
        var explicitCaps = Caps((UsageCapMeters.EgressBytes, 10));

        Assert.Same(explicitCaps, DefaultUsageCaps.None.Effective(explicitCaps));
        Assert.Empty(DefaultUsageCaps.None.Effective(Caps()));
    }
}
