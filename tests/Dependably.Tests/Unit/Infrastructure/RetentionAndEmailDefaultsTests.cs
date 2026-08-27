using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Two small resolvers whose whole value is the edge case each one refuses to get wrong: an
/// activity-retention override that must never resolve to "forever", and an email fold that has to
/// agree with the SQL <c>lower()</c> every account lookup uses.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionAndEmailDefaultsTests
{
    private static IConfiguration Config(string? activityRetentionDays) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(activityRetentionDays is null
                ? []
                : new Dictionary<string, string?> { ["ACTIVITY_RETENTION_DAYS"] = activityRetentionDays })
            .Build();

    [Fact]
    public void ActivityRetention_HonoursAPositiveOverride()
    {
        Assert.Equal(7, RetentionDefaults.ResolveActivityRetentionDays(Config("7")));
        Assert.Equal(3650, RetentionDefaults.ResolveActivityRetentionDays(Config("3650")));
    }

    [Theory]
    [InlineData(null)]            // no config object at all
    [InlineData("")]              // set but empty
    [InlineData("0")]             // non-positive
    [InlineData("-1")]
    [InlineData("forever")]       // unparseable
    [InlineData("9.5")]
    public void ActivityRetention_FallsBackRatherThanUnbounding(string? configured)
    {
        // The load-bearing case: activity rows carry per-download IP and actor data, so a
        // misconfigured override must land on the default bound, never disable the bound.
        var config = configured is null ? null : Config(configured);

        Assert.Equal(
            RetentionDefaults.ActivityRetentionDays,
            RetentionDefaults.ResolveActivityRetentionDays(config));
    }

    [Fact]
    public void ActivityRetention_DefaultMatchesTheSchemaColumnDefault()
    {
        Assert.Equal(90, RetentionDefaults.ActivityRetentionDays);
    }

    [Theory]
    [InlineData("Owner@Corp.COM", "owner@corp.com")]
    [InlineData("  spaced@example.test  ", "spaced@example.test")]
    [InlineData("already@lower.test", "already@lower.test")]
    [InlineData("MiXeD.Local+Tag@Example.Test", "mixed.local+tag@example.test")]
    public void EmailNormalizer_FoldsCaseAndTrims(string input, string expected)
    {
        Assert.Equal(expected, EmailNormalizer.Normalize(input));
    }

    [Fact]
    public void EmailNormalizer_LeavesTheAddressOtherwiseIntact()
    {
        // Deliberately NOT plus-address or dot stripping: those route to different mailboxes at
        // some providers, and SQL lower() does not do it either.
        Assert.Equal("a.b+tag@example.test", EmailNormalizer.Normalize("A.B+Tag@Example.Test"));
    }

    [Fact]
    public void EmailNormalizer_PassesNullThroughForOptionalAddresses()
    {
        Assert.Null(EmailNormalizer.Normalize(null));
        Assert.Equal(string.Empty, EmailNormalizer.Normalize("   "));
    }
}
