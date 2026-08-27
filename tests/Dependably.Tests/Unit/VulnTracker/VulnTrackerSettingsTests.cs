using Dependably.Infrastructure.VulnTracker;
using Xunit;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The base-URL parser and the write-surface validator for the one instance-level
/// vulnerability-tracker connection. The scheme check is an allowlist rather than a denylist, so
/// these tests pin that a scheme the code has never seen fails closed rather than being waved
/// through as "not one of the bad ones".
/// </summary>
public sealed class VulnTrackerSettingsTests
{
    [Theory]
    [InlineData("https://tracker.example.com")]
    [InlineData("https://tracker.example.com/")]
    [InlineData("http://tracker.internal:8000")]
    [InlineData("  https://tracker.example.com  ")]
    public void TryParseBaseUrl_accepts_absolute_http_urls(string value)
    {
        Assert.True(VulnTrackerSettings.TryParseBaseUrl(value, out var uri));
        Assert.NotNull(uri);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("tracker.example.com")]          // no scheme — relative, not absolute
    [InlineData("/lookup")]                       // path only
    [InlineData("file:///etc/passwd")]            // non-HTTP scheme
    [InlineData("ftp://tracker.example.com")]
    [InlineData("gopher://tracker.example.com")]
    [InlineData("javascript:alert(1)")]
    public void TryParseBaseUrl_rejects_everything_that_is_not_an_absolute_http_url(string? value)
    {
        Assert.False(VulnTrackerSettings.TryParseBaseUrl(value, out var uri));
        Assert.Null(uri);
    }

    [Fact]
    public void IsConfigured_tracks_the_base_url_only()
    {
        // A tracker that needs a credential answers 401, which the client treats as unreached —
        // so a missing token degrades to "no enrichment", never to "enrichment says fine". That
        // is why the token is deliberately not part of this predicate.
        var withoutToken = new VulnTrackerSettings("https://tracker.example.com", null, 168, 100);
        Assert.True(withoutToken.IsConfigured);

        var withoutUrl = new VulnTrackerSettings(null, "osvst_secret", 168, 100);
        Assert.False(withoutUrl.IsConfigured);
    }

    [Fact]
    public void Validate_accepts_a_complete_valid_request()
    {
        var (field, key) = VulnTrackerSettings.Validate("https://tracker.example.com", 168, 100);
        Assert.Null(field);
        Assert.Null(key);
    }

    [Fact]
    public void Validate_accepts_an_empty_base_url_because_that_is_how_the_feature_is_turned_off()
    {
        var (field, _) = VulnTrackerSettings.Validate("", 168, 100);
        Assert.Null(field);
    }

    [Fact]
    public void Validate_rejects_a_malformed_base_url()
    {
        var (field, key) = VulnTrackerSettings.Validate("not-a-url", 168, 100);
        Assert.Equal("baseUrl", field);
        Assert.Equal("error.vulnTracker.invalidBaseUrl", key);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(VulnTrackerSettings.MaxStalenessHoursCeiling + 1)]
    public void Validate_rejects_an_out_of_range_staleness_horizon(int hours)
    {
        // Zero and negatives matter beyond tidiness: the horizon bounds a security decision, and
        // a stored 0 would make every enrichment instantly stale, or — read the other way — turn
        // the horizon off entirely.
        var (field, key) = VulnTrackerSettings.Validate("https://tracker.example.com", hours, 100);
        Assert.Equal("maxStalenessHours", field);
        Assert.Equal("error.vulnTracker.invalidStaleness", key);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(VulnTrackerSettings.MaxBatchSize + 1)]
    public void Validate_rejects_a_batch_size_the_producer_would_refuse(int size)
    {
        // Storing a size over the producer's published cap would make every pass fail at request
        // time; refusing it at save time turns a recurring runtime failure into one 422.
        var (field, key) = VulnTrackerSettings.Validate("https://tracker.example.com", 168, size);
        Assert.Equal("batchSize", field);
        Assert.Equal("error.vulnTracker.invalidBatchSize", key);
    }

    [Fact]
    public void Validate_reports_the_base_url_first_when_several_fields_are_invalid()
    {
        var (field, _) = VulnTrackerSettings.Validate("not-a-url", 0, 0);
        Assert.Equal("baseUrl", field);
    }

    [Fact]
    public void Validate_accepts_both_bounds_of_each_range()
    {
        Assert.Null(VulnTrackerSettings.Validate("https://t.example.com", 1, 1).Field);
        Assert.Null(VulnTrackerSettings.Validate(
            "https://t.example.com",
            VulnTrackerSettings.MaxStalenessHoursCeiling,
            VulnTrackerSettings.MaxBatchSize).Field);
    }
}
