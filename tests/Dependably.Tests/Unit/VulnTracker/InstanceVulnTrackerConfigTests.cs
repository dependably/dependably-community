using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The resolver behind the one instance-level tracker connection: what it reads, what it does
/// with a row that is absent or corrupt, and that a save is visible immediately rather than after
/// the cache TTL. Time is frozen so the TTL assertions pin exact behaviour rather than a
/// tolerance.
/// </summary>
public sealed class InstanceVulnTrackerConfigTests
{
    private static InstanceVulnTrackerConfig Build(
        Dictionary<string, string?> rows,
        Microsoft.Extensions.Time.Testing.FakeTimeProvider time,
        Action? onRead = null)
        => new(
            (key, _) =>
            {
                onRead?.Invoke();
                return Task.FromResult(rows.TryGetValue(key, out string? v) ? v : null);
            },
            time);

    [Fact]
    public async Task Absent_rows_resolve_to_off_and_unconfigured()
    {
        var config = Build([], TestTime.Frozen());

        var resolved = await config.ResolveAsync();

        Assert.False(resolved.Enabled);
        Assert.False(resolved.Configured);
        Assert.False(resolved.IsActive);
        Assert.Null(resolved.Connection.BaseUrl);
        Assert.Null(resolved.Connection.Token);
        Assert.Equal(VulnTrackerSettings.DefaultMaxStalenessHours, resolved.Connection.MaxStalenessHours);
        Assert.Equal(VulnTrackerSettings.DefaultBatchSize, resolved.Connection.BatchSize);
    }

    [Fact]
    public async Task A_complete_row_set_resolves_active()
    {
        var config = Build(new()
        {
            ["vuln_tracker_enabled"] = "1",
            ["vuln_tracker_base_url"] = "https://tracker.example.com",
            ["vuln_tracker_token"] = "osvst_secret",
            ["vuln_tracker_max_staleness_hours"] = "48",
            ["vuln_tracker_batch_size"] = "250",
        }, TestTime.Frozen());

        var resolved = await config.ResolveAsync();

        Assert.True(resolved.Enabled);
        Assert.True(resolved.Configured);
        Assert.True(resolved.IsActive);
        Assert.Equal("https://tracker.example.com", resolved.Connection.BaseUrl);
        Assert.Equal("osvst_secret", resolved.Connection.Token);
        Assert.Equal(48, resolved.Connection.MaxStalenessHours);
        Assert.Equal(250, resolved.Connection.BatchSize);
    }

    [Fact]
    public async Task Enabled_without_a_base_url_is_not_active()
    {
        // Intent alone must not be enough. A half-filled row that reported active would put the
        // scan path into a state where it believes it has a tracker and every request fails.
        var config = Build(new() { ["vuln_tracker_enabled"] = "1" }, TestTime.Frozen());

        var resolved = await config.ResolveAsync();

        Assert.True(resolved.Enabled);
        Assert.False(resolved.Configured);
        Assert.False(resolved.IsActive);
    }

    [Fact]
    public async Task A_configured_connection_that_is_switched_off_is_not_active()
    {
        // The adversarial twin of the previous test: completeness alone must not be enough
        // either, or the enabled flag would be decorative and pausing enrichment would require
        // discarding the connection.
        var config = Build(new()
        {
            ["vuln_tracker_enabled"] = "0",
            ["vuln_tracker_base_url"] = "https://tracker.example.com",
        }, TestTime.Frozen());

        var resolved = await config.ResolveAsync();

        Assert.False(resolved.Enabled);
        Assert.True(resolved.Configured);
        Assert.False(resolved.IsActive);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("not-a-number")]
    [InlineData("99999999")]
    [InlineData("")]
    public async Task An_unusable_stored_number_falls_back_to_the_default_rather_than_being_trusted(string raw)
    {
        // These two values bound a security decision and an outbound request size. A hand-edited
        // or corrupted row carrying 0 would otherwise disable the staleness horizon, or send an
        // empty batch every pass — both of which look like working software.
        var config = Build(new()
        {
            ["vuln_tracker_base_url"] = "https://tracker.example.com",
            ["vuln_tracker_max_staleness_hours"] = raw,
            ["vuln_tracker_batch_size"] = raw,
        }, TestTime.Frozen());

        var resolved = await config.ResolveAsync();

        Assert.Equal(VulnTrackerSettings.DefaultMaxStalenessHours, resolved.Connection.MaxStalenessHours);
        Assert.Equal(VulnTrackerSettings.DefaultBatchSize, resolved.Connection.BatchSize);
    }

    [Fact]
    public async Task A_malformed_base_url_resolves_unconfigured_rather_than_being_dialed()
    {
        var config = Build(new()
        {
            ["vuln_tracker_enabled"] = "1",
            ["vuln_tracker_base_url"] = "file:///etc/passwd",
        }, TestTime.Frozen());

        var resolved = await config.ResolveAsync();

        Assert.False(resolved.Configured);
        Assert.False(resolved.IsActive);
    }

    [Fact]
    public async Task Repeated_reads_inside_the_ttl_hit_the_cache()
    {
        int reads = 0;
        var time = TestTime.Frozen();
        var config = Build(new() { ["vuln_tracker_base_url"] = "https://tracker.example.com" }, time, () => reads++);

        await config.ResolveAsync();
        int afterFirst = reads;
        await config.ResolveAsync();
        await config.ResolveAsync();

        Assert.Equal(afterFirst, reads);
    }

    [Fact]
    public async Task A_read_past_the_ttl_re_reads_the_store()
    {
        int reads = 0;
        var time = TestTime.Frozen();
        var config = Build(new() { ["vuln_tracker_base_url"] = "https://tracker.example.com" }, time, () => reads++);

        await config.ResolveAsync();
        int afterFirst = reads;

        time.Advance(TimeSpan.FromSeconds(6));
        await config.ResolveAsync();

        Assert.True(reads > afterFirst);
    }

    [Fact]
    public async Task Invalidate_makes_a_save_visible_without_waiting_out_the_ttl()
    {
        var rows = new Dictionary<string, string?> { ["vuln_tracker_base_url"] = "https://old.example.com" };
        var time = TestTime.Frozen();
        var config = Build(rows, time);

        Assert.Equal("https://old.example.com", (await config.ResolveAsync()).Connection.BaseUrl);

        rows["vuln_tracker_base_url"] = "https://new.example.com";

        // Without Invalidate the cached value is still served — the twin that proves the
        // invalidation below is doing the work rather than the TTL having quietly expired.
        Assert.Equal("https://old.example.com", (await config.ResolveAsync()).Connection.BaseUrl);

        config.Invalidate();

        Assert.Equal("https://new.example.com", (await config.ResolveAsync()).Connection.BaseUrl);
    }
}
