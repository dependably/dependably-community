using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// Covers <see cref="InstanceSmtpConfig"/>'s 5-second TTL cache and explicit
/// <see cref="InstanceSmtpConfig.Invalidate"/>, mirroring
/// <c>MetricsAccessConfigTests</c>. The instance-setting reader is a stubbed dictionary so no
/// real DB is needed; time is frozen via <see cref="TestTime"/> so the TTL boundary is asserted
/// deterministically rather than by wall-clock sleep.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstanceSmtpConfigTests
{
    private static InstanceSmtpConfig Build(
        Dictionary<string, string?> db, Microsoft.Extensions.Time.Testing.FakeTimeProvider clock)
    {
        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);
        return new InstanceSmtpConfig(Reader, clock);
    }

    [Fact]
    public async Task Resolve_NoDbRows_IsUnconfiguredAndDisabled()
    {
        var clock = TestTime.Frozen();
        var sut = Build([], clock);

        var r = await sut.ResolveAsync();

        Assert.False(r.Enabled);
        Assert.False(r.Configured);
        Assert.Equal(SmtpTransportSettings.DefaultPort, r.Transport.Port);
        Assert.Equal(SmtpTransportSettings.DefaultSecurity, r.Transport.Security);
    }

    [Fact]
    public async Task Resolve_FullyConfiguredRows_IsConfiguredAndEnabled()
    {
        var clock = TestTime.Frozen();
        var db = new Dictionary<string, string?>
        {
            ["smtp_enabled"] = "1",
            ["smtp_host"] = "smtp.example.com",
            ["smtp_port"] = "465",
            ["smtp_security"] = "ssl",
            ["smtp_username"] = "user",
            ["smtp_password"] = "pass",
            ["smtp_from_address"] = "noreply@example.com",
        };
        var sut = Build(db, clock);

        var r = await sut.ResolveAsync();

        Assert.True(r.Enabled);
        Assert.True(r.Configured);
        Assert.Equal("smtp.example.com", r.Transport.Host);
        Assert.Equal(465, r.Transport.Port);
        Assert.Equal("ssl", r.Transport.Security);
        Assert.Equal("noreply@example.com", r.Transport.FromAddress);
    }

    [Fact]
    public async Task Resolve_MalformedPort_FallsBackToDefault()
    {
        var clock = TestTime.Frozen();
        var db = new Dictionary<string, string?> { ["smtp_port"] = "not-a-number" };
        var sut = Build(db, clock);

        var r = await sut.ResolveAsync();

        Assert.Equal(SmtpTransportSettings.DefaultPort, r.Transport.Port);
    }

    [Fact]
    public async Task Cache_WithinTtl_ServesStaleValueUntilInvalidatedOrExpired()
    {
        var clock = TestTime.Frozen();
        var db = new Dictionary<string, string?> { ["smtp_enabled"] = "1" };
        var sut = Build(db, clock);

        var first = await sut.ResolveAsync();
        Assert.True(first.Enabled);

        // Mutate the underlying "DB" after the initial resolve, well within the 5s TTL.
        db["smtp_enabled"] = "0";
        var stillCached = await sut.ResolveAsync();
        Assert.True(stillCached.Enabled);
    }

    [Fact]
    public async Task Invalidate_ForcesImmediateRefresh_NoClockAdvanceNeeded()
    {
        var clock = TestTime.Frozen();
        var db = new Dictionary<string, string?> { ["smtp_enabled"] = "1" };
        var sut = Build(db, clock);

        var first = await sut.ResolveAsync();
        Assert.True(first.Enabled);

        db["smtp_enabled"] = "0";
        sut.Invalidate();

        var refreshed = await sut.ResolveAsync();
        Assert.False(refreshed.Enabled);
    }

    [Fact]
    public async Task Cache_PastTtl_RefreshesWithoutExplicitInvalidate()
    {
        var clock = TestTime.Frozen();
        var db = new Dictionary<string, string?> { ["smtp_enabled"] = "1" };
        var sut = Build(db, clock);

        var first = await sut.ResolveAsync();
        Assert.True(first.Enabled);

        db["smtp_enabled"] = "0";

        // Advance well clear of the 5s TTL boundary (seeded far from the edge per project
        // convention: no seeds landing exactly at a cutoff).
        clock.Advance(TimeSpan.FromSeconds(9));

        var refreshed = await sut.ResolveAsync();
        Assert.False(refreshed.Enabled);
    }

    [Fact]
    public async Task InvalidateThatRacesAnInFlightFill_DoesNotRepublishThePreUpdateTransport()
    {
        // Fill-after-invalidate race: an alert-send begins ResolveAsync on a cold cache and reads
        // the pre-update (enabled) SMTP transport; concurrently an operator disables SMTP via PUT,
        // whose commit + Invalidate lands mid-fill. On the pre-guard code the fill republishes the
        // stale enabled transport over the invalidation, so alert mail keeps flowing through a
        // channel the operator just turned off for the 5s TTL.
        //
        // The reader fires the racing Invalidate exactly once, after the generation snapshot and
        // before the fill publishes. Time is frozen so the TTL cannot mask the bug: fails on the
        // old code, passes on the guard.
        var clock = TestTime.Frozen();
        var backing = new Dictionary<string, string?> { ["smtp_enabled"] = "1" };

        bool raced = false;
        InstanceSmtpConfig sut = null!;
        Task<string?> Reader(string key, CancellationToken _)
        {
            if (key == "smtp_enabled" && !raced)
            {
                raced = true;
                sut.Invalidate(); // the racing PUT's invalidation, landing mid-fill
            }

            return Task.FromResult(backing.TryGetValue(key, out string? v) ? v : null);
        }

        sut = new InstanceSmtpConfig(Reader, clock);

        var first = await sut.ResolveAsync();
        Assert.True(first.Enabled); // legitimately read the pre-update state

        // The operator's disable is now the source of truth.
        backing["smtp_enabled"] = "0";

        // Killer assertion: the next resolve must observe the disable, not a stale enabled
        // transport republished by the racing fill's post-invalidate write.
        var second = await sut.ResolveAsync();
        Assert.False(second.Enabled);
    }
}
