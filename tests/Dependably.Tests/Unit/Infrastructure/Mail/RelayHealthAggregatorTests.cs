using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// <see cref="RelayHealthAggregator"/>: the operator's aggregate view of the shared SMTP relay
/// across every org's <c>alert_settings</c> health columns, plus the durable outbox's backlog.
/// Every case here pins the aggregate's arithmetic directly — no controller, no HTTP — so a
/// regression in the SQL surfaces at the narrowest possible layer.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RelayHealthAggregatorTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES ('org1', 'acme'), ('org2', 'globex'), ('org3', 'initech')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static EnvelopeProtector MakeProtector()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(key)
            })
            .Build();
        return new EnvelopeProtector(new EnvFileMasterKeyProvider(config));
    }

    private RelayHealthAggregator MakeAggregator() =>
        new(_db, new EmailOutboxRepository(_db, _clock));

    private static Task<AlertSettings> EnableEmailAsync(
        AlertSettingsRepository settings, string orgId, string recipients = "a@example.com") =>
        settings.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: recipients));

    [Fact]
    public async Task NoOrgHasFailed_ReportsHealthy()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, _clock);
        await EnableEmailAsync(settings, "org1");
        await settings.RecordEmailSuccessAsync("org1");

        var health = await MakeAggregator().GetAsync();

        Assert.False(health.Unhealthy);
        Assert.Equal(0, health.AffectedTenants);
        Assert.Equal(0, health.ConsecutiveFailures);
        Assert.Null(health.FirstFailureAt);
    }

    [Fact]
    public async Task NoAlertSettingsRowExists_ReportsHealthy()
    {
        // A fresh install with no org ever having saved alert settings — the aggregate must not
        // throw on an empty table, and must read as healthy rather than as an error state.
        var health = await MakeAggregator().GetAsync();

        Assert.False(health.Unhealthy);
        Assert.Equal(0, health.AffectedTenants);
        Assert.Equal(0, health.BacklogDepth);
        Assert.Equal(0, health.DeadLettered);
    }

    /// <summary>
    /// The load-bearing case from the issue's own example: several tenants failing at once must
    /// aggregate into one relay-wide signal — the count of affected tenants, the worst
    /// consecutive-failure streak among them, and the earliest onset time across all of them.
    /// </summary>
    [Fact]
    public async Task MultipleOrgsFailing_AggregatesAcrossAllOfThem()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, _clock);
        await EnableEmailAsync(settings, "org1");
        await EnableEmailAsync(settings, "org2");
        await EnableEmailAsync(settings, "org3");

        // org1 fails first (earliest failing_since), and racks up the deepest streak.
        await settings.RecordEmailFailureAsync("org1", "relay refused connection");
        _clock.Advance(TimeSpan.FromMinutes(5));
        await settings.RecordEmailFailureAsync("org2", "relay timed out");
        _clock.Advance(TimeSpan.FromMinutes(5));
        await settings.RecordEmailFailureAsync("org1", "relay refused connection");
        await settings.RecordEmailFailureAsync("org1", "relay refused connection");
        // org3 stays healthy throughout.
        await settings.RecordEmailSuccessAsync("org3");

        var health = await MakeAggregator().GetAsync();

        Assert.True(health.Unhealthy);
        Assert.Equal(2, health.AffectedTenants);
        Assert.Equal(3, health.ConsecutiveFailures); // org1's streak, the deepest of the two failing orgs.
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.FirstFailureAt); // org1's first failure, the earliest.
    }

    /// <summary>
    /// A channel that is currently disabled must not count as "affected" even if its historical
    /// last_status is 'failed' from before it was turned off — an operator fixing the relay should
    /// not chase a tenant that isn't even sending right now.
    /// </summary>
    [Fact]
    public async Task DisabledChannel_WithStaleFailedStatus_IsNotCountedAsAffected()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, _clock);
        await EnableEmailAsync(settings, "org1");
        await settings.RecordEmailFailureAsync("org1", "relay refused connection");

        // Disable the channel directly — RecordEmailFailureAsync deliberately never does this
        // itself, so a subsequent config save (or, here, a direct disable for the fixture) is the
        // only way a "failed" row also has email_enabled = 0.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE alert_settings SET email_enabled = 0 WHERE org_id = 'org1'");
        }

        var health = await MakeAggregator().GetAsync();

        Assert.False(health.Unhealthy);
        Assert.Equal(0, health.AffectedTenants);
    }

    /// <summary>
    /// A successful recovery must drop the recovered org out of the aggregate immediately — the
    /// relay-health surface reads current state, not history.
    /// </summary>
    [Fact]
    public async Task OneOrgRecovers_DropsOutOfTheAggregate()
    {
        using var ep = MakeProtector();
        var settings = new AlertSettingsRepository(_db, ep, _clock);
        await EnableEmailAsync(settings, "org1");
        await EnableEmailAsync(settings, "org2");

        await settings.RecordEmailFailureAsync("org1", "err");
        await settings.RecordEmailFailureAsync("org2", "err");
        await settings.RecordEmailSuccessAsync("org1");

        var health = await MakeAggregator().GetAsync();

        Assert.True(health.Unhealthy);
        Assert.Equal(1, health.AffectedTenants);
    }

    [Fact]
    public async Task Backlog_ReadsDepthOldestAndDeadLetterCount_IncludingNullOrgOperatorRows()
    {
        var outbox = new EmailOutboxRepository(_db, _clock);
        var policy = new EmailOutboxPolicy(new ConfigurationBuilder().Build());

        // A per-org alert message.
        await outbox.TryEnqueueAsync(
            new NewEmailOutboxMessage("org1", EmailOutboxMessageKinds.Alert, "coalesce-1", "alert-1",
                ["a@example.com"], "subj", "body"),
            policy);

        // An operator-scope message with a NULL org_id — the shape #532 introduced specifically so
        // system_admin mail has a home in the same table; SQL NULL semantics mean this row must
        // still be counted by a bare COUNT(*), which does not filter it out the way an org_id
        // equality predicate silently would.
        _clock.Advance(TimeSpan.FromSeconds(1));
        await outbox.TryEnqueueAsync(
            new NewEmailOutboxMessage(null, EmailOutboxMessageKinds.Invite, "coalesce-2", null,
                ["b@example.com"], "subj2", "body2"),
            policy);

        var health = await MakeAggregator().GetAsync();

        Assert.Equal(2, health.BacklogDepth);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.OldestQueuedAt);
        Assert.Equal(0, health.DeadLettered);
    }

    [Fact]
    public async Task Backlog_CountsDeadLetteredAndExpired_SeparatelyFromNonTerminalDepth()
    {
        var outbox = new EmailOutboxRepository(_db, _clock);
        var policy = new EmailOutboxPolicy(new ConfigurationBuilder().Build());

        await outbox.TryEnqueueAsync(
            new NewEmailOutboxMessage("org1", EmailOutboxMessageKinds.Alert, "coalesce-1", "alert-1",
                ["a@example.com"], "subj", "body"),
            policy);
        var claimed = await outbox.ClaimDueAsync(10);
        await outbox.MarkDeadLetterAsync(claimed[0].Id, EmailOutboxFailureClasses.Permanent, "bad recipient");

        // A second, still-pending row keeps the non-terminal depth from being conflated with the
        // dead-letter count.
        await outbox.TryEnqueueAsync(
            new NewEmailOutboxMessage("org1", EmailOutboxMessageKinds.Alert, "coalesce-3", "alert-2",
                ["a@example.com"], "subj3", "body3"),
            policy);

        var health = await MakeAggregator().GetAsync();

        Assert.Equal(1, health.BacklogDepth);
        Assert.Equal(1, health.DeadLettered);
    }
}
