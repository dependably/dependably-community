using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Webhooks;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Integration;

/// <summary>
/// The three delivery-failure counters (webhook subscription, Slack, alert email) are incremented
/// by the database and read back with <c>UPDATE … RETURNING</c>, so the value a caller acts on is
/// the one its own increment produced rather than a copy read a statement earlier.
///
/// Every other test of those counters runs against SQLite — which is the one provider where the
/// concurrency they defend against cannot occur, because a file-backed deployment runs a single
/// writer process. Multiple replicas recording failures for the same org at the same time is a
/// Postgres-only topology, so the provider this fix is aimed at was the one its SQL never executed
/// on. These run the real statements against a live server: they prove the syntax, the
/// <c>RETURNING</c> projection, and the int-to-long materialisation of the returned tuple all work
/// on Npgsql, none of which SQLite can vouch for.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class NotificationFailureCounterPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private const string OrgId = "o1";

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

    [Fact]
    public async Task Failure_counters_increment_and_report_their_own_value_on_live_postgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, 'acme')", new { id = OrgId });
        }

        var clock = TestTime.Frozen();
        using var ep = MakeProtector();

        // The assertions read the columns with plain scalar SQL rather than through the
        // repositories' row projections. Those projections declare every integer column as
        // long — correct for SQLite, which returns INTEGER as Int64, and unmaterialisable on
        // Postgres, where the same column is int4. That is a pre-existing defect on the read
        // path, untouched by the counters under test here, and routing around it keeps this test
        // about the statements it is meant to cover.
        var webhooks = new WebhookSubscriptionRepository(store, ep, clock);
        string subId = Guid.NewGuid().ToString("N");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO webhook_subscription
                    (id, org_id, url, event_types, enabled, created_at, updated_at)
                VALUES
                    (@subId, @orgId, 'https://hooks.example.com/hook', '["package.publish"]', 1,
                     '2026-06-15T12:00:00Z', '2026-06-15T12:00:00Z')
                """,
                new { subId, orgId = OrgId });
        }

        const int threshold = 3;
        var duration = TimeSpan.FromHours(48);

        // ── webhook subscription ─────────────────────────────────────────────
        Assert.False(await webhooks.RecordFailureAsync(OrgId, subId, "502", threshold, duration));
        Assert.Equal(1, await WebhookFailuresAsync(store, subId));

        Assert.False(await webhooks.RecordFailureAsync(OrgId, subId, "502", threshold, duration));
        Assert.Equal(2, await WebhookFailuresAsync(store, subId));

        // The third failure is the one whose own increment lands on the threshold, so it is the
        // one that reports the auto-disable — and the follow-up statement disables the row.
        Assert.True(await webhooks.RecordFailureAsync(OrgId, subId, "502", threshold, duration));
        Assert.Equal(3, await WebhookFailuresAsync(store, subId));
        Assert.Equal(0, await ScalarAsync(store,
            "SELECT enabled FROM webhook_subscription WHERE id = @subId", new { subId }));
        Assert.NotNull(await TextAsync(store,
            "SELECT failing_since FROM webhook_subscription WHERE id = @subId", new { subId }));

        // A success resets the streak, so the counter is genuinely relative to what is stored.
        await webhooks.RecordSuccessAsync(OrgId, subId);
        Assert.Equal(0, await WebhookFailuresAsync(store, subId));

        // ── Slack ────────────────────────────────────────────────────────────
        var settings = new AlertSettingsRepository(store, ep, clock);
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO alert_settings (org_id, slack_enabled, email_enabled, email_recipients)
                VALUES (@orgId, 1, 1, 'ops@example.com')
                """,
                new { orgId = OrgId });
        }

        Assert.False(await settings.RecordSlackFailureAsync(OrgId, "502", threshold, duration));
        Assert.Equal(1, await ScalarAsync(store,
            "SELECT slack_consecutive_failures FROM alert_settings WHERE org_id = @orgId", new { orgId = OrgId }));

        Assert.False(await settings.RecordSlackFailureAsync(OrgId, "502", threshold, duration));
        Assert.True(await settings.RecordSlackFailureAsync(OrgId, "502", threshold, duration));

        Assert.Equal(3, await ScalarAsync(store,
            "SELECT slack_consecutive_failures FROM alert_settings WHERE org_id = @orgId", new { orgId = OrgId }));
        Assert.Equal(0, await ScalarAsync(store,
            "SELECT slack_enabled FROM alert_settings WHERE org_id = @orgId", new { orgId = OrgId }));

        // ── alert email: same increment, and deliberately no auto-disable ─────
        for (int i = 0; i < 5; i++)
        {
            await settings.RecordEmailFailureAsync(OrgId, "relay refused");
        }

        Assert.Equal(5, await ScalarAsync(store,
            "SELECT email_consecutive_failures FROM alert_settings WHERE org_id = @orgId", new { orgId = OrgId }));
        Assert.Equal(1, await ScalarAsync(store,
            "SELECT email_enabled FROM alert_settings WHERE org_id = @orgId", new { orgId = OrgId }));
    }

    private static Task<long> WebhookFailuresAsync(IMetadataStore store, string subId) =>
        ScalarAsync(store, "SELECT consecutive_failures FROM webhook_subscription WHERE id = @subId", new { subId });

    private static async Task<long> ScalarAsync(IMetadataStore store, string sql, object args)
    {
        await using var conn = await store.OpenAsync();
        return Convert.ToInt64(await conn.ExecuteScalarAsync<object>(sql, args));
    }

    private static async Task<string?> TextAsync(IMetadataStore store, string sql, object args)
    {
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(sql, args);
    }
}
