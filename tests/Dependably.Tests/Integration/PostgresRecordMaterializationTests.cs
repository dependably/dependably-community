using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Infrastructure.Privacy;
using Dependably.Infrastructure.Webhooks;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Postgres and SQLite hand Dapper different CLR types for the same declared column, and a
/// positional record binds by exact constructor signature — so a projection written against one
/// provider's types throws <c>InvalidOperationException ("A parameterless default constructor or
/// one matching signature ... is required")</c> on the other, at runtime, on first read. SQLite
/// reports every INTEGER as <c>Int64</c>; Postgres reports INTEGER as <c>Int32</c> (int4).
///
/// The SQLite-only suite cannot see this class of defect at all: the projections it exercises
/// are correct for SQLite by construction. This test drives the real repository read methods
/// against a live Postgres server, so the materialization actually happens, and asserts the
/// seeded values rather than "did not throw" — a column that silently binds to its default
/// (Dapper's converting path fills an unmatched constructor parameter with <c>default</c>) fails
/// here too.
///
/// Deliberately covers the integer-bearing projections on the tenant-facing delivery paths —
/// webhooks, Slack/email alert settings, the alert-raise gate, and the email outbox — plus the
/// "me" projection, the GDPR export, the RPM repodata render and the PyPI file list.
/// <c>DapperPositionalRecordComplianceTests</c> is the static counterpart that covers the
/// projections this test cannot reach (private records inside controllers) and any new one.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresRecordMaterializationTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private const string OrgId = "o1";
    private const string UserId = "u1";
    private const string UserEmail = "subject@materialization.test";
    private const string LockoutKey = "lockout-key-1";

    [Fact]
    public async Task Every_integer_bearing_projection_materializes_against_live_postgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        var clock = TestTime.Frozen();
        using var envelope = MakeProtector();

        await SeedAsync(store, clock.GetUtcNow().ToUtcIso());

        // Each projection is probed independently and its failure recorded rather than thrown, so
        // one live-Postgres reset reports EVERY broken projection instead of only the first. A
        // provider-mapping regression is systemic — it lands on several projections at once — and
        // an abort-on-first-failure test would hide all but one of them behind a re-run loop.
        var failures = new List<string>();
        async Task ProbeAsync(string projection, Func<Task> probe)
        {
            try
            {
                await probe();
            }
            catch (Exception ex)
            {
                failures.Add($"{projection}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // ── webhook_subscription: enabled + consecutive_failures ────────────
        var webhooks = new WebhookSubscriptionRepository(store, envelope, clock);

        await ProbeAsync("WebhookSubscriptionRepository.RawRow", async () =>
        {
            var listed = Assert.Single(await webhooks.ListAsync(OrgId));
            Assert.True(listed.Enabled);
            Assert.Equal(3, listed.ConsecutiveFailures);
        });

        await ProbeAsync("WebhookSubscriptionRepository.RawDeliveryRow", async () =>
        {
            var fanout = Assert.Single(await webhooks.ListEnabledForEventAsync(OrgId, "package.published"));
            Assert.Equal(3, fanout.ConsecutiveFailures);
        });

        // ── alert_settings: five integer flags plus the email-channel read ──
        var alertSettings = new AlertSettingsRepository(store, envelope, clock);

        await ProbeAsync("AlertSettingsRepository.RawRow", async () =>
        {
            var settings = await alertSettings.GetAsync(OrgId);
            Assert.False(settings.QuarantineAlertsEnabled);
            Assert.True(settings.VulnAlertsEnabled);
            Assert.True(settings.SlackEnabled);
            Assert.Equal(5, settings.SlackConsecutiveFailures);
            Assert.True(settings.EmailEnabled);
            Assert.Equal(7, settings.EmailConsecutiveFailures);
        });

        await ProbeAsync("AlertSettingsRepository.RawEmailDeliveryRow", async () =>
        {
            // Returns null unless the row's email_enabled column materialized as 1.
            var emailChannel = await alertSettings.GetDecryptedEmailDeliveryConfigAsync(OrgId);
            Assert.NotNull(emailChannel);
            Assert.Equal(["ops@materialization.test"], emailChannel.Recipients);
        });

        // ── alert_settings again, through the raise gate on the Core side ───
        await ProbeAsync("AlertRepository.RawRaiseSettings", async () =>
        {
            var raise = await new AlertRepository(store, clock).GetRaiseSettingsAsync(OrgId);
            Assert.False(raise.QuarantineAlertsEnabled);
            Assert.True(raise.VulnAlertsEnabled);
        });

        // ── email_outbox: attempts on the drain, occurrence_count on coalesce ──
        var outbox = new EmailOutboxRepository(store, clock);

        // Coalescing only matches a still-pending row, so this is read before the claim below
        // moves the row to 'sending'.
        await ProbeAsync("EmailOutboxRepository.EmailOutboxCoalesceTarget", async () =>
        {
            var coalesceTarget = await outbox.FindCoalesceTargetAsync(OrgId, "vuln:critical");
            Assert.NotNull(coalesceTarget);
            Assert.Equal(4, coalesceTarget.OccurrenceCount);
        });

        await ProbeAsync("EmailOutboxRepository.RawRow", async () =>
        {
            var claimed = Assert.Single(await outbox.ClaimDueAsync(batchSize: 10));
            Assert.Equal("outbox-1", claimed.Id);
            // The row is seeded with 2 attempts and the claim consumes the third, so a
            // materialized attempts column reads 3 here and a defaulted one would read 1.
            Assert.Equal(3, claimed.Attempts);
        });

        // ── users: must_change_password + mfa_enabled on the "me" projection ──
        await ProbeAsync("UserService.UserRow", async () =>
        {
            var users = new UserService(store, new OrgRepository(store));
            var me = await users.GetUserContextAsync(UserId, OrgId);
            Assert.NotNull(me);
            Assert.True(me.MustChangePassword);
        });

        // ── the GDPR export: users, login_attempts, account_send_throttle ───
        await ProbeAsync("PersonalDataExportRepository UserRow/LoginAttemptRow/SendThrottleRow", async () =>
        {
            var export = await new PersonalDataExportRepository(store)
                .ExportAsync(UserId, OrgId, UserEmail, LockoutKey, CancellationToken.None);
            Assert.NotNull(export.User);
            Assert.Equal(1, export.User.MustChangePassword);
            Assert.Equal(1, export.User.MfaEnabled);
            Assert.Equal(9, export.User.TokenVersion);
            Assert.NotNull(export.LoginAttempts);
            Assert.Equal(4, export.LoginAttempts.FailedCount);
            Assert.Equal(2, Assert.Single(export.SendThrottles).SendCount);
        });

        // ── rpm_metadata: six integer columns plus package_versions.size_bytes ──
        await ProbeAsync("RpmRepodataService.RpmPrimaryRow", async () =>
        {
            string primary = await new RpmRepodataService(
                    store, NullLogger<RpmRepodataService>.Instance, clock)
                .BuildPrimaryAsync(OrgId, CancellationToken.None);
            // package=size_bytes, installed=installed_size, archive=archive_size,
            // build=build_time — four separate integer columns from the same projection.
            Assert.Contains("epoch=\"1\"", primary, StringComparison.Ordinal);
            Assert.Contains("build=\"1700000000\"", primary, StringComparison.Ordinal);
            Assert.Contains("package=\"4096\"", primary, StringComparison.Ordinal);
            Assert.Contains("installed=\"500000\"", primary, StringComparison.Ordinal);
            Assert.Contains("archive=\"400000\"", primary, StringComparison.Ordinal);
        });

        // ── package_version_files: size_bytes on the PyPI multi-file read ───
        await ProbeAsync("PackageVersionFilesRepository.PackageVersionFile", async () =>
        {
            var file = Assert.Single(
                await new PackageVersionFilesRepository(store, clock).GetByVersionAsync("v1"));
            Assert.Equal(1234, file.SizeBytes);
        });

        Assert.True(
            failures.Count == 0,
            $"{failures.Count} projection(s) failed to materialize against live Postgres:\n"
            + string.Join("\n", failures));
    }

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

    /// <summary>
    /// Seeds one row per projection under test, each carrying a distinct non-default integer so a
    /// value that silently binds to zero is distinguishable from one that binds correctly.
    /// </summary>
    private static async Task SeedAsync(NpgsqlMetadataStore store, string now)
    {
        await using var conn = await store.OpenAsync();

        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@OrgId, 'materialization-org')", new { OrgId });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@OrgId)", new { OrgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, must_change_password, mfa_enabled, token_version)
            VALUES (@UserId, @OrgId, @UserEmail, 'x', 1, 1, 9)
            """,
            new { UserId, OrgId, UserEmail });

        await conn.ExecuteAsync(
            """
            INSERT INTO webhook_subscription
                (id, org_id, url, event_types, enabled, consecutive_failures, created_at, updated_at)
            VALUES ('wh1', @OrgId, 'https://hook.materialization.test/x',
                    '["package.published"]', 1, 3, @now, @now)
            """,
            new { OrgId, now });

        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings
                (org_id, quarantine_alerts_enabled, vuln_alerts_enabled, vuln_min_severity,
                 slack_enabled, slack_consecutive_failures,
                 email_enabled, email_recipients, email_consecutive_failures, updated_at)
            VALUES (@OrgId, 0, 1, 'HIGH', 1, 5, 1, 'ops@materialization.test', 7, @now)
            """,
            new { OrgId, now });

        await conn.ExecuteAsync(
            """
            INSERT INTO email_outbox
                (id, org_id, message_kind, coalesce_key, recipients, subject, body,
                 occurrence_count, state, attempts, next_attempt_at, retry_deadline_at,
                 expires_at, created_at)
            VALUES
                ('outbox-1', @OrgId, 'alert', 'vuln:critical', 'ops@materialization.test',
                 'subject', 'body', 4, 'pending', 2, @now, @later, @later, @now)
            """,
            new { OrgId, now, later = TestTime.KnownNow.AddHours(6).ToUtcIso() });

        await conn.ExecuteAsync(
            """
            INSERT INTO login_attempts (email_hash, failed_count, last_attempt)
            VALUES (@LockoutKey, 4, @now)
            """,
            new { LockoutKey, now });

        await conn.ExecuteAsync(
            """
            INSERT INTO account_send_throttle (email_hash, purpose, window_start, send_count)
            VALUES (@LockoutKey, 'password_reset', @now, 2)
            """,
            new { LockoutKey, now });

        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1', @OrgId, 'rpm', 'nano', 'nano', 0),
                   ('p2', @OrgId, 'pypi', 'widget', 'widget', 0)
            """,
            new { OrgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES ('v0', 'p1', '7.2-1.el9', 'pkg:rpm/nano@7.2-1.el9', 'rpm/nano', 'nano-7.2-1.el9.x86_64.rpm',
                    4096, 'deadbeef', 'uploaded'),
                   ('v1', 'p2', '1.0.0', 'pkg:pypi/widget@1.0.0', 'pypi/widget', 'widget-1.0.0.tar.gz',
                    1234, 'cafebabe', 'uploaded')
            """);

        await conn.ExecuteAsync(
            """
            INSERT INTO rpm_metadata
                (id, package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch,
                 build_time, installed_size, archive_size, header_start, header_end, owner_kind)
            VALUES ('rm1', 'v0', 'nano', 1, '7.2', '1.el9', 'x86_64',
                    1700000000, 500000, 400000, 4096, 8192, 'package_version')
            """);

        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_files
                (id, package_version_id, org_id, filename, blob_key, size_bytes, checksum_sha256, created_at)
            VALUES ('pvf1', 'v1', @OrgId, 'widget-1.0.0.tar.gz', 'pypi/widget', 1234, 'cafebabe', @now)
            """,
            new { OrgId, now });
    }
}
