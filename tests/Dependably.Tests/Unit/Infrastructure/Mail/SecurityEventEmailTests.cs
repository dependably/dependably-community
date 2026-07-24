using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// Unit tests for <see cref="SecurityEventEmailJob"/> (the account-security notification job:
/// MFA enabled/disabled, password changed) and the three <see cref="TransactionalEmailService"/>
/// entry points that enqueue it. Mirrors the <c>PasswordResetEmailJob</c>/<c>EmailDeliveryQueueTests</c>
/// coverage shape, plus the one deliberate divergence (rendering in a caller-resolved language
/// rather than being English-pinned) and a mixed-outcome scenario exercising the shared queue with
/// two heterogeneous jobs in flight at once.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SecurityEventEmailTests
{
    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    /// <summary>Records every send and routes success/failure by a "bad" substring in the sole
    /// recipient address, letting a single test drive both outcomes through one shared instance
    /// (real SMTP failures are transport-level, not per-recipient, but this is the simplest way
    /// to prove two heterogeneous jobs in flight resolve independently).</summary>
    private sealed class FakeMailSender : SmtpMailSender
    {
        public FakeMailSender() : base(new Dependably.Security.SsrfConnectCallback(_ => false))
        {
        }

        public int Calls { get; private set; }

        public override Task SendAsync(
            SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
            CancellationToken ct = default)
        {
            Calls++;
            return to.Any(a => a.Contains("bad", StringComparison.Ordinal))
                ? Task.FromException(new InvalidOperationException("simulated SMTP failure"))
                : Task.CompletedTask;
        }
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;

        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? ex, Func<TState, Exception?, string> formatter) =>
            Entries.Add((level, formatter(state, ex)));
    }

    private static InstanceSmtpConfig BuildInstance(Dictionary<string, string?> db, FakeTimeProvider clock)
    {
        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);
        return new InstanceSmtpConfig(Reader, clock);
    }

    private static Dictionary<string, string?> EnabledConfig(string host) => new()
    {
        ["smtp_enabled"] = "1",
        ["smtp_host"] = host,
        ["smtp_from_address"] = "noreply@example.com",
        ["smtp_security"] = "none",
    };

    // ── Resolve gate ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ResolveAsync_InstanceNotConfigured_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.PasswordChanged, "user@example.com", "en", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        Assert.Null(await job.ResolveAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ResolveAsync_InstanceConfiguredButDisabled_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        var db = EnabledConfig("smtp.example.com");
        db["smtp_enabled"] = "0";
        var job = new SecurityEventEmailJob(
            SecurityEventKind.MfaEnabled, "user@example.com", "en", clock.GetUtcNow(),
            BuildInstance(db, clock), RealLocalizer(), NullLogger.Instance);

        Assert.Null(await job.ResolveAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ResolveAsync_InstanceConfiguredAndEnabled_ResolvesTransportAndSoleRecipient()
    {
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.MfaDisabled, "user@example.com", "en", clock.GetUtcNow(),
            BuildInstance(EnabledConfig("smtp.example.com"), clock), RealLocalizer(), NullLogger.Instance);

        var resolved = await job.ResolveAsync(CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal("smtp.example.com", resolved.Value.Transport.Host);
        Assert.Equal(["user@example.com"], resolved.Value.Recipients);
    }

    // ── Render: per-kind content, ISO timestamp, no secrets leaked ──────────

    [Theory]
    [InlineData(SecurityEventKind.MfaEnabled, "two-factor authentication was enabled")]
    [InlineData(SecurityEventKind.MfaDisabled, "two-factor authentication was disabled")]
    [InlineData(SecurityEventKind.PasswordChanged, "password was changed")]
    public void Render_EnglishDefault_SubjectMatchesEventKind(SecurityEventKind kind, string expectedSubjectFragment)
    {
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            kind, "user@example.com", "en", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        (string subject, _) = job.Render();

        Assert.Contains(expectedSubjectFragment, subject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Render_IncludesEventTimestamp_AsInvariantIsoForm()
    {
        var clock = TestTime.Frozen();
        var occurredAt = clock.GetUtcNow();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.PasswordChanged, "user@example.com", "en", occurredAt,
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        (_, string body) = job.Render();

        Assert.Contains(occurredAt.ToString("yyyy-MM-dd HH:mm"), body);
    }

    [Fact]
    public void Render_PasswordChanged_LeaksNoTokenOrPasswordValue()
    {
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.PasswordChanged, "user@example.com", "en", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        (string subject, string body) = job.Render();

        // The body carries a security-awareness notice and a timestamp — never a credential,
        // token, or reset link value (this is a notification, not a reset flow).
        Assert.DoesNotContain("http", subject + body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("token", subject + body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("if this was you", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Render_SupportedNonEnglishLanguage_RendersInThatLanguage_NotEnglishPinned()
    {
        var clock = TestTime.Frozen();
        var enJob = new SecurityEventEmailJob(
            SecurityEventKind.MfaEnabled, "user@example.com", "en", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);
        var frJob = new SecurityEventEmailJob(
            SecurityEventKind.MfaEnabled, "user@example.com", "fr", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        (string enSubject, _) = enJob.Render();
        (string frSubject, _) = frJob.Render();

        Assert.NotEqual(enSubject, frSubject);
        Assert.Contains("authentification", frSubject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Render_UnsupportedLanguage_FallsBackToEnglish()
    {
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.MfaEnabled, "user@example.com", "de", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        (string subject, _) = job.Render();

        Assert.Contains("two-factor authentication was enabled", subject, StringComparison.OrdinalIgnoreCase);
    }

    // ── PII-safe logging: domain only, never the local-part ─────────────────

    [Fact]
    public async Task RecordSuccessAsync_LogsDomainOnly_NeverLocalPart()
    {
        var log = new CapturingLogger();
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.MfaEnabled, "quinlan.vega@example.com", "en", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), log);

        await job.RecordSuccessAsync();

        string message = Assert.Single(log.Entries).Message;
        Assert.Contains("example.com", message);
        Assert.DoesNotContain("quinlan.vega", message);
    }

    [Fact]
    public async Task RecordFailureAsync_LogsDomainOnly_NeverLocalPart()
    {
        var log = new CapturingLogger();
        var clock = TestTime.Frozen();
        var job = new SecurityEventEmailJob(
            SecurityEventKind.PasswordChanged, "quinlan.vega@example.com", "en", clock.GetUtcNow(),
            BuildInstance([], clock), RealLocalizer(), log);

        await job.RecordFailureAsync("simulated failure");

        string message = Assert.Single(log.Entries).Message;
        Assert.Contains("example.com", message);
        Assert.DoesNotContain("quinlan.vega", message);
        Assert.Contains("simulated failure", message);
    }

    // ── TransactionalEmailService: end-to-end through the shared queue ──────

    [Fact]
    public async Task EnqueueMfaEnabled_InstanceNotConfigured_NoSendAttempted()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var service = new TransactionalEmailService(queue, BuildInstance([], clock), RealLocalizer(), NullLogger<TransactionalEmailService>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        service.EnqueueMfaEnabled("user@example.com", "en", clock.GetUtcNow());
        await Task.Delay(200);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(0, sender.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
    }

    [Fact]
    public async Task EnqueueMfaDisabled_InstanceConfigured_DeliversViaSharedQueue_ToSoleRecipient()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var service = new TransactionalEmailService(
            queue, BuildInstance(EnabledConfig("good.example.com"), clock), RealLocalizer(), NullLogger<TransactionalEmailService>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        service.EnqueueMfaDisabled("acting-user@example.com", "en", clock.GetUtcNow());

        // now-ok: polling deadline awaiting real async completion of the queued delivery.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (sender.Calls < 1 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, sender.Calls);
        Assert.Equal(1, queue.DeliveredCount);
    }

    [Fact]
    public async Task EnqueuePasswordChanged_InstanceConfigured_DeliversViaSharedQueue()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var service = new TransactionalEmailService(
            queue, BuildInstance(EnabledConfig("good.example.com"), clock), RealLocalizer(), NullLogger<TransactionalEmailService>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        service.EnqueuePasswordChanged("acting-user@example.com", "en", clock.GetUtcNow());

        // now-ok: polling deadline awaiting real async completion of the queued delivery.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (sender.Calls < 1 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, sender.Calls);
        Assert.Equal(1, queue.DeliveredCount);
    }

    // ── Mixed outcome: two heterogeneous jobs in flight, one fails / one succeeds ────

    /// <summary>
    /// Enqueues an MFA-enabled notification to a "good" address alongside a password-changed
    /// notification to a "bad" one on the same shared queue instance. The two event kinds and
    /// their outcomes must resolve independently — one job's failure must never suppress or
    /// block the other's success, and the queue's aggregate counters must reflect exactly one
    /// of each rather than either double-counting or masking the failure.
    /// </summary>
    [Fact]
    public async Task MixedEvents_OneGoodOneBadRecipient_ResolveIndependently_NotAllPassOrAllFail()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var service = new TransactionalEmailService(
            queue, BuildInstance(EnabledConfig("smtp.example.com"), clock), RealLocalizer(), NullLogger<TransactionalEmailService>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        service.EnqueueMfaEnabled("good-user@example.com", "en", clock.GetUtcNow());
        service.EnqueuePasswordChanged("bad-user@example.com", "en", clock.GetUtcNow());

        // now-ok: polling deadline awaiting the background queue's real async delivery loop;
        // the frozen clock (not this wall-clock read) drives the failing job's retry backoff.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(2);
        while (queue.DeliveredCount < 1 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        // Pump the failing job's retry backoff (1s/5s/30s) through to its terminal failure
        // without waiting out 36 real seconds.
        foreach (var step in new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30) })
        {
            clock.Advance(step);
            await Task.Delay(50);
        }

        // now-ok: polling deadline awaiting the background queue's real async delivery loop.
        var failDeadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(2);
        while (queue.FailedCount < 1 && DateTimeOffset.UtcNow < failDeadline)
        {
            await Task.Delay(10);
        }

        try { await queue.StopAsync(CancellationToken.None); } catch { }

        // Exactly one succeeded and exactly one failed — never both-pass and never both-fail.
        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);
    }
}
