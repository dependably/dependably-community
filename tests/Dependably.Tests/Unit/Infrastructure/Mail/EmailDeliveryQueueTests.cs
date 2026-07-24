using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// Unit tests for the generic <see cref="EmailDeliveryQueue"/> core (the channel/worker/retry
/// engine every outbound-email delivery job shares) driven with a bare test double
/// (<see cref="FakeJob"/>), plus the transactional password-reset job
/// (<see cref="PasswordResetEmailJob"/> via <see cref="TransactionalEmailService"/>) that is the
/// second consumer of that shared core alongside <c>AlertEmailQueue</c> (covered separately in
/// <c>AlertEmailQueueTests</c>).
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailDeliveryQueueTests
{
    private static IStringLocalizer<SharedResource> RealLocalizer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddLocalization(o => o.ResourcesPath = "Resources");
        return services.BuildServiceProvider().GetRequiredService<IStringLocalizer<SharedResource>>();
    }

    /// <summary>Records every send and routes success/failure by a "bad" substring in the
    /// transport host, exactly like <c>AlertEmailQueueTests.FakeMailSender</c>.</summary>
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
            return transport.Host?.Contains("bad", StringComparison.Ordinal) == true
                ? Task.FromException(new InvalidOperationException("simulated SMTP failure"))
                : Task.CompletedTask;
        }
    }

    /// <summary>Bare <see cref="IEmailDeliveryJob"/> test double that records every call it
    /// receives, so the queue's scheduling behavior can be asserted independently of any real
    /// delivery channel.</summary>
    private sealed class FakeJob : IEmailDeliveryJob
    {
        private readonly (SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)? _resolved;

        public FakeJob((SmtpTransportSettings, IReadOnlyList<string>)? resolved) => _resolved = resolved;

        public int ResolveCalls { get; private set; }
        public int RenderCalls { get; private set; }
        public int SuccessCalls { get; private set; }
        public int FailureCalls { get; private set; }
        public string? LastError { get; private set; }

        public Task<(SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)?> ResolveAsync(CancellationToken ct)
        {
            ResolveCalls++;
            return Task.FromResult(_resolved);
        }

        public (string Subject, string Body) Render()
        {
            RenderCalls++;
            return ("test subject", "test body");
        }

        public Task RecordSuccessAsync()
        {
            SuccessCalls++;
            return Task.CompletedTask;
        }

        public Task RecordFailureAsync(string error)
        {
            FailureCalls++;
            LastError = error;
            return Task.CompletedTask;
        }
    }

    private static SmtpTransportSettings Transport(string host) =>
        new(Host: host, Port: 587, Security: "none", Username: null, Password: null, FromAddress: "noreply@example.com");

    // ── Generic queue: resolve-null no-op ───────────────────────────────────

    /// <summary>Captures every log invocation on a plain (non-Serilog-static) <see cref="ILogger{T}"/>
    /// double so a test can assert a specific message fired, without touching the static Serilog
    /// logger that is a known source of test flake in this repo.</summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    [Fact]
    public async Task DeliverAsync_ResolveReturnsNull_NeverRendersOrRecords()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var job = new FakeJob(null);

        await queue.DeliverAsync(job, CancellationToken.None);

        Assert.Equal(1, job.ResolveCalls);
        Assert.Equal(0, job.RenderCalls);
        Assert.Equal(0, job.SuccessCalls);
        Assert.Equal(0, job.FailureCalls);
        Assert.Equal(0, sender.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
    }

    /// <summary>The silent-drop branch (no transport resolved) now logs at Information so
    /// operators can see mail is being skipped rather than the drop being invisible.</summary>
    [Fact]
    public async Task DeliverAsync_ResolveReturnsNull_LogsInformationNamingTheJobType()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var logger = new CapturingLogger<EmailDeliveryQueue>();
        var queue = new EmailDeliveryQueue(sender, clock, logger);
        var job = new FakeJob(null);

        await queue.DeliverAsync(job, CancellationToken.None);

        Assert.Contains(logger.Entries, e =>
            e.Level == LogLevel.Information &&
            e.Message.Contains(nameof(FakeJob), StringComparison.Ordinal) &&
            e.Message.Contains("unavailable", StringComparison.OrdinalIgnoreCase));
    }

    // ── Generic queue: retry backoff on a bare job ──────────────────────────

    [Fact]
    public async Task DeliverAsync_TransientFailure_RetriesAtExactBackoffThenRecordsFailureOnce()
    {
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var job = new FakeJob((Transport("bad.example.com"), new[] { "a@example.com" }));

        var deliverTask = queue.DeliverAsync(job, CancellationToken.None);

        async Task WaitForCalls(int n)
        {
            // now-ok: polling deadline awaiting the fake job's recorded call count in real time.
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
            while (sender.Calls < n && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(10);
            }
        }

        await WaitForCalls(1);
        Assert.Equal(1, sender.Calls);

        clock.Advance(TimeSpan.FromSeconds(1));
        await WaitForCalls(2);
        Assert.Equal(2, sender.Calls);

        clock.Advance(TimeSpan.FromSeconds(5));
        await WaitForCalls(3);
        Assert.Equal(3, sender.Calls);

        clock.Advance(TimeSpan.FromSeconds(30));
        await WaitForCalls(4);
        Assert.Equal(4, sender.Calls);

        await deliverTask;

        Assert.Equal(1, job.RenderCalls);
        Assert.Equal(0, job.SuccessCalls);
        Assert.Equal(1, job.FailureCalls);
        Assert.Contains("simulated SMTP failure", job.LastError);
        Assert.Equal(1, queue.FailedCount);
        Assert.Equal(0, queue.DeliveredCount);
    }

    [Fact]
    public async Task DeliverAsync_Success_RecordsSuccessOnce()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var job = new FakeJob((Transport("good.example.com"), new[] { "a@example.com" }));

        await queue.DeliverAsync(job, CancellationToken.None);

        Assert.Equal(1, sender.Calls);
        Assert.Equal(1, job.SuccessCalls);
        Assert.Equal(0, job.FailureCalls);
        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
    }

    // ── PasswordResetEmailJob: resolve gate ─────────────────────────────────

    private static InstanceSmtpConfig BuildInstance(Dictionary<string, string?> db, FakeTimeProvider clock)
    {
        Task<string?> Reader(string key, CancellationToken _) =>
            Task.FromResult(db.TryGetValue(key, out string? v) ? v : null);
        return new InstanceSmtpConfig(Reader, clock);
    }

    [Fact]
    public async Task PasswordResetEmailJob_InstanceNotConfigured_ResolveReturnsNull()
    {
        var clock = TestTime.Frozen();
        var instance = BuildInstance([], clock);
        var job = new PasswordResetEmailJob(
            "user@example.com", "https://example.com/reset?token=abc", clock.GetUtcNow().AddMinutes(30),
            instance, RealLocalizer(), NullLogger.Instance);

        var resolved = await job.ResolveAsync(CancellationToken.None);

        Assert.Null(resolved);
    }

    [Fact]
    public async Task PasswordResetEmailJob_InstanceConfiguredButDisabled_ResolveReturnsNull()
    {
        var clock = TestTime.Frozen();
        var instance = BuildInstance(new Dictionary<string, string?>
        {
            ["smtp_enabled"] = "0",
            ["smtp_host"] = "smtp.example.com",
            ["smtp_from_address"] = "noreply@example.com",
            ["smtp_security"] = "none",
        }, clock);
        var job = new PasswordResetEmailJob(
            "user@example.com", "https://example.com/reset?token=abc", clock.GetUtcNow().AddMinutes(30),
            instance, RealLocalizer(), NullLogger.Instance);

        var resolved = await job.ResolveAsync(CancellationToken.None);

        Assert.Null(resolved);
    }

    [Fact]
    public async Task PasswordResetEmailJob_InstanceConfiguredAndEnabled_ResolvesTransportAndSoleRecipient()
    {
        var clock = TestTime.Frozen();
        var instance = BuildInstance(new Dictionary<string, string?>
        {
            ["smtp_enabled"] = "1",
            ["smtp_host"] = "smtp.example.com",
            ["smtp_from_address"] = "noreply@example.com",
            ["smtp_security"] = "none",
        }, clock);
        var job = new PasswordResetEmailJob(
            "user@example.com", "https://example.com/reset?token=abc", clock.GetUtcNow().AddMinutes(30),
            instance, RealLocalizer(), NullLogger.Instance);

        var resolved = await job.ResolveAsync(CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal("smtp.example.com", resolved.Value.Transport.Host);
        Assert.Equal(["user@example.com"], resolved.Value.Recipients);
    }

    [Fact]
    public void PasswordResetEmailJob_Render_IncludesResetLinkAndExpiry()
    {
        var clock = TestTime.Frozen();
        var expiresAt = clock.GetUtcNow().AddMinutes(30);
        var job = new PasswordResetEmailJob(
            "user@example.com", "https://example.com/reset?token=abc123", expiresAt,
            BuildInstance([], clock), RealLocalizer(), NullLogger.Instance);

        (string subject, string body) = job.Render();

        Assert.Contains("password", subject, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://example.com/reset?token=abc123", body);
        Assert.Contains(expiresAt.ToString("yyyy-MM-dd HH:mm"), body);
    }

    // ── TransactionalEmailService: end-to-end through the shared queue ──────

    [Fact]
    public async Task TransactionalEmailService_InstanceNotConfigured_NoSendAttempted()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var instance = BuildInstance([], clock);
        var service = new TransactionalEmailService(queue, instance, RealLocalizer(), NullLogger<TransactionalEmailService>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        service.EnqueuePasswordReset("user@example.com", "https://example.com/reset?token=abc", clock.GetUtcNow().AddMinutes(30));
        await Task.Delay(200);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(0, sender.Calls);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
    }

    [Fact]
    public async Task TransactionalEmailService_InstanceConfigured_DeliversViaSharedQueue()
    {
        var clock = TestTime.Frozen();
        var sender = new FakeMailSender();
        var queue = new EmailDeliveryQueue(sender, clock, NullLogger<EmailDeliveryQueue>.Instance);
        var instance = BuildInstance(new Dictionary<string, string?>
        {
            ["smtp_enabled"] = "1",
            ["smtp_host"] = "good.example.com",
            ["smtp_from_address"] = "noreply@example.com",
            ["smtp_security"] = "none",
        }, clock);
        var service = new TransactionalEmailService(queue, instance, RealLocalizer(), NullLogger<TransactionalEmailService>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        service.EnqueuePasswordReset("user@example.com", "https://example.com/reset?token=abc", clock.GetUtcNow().AddMinutes(30));

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
}
