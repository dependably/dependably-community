using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// <see cref="ProtectedSecretBootCheck"/>: the boot-time run of the stored-secret verifier must
/// not hold up startup, must not touch the database before the host is listening, must log a
/// warning naming each failing row without its value, and must swallow its own failure.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProtectedSecretBootCheckTests : IAsyncLifetime
{
    // Generous: the wait covers a real background task on a loaded CI host, not a timing claim.
    private static readonly TimeSpan Completion = TimeSpan.FromSeconds(30);

    private readonly TestMetadataStore _db = new();
    private readonly byte[] _masterKey = RandomNumberGenerator.GetBytes(32);
    private readonly ManualLifetime _lifetime = new();
    private readonly CapturingLogger _logger = new();
    private EnvelopeProtector _envelope = null!;

    public Task InitializeAsync()
    {
        _envelope = TestEnvelope.Configured(_masterKey);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        _envelope.Dispose();
        _lifetime.Dispose();
        await _db.DisposeAsync();
    }

    private ProtectedSecretBootCheck BootCheck(Dictionary<string, string?>? settings = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings ?? new Dictionary<string, string?>()).Build();
        var verifier = new ProtectedSecretVerifier(_db, _envelope, config, TestTime.Frozen());
        return new ProtectedSecretBootCheck(verifier, _lifetime, config, _logger);
    }

    private async Task<(string Plaintext, string Stored)> SeedCorruptWebhookAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        const string plaintext = "webhook-hmac-secret";
        string stored = CorruptCiphertext.Envelope(_envelope, plaintext);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-a', 'org-a')");
        await conn.ExecuteAsync(
            "INSERT INTO webhook_subscription (id, org_id, url, secret) VALUES ('wh-bad', 'org-a', 'https://h.example.com', @stored)",
            new { stored });
        return (plaintext, stored);
    }

    [Fact]
    public async Task StartReturnsAtOnce_AndTheSweepWaitsForTheHostToStart()
    {
        var (plaintext, stored) = await SeedCorruptWebhookAsync();
        var check = BootCheck();

        await check.StartAsync(CancellationToken.None);

        // Started, not run: nothing logged and the sweep still pending until the host is listening.
        Assert.Empty(_logger.Entries);
        Assert.False(check.ExecuteTask!.IsCompleted);

        _lifetime.SignalStarted();
        await check.ExecuteTask.WaitAsync(Completion);

        var (_, message) = Assert.Single(_logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("webhook_secret", message, StringComparison.Ordinal);
        Assert.Contains("webhook_subscription", message, StringComparison.Ordinal);
        Assert.Contains("wh-bad (org org-a)", message, StringComparison.Ordinal);
        Assert.DoesNotContain(plaintext, message, StringComparison.Ordinal);
        Assert.DoesNotContain(stored[EnvelopeProtector.EncryptedPrefix.Length..][..16], message, StringComparison.Ordinal);

        await check.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task OptedOut_DoesNotSweep()
    {
        await SeedCorruptWebhookAsync();
        var check = BootCheck(new() { [ProtectedSecretBootCheck.EnabledSetting] = "false" });

        await check.StartAsync(CancellationToken.None);
        _lifetime.SignalStarted();
        await check.ExecuteTask!.WaitAsync(Completion);

        Assert.DoesNotContain(_logger.Entries, e => e.Level >= LogLevel.Warning);
        Assert.Contains(_logger.Entries, e => e.Message.Contains("is off", StringComparison.Ordinal));
    }

    [Fact]
    public async Task UnrecognisedSetting_KeepsTheSweepOn()
    {
        await SeedCorruptWebhookAsync();
        var check = BootCheck(new() { [ProtectedSecretBootCheck.EnabledSetting] = "nope" });

        await check.StartAsync(CancellationToken.None);
        _lifetime.SignalStarted();
        await check.ExecuteTask!.WaitAsync(Completion);

        Assert.Contains(_logger.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("wh-bad", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SweepThatThrows_IsLoggedAndDoesNotFaultTheService()
    {
        // No schema applied: the first query throws, as a database outage at boot would.
        var check = BootCheck();

        await check.StartAsync(CancellationToken.None);
        _lifetime.SignalStarted();
        await check.ExecuteTask!.WaitAsync(Completion);

        Assert.Equal(TaskStatus.RanToCompletion, check.ExecuteTask.Status);
        Assert.Contains(_logger.Entries, e => e.Level == LogLevel.Warning
            && e.Message.Contains("could not complete", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StoppingBeforeTheHostStarts_EndsWithoutSweeping()
    {
        await SeedCorruptWebhookAsync();
        var check = BootCheck();

        await check.StartAsync(CancellationToken.None);
        await check.StopAsync(CancellationToken.None);

        Assert.True(check.ExecuteTask!.IsCompleted);
        Assert.Empty(_logger.Entries);
    }

    [Fact]
    public void LogReport_NamesAtMostTheCapPerKind_AndCountsTheRest()
    {
        int failed = ProtectedSecretBootCheck.LoggedRowsPerKind + 7;
        var failures = Enumerable.Range(0, failed)
            .Select(i => new ProtectedSecretFailure(
                ProtectedSecretKinds.UpstreamCredential, "upstream_registry", $"up-{i:D3}", "org-a",
                ProtectedSecretFailureReasons.AuthenticationFailed))
            .ToList();
        var report = new ProtectedSecretReport(
            TestTime.KnownNow, true,
            [new ProtectedSecretKindResult(ProtectedSecretKinds.UpstreamCredential, "upstream_registry", failed, 0, 0, failed, null)],
            failures, false);

        BootCheck().LogReport(report);

        var (level, message) = Assert.Single(_logger.Entries);
        Assert.Equal(LogLevel.Warning, level);
        Assert.Contains($"up-{ProtectedSecretBootCheck.LoggedRowsPerKind - 1:D3}", message, StringComparison.Ordinal);
        Assert.DoesNotContain($"up-{ProtectedSecretBootCheck.LoggedRowsPerKind:D3}", message, StringComparison.Ordinal);
        Assert.Contains(" and 7 more", message, StringComparison.Ordinal);
    }

    private sealed class ManualLifetime : IHostApplicationLifetime, IDisposable
    {
        private readonly CancellationTokenSource _started = new();

        public CancellationToken ApplicationStarted => _started.Token;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void SignalStarted() => _started.Cancel();

        public void StopApplication()
        {
        }

        public void Dispose() => _started.Dispose();
    }

    private sealed class CapturingLogger : ILogger<ProtectedSecretBootCheck>
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(LogLevel Level, string Message)> _entries = new();

        public IReadOnlyList<(LogLevel Level, string Message)> Entries => [.. _entries];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            _entries.Enqueue((logLevel, formatter(state, exception)));
    }
}
