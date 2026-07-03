using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Webhooks;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for the outbound webhook pipeline:
/// <list type="bullet">
///   <item>HMAC-SHA256 payload signing and header format</item>
///   <item>Payload shape (snake_case, embedded data fragment)</item>
///   <item>Event-type subscription filtering</item>
///   <item>Auto-disable triggers (count + duration)</item>
///   <item>Mixed partial-failure fan-out (one succeeds, one fails — independently)</item>
///   <item>Secret round-trip via EnvelopeProtector</item>
/// </list>
/// </summary>
[Trait("Category", "Unit")]
public sealed class WebhookDeliveryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── helpers ───────────────────────────────────────────────────────────────

    private static PackageEventEnvelope SampleEnvelope(
        string eventType = "package.publish",
        string orgId = "org1",
        string orgSlug = "acme") => new(
            EventType: eventType,
            OrgId: orgId,
            OrgSlug: orgSlug,
            Ecosystem: "npm",
            Name: "lodash",
            Version: "4.17.21",
            Purl: "pkg:npm/lodash@4.17.21",
            ArtifactHash: "sha256:abc123",
            Actor: "u1",
            OccurredAt: Clock.GetUtcNow(),
            DataJson: """{"ecosystem":"npm","name":"lodash","version":"4.17.21"}""");

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

    // An EnvelopeProtector with no DEPENDABLY_MASTER_KEY — IsConfigured is false and
    // Protect throws. Mirrors the DAST/default deployment where secrets-at-rest is off.
    private static EnvelopeProtector MakeUnconfiguredProtector()
    {
        var config = new ConfigurationBuilder().Build();
        return new EnvelopeProtector(new EnvFileMasterKeyProvider(config));
    }

    private static async Task WaitAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting real async completion of the queue consumer
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(3));
        while (!condition() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        if (!condition())
        {
            throw new TimeoutException("Condition never satisfied.");
        }
    }

    // ── HMAC signing ──────────────────────────────────────────────────────────

    [Fact]
    public void ComputeHmacSha256Hex_DeterministicForSameInputs()
    {
        byte[] body = Encoding.UTF8.GetBytes("""{"event":"package.publish"}""");
        string sig1 = WebhookDeliveryClient.ComputeHmacSha256Hex("secret", body);
        string sig2 = WebhookDeliveryClient.ComputeHmacSha256Hex("secret", body);

        Assert.Equal(sig1, sig2);
        Assert.Matches("^[0-9a-f]{64}$", sig1);
    }

    [Fact]
    public void ComputeHmacSha256Hex_DiffersForDifferentSecrets()
    {
        byte[] body = Encoding.UTF8.GetBytes("test");
        string sig1 = WebhookDeliveryClient.ComputeHmacSha256Hex("secret1", body);
        string sig2 = WebhookDeliveryClient.ComputeHmacSha256Hex("secret2", body);

        Assert.NotEqual(sig1, sig2);
    }

    [Fact]
    public void ComputeHmacSha256Hex_OutputIsKnownVector()
    {
        // RFC 4231 test vector: HMAC-SHA-256, key=4Jk... (but we use simple ASCII for readability)
        // Verified externally: echo -n "Hello" | openssl dgst -sha256 -hmac "key"
        byte[] body = Encoding.UTF8.GetBytes("Hello");
        string sig = WebhookDeliveryClient.ComputeHmacSha256Hex("key", body);

        Assert.Equal("c70b9f4d665bd62974afc83582de810e72a41a58db82c538a9d734c9266d321e", sig);
    }

    // ── Payload shape ─────────────────────────────────────────────────────────

    [Fact]
    public void BuildPayloadBytes_ContainsExpectedTopLevelFields_SnakeCase()
    {
        var env = SampleEnvelope();
        byte[] bytes = WebhookDeliveryClient.BuildPayloadBytes(env, "delivery-1");

        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;

        Assert.Equal("package.publish", root.GetProperty("event").GetString());
        Assert.Equal("delivery-1", root.GetProperty("delivery_id").GetString());
        Assert.Equal("acme", root.GetProperty("org").GetString());
        Assert.Equal("npm", root.GetProperty("ecosystem").GetString());
        Assert.Equal("lodash", root.GetProperty("name").GetString());
        Assert.Equal("4.17.21", root.GetProperty("version").GetString());
        Assert.Equal("pkg:npm/lodash@4.17.21", root.GetProperty("purl").GetString());
        Assert.Equal("sha256:abc123", root.GetProperty("artifact_hash").GetString());
        Assert.Equal("u1", root.GetProperty("actor").GetString());
    }

    [Fact]
    public void BuildPayloadBytes_DataFieldIsEmbeddedObject_NotString()
    {
        var env = SampleEnvelope();
        byte[] bytes = WebhookDeliveryClient.BuildPayloadBytes(env, "d1");

        using var doc = JsonDocument.Parse(bytes);
        var data = doc.RootElement.GetProperty("data");

        // data must be a nested object, not a JSON string containing JSON
        Assert.Equal(JsonValueKind.Object, data.ValueKind);
        Assert.Equal("npm", data.GetProperty("ecosystem").GetString());
        Assert.Equal("lodash", data.GetProperty("name").GetString());
    }

    [Fact]
    public void BuildPayloadBytes_NullArtifactHash_SerializesAsNull()
    {
        var env = SampleEnvelope() with { ArtifactHash = null };
        byte[] bytes = WebhookDeliveryClient.BuildPayloadBytes(env, "d1");

        using var doc = JsonDocument.Parse(bytes);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("artifact_hash").ValueKind);
    }

    [Fact]
    public void BuildPayloadBytes_NullActor_SerializesAsNull()
    {
        var env = SampleEnvelope() with { Actor = null };
        byte[] bytes = WebhookDeliveryClient.BuildPayloadBytes(env, "d1");

        using var doc = JsonDocument.Parse(bytes);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("actor").ValueKind);
    }

    // ── Event-type subscription filtering ─────────────────────────────────────

    [Fact]
    public async Task ListEnabledForEventAsync_ReturnsOnlyMatchingSubscriptions()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://a.example.com/hook",
            ["package.publish", "package.yank"],
            Secret: null, Description: null));

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://b.example.com/hook",
            ["package.vuln"],
            Secret: null, Description: null));

        var forPublish = await repo.ListEnabledForEventAsync("org1", "package.publish");
        var forVuln = await repo.ListEnabledForEventAsync("org1", "package.vuln");
        var forUnlist = await repo.ListEnabledForEventAsync("org1", "package.unlist");

        Assert.Single(forPublish);
        Assert.Equal("https://a.example.com/hook", forPublish[0].Url);

        Assert.Single(forVuln);
        Assert.Equal("https://b.example.com/hook", forVuln[0].Url);

        Assert.Empty(forUnlist);
    }

    [Fact]
    public async Task ListEnabledForEventAsync_IgnoresDisabledSubscriptions()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://c.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        await repo.UpdateAsync("org1", sub.Id, new UpdateWebhookSubscription(
            sub.Url, sub.EventTypes, Enabled: false, Secret: null, Description: null));

        var results = await repo.ListEnabledForEventAsync("org1", "package.publish");
        Assert.Empty(results);
    }

    [Fact]
    public async Task ListEnabledForEventAsync_IsolatesByOrgId()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        await repo.AddAsync("org2", new NewWebhookSubscription(
            "https://org2.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        var results = await repo.ListEnabledForEventAsync("org1", "package.publish");
        Assert.DoesNotContain(results, r => r.OrgId == "org2");
    }

    // ── Secret round-trip ─────────────────────────────────────────────────────

    [Fact]
    public async Task AddAsync_SecretIsEncryptedAtRest_DecryptedForDelivery()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        const string plaintext = "my-hmac-secret";

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://secret.example.com/hook",
            ["package.publish"],
            Secret: plaintext, Description: null));

        Assert.True(sub.HasSecret);

        // Raw DB value must not equal plaintext — it should carry the enc:v1: prefix
        await using var conn = await _db.OpenAsync();
        string? rawSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT secret FROM webhook_subscription WHERE id = @id", new { id = sub.Id });
        Assert.NotNull(rawSecret);
        Assert.StartsWith("enc:v1:", rawSecret);

        // ListEnabledForEventAsync must return the decrypted value for delivery
        var delivery = await repo.ListEnabledForEventAsync("org1", "package.publish");
        var match = delivery.FirstOrDefault(d => d.Id == sub.Id);
        Assert.NotNull(match);
        Assert.Equal(plaintext, match!.Secret);
    }

    [Fact]
    public async Task ListAsync_MaterializesRows_WithAndWithoutSecret()
    {
        // The management List projection computes HasSecret from a typeless CASE column;
        // it must materialize whether or not a secret is stored, and for both the empty
        // and populated table. Regression for a Dapper/SQLite type-inference failure on
        // the expression column that surfaced only on the multi-row QueryAsync path.
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        Assert.Empty(await repo.ListAsync("org1"));

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://no-secret.example.com/hook", ["package.publish"],
            Secret: null, Description: null));
        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://with-secret.example.com/hook", ["package.yank"],
            Secret: "a-secret", Description: "signed"));

        var all = await repo.ListAsync("org1");
        Assert.Equal(2, all.Count);
        Assert.Contains(all, s => s.Url == "https://no-secret.example.com/hook" && !s.HasSecret);
        Assert.Contains(all, s => s.Url == "https://with-secret.example.com/hook" && s.HasSecret);
    }

    [Fact]
    public async Task AddAsync_EmptySecretWithoutMasterKey_StoresUnsignedWithoutThrowing()
    {
        // An empty-string secret means unsigned delivery. It must not reach
        // EnvelopeProtector.Protect (which throws when no master key is configured) —
        // otherwise create returns an unhandled 500 instead of succeeding unsigned.
        using var ep = MakeUnconfiguredProtector();
        Assert.False(ep.IsConfigured);
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://empty-secret.example.com/hook",
            ["package.publish"],
            Secret: "", Description: null));

        Assert.False(sub.HasSecret);

        await using var conn = await _db.OpenAsync();
        string? rawSecret = await conn.ExecuteScalarAsync<string>(
            "SELECT secret FROM webhook_subscription WHERE id = @id", new { id = sub.Id });
        Assert.Null(rawSecret);
    }

    [Fact]
    public async Task UpdateAsync_EmptySecretLeavesExistingSecretUnchanged()
    {
        // An empty secret on update is "no change", never a rotation to empty and never a
        // Protect call — the previously stored secret survives.
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://keep-secret.example.com/hook",
            ["package.publish"],
            Secret: "original-secret", Description: null));

        var updated = await repo.UpdateAsync("org1", sub.Id, new UpdateWebhookSubscription(
            sub.Url, sub.EventTypes, Enabled: true, Secret: "", Description: "changed"));

        Assert.NotNull(updated);
        Assert.True(updated!.HasSecret);

        var delivery = await repo.ListEnabledForEventAsync("org1", "package.publish");
        var match = delivery.FirstOrDefault(d => d.Id == sub.Id);
        Assert.NotNull(match);
        Assert.Equal("original-secret", match!.Secret);
    }

    // ── Auto-disable: count threshold ─────────────────────────────────────────

    [Fact]
    public async Task RecordFailureAsync_AutoDisablesAfterConsecutiveThreshold()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://fail.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        // Invoke failures up to threshold - 1: should NOT auto-disable
        for (int i = 0; i < WebhookDispatchQueue.AutoDisableAfterFailures - 1; i++)
        {
            bool disabled = await repo.RecordFailureAsync("org1", sub.Id, "err",
                WebhookDispatchQueue.AutoDisableAfterFailures,
                WebhookDispatchQueue.AutoDisableAfterDuration);
            Assert.False(disabled, $"Should not disable at failure {i + 1}");
        }

        // Final failure crosses the threshold — should auto-disable
        bool finalDisabled = await repo.RecordFailureAsync("org1", sub.Id, "err",
            WebhookDispatchQueue.AutoDisableAfterFailures,
            WebhookDispatchQueue.AutoDisableAfterDuration);
        Assert.True(finalDisabled);

        var updated = await repo.GetAsync("org1", sub.Id);
        Assert.False(updated!.Enabled);
    }

    [Fact]
    public async Task RecordFailureAsync_AutoDisablesWhenDurationWindowExceeded()
    {
        // Use a very short duration to trigger the time-based auto-disable quickly.
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://timeout.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        // Manually set failing_since to 49 hours ago so the window is already exceeded
        string staleFailingSince = Clock.GetUtcNow().AddHours(-49).ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE webhook_subscription SET failing_since = @s WHERE id = @id",
            new { s = staleFailingSince, id = sub.Id });

        // Even the first new failure should now trigger auto-disable because duration elapsed
        bool disabled = await repo.RecordFailureAsync("org1", sub.Id, "timeout",
            WebhookDispatchQueue.AutoDisableAfterFailures,
            WebhookDispatchQueue.AutoDisableAfterDuration);
        Assert.True(disabled);

        var updated = await repo.GetAsync("org1", sub.Id);
        Assert.False(updated!.Enabled);
    }

    [Fact]
    public async Task RecordSuccessAsync_ResetsFailureCounters()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://recover.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        // Record some failures
        await repo.RecordFailureAsync("org1", sub.Id, "err",
            WebhookDispatchQueue.AutoDisableAfterFailures,
            WebhookDispatchQueue.AutoDisableAfterDuration);

        await repo.RecordSuccessAsync("org1", sub.Id);

        var updated = await repo.GetAsync("org1", sub.Id);
        Assert.Equal(0, updated!.ConsecutiveFailures);
        Assert.Null(updated.FailingSince);
        Assert.Null(updated.LastError);
        Assert.Equal("ok", updated.LastStatus);
    }

    // ── Mixed partial-failure fan-out ─────────────────────────────────────────

    /// <summary>
    /// When two subscriptions are registered for the same event and one succeeds while the
    /// other fails, outcomes are accounted independently — the successful subscription resets
    /// its failure counter and the failing one increments its own. Neither affects the other.
    ///
    /// This test exercises the repository-level accounting that the dispatch queue relies on:
    /// <see cref="WebhookSubscriptionRepository.RecordSuccessAsync"/> and
    /// <see cref="WebhookSubscriptionRepository.RecordFailureAsync"/> are called on a per-
    /// subscription basis, so a batch failure in one subscription never contaminates another.
    /// </summary>
    [Fact]
    public async Task FanOut_PartialFailure_OutcomesAreAccountedIndependently()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var subGood = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        var subBad = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://bad.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        // Pre-condition: both start clean (0 failures)
        Assert.Equal(0, subGood.ConsecutiveFailures);
        Assert.Equal(0, subBad.ConsecutiveFailures);

        // Simulate what the dispatch queue would do: good sub succeeds, bad sub fails.
        // Both operations must be independent — bad failure must not affect good.
        await repo.RecordSuccessAsync("org1", subGood.Id);
        await repo.RecordFailureAsync("org1", subBad.Id, "502 Bad Gateway",
            WebhookDispatchQueue.AutoDisableAfterFailures,
            WebhookDispatchQueue.AutoDisableAfterDuration);

        // Simulate a second round: good succeeds again, bad fails again.
        await repo.RecordSuccessAsync("org1", subGood.Id);
        await repo.RecordFailureAsync("org1", subBad.Id, "502 Bad Gateway",
            WebhookDispatchQueue.AutoDisableAfterFailures,
            WebhookDispatchQueue.AutoDisableAfterDuration);

        var afterGood = await repo.GetAsync("org1", subGood.Id);
        var afterBad = await repo.GetAsync("org1", subBad.Id);

        // Good subscription: zero failures, success status, still enabled
        Assert.NotNull(afterGood);
        Assert.Equal(0, afterGood!.ConsecutiveFailures);
        Assert.Equal("ok", afterGood.LastStatus);
        Assert.True(afterGood.Enabled);

        // Bad subscription: 2 failures (one per round), still enabled (threshold not reached)
        Assert.NotNull(afterBad);
        Assert.Equal(2, afterBad!.ConsecutiveFailures);
        Assert.Equal("failed", afterBad.LastStatus);
        Assert.True(afterBad.Enabled);
    }

    /// <summary>
    /// Full end-to-end partial-failure fan-out through the running queue: dispatching one event
    /// to two subscriptions where the HTTP endpoint is up for one ("good") and returns 502 for
    /// the other ("bad") results in exactly one delivered and eventually one failed count.
    /// Because the queue retries on failure, the "bad" subscription goes through the full
    /// backoff schedule before being counted as failed. The test waits for the outcome.
    /// </summary>
    [Fact(Timeout = 90_000)]
    public async Task FanOut_QueueEndToEnd_OneSucceeds_OneFails_IndependentCounters()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook2",
            ["package.publish"],
            Secret: null, Description: null));

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://bad.example.com/hook2",
            ["package.publish"],
            Secret: null, Description: null));

        var mockClient = BuildPartialFailureClient();

        var queue = new WebhookDispatchQueue(
            repo, mockClient, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope(eventType: "package.publish", orgId: "org1"));

        // now-ok: polling real async queue until both subscriptions have a terminal outcome.
        // "bad" sub goes through 1s + 5s + 30s retries before failing, so allow 60s.
        await WaitAsync(() => queue.DeliveredCount + queue.FailedCount >= 2, TimeSpan.FromSeconds(60));

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);
    }

    // ── Overflow / drop path ──────────────────────────────────────────────────

    [Fact]
    public void Dispatch_WhenChannelFull_DropsAndIncrementsCounter()
    {
        // Use real instances but never start the consumer, so nothing is dequeued.
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        var httpClient = new HttpClient(new PartialFailureDelegatingHandler(null, null));
        var client = new WebhookDeliveryClient(httpClient);

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["WEBHOOK_QUEUE_CAPACITY"] = "1" })
            .Build();

        var queue = new WebhookDispatchQueue(repo, client, cfg,
            NullLogger<WebhookDispatchQueue>.Instance);

        // Enqueue 5 without starting the consumer (channel capacity = 1)
        for (int i = 0; i < 5; i++)
        {
            queue.Dispatch(SampleEnvelope());
        }

        // 1 slot fits in the channel; the remaining 4 must be dropped.
        Assert.Equal(4, queue.DroppedCount);
    }

    // ── SSRF URL validation ───────────────────────────────────────────────────

    [Theory]
    [InlineData("http://169.254.169.254/metadata", false, "blocked")]
    [InlineData("http://127.0.0.1/hook", false, "blocked")]
    [InlineData("http://[::1]/hook", false, "blocked")]
    [InlineData("http://10.0.0.1/hook", false, "private")] // blocked when allowPrivate=false
    [InlineData("http://192.168.1.1/hook", false, "private")]
    [InlineData("http://172.16.0.1/hook", false, "private")]
    [InlineData("http://10.0.0.1/hook", true, null)]       // allowed when allowPrivate=true
    [InlineData("https://example.com/hook", false, null)]  // always allowed
    [InlineData("ftp://example.com/hook", false, "scheme")]
    public void ValidateWebhookUrl_RejectsBlockedRangesAndSchemes(
        string url, bool allowPrivate, string? expectedFragment)
    {
        string? error = WebhookDeliveryClient.ValidateWebhookUrl(url, allowPrivate);

        if (expectedFragment is null)
        {
            Assert.Null(error);
        }
        else
        {
            Assert.NotNull(error);
        }
    }

    // ── Infrastructure helpers ────────────────────────────────────────────────

    private static IConfiguration BuildCfg(int capacity = 1024) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WEBHOOK_QUEUE_CAPACITY"] = capacity.ToString()
            })
            .Build();

    /// <summary>
    /// Builds a <see cref="WebhookDeliveryClient"/> backed by a fake HTTP handler that
    /// succeeds for URLs containing "good" and returns 502 for URLs containing "bad".
    /// Uses the same construction pattern as production (new HttpClient(handler)).
    /// </summary>
    private static WebhookDeliveryClient BuildPartialFailureClient(
        Action? onGood = null, Action? onBad = null)
    {
        var handler = new PartialFailureDelegatingHandler(onGood, onBad);
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        return new WebhookDeliveryClient(http);
    }

    private sealed class PartialFailureDelegatingHandler : DelegatingHandler
    {
        private readonly Action? _onGood;
        private readonly Action? _onBad;

        public PartialFailureDelegatingHandler(Action? onGood, Action? onBad)
            : base(new HttpClientHandler())
        {
            _onGood = onGood;
            _onBad = onBad;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri?.ToString() ?? "";
            if (url.Contains("good"))
            {
                _onGood?.Invoke();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }

            _onBad?.Invoke();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway));
        }
    }
}
