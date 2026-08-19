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

    /// <summary>
    /// Production's retry schedule with the intervals removed, for the tests whose subject is the
    /// terminal outcome of the retry chain rather than its pacing. The same four attempts run and
    /// the durable bookkeeping is identical; what disappears is the need to drive a clock from the
    /// test to let the chain proceed, which is a race the test cannot win reliably on a loaded
    /// machine. The intervals themselves are pinned where they belong — in the tests that assert
    /// on backoff and on the per-envelope budget, which keep the real schedule.
    /// </summary>
    private static readonly TimeSpan[] NoBackoff =
        [TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero];

    /// <summary>
    /// Polls the DURABLE end state (the persisted subscription row) rather than the queue's in-memory
    /// counters. The counters are incremented only after the outcome write lands, so they do imply
    /// durable state — but asserting on the row keeps the test independent of that internal
    /// ordering, so a future reordering of the queue's bookkeeping cannot silently reintroduce a
    /// race between the counter and the write.
    /// </summary>
    private static async Task WaitAsync(Func<Task<bool>> condition, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting real async completion of the durable write path
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (!await condition() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        if (!await condition())
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
        string staleFailingSince = Clock.GetUtcNow().AddHours(-49).ToUtcIso();
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

    /// <summary>
    /// The lost-update this counter used to permit, made deterministic. A competing writer lands
    /// its own failures in the window a read-then-write leaves open — the window a second dispatch
    /// worker or a second replica occupies in production — and the counter must still end up
    /// holding every failure that happened.
    ///
    /// The interleave is driven from the injected clock rather than from real threads on purpose:
    /// <c>Microsoft.Data.Sqlite</c> executes its async API synchronously, so parallel tasks against
    /// this store cannot interleave at all and a thread-race test here would pass over a broken
    /// counter. The repository reads the clock once for the timestamp and once for the
    /// auto-disable window; firing the competing write on that second read places it exactly in
    /// the gap a read-then-write has and an atomic increment does not.
    /// </summary>
    [Fact]
    public async Task RecordFailureAsync_CompetingWriterLandsMidCall_NoFailureIsLost()
    {
        using var ep = MakeProtector();
        var sub = await new WebhookSubscriptionRepository(_db, ep, Clock).AddAsync(
            "org1",
            new NewWebhookSubscription(
                "https://raced.example.com/hook", ["package.publish"], Secret: null, Description: null));

        // Seven other failures for the same subscription land while this call is in flight.
        var racingClock = new HookOnSecondReadTimeProvider(() =>
        {
            using var conn = _db.OpenAsync().GetAwaiter().GetResult();
            conn.Execute(
                // xtenant: a test's competing writer, keyed by the subscription id under test
                "UPDATE webhook_subscription SET consecutive_failures = consecutive_failures + 7 WHERE id = @id",
                new { id = sub.Id });
        });

        var repo = new WebhookSubscriptionRepository(_db, ep, racingClock);
        await repo.RecordFailureAsync("org1", sub.Id, "502 Bad Gateway",
            WebhookDispatchQueue.AutoDisableAfterFailures, WebhookDispatchQueue.AutoDisableAfterDuration);

        var afterRace = await repo.GetAsync("org1", sub.Id);
        Assert.Equal(8, afterRace!.ConsecutiveFailures);

        // And the next failure counts from the true total, not from what this call thought it wrote.
        var plain = new WebhookSubscriptionRepository(_db, ep, Clock);
        await plain.RecordFailureAsync("org1", sub.Id, "502 Bad Gateway",
            WebhookDispatchQueue.AutoDisableAfterFailures, WebhookDispatchQueue.AutoDisableAfterDuration);
        Assert.Equal(9, (await plain.GetAsync("org1", sub.Id))!.ConsecutiveFailures);
    }

    /// <summary>
    /// A <see cref="TimeProvider"/> that runs a callback on its second <c>GetUtcNow</c>, used to
    /// land a competing write in the middle of a repository call deterministically.
    /// </summary>
    private sealed class HookOnSecondReadTimeProvider : TimeProvider
    {
        private readonly Action _onSecondRead;
        private int _reads;

        public HookOnSecondReadTimeProvider(Action onSecondRead) => _onSecondRead = onSecondRead;

        public override DateTimeOffset GetUtcNow()
        {
            if (Interlocked.Increment(ref _reads) == 2)
            {
                _onSecondRead();
            }

            return TestTime.KnownNow;
        }
    }

    /// <summary>
    /// Exactly one failure — the one that lands on the threshold — reports the auto-disable, and
    /// the subscription ends up disabled. This is an invariant that must survive the change to an
    /// atomic increment, not evidence for it: four sequential failures behave the same either way,
    /// so it passes on a read-then-write counter too. The distinguishing case is concurrent, and
    /// <see cref="RecordFailureAsync_CompetingWriterLandsMidCall_NoFailureIsLost"/> is what pins it.
    /// </summary>
    [Fact]
    public async Task RecordFailureAsync_FailureLandingOnTheThreshold_IsTheOneThatReportsAutoDisable()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://threshold.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        const int remaining = 4;
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE webhook_subscription SET consecutive_failures = @n WHERE id = @id",
                new { n = WebhookDispatchQueue.AutoDisableAfterFailures - remaining, id = sub.Id });
        }

        var disabled = new List<bool>();
        for (int i = 0; i < remaining; i++)
        {
            disabled.Add(await repo.RecordFailureAsync("org1", sub.Id, "502 Bad Gateway",
                WebhookDispatchQueue.AutoDisableAfterFailures,
                WebhookDispatchQueue.AutoDisableAfterDuration));
        }

        var reread = await repo.GetAsync("org1", sub.Id);
        Assert.Equal(WebhookDispatchQueue.AutoDisableAfterFailures, reread!.ConsecutiveFailures);
        Assert.False(reread.Enabled);
        Assert.Equal(1, disabled.Count(d => d));
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
    /// retry chain before being counted as failed. The chain runs on <see cref="NoBackoff"/>, so
    /// it reaches that terminal outcome without the test waiting out — or hand-driving a clock
    /// through — the real 36-second (1s + 5s + 30s) schedule.
    /// </summary>
    [Fact]
    public async Task FanOut_QueueEndToEnd_OneSucceeds_OneFails_IndependentCounters()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var subGood = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook2",
            ["package.publish"],
            Secret: null, Description: null));

        var subBad = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://bad.example.com/hook2",
            ["package.publish"],
            Secret: null, Description: null));

        var mockClient = BuildPartialFailureClient();

        var queue = new WebhookDispatchQueue(
            repo, mockClient, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance,
            NoBackoff);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope(eventType: "package.publish", orgId: "org1"));

        // Wait on the DURABLE end state (the persisted subscription rows) rather than the
        // in-memory counters, so the assertion does not depend on the queue's internal increment
        // ordering. No clock is driven: the retry chain has no intervals left to wait out.
        await WaitAsync(async () =>
        {
            var good = await repo.GetAsync("org1", subGood.Id);
            var bad = await repo.GetAsync("org1", subBad.Id);
            return good?.LastStatus is not null && bad?.LastStatus is not null;
        });

        // Graceful drain — StopAsync signals ExecuteAsync's stopping token itself, but by the
        // time we get here both durable writes have already landed, so there is nothing
        // in-flight left for a cancellation to interrupt.
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);
    }

    // ── Cross-tenant non-delivery ────────────────────────────────────────────

    /// <summary>
    /// Two orgs each register an enabled subscription for the same event type. Dispatching a
    /// <see cref="PackageEventEnvelope"/> for org1 only must never reach org2's endpoint — the
    /// existing multi-org tests (<see cref="FanOut_QueueEndToEnd_OneSucceeds_OneFails_IndependentCounters"/>)
    /// prove independent per-org *outcomes* but never assert that the wrong tenant's URL received
    /// zero requests. This is the "must-NOT" twin: org2's URL gets no POST at all, and the one
    /// delivered body carries only org1's slug/data.
    /// </summary>
    [Fact]
    public async Task Dispatch_EventForOrg1_NeverDeliveredToOrg2Endpoint()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        var webhookClock = new FakeTimeProvider(Clock.GetUtcNow());

        var subOrg1 = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://org1-endpoint.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        var subOrg2 = await repo.AddAsync("org2", new NewWebhookSubscription(
            "https://org2-endpoint.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        var handler = new RecordingDelegatingHandler();
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var client = new WebhookDeliveryClient(http);

        var queue = new WebhookDispatchQueue(
            repo, client, webhookClock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope(eventType: "package.publish", orgId: "org1", orgSlug: "acme"));

        await WaitAsync(async () => (await repo.GetAsync("org1", subOrg1.Id))?.LastStatus is not null);

        // Graceful drain — StopAsync signals ExecuteAsync's stopping token itself, but by the
        // time we get here the durable write has already landed, so there is nothing in-flight
        // left for a cancellation to interrupt.
        try { await queue.StopAsync(CancellationToken.None); } catch { }

        // Exactly one POST was ever sent, and it went to org1's endpoint — org2's endpoint
        // received nothing at all.
        Assert.Single(handler.Requests);
        var (url, body) = handler.Requests[0];
        Assert.Equal("https://org1-endpoint.example.com/hook", url);
        Assert.DoesNotContain(handler.Requests, r => r.Url == "https://org2-endpoint.example.com/hook");

        // The delivered body carries org1's slug and no trace of org2's.
        Assert.Contains("\"acme\"", body);
        Assert.DoesNotContain("beta", body);

        // org2's subscription was never touched: no delivery attempted, no failure recorded.
        var org2Sub = await repo.GetAsync("org2", subOrg2.Id);
        Assert.NotNull(org2Sub);
        Assert.Null(org2Sub!.LastStatus);
        Assert.Equal(0, org2Sub.ConsecutiveFailures);
    }

    /// <summary>Records every request as an (url, body) pair and always returns 200 OK. Used by
    /// cross-tenant non-delivery tests, which need to know exactly which URL(s) were called —
    /// not just an aggregate count or the last body, unlike <see cref="PartialFailureDelegatingHandler"/>.</summary>
    private sealed class RecordingDelegatingHandler : DelegatingHandler
    {
        public List<(string Url, string Body)> Requests { get; } = [];

        public RecordingDelegatingHandler() : base(new HttpClientHandler()) { }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri?.ToString() ?? "";
            string body = request.Content is null
                ? ""
                : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add((url, body));
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    // ── Shutdown mid-bookkeeping (host-stopping token cancelled after send succeeds) ──

    /// <summary>
    /// Simulates host shutdown landing in the window between the webhook POST succeeding and
    /// the durable outcome write: the fake handler cancels the stopping token synchronously,
    /// before returning the 200 response, so <see cref="WebhookDispatchQueue.DeliverToSubscriptionAsync"/>
    /// resumes with an already-cancelled token. The delivery must still be recorded as durable
    /// state (not lost to a swallowed <see cref="OperationCanceledException"/>), and
    /// <see cref="WebhookDispatchQueue.DeliveredCount"/> must only report 1 once that write has
    /// actually landed.
    /// </summary>
    [Fact]
    public async Task DeliverToSubscriptionAsync_ShutdownCancelsTokenRightAfterSendSucceeds_OutcomeStillRecorded()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        using var cts = new CancellationTokenSource();
        var handler = new CancelOnSendHandler(cts);
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var client = new WebhookDeliveryClient(http);

        var queue = new WebhookDispatchQueue(
            repo, client, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);
        var delivery = new WebhookSubscriptionDelivery(
            sub.Id, "org1", sub.Url, Secret: null, sub.EventTypes, sub.ConsecutiveFailures, sub.FailingSince);

        // Drives the delivery path directly (no queue/BackgroundService loop needed) with a
        // token that gets cancelled synchronously the instant the POST "lands" — the exact
        // window the shutdown bug races.
        await queue.DeliverToSubscriptionAsync(SampleEnvelope(), delivery, cts.Token);

        Assert.True(cts.IsCancellationRequested);
        Assert.Equal(1, queue.DeliveredCount);

        var reread = await repo.GetAsync("org1", sub.Id);
        Assert.Equal("ok", reread!.LastStatus);
        Assert.Equal(0, reread.ConsecutiveFailures);
    }

    /// <summary>
    /// Same shutdown-window scenario on the terminal-failure path: once retries are exhausted,
    /// the failure bookkeeping (which drives auto-disable) must also survive a stopping token
    /// cancelled at the moment the last attempt finishes. The chain runs on
    /// <see cref="NoBackoff"/> so the test reaches that final attempt without waiting out — or
    /// hand-driving a clock through — the real 1s/5s/30s schedule.
    /// </summary>
    [Fact]
    public async Task DeliverToSubscriptionAsync_ShutdownCancelsTokenRightAfterFinalAttemptFails_FailureStillRecorded()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://bad.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        using var cts = new CancellationTokenSource();
        var handler = new CancelOnFinalFailureHandler(cts);
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var client = new WebhookDeliveryClient(http);

        // Seed the subscription one failure short of the auto-disable threshold so this
        // delivery's failure crosses it — proving the auto-disable-driving count itself
        // survived the cancelled token, not just a generic status string.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE webhook_subscription SET consecutive_failures = @n WHERE id = @id",
                new { n = WebhookDispatchQueue.AutoDisableAfterFailures - 1, id = sub.Id });
        }

        var queue = new WebhookDispatchQueue(
            repo, client, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance,
            NoBackoff);
        var delivery = new WebhookSubscriptionDelivery(
            sub.Id, "org1", sub.Url, Secret: null, sub.EventTypes,
            ConsecutiveFailures: WebhookDispatchQueue.AutoDisableAfterFailures - 1, FailingSince: null);

        await queue.DeliverToSubscriptionAsync(SampleEnvelope(), delivery, cts.Token);

        Assert.True(cts.IsCancellationRequested);
        Assert.Equal(1, queue.FailedCount);

        var reread = await repo.GetAsync("org1", sub.Id);
        Assert.Equal("failed", reread!.LastStatus);
        Assert.False(reread.Enabled, "Auto-disable must still fire from the durably-recorded failure count.");
    }

    /// <summary>Cancels the given token synchronously right before returning a 200 response.</summary>
    private sealed class CancelOnSendHandler : DelegatingHandler
    {
        private readonly CancellationTokenSource _cancelOnSend;
        public CancelOnSendHandler(CancellationTokenSource cancelOnSend) : base(new HttpClientHandler())
        {
            _cancelOnSend = cancelOnSend;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _cancelOnSend.Cancel();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    /// <summary>
    /// Fails every attempt with 502; on the last attempt of the retry budget (1 initial + 3
    /// retries = 4 total), cancels the given token synchronously right before returning —
    /// simulating shutdown landing exactly as the retry budget is exhausted.
    /// </summary>
    private sealed class CancelOnFinalFailureHandler : DelegatingHandler
    {
        private readonly CancellationTokenSource _cancelOnFinal;
        private int _attempts;

        public CancelOnFinalFailureHandler(CancellationTokenSource cancelOnFinal)
            : base(new HttpClientHandler())
        {
            _cancelOnFinal = cancelOnFinal;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int attempt = Interlocked.Increment(ref _attempts);
            if (attempt >= 4)
            {
                _cancelOnFinal.Cancel();
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway));
        }
    }

    // ── Shutdown drain (channel still buffered when the stopping token is cancelled) ──

    /// <summary>
    /// Reproduces the shutdown-drop defect deterministically by invoking <c>ExecuteAsync</c>
    /// directly (via the <see cref="WebhookDispatchQueue.ExecuteAsyncForTests"/> test hook) with
    /// an already-cancelled token — <see cref="BackgroundService.StartAsync"/> itself
    /// short-circuits and never calls <c>ExecuteAsync</c> at all in that case, so it cannot
    /// exercise the real race being tested (a stopping token cancelled while the read loop is
    /// genuinely running, mid-shutdown, with an envelope still buffered). The main
    /// <c>ReadAllAsync</c> loop observes cancellation on its very first <c>WaitToReadAsync</c>
    /// call — before it ever gets a chance to dequeue — exactly like <c>ApplicationStopping</c>
    /// firing in that window. On the old code this drops the envelope silently; the shutdown
    /// drain must still deliver it.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_StillDrainsBufferedEnvelope()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook",
            ["package.publish"],
            Secret: null, Description: null));

        var mockClient = BuildPartialFailureClient();
        var queue = new WebhookDispatchQueue(
            repo, mockClient, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);

        // Buffer the envelope before the worker ever starts reading.
        queue.Dispatch(SampleEnvelope(eventType: "package.publish", orgId: "org1"));

        // Drives ExecuteAsync directly with an already-cancelled token — the exact state the
        // stopping token is in by the time BackgroundService.StopAsync signals cancellation.
        await queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        Assert.Equal(1, queue.DeliveredCount);
        var reread = await repo.GetAsync("org1", sub.Id);
        Assert.Equal("ok", reread!.LastStatus);
    }

    /// <summary>
    /// Mixed partial-failure variant of the same shutdown-drain scenario: two envelopes are
    /// buffered before <c>ExecuteAsync</c> runs with an already-cancelled token, one routed to a
    /// reachable endpoint and one to an unreachable one. The drain must deliver the first and
    /// durably record the second's failure, independently, mirroring
    /// <see cref="FanOut_QueueEndToEnd_OneSucceeds_OneFails_IndependentCounters"/> but through the
    /// shutdown-drain path instead of the normal read loop.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_DrainsMixedSuccessAndFailure()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var subGood = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/drain",
            ["package.publish"],
            Secret: null, Description: null));

        var subBad = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://bad.example.com/drain",
            ["package.publish"],
            Secret: null, Description: null));

        var mockClient = BuildPartialFailureClient();
        var queue = new WebhookDispatchQueue(
            repo, mockClient, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance,
            NoBackoff);

        // Both subscriptions match the same event type, so one Dispatch fans out to both — one
        // succeeds, one exhausts its retry budget — before the worker ever starts reading.
        queue.Dispatch(SampleEnvelope(eventType: "package.publish", orgId: "org1"));

        var executeTask = queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // The failing subscription runs its whole retry chain inside the drain itself, on
        // NoBackoff, so the drain completes without the test driving a clock through it.
        await WaitAsync(async () =>
        {
            var good = await repo.GetAsync("org1", subGood.Id);
            var bad = await repo.GetAsync("org1", subBad.Id);
            return good?.LastStatus is not null && bad?.LastStatus is not null;
        });

        await executeTask;

        Assert.Equal(1, queue.DeliveredCount);
        Assert.Equal(1, queue.FailedCount);

        var goodReread = await repo.GetAsync("org1", subGood.Id);
        var badReread = await repo.GetAsync("org1", subBad.Id);
        Assert.Equal("ok", goodReread!.LastStatus);
        Assert.Equal("failed", badReread!.LastStatus);
    }

    // ── Cross-tenant fairness ────────────────────────────────────────────────

    /// <summary>
    /// The cross-tenant property this queue exists to keep: org1's subscriber endpoint accepts
    /// the connection and never answers — the trivial slow-loris a tenant is free to point a
    /// subscription at, since it is a public address the SSRF guard has no reason to block — and
    /// org2's event must still be delivered while org1's delivery is still hanging.
    ///
    /// The wait is gated, not timed: org1's handler parks on a <see cref="TaskCompletionSource"/>
    /// the test controls, and the assertion is that org2's durable row reached "ok" while that
    /// gate is provably still closed. No clock is advanced, so nothing about the pass depends on
    /// timeouts or scheduling luck. A single process-wide reader cannot satisfy this at all:
    /// org2's envelope stays behind org1's for as long as org1's endpoint chooses.
    /// </summary>
    [Fact]
    public async Task Dispatch_OneOrgsEndpointHangs_AnotherOrgsEventIsStillDelivered()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://hang.example.com/hook", ["package.publish"], Secret: null, Description: null));
        var subOrg2 = await repo.AddAsync("org2", new NewWebhookSubscription(
            "https://good.example.com/hook", ["package.publish"], Secret: null, Description: null));

        var handler = new HangingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope(orgId: "org1", orgSlug: "acme"));
        await handler.HangEntered.Task;

        queue.Dispatch(SampleEnvelope(orgId: "org2", orgSlug: "beta"));
        await WaitAsync(async () => (await repo.GetAsync("org2", subOrg2.Id))?.LastStatus is not null);

        Assert.Equal("ok", (await repo.GetAsync("org2", subOrg2.Id))!.LastStatus);
        Assert.True(handler.IsParked,
            "org1's delivery must still be parked in its handler — otherwise the test proved nothing.");

        handler.HangReleased.TrySetResult();
        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }
    }

    /// <summary>
    /// The mixed partial-failure form of the same scenario, and the shape a real instance is in
    /// during an incident: one tenant's endpoint is hung while another tenant's fan-out has one
    /// endpoint answering and one failing. The healthy delivery lands, the failing one exhausts
    /// its retry budget and is durably recorded as failed, and the two are accounted
    /// independently — all while the first tenant's delivery is still hanging.
    ///
    /// Like its sibling above, the wait is gated rather than timed: org2's fan-out runs on
    /// <see cref="NoBackoff"/> so it reaches its terminal outcome with no clock involved, and
    /// org1 stays parked in its handler until the test releases it. Nothing about the pass
    /// depends on scheduling luck.
    /// </summary>
    [Fact]
    public async Task Dispatch_OneOrgsEndpointHangs_AnotherOrgsMixedFanOutStillCompletes()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://hang.example.com/hook", ["package.publish"], Secret: null, Description: null));
        var subGood = await repo.AddAsync("org2", new NewWebhookSubscription(
            "https://good.example.com/hook", ["package.publish"], Secret: null, Description: null));
        var subBad = await repo.AddAsync("org2", new NewWebhookSubscription(
            "https://bad.example.com/hook", ["package.publish"], Secret: null, Description: null));

        var handler = new HangingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance,
            NoBackoff);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope(orgId: "org1", orgSlug: "acme"));
        await handler.HangEntered.Task;

        queue.Dispatch(SampleEnvelope(orgId: "org2", orgSlug: "beta"));

        // No clock is driven here, which is also what keeps org1's hung delivery hanging for its
        // own reasons: the per-envelope fair-share budget runs on the injected clock, so a frozen
        // clock cannot cut org1 off mid-test and leave the fairness claim unproven.
        await WaitAsync(async () =>
        {
            var good = await repo.GetAsync("org2", subGood.Id);
            var bad = await repo.GetAsync("org2", subBad.Id);
            return good?.LastStatus is not null && bad?.LastStatus is not null;
        });

        Assert.Equal("ok", (await repo.GetAsync("org2", subGood.Id))!.LastStatus);
        Assert.Equal("failed", (await repo.GetAsync("org2", subBad.Id))!.LastStatus);
        Assert.Equal(1, (await repo.GetAsync("org2", subBad.Id))!.ConsecutiveFailures);
        Assert.True(handler.IsParked,
            "org1's delivery must still be parked in its handler — otherwise the test proved nothing.");

        handler.HangReleased.TrySetResult();
        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }
    }

    /// <summary>
    /// A fan-out handed an already-cancelled token stops at its pre-flight guard: no subscription
    /// is contacted, nothing is recorded, and it reports that it did not carry the envelope to a
    /// conclusion — which is what makes the envelope eligible to be drained rather than counted as
    /// delivered. This exercises the guard only; the fan-out never reaches the concurrency gate,
    /// so the gate's own cancellation contract is pinned by
    /// <see cref="FanOut_CancelledMidFanOut_ReturnsWithoutThrowing"/> instead.
    /// </summary>
    [Fact]
    public async Task FanOut_AlreadyCancelledToken_AttemptsNothing()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook", ["package.publish"], Secret: null, Description: null));

        var queue = new WebhookDispatchQueue(
            repo, BuildPartialFailureClient(), Clock, BuildCfg(),
            NullLogger<WebhookDispatchQueue>.Instance);

        bool completed = await queue.FanOutAsyncForTests(SampleEnvelope(), new CancellationToken(canceled: true));

        Assert.False(completed);
        Assert.Equal(0, queue.DeliveredCount);
        Assert.Equal(0, queue.FailedCount);
        Assert.Null((await repo.GetAsync("org1", sub.Id))!.LastStatus);
    }

    /// <summary>
    /// The same contract at the moment it actually bites: cancellation arriving <em>during</em> a
    /// fan-out, with more subscriptions than the concurrency bound so some are still queued behind
    /// the gate when it fires. Both of <see cref="SemaphoreSlim.WaitAsync(CancellationToken)"/>'s
    /// cancellation paths raise — including the one where a slot is free — so the waiters fault,
    /// and an unguarded <c>Task.WhenAll</c> rethrows out of the fan-out. That is the shutdown path:
    /// the drain calls the fan-out with a token that fires when the drain window closes, and has no
    /// handler of its own, so the exception escapes the whole <see cref="BackgroundService"/>.
    /// </summary>
    [Fact]
    public async Task FanOut_CancelledMidFanOut_ReturnsWithoutThrowing()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        for (int i = 0; i < 3; i++)
        {
            await repo.AddAsync("org1", new NewWebhookSubscription(
                $"https://good-{i}.example.com/hook", ["package.publish"],
                Secret: null, Description: null));
        }

        using var cts = new CancellationTokenSource();
        var client = new WebhookDeliveryClient(new HttpClient(new CancelOnSendHandler(cts)));

        // Concurrency 1, so the second and third subscriptions are still waiting on the gate when
        // the first delivery cancels the token.
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WEBHOOK_QUEUE_CAPACITY"] = "1024",
                ["WEBHOOK_FANOUT_CONCURRENCY"] = "1"
            })
            .Build();

        var queue = new WebhookDispatchQueue(
            repo, client, Clock, cfg, NullLogger<WebhookDispatchQueue>.Instance);

        await queue.FanOutAsyncForTests(SampleEnvelope(), cts.Token);

        Assert.True(cts.IsCancellationRequested);
    }

    /// <summary>Parks any request whose URL contains "hang" until the test releases it; 502 for
    /// "bad", 200 otherwise. The gate is what makes the fairness assertions deterministic — the
    /// hung delivery is provably still in flight at the moment the other org's outcome is
    /// asserted.</summary>
    private sealed class HangingDelegatingHandler : DelegatingHandler
    {
        private readonly bool _parkOnlyFirstRequest;
        private int _requests;
        private int _parked;

        public TaskCompletionSource HangEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource HangReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Whether a request is parked in the handler right now. This is what distinguishes
        /// "still hanging" from "cancelled out from under us": a delivery that gets cancelled
        /// leaves the park, while <see cref="HangReleased"/> stays uncompleted either way — so
        /// asserting on that source alone cannot tell the two apart, and passes green over a
        /// test that has stopped proving its point.
        /// </summary>
        public bool IsParked => Volatile.Read(ref _parked) == 1;

        public HangingDelegatingHandler(bool parkOnlyFirstRequest = false) : base(new HttpClientHandler())
        {
            _parkOnlyFirstRequest = parkOnlyFirstRequest;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri?.ToString() ?? "";
            bool park = url.Contains("hang")
                && (!_parkOnlyFirstRequest || Interlocked.Increment(ref _requests) == 1);
            if (park)
            {
                Interlocked.Exchange(ref _parked, 1);
                HangEntered.TrySetResult();
                try
                {
                    await HangReleased.Task.WaitAsync(cancellationToken);
                }
                finally
                {
                    Interlocked.Exchange(ref _parked, 0);
                }
            }

            return new HttpResponseMessage(
                url.Contains("bad") ? HttpStatusCode.BadGateway : HttpStatusCode.OK);
        }
    }

    // ── Stopping path ────────────────────────────────────────────────────────

    /// <summary>
    /// The fairness bound has to hold on the way down too. The shutdown drain has a bounded
    /// window, and if the first org drained can hold it open — a slow-loris endpoint is a tenant's
    /// own choice — then every other org's queued events are silently abandoned on every deploy
    /// and every restart. Running each drained envelope under the same per-envelope budget as
    /// normal service is what stops that: org1's hung endpoint costs its own budget and no more,
    /// and org2's envelope is still delivered.
    ///
    /// The budget runs on the injected clock, so the abandonment is reached by advancing virtual
    /// time rather than by waiting out a real deadline.
    /// </summary>
    [Fact]
    public async Task Drain_OneOrgsHungEndpoint_DoesNotConsumeAnotherOrgsShareOfTheWindow()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        var webhookClock = new FakeTimeProvider(Clock.GetUtcNow());

        var subHang = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://hang.example.com/hook", ["package.publish"], Secret: null, Description: null));
        var subGood = await repo.AddAsync("org2", new NewWebhookSubscription(
            "https://good.example.com/hook", ["package.publish"], Secret: null, Description: null));

        var handler = new HangingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WEBHOOK_QUEUE_CAPACITY"] = "1024",
                ["WEBHOOK_ENVELOPE_BUDGET_SECONDS"] = "30"
            })
            .Build();

        var queue = new WebhookDispatchQueue(
            repo, client, webhookClock, cfg, NullLogger<WebhookDispatchQueue>.Instance);

        // Both envelopes are queued before any worker runs, so both are drained rather than served.
        queue.Dispatch(SampleEnvelope(orgId: "org1", orgSlug: "acme"));
        queue.Dispatch(SampleEnvelope(orgId: "org2", orgSlug: "beta"));

        var executeTask = queue.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // KEEPS its pump, and keeps the real backoff schedule: virtual time IS this test's
        // subject. org1's endpoint accepts the connection and never answers, so the only thing
        // that ends its turn is WEBHOOK_ENVELOPE_BUDGET_SECONDS expiring on the injected clock —
        // until it does, org2's envelope never gets its share of the drain window. There is no
        // backoff chain to skip here: neither envelope retries.
        await ClockPump.UntilAsync(webhookClock, async () =>
            (await repo.GetAsync("org2", subGood.Id))?.LastStatus is not null,
            TimeSpan.FromSeconds(5), maxAdvances: 60);

        handler.HangReleased.TrySetResult();
        await executeTask;

        Assert.Equal("ok", (await repo.GetAsync("org2", subGood.Id))!.LastStatus);
        Assert.Equal(1, queue.DeliveredCount);

        // org1's envelope was abandoned on its own budget, so nothing terminal was recorded for it.
        Assert.Null((await repo.GetAsync("org1", subHang.Id))!.LastStatus);
    }

    /// <summary>
    /// An envelope a worker had already taken off its lane when the host began stopping is not
    /// lost: it goes back to the head of its lane and the drain delivers it. Dropping it instead
    /// costs one envelope per worker on every deploy, and the worker count is operator-configured,
    /// so the loss scales with the tuning knob.
    /// </summary>
    [Fact]
    public async Task InFlightEnvelopeInterruptedByShutdown_IsDeliveredByTheDrain()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://hang.example.com/hook", ["package.publish"], Secret: null, Description: null));

        // Parks the first attempt only: the retry the drain makes answers normally, so the
        // envelope's delivery is observable rather than merely re-queued.
        var handler = new HangingDelegatingHandler(parkOnlyFirstRequest: true);
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);

        using var cts = new CancellationTokenSource();
        var executeTask = queue.ExecuteAsyncForTests(cts.Token);

        queue.Dispatch(SampleEnvelope(orgId: "org1", orgSlug: "acme"));
        await handler.HangEntered.Task;

        await cts.CancelAsync();
        await executeTask;

        Assert.Equal("ok", (await repo.GetAsync("org1", sub.Id))!.LastStatus);
        Assert.Equal(1, queue.DeliveredCount);
    }

    /// <summary>
    /// A per-envelope budget configured past the platform's maximum timer duration must not reach
    /// the workers. The budget becomes a timer, and constructing that timer throws — once per
    /// envelope, inside a worker, where the pool's <see cref="Task.WhenAll(Task[])"/> leaves the
    /// fault unobserved while any sibling survives. The queue keeps delivering on the documented
    /// default instead, and the refusal is a startup warning rather than a silent loss of workers.
    /// </summary>
    [Fact]
    public async Task Dispatch_EnvelopeBudgetConfiguredBeyondTheTimerCeiling_StillDelivers()
    {
        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);

        var sub = await repo.AddAsync("org1", new NewWebhookSubscription(
            "https://good.example.com/hook", ["package.publish"], Secret: null, Description: null));

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WEBHOOK_QUEUE_CAPACITY"] = "1024",
                ["WEBHOOK_ENVELOPE_BUDGET_SECONDS"] = "2000000000"
            })
            .Build();

        var queue = new WebhookDispatchQueue(
            repo, BuildPartialFailureClient(), Clock, cfg, NullLogger<WebhookDispatchQueue>.Instance);

        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope(orgId: "org1", orgSlug: "acme"));
        await WaitAsync(async () => (await repo.GetAsync("org1", sub.Id))?.LastStatus is not null);

        Assert.Equal("ok", (await repo.GetAsync("org1", sub.Id))!.LastStatus);

        await cts.CancelAsync();
        try { await queue.StopAsync(CancellationToken.None); } catch { }
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

        var queue = new WebhookDispatchQueue(repo, client, Clock, cfg,
            NullLogger<WebhookDispatchQueue>.Instance);

        // Enqueue 5 without starting the consumer (queue depth = 1 per org)
        for (int i = 0; i < 5; i++)
        {
            queue.Dispatch(SampleEnvelope());
        }

        // 1 slot fits in the org's lane; the remaining 4 must be dropped.
        Assert.Equal(4, queue.DroppedCount);
    }

    /// <summary>
    /// Overflow is charged to the org that caused it. One org filling its lane must not cost
    /// another org its event — on a single shared buffer, a tenant publishing in a loop evicts
    /// every other tenant's notifications, which is the drop half of the same cross-tenant defect
    /// as the stall.
    /// </summary>
    [Fact]
    public async Task Dispatch_OneOrgFillsItsQueue_AnotherOrgsEventIsStillAccepted()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        var client = BuildPartialFailureClient();

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["WEBHOOK_QUEUE_CAPACITY"] = "1" })
            .Build();

        // Never started: nothing is dequeued, so org1's single slot stays occupied.
        var queue = new WebhookDispatchQueue(repo, client, Clock, cfg,
            NullLogger<WebhookDispatchQueue>.Instance);

        for (int i = 0; i < 5; i++)
        {
            queue.Dispatch(SampleEnvelope(orgId: "org1", orgSlug: "acme"));
        }

        Assert.Equal(4, queue.DroppedCount);

        queue.Dispatch(SampleEnvelope(orgId: "org2", orgSlug: "beta"));

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
