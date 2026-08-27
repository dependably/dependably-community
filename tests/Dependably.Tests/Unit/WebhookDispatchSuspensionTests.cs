using System.Net;
using System.Security.Cryptography;
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
/// A suspended/archived/deleting org's webhook subscriptions never receive a delivery attempt
/// (see TenantLifecycle) — the subscription URL is tenant-owned, exactly the third-party egress
/// the suspension is meant to stop. Checked in <see cref="WebhookDispatchQueue.FanOutAsync"/>
/// against the envelope's current org status rather than at enqueue time, so an envelope queued
/// moments before suspension still sees the status at delivery time.
///
/// Every mixed-pass assertion pairs the negative probe (the non-active org's endpoint receives
/// zero requests) with its adversarial twin (an active org's endpoint in the SAME pass still
/// receives its delivery) — proving the queue skips one org's lane rather than the whole pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class WebhookDispatchSuspensionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task SeedOrgAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });
    }

    private static PackageEventEnvelope SampleEnvelope(string orgId) => new(
        EventType: "package.publish",
        OrgId: orgId,
        OrgSlug: orgId,
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

    // ── Direct FanOutAsync check (no running queue) ─────────────────────────────

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task FanOut_NeverDeliversTo_ANonActiveOrgsSubscription(string nonActiveStatus)
    {
        await SeedOrgAsync("locked", nonActiveStatus);

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        await repo.AddAsync("locked", new NewWebhookSubscription(
            "https://locked-endpoint.example.com/hook", ["package.publish"],
            Secret: null, Description: null));

        var handler = new RecordingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, new OrgRepository(_db), Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);

        bool reachedConclusion = await queue.FanOutAsyncForTests(SampleEnvelope("locked"), CancellationToken.None);

        Assert.True(reachedConclusion);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task FanOut_ResumesDelivery_OnceTheOrgIsReinstated()
    {
        await SeedOrgAsync("reinstated", "suspended");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        await repo.AddAsync("reinstated", new NewWebhookSubscription(
            "https://reinstated-endpoint.example.com/hook", ["package.publish"],
            Secret: null, Description: null));

        var handler = new RecordingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, new OrgRepository(_db), Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);

        await queue.FanOutAsyncForTests(SampleEnvelope("reinstated"), CancellationToken.None);
        Assert.Empty(handler.Requests);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET status = 'active' WHERE id = 'reinstated'");
        }

        await queue.FanOutAsyncForTests(SampleEnvelope("reinstated"), CancellationToken.None);
        Assert.Single(handler.Requests);
    }

    /// <summary>
    /// A soft-deleted org (<c>orgs.deleted_at</c> set) is not active even though
    /// <c>UpdateOrgStatusAsync</c> never touches <c>status</c> — <c>OrgRepository.SoftDeleteAsync</c>
    /// leaves it at <c>'active'</c>. Every SQL call site pairs <c>o.deleted_at IS NULL</c> with
    /// <c>o.status = 'active'</c>; this pins the in-process form (<see cref="TenantLifecycle.IsActive(Org?)"/>)
    /// against the same gap, closing the window a status-only check would otherwise leave open for
    /// the whole 30-day soft-delete restore grace period.
    /// </summary>
    [Fact]
    public async Task FanOut_NeverDeliversTo_ASoftDeletedOrgsSubscription_EvenThoughStatusIsStillActive()
    {
        await SeedOrgAsync("softdeleted", "active");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @now WHERE id = 'softdeleted'",
                new { now = Clock.GetUtcNow().ToUtcIso() });
        }

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        await repo.AddAsync("softdeleted", new NewWebhookSubscription(
            "https://softdeleted-endpoint.example.com/hook", ["package.publish"],
            Secret: null, Description: null));

        var handler = new RecordingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, new OrgRepository(_db), Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);

        await queue.FanOutAsyncForTests(SampleEnvelope("softdeleted"), CancellationToken.None);
        Assert.Empty(handler.Requests);
    }

    // ── Full running queue: the adversarial twin ────────────────────────────────

    /// <summary>
    /// End-to-end through the running queue (not the direct <c>FanOutAsyncForTests</c> call
    /// above): dispatching an event for a suspended org and, in the same running pass, an event
    /// for an active org — only the active org's endpoint is ever POSTed to.
    /// </summary>
    [Fact]
    public async Task Dispatch_SuspendedOrgEnvelope_NeverDelivered_ButAnActiveOrgsEnvelope_StillIs()
    {
        await SeedOrgAsync("locked", "suspended");
        await SeedOrgAsync("live", "active");

        using var ep = MakeProtector();
        var repo = new WebhookSubscriptionRepository(_db, ep, Clock);
        await repo.AddAsync("locked", new NewWebhookSubscription(
            "https://locked-endpoint.example.com/hook", ["package.publish"],
            Secret: null, Description: null));
        var subLive = await repo.AddAsync("live", new NewWebhookSubscription(
            "https://live-endpoint.example.com/hook", ["package.publish"],
            Secret: null, Description: null));

        var handler = new RecordingDelegatingHandler();
        var client = new WebhookDeliveryClient(new HttpClient(handler));
        var queue = new WebhookDispatchQueue(
            repo, client, new OrgRepository(_db), Clock, BuildCfg(), NullLogger<WebhookDispatchQueue>.Instance);
        using var cts = new CancellationTokenSource();
        _ = queue.StartAsync(cts.Token);

        queue.Dispatch(SampleEnvelope("locked"));
        queue.Dispatch(SampleEnvelope("live"));

        await WaitAsync(async () => (await repo.GetAsync("live", subLive.Id))?.LastStatus is not null);

        try { await queue.StopAsync(CancellationToken.None); } catch { }

        Assert.Single(handler.Requests);
        Assert.Equal("https://live-endpoint.example.com/hook", handler.Requests[0].Url);
        Assert.DoesNotContain(handler.Requests, r => r.Url == "https://locked-endpoint.example.com/hook");

        var lockedSub = (await repo.ListEnabledForEventAsync("locked", "package.publish", default)).Single();
        Assert.Null((await repo.GetAsync("locked", lockedSub.Id))!.LastStatus);
    }

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

    private static IConfiguration BuildCfg(int capacity = 1024) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WEBHOOK_QUEUE_CAPACITY"] = capacity.ToString(),
            })
            .Build();

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
}
