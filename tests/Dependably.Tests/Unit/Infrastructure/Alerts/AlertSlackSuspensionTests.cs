using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// A suspended/archived/deleting org's Slack alert is never delivered (see TenantLifecycle) — the
/// webhook URL is tenant-supplied, exactly the third-party egress the suspension is meant to stop.
///
/// Regression coverage for a gap an adversarial review found: <see cref="AlertSlackQueue"/>'s
/// <c>TenantLifecycle.IsActive(...)</c> check had no test that would fail if the check were removed
/// or made to fail open. Every assertion below pairs the negative probe with the adversarial twin
/// (an active org's alert in the SAME pass is still delivered), matching every other worker's
/// suspension test in this repo.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlertSlackSuspensionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly EnvelopeProtector _protector = MakeProtector();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

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

    private async Task<AlertRecord> SeedOrgWithAlertAsync(string orgId, string status)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, status) VALUES (@orgId, @orgId, @status)",
            new { orgId, status });

        var settings = new AlertSettingsRepository(_db, _protector, Clock);
        await settings.UpdateSlackAsync(orgId, new UpdateAlertSlack(
            SlackEnabled: true, SlackWebhookUrl: $"https://{orgId}-endpoint.example.com/hook"));

        var alerts = new AlertRepository(_db, Clock);
        var alert = await alerts.TryInsertAsync(new NewAlert(
            orgId, AlertTypes.QuarantineNew, Severity: null, SourceRef: Guid.NewGuid().ToString("N"),
            Ecosystem: "npm", Purl: $"pkg:npm/{orgId}-pkg@1.0.0",
            Title: "New quarantine item", Detail: null));
        return alert!;
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task DeliverAsync_NeverDeliversTo_ANonActiveOrgsSlackWebhook_ButStillDeliversAnActiveOrgInTheSamePass(
        string nonActiveStatus)
    {
        var handler = new RecordingDelegatingHandler();
        var lockedAlert = await SeedOrgWithAlertAsync("locked", nonActiveStatus);
        var liveAlert = await SeedOrgWithAlertAsync("live", "active");

        var queue = BuildQueue(handler);

        bool lockedConclusion = await queue.DeliverAsync(lockedAlert, CancellationToken.None);
        bool liveConclusion = await queue.DeliverAsync(liveAlert, CancellationToken.None);

        Assert.True(lockedConclusion);
        Assert.True(liveConclusion);

        // Negative probe: no POST to the suspended org's webhook.
        Assert.DoesNotContain(handler.Requests, r => r.Contains("locked-endpoint", StringComparison.Ordinal));
        // Adversarial twin: the active org's webhook IS reached.
        Assert.Contains(handler.Requests, r => r.Contains("live-endpoint", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DeliverAsync_ResumesDelivery_OnceTheOrgIsReinstated()
    {
        var handler = new RecordingDelegatingHandler();
        var alert = await SeedOrgWithAlertAsync("reinstated", "suspended");
        var queue = BuildQueue(handler);

        await queue.DeliverAsync(alert, CancellationToken.None);
        Assert.Empty(handler.Requests);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE orgs SET status = 'active' WHERE id = 'reinstated'");
        }

        await queue.DeliverAsync(alert, CancellationToken.None);
        Assert.Contains(handler.Requests, r => r.Contains("reinstated-endpoint", StringComparison.Ordinal));
    }

    /// <summary>
    /// A soft-deleted org (<c>orgs.deleted_at</c> set) is not active even though its <c>status</c>
    /// column is untouched at <c>'active'</c> — see <see cref="Dependably.Infrastructure.TenantLifecycle.IsActive(Dependably.Infrastructure.Org?)"/>.
    /// </summary>
    [Fact]
    public async Task DeliverAsync_NeverDeliversTo_ASoftDeletedOrgsSlackWebhook_EvenThoughStatusIsStillActive()
    {
        var alert = await SeedOrgWithAlertAsync("softdeleted", "active");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @now WHERE id = 'softdeleted'",
                new { now = Clock.GetUtcNow().ToUtcIso() });
        }

        var handler = new RecordingDelegatingHandler();
        var queue = BuildQueue(handler);

        await queue.DeliverAsync(alert, CancellationToken.None);
        Assert.Empty(handler.Requests);
    }

    private AlertSlackQueue BuildQueue(HttpMessageHandler handler)
    {
        var settings = new AlertSettingsRepository(_db, _protector, Clock);
        var alerts = new AlertRepository(_db, Clock);
        var client = new SlackWebhookClient(new HttpClient(handler));
        var cfg = new ConfigurationBuilder().Build();
        return new AlertSlackQueue(
                   new AlertSlackQueueServices(
                   settings, alerts, client, new OrgRepository(_db), Clock, cfg, NullLogger<AlertSlackQueue>.Instance));
    }

    private sealed class RecordingDelegatingHandler : DelegatingHandler
    {
        public List<string> Requests { get; } = [];

        public RecordingDelegatingHandler() : base(new HttpClientHandler()) { }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri?.ToString() ?? "");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
