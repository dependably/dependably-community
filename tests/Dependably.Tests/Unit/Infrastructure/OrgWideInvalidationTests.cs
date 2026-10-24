using Dapper;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The org-wide invalidation across replicas: two full-host replicas, each with its own
/// per-process caches, share one database and one in-memory pub/sub channel. A reservation or
/// settings change on replica A must reach replica B's reservation list, settings record,
/// rendered-metadata epoch and lookup outcomes for that org on B's next request, and touch
/// nothing B holds for another org.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgWideInvalidationTests : IClassFixture<InMemoryDbFixture>
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly InMemoryDbFixture _fixture;

    public OrgWideInvalidationTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task OrgWideInvalidationOnA_ClearsBsListSettingsEpochAndLookups_AndNotAnotherOrgs()
    {
        var d = await DeploymentAsync();
        await Deployment.WarmAsync(d.B, d.OrgA);
        await Deployment.WarmAsync(d.B, d.OrgB);

        d.A.Coordinator.InvalidateOrg(d.OrgA);

        Assert.False(d.B.HasCachedReservationList(d.OrgA));
        Assert.False(d.B.HasCachedSettings(d.OrgA));
        Assert.False(d.B.Maven.TryGet(MetadataKey(d.OrgA), out _));
        Assert.Null(d.B.Lookups.TryGet(LookupKey(d.OrgA)));

        // Adversarial twin: the same four entries for another org on the same replica survive.
        Assert.True(d.B.HasCachedReservationList(d.OrgB));
        Assert.True(d.B.HasCachedSettings(d.OrgB));
        Assert.True(d.B.Maven.TryGet(MetadataKey(d.OrgB), out _));
        Assert.NotNull(d.B.Lookups.TryGet(LookupKey(d.OrgB)));
    }

    [Fact]
    public async Task ReservationAddedOnA_IsSeenByBsNextCheck_WithoutWaitingOutTheListTtl()
    {
        var d = await DeploymentAsync();
        Assert.False(await d.B.Reserved.IsReservedAsync(d.OrgA, "maven", "com.acme.lib"));
        Assert.True(d.B.HasCachedReservationList(d.OrgA));

        await d.A.Reserved.AddAsync(d.OrgA, "maven", "com.acme", createdBy: null);

        Assert.True(await d.B.Reserved.IsReservedAsync(d.OrgA, "maven", "com.acme.lib"));
    }

    [Fact]
    public async Task ReservationDeletedOnA_IsSeenByBsNextCheck_WithoutWaitingOutTheListTtl()
    {
        var d = await DeploymentAsync();
        var entry = await d.A.Reserved.AddAsync(d.OrgA, "maven", "com.acme", createdBy: null);
        Assert.True(await d.B.Reserved.IsReservedAsync(d.OrgA, "maven", "com.acme.lib"));

        Assert.Equal(1, await d.A.Reserved.DeleteAsync(d.OrgA, entry.Id));

        Assert.False(await d.B.Reserved.IsReservedAsync(d.OrgA, "maven", "com.acme.lib"));
    }

    [Fact]
    public async Task ReservationChangeOnA_ExpiresBsRenderedMetadataAndLookups()
    {
        var d = await DeploymentAsync();
        await Deployment.WarmAsync(d.B, d.OrgA);

        await d.A.Reserved.AddAsync(d.OrgA, "maven", "com.acme", createdBy: null);

        Assert.False(d.B.Maven.TryGet(MetadataKey(d.OrgA), out _));
        Assert.Null(d.B.Lookups.TryGet(LookupKey(d.OrgA)));
    }

    [Fact]
    public async Task TheOrgWideMessageCarriesOnlyTheOrgId_AndThePublisherDoesNotReapplyItsOwn()
    {
        var d = await DeploymentAsync();

        await d.A.Reserved.AddAsync(d.OrgA, "maven", "com.acme", createdBy: null);

        string payload = Assert.Single(d.Channel.Payloads);
        Assert.True(MetadataInvalidationCodec.TryDecode(payload, out var decoded, out string origin));
        Assert.Equal(MetadataInvalidation.ForOrg(d.OrgA), decoded);
        Assert.Equal(d.A.Endpoint.Origin, origin);
        Assert.Equal(0, d.A.Endpoint.Applied);
        Assert.Equal(1, d.B.Endpoint.Applied);
    }

    [Fact]
    public async Task ReceivingTheSameOrgWideMessageTwice_IsHarmless()
    {
        var d = await DeploymentAsync();
        await Deployment.WarmAsync(d.B, d.OrgA);
        string payload = MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg(d.OrgA), origin: "peer");

        d.B.Endpoint.Receive(payload);
        d.B.Endpoint.Receive(payload);

        Assert.Equal(2, d.B.Endpoint.Applied);
        Assert.False(d.B.HasCachedReservationList(d.OrgA));
        Assert.Empty(await d.B.Reserved.ListAsync(d.OrgA));
        Assert.True(d.B.HasCachedReservationList(d.OrgA));
    }

    /// <summary>
    /// The receiver clears the inputs (reservation list, settings) before it expires the epoch.
    /// The epoch's expiry callback runs synchronously inside the bump, so it stands in for a
    /// rebuild that starts the instant the new epoch exists: it must find no cached list or
    /// settings, and a list it reads must already include the change committed on A. With the
    /// epoch bumped first, that rebuild would render from the cached pre-change list and store
    /// the result on the fresh epoch for the full metadata TTL.
    /// </summary>
    [Fact]
    public async Task ReceivedOrgWideMessage_ClearsInputsBeforeTheEpochMoves()
    {
        var d = await DeploymentAsync();
        await Deployment.WarmAsync(d.B, d.OrgA);
        await InsertReservationAsync(d.OrgA, "com.acme");

        bool? listCachedAtBump = null;
        bool? settingsCachedAtBump = null;
        IReadOnlyList<ReservedNamespaceEntry>? listReadAtBump = null;
        d.B.Epoch.GetToken(d.OrgA).RegisterChangeCallback(_ =>
        {
            listCachedAtBump = d.B.HasCachedReservationList(d.OrgA);
            settingsCachedAtBump = d.B.HasCachedSettings(d.OrgA);
            listReadAtBump = Task.Run(() => d.B.Reserved.ListAsync(d.OrgA)).GetAwaiter().GetResult();
        }, state: null);

        d.B.Endpoint.Receive(
            MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg(d.OrgA), origin: "peer"));

        Assert.False(listCachedAtBump);
        Assert.False(settingsCachedAtBump);
        Assert.NotNull(listReadAtBump);
        Assert.Contains(listReadAtBump, e => e.Pattern == "com.acme");
    }

    /// <summary>
    /// The reverse race: a list read on B that started before the message and finishes after it
    /// must not cache what it read. Its generation was snapshotted before the read and is
    /// cancelled by the clear, so the entry it stores is already expired and B's next check
    /// reads the committed list.
    /// </summary>
    [Fact]
    public async Task ListReadInFlightAcrossTheMessage_DoesNotCacheThePreChangeList()
    {
        var d = await DeploymentAsync();
        var readStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var inFlight = d.B.ReservationList.GetOrReadAsync(
            d.OrgA,
            async _ =>
            {
                readStarted.SetResult();
                await release.Task;
                return Array.Empty<ReservedNamespaceEntry>();
            },
            CancellationToken.None);
        await readStarted.Task;

        await d.A.Reserved.AddAsync(d.OrgA, "maven", "com.acme", createdBy: null);
        release.SetResult();
        Assert.Empty(await inFlight);

        Assert.False(d.B.HasCachedReservationList(d.OrgA));
        Assert.True(await d.B.Reserved.IsReservedAsync(d.OrgA, "maven", "com.acme.lib"));
    }

    /// <summary>
    /// A message for one org reaching a replica that never cached anything for it is a no-op,
    /// not an error: every step tolerates an absent entry.
    /// </summary>
    [Fact]
    public async Task OrgWideMessageForAColdOrg_AppliesWithoutError()
    {
        var d = await DeploymentAsync();

        var thrown = Record.Exception(() => d.A.Coordinator.InvalidateOrg(d.OrgB));

        Assert.Null(thrown);
        Assert.Equal(1, d.B.Endpoint.Applied);
    }

    /// <summary>
    /// A message naming a blank org is dropped before any step runs. Accepted, it would clear
    /// the reservation list and settings for that key and then throw at the epoch, which
    /// rejects a blank org.
    /// </summary>
    [Theory]
    [InlineData(" ")]
    [InlineData(" \t ")]
    public async Task OrgWideMessageWithABlankOrg_IsDroppedWithoutThrowingOrEvicting(string blankOrg)
    {
        var d = await DeploymentAsync();
        await Deployment.WarmAsync(d.B, d.OrgA);
        string payload = $"{{\"v\":1,\"origin\":\"peer\",\"ecosystem\":\"org\",\"org_id\":\"{blankOrg.Replace("\t", "\\t")}\"}}";

        var thrown = Record.Exception(() => d.B.Endpoint.Receive(payload));

        Assert.Null(thrown);
        Assert.Equal(0, d.B.Endpoint.Applied);
        Assert.True(d.B.HasCachedReservationList(d.OrgA));
        Assert.True(d.B.HasCachedSettings(d.OrgA));
        Assert.True(d.B.Maven.TryGet(MetadataKey(d.OrgA), out _));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static MavenMetadataKey MetadataKey(string orgId) => new(orgId, "com.acme.lib", "core");

    private static string LookupKey(string orgId) => PackageLookupCache.KeyFor(orgId, "maven", "com.acme.lib:core", null);

    private async Task InsertReservationAsync(string orgId, string pattern)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern)
            VALUES (@id, @orgId, 'maven', @pattern)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, pattern });
    }

    private async Task<Deployment> DeploymentAsync()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"owi-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"owi-b-{Guid.NewGuid():N}");
        var channel = new InMemoryInvalidationChannel();
        var time = TestTime.Frozen();
        var a = TestInvalidationReplica.Join(channel, _fixture.Store, time);
        var b = TestInvalidationReplica.Join(channel, _fixture.Store, time);
        return new Deployment(orgA, orgB, channel, a, b);
    }

    private sealed record Deployment(
        string OrgA,
        string OrgB,
        InMemoryInvalidationChannel Channel,
        TestInvalidationReplica A,
        TestInvalidationReplica B)
    {
        // Fills each of the four per-org caches on `replica` for `orgId` and checks each took.
        public static async Task WarmAsync(TestInvalidationReplica replica, string orgId)
        {
            await replica.Reserved.ListAsync(orgId);
            Assert.NotNull(await replica.Orgs.GetSettingsAsync(orgId));
            replica.Maven.Set(MetadataKey(orgId), [1, 2, 3], Ttl);
            await replica.Lookups.SingleFlightAsync(
                LookupKey(orgId),
                () => Task.FromResult(PackageLookupOutcome.VersionRequired("maven")),
                CancellationToken.None);

            Assert.True(replica.HasCachedReservationList(orgId));
            Assert.True(replica.HasCachedSettings(orgId));
            Assert.True(replica.Maven.TryGet(MetadataKey(orgId), out _));
            Assert.NotNull(replica.Lookups.TryGet(LookupKey(orgId)));
        }
    }
}
