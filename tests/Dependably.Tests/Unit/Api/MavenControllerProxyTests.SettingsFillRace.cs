using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The Maven metadata render path over a host-shaped replica whose <see cref="OrgRepository"/>
/// caches settings in the same memory cache as its rendered documents. A settings read already in
/// flight when the proxy-settings PUT commits must not leave the pre-change policy cached, because
/// the next render captures the fresh epoch before reading settings and would store a document
/// rendered under the old policy, bound to that fresh epoch, for the full rendered TTL.
/// </summary>
public sealed partial class MavenControllerProxyTests
{
    [Fact]
    public async Task Metadata_SettingsFillStraddlingAProxySettingsPut_NextRenderUsesTheNewPolicy()
    {
        const string artifactId = "settings-fill";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "2.0");
        await DeprecateLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        var (replica, hooked, clock) = SettingsRaceReplica();

        // What the proxy-settings PUT does, landing between an in-flight settings read and its
        // cache write: commit through the settings repository (which clears the settings cache),
        // then invalidate the org (settings again, then the epoch and lookups).
        hooked.AfterRead = async () =>
        {
            await new OrgSettingsRepository(_db, replica.Orgs).UpsertProxySettingsAsync(
                _orgId, new ProxyPolicySettings(BlockDeprecated: "block_all"));
            replica.Coordinator.InvalidateOrg(_orgId);
        };
        var inFlight = await replica.Orgs.GetSettingsAsync(_orgId);
        Assert.Equal("off", inFlight!.BlockDeprecated);

        Assert.Equal(["2.0"], await ReplicaVersionsAsync(replica, artifactPath));

        // Past the settings TTL but well inside the rendered TTL: whatever the render stored is
        // what this replica keeps serving.
        clock.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal(["2.0"], await ReplicaVersionsAsync(replica, artifactPath));
    }

    /// <summary>
    /// Adversarial twin: when the in-flight settings read straddles nothing for this org (only
    /// another org is invalidated), the settings it read are cached and the document rendered
    /// from them is cached and reused, so the guard expires nothing it has no reason to.
    /// </summary>
    [Fact]
    public async Task Metadata_SettingsFillStraddlingAnotherOrgsChange_SettingsAndDocumentStayCached()
    {
        const string artifactId = "settings-fill-steady";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        StubUpstreamMetadata(artifactPath, "9.9.9");
        var (replica, hooked, _) = SettingsRaceReplica();

        hooked.AfterRead = () =>
        {
            replica.Coordinator.InvalidateOrg("some-other-org");
            return Task.CompletedTask;
        };
        Assert.NotNull(await replica.Orgs.GetSettingsAsync(_orgId));
        Assert.True(replica.HasCachedSettings(_orgId));

        Assert.Equal(["1.0", "9.9.9"], await ReplicaVersionsAsync(replica, artifactPath));
        Assert.Equal(["1.0", "9.9.9"], await ReplicaVersionsAsync(replica, artifactPath));
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));
    }

    private (TestInvalidationReplica Replica, AfterDbReadHookStore Hooked, FakeTimeProvider Clock) SettingsRaceReplica()
    {
        var clock = TestTime.Frozen();
        var hooked = new AfterDbReadHookStore(_db);
        var replica = TestInvalidationReplica.Join(new InMemoryInvalidationChannel(), hooked, clock);
        return (replica, hooked, clock);
    }
}
