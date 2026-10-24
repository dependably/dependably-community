using System.Xml.Linq;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Two full-host replicas behind one load balancer: each has its own reservation list, settings
/// cache, org epoch and rendered Maven cache, and they share the database and the invalidation
/// channel. A management change handled by replica A must change what replica B serves on its
/// very next request.
/// </summary>
public sealed partial class MavenControllerProxyTests
{
    [Fact]
    public async Task PeerReplica_ReservationAddedOnA_BsNextRequestServesNoUpstreamVersions()
    {
        const string artifactId = "peer-reserved";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        StubUpstreamMetadata(artifactPath, "9.9.9");
        var (a, b) = TwoReplicas();

        // B renders and caches the merged document, and caches the empty reservation list.
        Assert.Equal(["1.0", "9.9.9"], await ReplicaVersionsAsync(b, artifactPath));

        await a.Reserved.AddAsync(_orgId, "maven", RaceGroupId, _userId);

        Assert.Equal(["1.0"], await ReplicaVersionsAsync(b, artifactPath));
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));
    }

    [Fact]
    public async Task PeerReplica_ProxySettingsChangedOnA_BsNextRequestRendersTheNewPolicy()
    {
        const string artifactId = "peer-settings";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "2.0");
        await DeprecateLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        var (a, b) = TwoReplicas();

        Assert.Equal(["1.0", "2.0"], await ReplicaVersionsAsync(b, artifactPath));

        // What the proxy-settings PUT on A does: commit the policy, then invalidate the org.
        await SetBlockDeprecatedAsync("block_all");
        a.Coordinator.InvalidateOrg(_orgId);

        Assert.Equal(["2.0"], await ReplicaVersionsAsync(b, artifactPath));
    }

    /// <summary>
    /// Adversarial twin: an org-wide change for a different org on A leaves B's cached document
    /// for this org in place, so B keeps serving it without asking upstream again.
    /// </summary>
    [Fact]
    public async Task PeerReplica_ChangeForAnotherOrgOnA_LeavesBsDocumentCached()
    {
        const string artifactId = "peer-other-org";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        StubUpstreamMetadata(artifactPath, "9.9.9");
        var (a, b) = TwoReplicas();

        Assert.Equal(["1.0", "9.9.9"], await ReplicaVersionsAsync(b, artifactPath));

        a.Coordinator.InvalidateOrg("some-other-org");

        Assert.Equal(["1.0", "9.9.9"], await ReplicaVersionsAsync(b, artifactPath));
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));
        Assert.Equal(1, b.Endpoint.Applied);
    }

    private (TestInvalidationReplica A, TestInvalidationReplica B) TwoReplicas()
    {
        var channel = new InMemoryInvalidationChannel();
        return (
            TestInvalidationReplica.Join(channel, _db, TimeProvider.System),
            TestInvalidationReplica.Join(channel, _db, TimeProvider.System));
    }

    private async Task<string[]> ReplicaVersionsAsync(TestInvalidationReplica replica, string artifactPath)
    {
        var result = await BuildController(
                CleanOsv(), metadataCache: replica.Maven, reservedNamespaces: replica.Reserved, orgs: replica.Orgs)
            .Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        var content = Assert.IsType<ContentResult>(result);
        return XDocument.Parse(content.Content!)
            .Descendants("version")
            .Select(v => v.Value)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }
}
