using System.Net;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// With an org's proxy passthrough off, no Maven request reaches an upstream registry: an
/// artifact miss, a SNAPSHOT freshness check on a cached alias and a <c>maven-metadata.xml</c>
/// render all answer from local state. The passthrough-on twins prove each stub is reachable, so
/// a zero count means the gate held rather than the stub missing.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MavenProxyPassthroughTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Group = "com.example.passthru";
    private const string GroupPath = "com/example/passthru";

    private readonly DependablyFactory _factory;

    public MavenProxyPassthroughTests(DependablyFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        await ((IAsyncLifetime)_factory).InitializeAsync();
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE upstream_registry SET url = @url WHERE org_id = @orgId AND ecosystem = 'maven'",
            new { url = _factory.MockUpstream.Urls[0], orgId });
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetPassthroughAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private static string NewArtifactId() => $"lib{Guid.NewGuid():N}"[..16];

    private int UpstreamRequests(string artifactId) =>
        _factory.MockUpstream.LogEntries.Count(e =>
            e.RequestMessage?.Path?.Contains(artifactId, StringComparison.Ordinal) == true);

    private void StubReleaseJar(string artifactId, string version)
    {
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{GroupPath}/{artifactId}/{version}/{artifactId}-{version}.jar").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/java-archive")
                .WithBody(Encoding.UTF8.GetBytes($"jar bytes {artifactId}")));
    }

    private void StubSnapshot(string artifactId, string version)
    {
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{GroupPath}/{artifactId}/{version}/maven-metadata.xml").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{GroupPath}/{artifactId}/{version}/{artifactId}-{version}.jar").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/java-archive")
                .WithBody(Encoding.UTF8.GetBytes($"snapshot bytes {artifactId}")));
    }

    private void StubVersionList(string artifactId, string version)
    {
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{GroupPath}/{artifactId}/maven-metadata.xml").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody($"""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <metadata><groupId>{Group}</groupId><artifactId>{artifactId}</artifactId>
                    <versioning><versions><version>{version}</version></versions></versioning></metadata>
                    """));
    }

    [Fact]
    public async Task ArtifactMiss_PassthroughOn_FetchesUpstreamAndServes()
    {
        string id = NewArtifactId();
        StubReleaseJar(id, "1.0.0");
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var resp = await client.GetAsync($"/maven/{GroupPath}/{id}/1.0.0/{id}-1.0.0.jar");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(UpstreamRequests(id) >= 1);
    }

    [Fact]
    public async Task ArtifactMiss_PassthroughOff_Returns404_AndSendsNothingUpstream()
    {
        string id = NewArtifactId();
        StubReleaseJar(id, "1.0.0");
        await SetPassthroughAsync(false);
        try
        {
            using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

            var jar = await client.GetAsync($"/maven/{GroupPath}/{id}/1.0.0/{id}-1.0.0.jar");
            var sidecar = await client.GetAsync($"/maven/{GroupPath}/{id}/1.0.0/{id}-1.0.0.jar.sha1");

            Assert.Equal(HttpStatusCode.NotFound, jar.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, sidecar.StatusCode);
            Assert.Equal(0, UpstreamRequests(id));
        }
        finally
        {
            await SetPassthroughAsync(true);
        }
    }

    [Fact]
    public async Task SnapshotFreshness_PassthroughOn_ChecksUpstreamMetadataOnCacheHit()
    {
        string id = NewArtifactId();
        StubSnapshot(id, "1.0-SNAPSHOT");
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        string path = $"/maven/{GroupPath}/{id}/1.0-SNAPSHOT/{id}-1.0-SNAPSHOT.jar";

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);
        int afterFirst = UpstreamRequests(id);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);

        Assert.True(UpstreamRequests(id) > afterFirst);
    }

    [Fact]
    public async Task SnapshotFreshness_PassthroughOff_ServesCachedAlias_AndSendsNothingUpstream()
    {
        string id = NewArtifactId();
        StubSnapshot(id, "1.0-SNAPSHOT");
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        string path = $"/maven/{GroupPath}/{id}/1.0-SNAPSHOT/{id}-1.0-SNAPSHOT.jar";
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);
        int afterFirst = UpstreamRequests(id);
        Assert.True(afterFirst >= 1);

        await SetPassthroughAsync(false);
        try
        {
            var resp = await client.GetAsync(path);

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal(afterFirst, UpstreamRequests(id));
        }
        finally
        {
            await SetPassthroughAsync(true);
        }
    }

    [Fact]
    public async Task Metadata_PassthroughOn_MergesUpstreamVersions()
    {
        string id = NewArtifactId();
        StubVersionList(id, "2.0.0");
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var resp = await client.GetAsync($"/maven/{GroupPath}/{id}/maven-metadata.xml");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("<version>2.0.0</version>", await resp.Content.ReadAsStringAsync());
        Assert.True(UpstreamRequests(id) >= 1);
    }

    [Fact]
    public async Task Metadata_PassthroughOff_RendersLocalOnly_AndSendsNothingUpstream()
    {
        string id = NewArtifactId();
        StubVersionList(id, "2.0.0");
        await SetPassthroughAsync(false);
        try
        {
            using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

            var resp = await client.GetAsync($"/maven/{GroupPath}/{id}/maven-metadata.xml");

            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
            Assert.Equal(0, UpstreamRequests(id));
        }
        finally
        {
            await SetPassthroughAsync(true);
        }
    }
}
