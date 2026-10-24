using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// A reservation change takes effect on Maven metadata the moment the management request returns,
/// not when the rendered document's proxy TTL runs out. The Maven metadata cache key has no
/// proxy-versus-local component, so without an org-wide expiry a document rendered with upstream
/// versions before a reservation keeps serving them after it — and a local-only document rendered
/// under a reservation keeps hiding upstream after the reservation is lifted.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ReservedNamespaceMetadataEvictionTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string HostedVersion = "1.0.0";
    private const string UpstreamVersion = "9.9.9";

    private readonly DependablyFactory _factory;

    public ReservedNamespaceMetadataEvictionTests(DependablyFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        await ((IAsyncLifetime)_factory).InitializeAsync();

        // The default org's Maven upstream is seeded at Maven Central; point it at the mock so
        // the test never leaves the host.
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
        await conn.ExecuteAsync(
            "UPDATE upstream_registry SET url = @url WHERE org_id = @orgId AND ecosystem = 'maven'",
            new { url = _factory.MockUpstream.Urls[0], orgId });
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AddingAReservation_RebuildsCachedUpstreamMergedMetadata_WithoutAskingUpstream()
    {
        var (groupId, artifactId, upstreamPath) = await SeedCoordinateAsync();
        using var client = await PullClientAsync();
        using var admin = await AdminClientAsync();

        // Rendered and cached with the upstream version merged in.
        Assert.Equal([HostedVersion, UpstreamVersion], await VersionsAsync(client, groupId, artifactId));
        Assert.Equal(1, UpstreamRequests(upstreamPath));

        await ReserveAsync(admin, groupId);

        // The next read is rebuilt on the reserved path: the upstream version is gone and the
        // reserved name was not sent upstream again.
        Assert.Equal([HostedVersion], await VersionsAsync(client, groupId, artifactId));
        Assert.Equal(1, UpstreamRequests(upstreamPath));
    }

    [Fact]
    public async Task RemovingAReservation_RebuildsCachedLocalOnlyMetadata_WithUpstreamMerged()
    {
        var (groupId, artifactId, upstreamPath) = await SeedCoordinateAsync();
        using var client = await PullClientAsync();
        using var admin = await AdminClientAsync();

        string reservationId = await ReserveAsync(admin, groupId);

        // Rendered and cached on the local-only path.
        Assert.Equal([HostedVersion], await VersionsAsync(client, groupId, artifactId));
        Assert.Equal(0, UpstreamRequests(upstreamPath));

        var remove = await admin.DeleteAsync($"/api/v1/reserved-namespaces/{reservationId}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);

        Assert.Equal([HostedVersion, UpstreamVersion], await VersionsAsync(client, groupId, artifactId));
        Assert.Equal(1, UpstreamRequests(upstreamPath));
    }

    [Fact]
    public async Task AReservationOnAnotherGroup_StillExpiresTheOrgsCache_ButTheDocumentKeepsUpstream()
    {
        // The expiry is org-wide, so an unrelated reservation rebuilds this document too; the
        // rebuild must still merge upstream, because nothing reserved this coordinate.
        var (groupId, artifactId, upstreamPath) = await SeedCoordinateAsync();
        using var client = await PullClientAsync();
        using var admin = await AdminClientAsync();

        Assert.Equal([HostedVersion, UpstreamVersion], await VersionsAsync(client, groupId, artifactId));

        await ReserveAsync(admin, $"com.unrelated{Guid.NewGuid():N}"[..28]);

        Assert.Equal([HostedVersion, UpstreamVersion], await VersionsAsync(client, groupId, artifactId));
        Assert.True(UpstreamRequests(upstreamPath) >= 1);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<(string GroupId, string ArtifactId, string UpstreamPath)> SeedCoordinateAsync()
    {
        string groupId = $"com.rsvd{Guid.NewGuid():N}"[..20];
        const string artifactId = "lib";
        string upstreamPath = $"/{groupId.Replace('.', '/')}/{artifactId}/maven-metadata.xml";

        await _factory.PushMavenArtifact(groupId, artifactId, HostedVersion);
        _factory.MockUpstream
            .Given(Request.Create().WithPath(upstreamPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/xml")
                .WithBody(
                    $"""
                    <?xml version="1.0" encoding="UTF-8"?>
                    <metadata>
                      <groupId>{groupId}</groupId>
                      <artifactId>{artifactId}</artifactId>
                      <versioning>
                        <latest>{UpstreamVersion}</latest>
                        <release>{UpstreamVersion}</release>
                        <versions><version>{UpstreamVersion}</version></versions>
                      </versioning>
                    </metadata>
                    """));
        return (groupId, artifactId, upstreamPath);
    }

    private int UpstreamRequests(string upstreamPath) =>
        _factory.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, upstreamPath, StringComparison.Ordinal));

    private async Task<HttpClient> PullClientAsync() =>
        _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

    private async Task<HttpClient> AdminClientAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static async Task<string> ReserveAsync(HttpClient admin, string groupId)
    {
        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "maven", pattern = groupId });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        using var created = await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync());
        return created.RootElement.GetProperty("id").GetString()!;
    }

    private static async Task<List<string>> VersionsAsync(HttpClient client, string groupId, string artifactId)
    {
        var resp = await client.GetAsync($"/maven/{groupId.Replace('.', '/')}/{artifactId}/maven-metadata.xml");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = XDocument.Parse(await resp.Content.ReadAsStringAsync());
        return [.. doc.Descendants("version").Select(v => v.Value)];
    }
}
