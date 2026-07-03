using System.Net;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end for the edge-node metadata TTL cache: a headless edge whose sole upstream is one
/// master serves PyPI JSON-API metadata locally, and — once the master goes down — keeps
/// resolving from the cached copy within the serve-stale window instead of failing the install.
///
/// This pins the effectiveness case for the edge: version-resolving installs (npm/pip) fetch
/// metadata FIRST, so without a metadata cache a flaky link to the master breaks resolution even
/// when every artifact is warm. Edge mode enables the cache by default (120s positive TTL). The
/// PyPI JSON-API path (<c>GET /pypi/{name}/json</c>) proxies metadata straight through
/// <c>UpstreamClient.GetOrFetchMetadataAsync</c> with no rendered-response cache in front, so a
/// frozen clock advanced past the TTL exercises the serve-stale path directly.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeMetadataCacheTests
{
    private const string EdgeToken = DependablyFactory.DefaultEdgeToken;

    [Fact]
    public async Task EdgePyPiJson_ServedStale_WhenMasterDown_WithinMaxStale()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            MasterKey = Convert.ToBase64String(new byte[32]),
            FrozenClock = clock,
        };

        string name = $"edgemeta{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string masterPath = $"/pypi/{name}/json";
        string jsonDoc = $$"""
            { "info": { "name": "{{name}}", "version": "1.0.0" },
              "releases": { "1.0.0": [] } }
            """;

        // Master JSON-API route — gated on the edge Bearer token so a hit proves auth attaches.
        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath)
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(jsonDoc));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBasic(token);

        // Cold fetch warms the metadata cache from the master.
        var cold = await client.GetAsync($"/pypi/{name}/json");
        Assert.Equal(HttpStatusCode.OK, cold.StatusCode);
        Assert.Contains("1.0.0", await cold.Content.ReadAsStringAsync());
        Assert.Equal(1, MasterCalls(f, masterPath));

        // The master goes down: the JSON route now 503s.
        f.MockUpstream.Reset();
        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));

        // Within the positive TTL (edge default 120s): a warm hit serves from cache, master
        // untouched (Reset cleared the log; still no upstream call).
        clock.Advance(TimeSpan.FromSeconds(60));
        var warm = await client.GetAsync($"/pypi/{name}/json");
        Assert.Equal(HttpStatusCode.OK, warm.StatusCode);
        Assert.Contains("1.0.0", await warm.Content.ReadAsStringAsync());
        Assert.Equal(0, MasterCalls(f, masterPath));

        // Past the TTL but within max-stale: the refresh fetch hits the master (now 503), and the
        // stale JSON document is served rather than failing the resolution.
        clock.Advance(TimeSpan.FromSeconds(120));
        var stale = await client.GetAsync($"/pypi/{name}/json");
        Assert.Equal(HttpStatusCode.OK, stale.StatusCode);
        Assert.Contains("1.0.0", await stale.Content.ReadAsStringAsync());
        // The stale serve attempted one refresh against the (down) master.
        Assert.True(MasterCalls(f, masterPath) >= 1);
    }

    private static int MasterCalls(DependablyFactory f, string path) =>
        f.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));
}
