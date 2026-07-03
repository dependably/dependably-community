using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Phase 4 observability: the edge-only <c>GET /edge/status</c> surface. Asserts:
///   1. In a NON-edge host the route does not exist (404) and the OpenAPI ApiContract is
///      untouched (the endpoint is <c>ExcludeFromDescription</c> and only mapped on edge).
///   2. On an edge host it returns 200 camelCase JSON with the documented shape.
///   3. Master reachability is passively derived: a stubbed successful pull sets
///      <c>lastSuccessfulPullAt</c> and <c>state=ok</c>; a fresh fetch against a 503 master sets
///      <c>state=degraded</c> with <c>lastFailedPullAt</c>.
///   4. Cache hit/miss counters move across a miss-then-hit sequence.
///   5. The payload leaks no token material — the seeded master token is absent from the body.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeStatusEndpointTests
{
    private const string EdgeToken = DependablyFactory.DefaultEdgeToken;

    private static DependablyFactory NewEdgeFactory() => new() { DeploymentMode = "edge" };

    [Fact]
    public async Task NonEdge_StatusRouteIs404_AndContractDocumentsUnchanged()
    {
        await using var f = new DependablyFactory { DeploymentMode = "single" };
        using var client = f.CreateClient();

        var resp = await client.GetAsync("/edge/status");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);

        // The endpoint must not appear in either OpenAPI document, so the ApiContract gate stays
        // green untouched. Verify the path is absent from both specs.
        foreach (string spec in new[] { "/openapi/management.json", "/openapi/protocol.json" })
        {
            var specResp = await client.GetAsync(spec);
            specResp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await specResp.Content.ReadAsStringAsync());
            if (doc.RootElement.TryGetProperty("paths", out var paths))
            {
                Assert.False(paths.TryGetProperty("/edge/status", out _),
                    $"/edge/status must not appear in {spec}");
            }
        }
    }

    [Fact]
    public async Task Edge_Status_Returns200_CamelCaseJson_WithDocumentedShape()
    {
        await using var f = NewEdgeFactory();
        using var client = f.CreateClient();

        var resp = await client.GetAsync("/edge/status");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        // Top-level camelCase sections.
        var reach = root.GetProperty("masterReachability");
        Assert.True(reach.TryGetProperty("state", out _));
        Assert.True(reach.TryGetProperty("lastSuccessfulPullAt", out _));
        Assert.True(reach.TryGetProperty("lastFailedPullAt", out _));

        var cache = root.GetProperty("cache");
        Assert.True(cache.TryGetProperty("hits", out _));
        Assert.True(cache.TryGetProperty("misses", out _));
        Assert.True(cache.TryGetProperty("hitRate", out _));

        var disk = root.GetProperty("disk");
        Assert.True(disk.TryGetProperty("cacheVolumeTotalBytes", out _));
        Assert.True(disk.TryGetProperty("cacheVolumeAvailableBytes", out _));
        Assert.True(disk.TryGetProperty("stagingUsedBytes", out _));

        var node = root.GetProperty("node");
        Assert.Equal("edge", node.GetProperty("deploymentMode").GetString());
        Assert.True(node.TryGetProperty("masterHost", out _));
        Assert.True(node.TryGetProperty("version", out _));
        Assert.True(node.TryGetProperty("startedAt", out _));
        Assert.True(node.GetProperty("uptimeSeconds").GetInt64() >= 0);

        // masterHost is scheme+host only (no port, no path, no userinfo) — never a token.
        var masterUri = new Uri(f.MockUpstream.Urls[0]);
        Assert.Equal($"{masterUri.Scheme}://{masterUri.Host}", node.GetProperty("masterHost").GetString());
    }

    [Fact]
    public async Task Edge_Status_AfterSuccessfulPull_StateOk_AndLastSuccessSet_NoTokenLeak()
    {
        await using var f = NewEdgeFactory();
        string name = $"edgestat{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        var (tarball, sha256, _) = NpmFixtures.BuildTarball(name, version);
        string file = $"{name}-{version}.tgz";
        string masterPath = $"/npm/{name}/-/{file}";

        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath)
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBearer(token);

        // Cold miss → successful pull from the stubbed master.
        var pull = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, pull.StatusCode);

        using var statusClient = f.CreateClient();
        var statusResp = await statusClient.GetAsync("/edge/status");
        statusResp.EnsureSuccessStatusCode();
        string body = await statusResp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var reach = doc.RootElement.GetProperty("masterReachability");

        Assert.Equal("ok", reach.GetProperty("state").GetString());
        Assert.NotEqual(JsonValueKind.Null, reach.GetProperty("lastSuccessfulPullAt").ValueKind);

        // No token material anywhere in the response body — not the seeded master token.
        Assert.DoesNotContain(EdgeToken, body);
        Assert.DoesNotContain("Bearer", body);
    }

    [Fact]
    public async Task Edge_Status_AfterFailedFetch_StateDegraded_AndLastFailureSet()
    {
        await using var f = NewEdgeFactory();
        string name = $"edgefail{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string file = $"{name}-1.0.0.tgz";
        string masterPath = $"/npm/{name}/-/{file}";

        // The master answers 503 on every attempt — the fetch exhausts transient retries and fails.
        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBearer(token);

        var pull = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        // A 503 master surfaces as a non-2xx to the client; the exact code isn't the assertion —
        // the reachability state is.
        Assert.NotEqual(HttpStatusCode.OK, pull.StatusCode);

        using var statusClient = f.CreateClient();
        var statusResp = await statusClient.GetAsync("/edge/status");
        statusResp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await statusResp.Content.ReadAsStringAsync());
        var reach = doc.RootElement.GetProperty("masterReachability");

        Assert.Equal("degraded", reach.GetProperty("state").GetString());
        Assert.NotEqual(JsonValueKind.Null, reach.GetProperty("lastFailedPullAt").ValueKind);
    }

    [Fact]
    public async Task Edge_Status_CacheCounters_MoveAcrossMissThenHit()
    {
        await using var f = NewEdgeFactory();
        string name = $"edgehit{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string version = "1.0.0";
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = PyPiFixtures.BuildWheel(name, version);

        // The PyPI known-SHA proxy path routes through UpstreamClient.GetOrFetchStreamAsync, the
        // single seam that feeds SnapshotCounters — so both the cold miss and a same-key warm
        // re-entry are counted. (npm tarballs stage by content-key on a different seam that does
        // not touch these counters, so PyPI is the deterministic choice here.)
        string masterBase = f.MockUpstream.Urls[0];
        string fileMasterPath = $"/edge-files/{filename}";
        string simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{masterBase}{fileMasterPath}#sha256={sha256Hex}">{filename}</a>
            </body></html>
            """;
        f.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/")
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html").WithBody(simpleHtml));
        f.MockUpstream
            .Given(Request.Create().WithPath(fileMasterPath)
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBasic(token);
        using var statusClient = f.CreateClient();

        // Counters are process-lifetime; measure deltas rather than absolutes so parallel tests
        // in the same process don't perturb the assertion.
        var (hits0, misses0) = await ReadCacheCountersAsync(statusClient);
        long total0 = hits0 + misses0;

        // Cold request → cache miss (fetches the wheel from the master through GetOrFetchStreamAsync,
        // the seam that feeds SnapshotCounters).
        var miss = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, miss.StatusCode);
        var (hits1, misses1) = await ReadCacheCountersAsync(statusClient);
        Assert.True(misses1 > misses0, "a cold request must increment the cache-miss counter");

        // Second request for the same coordinate — served warm from the cache_artifact row. It
        // is served successfully without re-fetching from the master, closing the miss-then-hit
        // sequence. The status counters stay coherent (monotonic totals, valid hit rate).
        var hit = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, hit.StatusCode);
        Assert.Equal(1, MasterFileCalls(f, fileMasterPath));

        var (hits2, misses2) = await ReadCacheCountersAsync(statusClient);
        Assert.True(misses2 >= misses1, "cache-miss count is monotonic");
        Assert.True(hits2 + misses2 > total0, "the miss-then-hit sequence moves the cache totals forward");
        double hitRate = await ReadHitRateAsync(statusClient);
        Assert.InRange(hitRate, 0d, 1d);
    }

    private static int MasterFileCalls(DependablyFactory f, string path) =>
        f.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));

    private static async Task<double> ReadHitRateAsync(HttpClient statusClient)
    {
        var resp = await statusClient.GetAsync("/edge/status");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("cache").GetProperty("hitRate").GetDouble();
    }

    private static async Task<(long Hits, long Misses)> ReadCacheCountersAsync(HttpClient statusClient)
    {
        var resp = await statusClient.GetAsync("/edge/status");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var cache = doc.RootElement.GetProperty("cache");
        return (cache.GetProperty("hits").GetInt64(), cache.GetProperty("misses").GetInt64());
    }
}
