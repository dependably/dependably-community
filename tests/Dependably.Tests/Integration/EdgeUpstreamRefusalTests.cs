using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Edge-node behavior for a deterministic upstream auth/policy refusal (401/403) from the sole
/// master upstream. A 403 is not a transient condition: the retry policy must not retry it, the
/// client must receive a distinguishable 502-family response, and the edge master-reachability
/// signal must not be polluted by it — a refusal is a verdict about the credential, not a
/// statement that the master is unreachable.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeUpstreamRefusalTests
{
    private const string EdgeToken = DependablyFactory.DefaultEdgeToken;

    [Fact]
    public async Task NpmTarball_MasterReturns403_SingleAttempt_502Refusal_NoMasterUnreachableRecorded()
    {
        await using var f = new DependablyFactory { DeploymentMode = "edge" };

        string name = $"edgerefuse{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string file = $"{name}-1.0.0.tgz";
        string masterPath = $"/npm/{name}/-/{file}";

        // The master refuses the tarball fetch — a deterministic policy/auth verdict, not a
        // transient failure. The request-count assertion below is what proves the retry loop
        // stopped after one attempt instead of hitting this stub three times.
        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.Forbidden));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBearer(token);

        var pull = await client.GetAsync($"/npm/tarballs/{name}/{file}");

        // 502-family refusal response, distinguishable in the body from the generic
        // "upstream unreachable" failure title.
        Assert.Equal(HttpStatusCode.BadGateway, pull.StatusCode);
        string body = await pull.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        string title = doc.RootElement.GetProperty("title").GetString()!;
        Assert.Contains("refused", title, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Upstream fetch failed", body);

        // Exactly one upstream attempt — the deterministic 401/403 verdict is never retried.
        Assert.Equal(1, MasterCalls(f, masterPath));

        // The edge master-reachability signal is not polluted by the refusal: this factory has
        // made no other upstream calls, so a failure recording would flip state to "degraded".
        // It stays "unknown" instead.
        using var statusClient = f.CreateClient();
        var statusResp = await statusClient.GetAsync("/edge/status");
        statusResp.EnsureSuccessStatusCode();
        using var statusDoc = JsonDocument.Parse(await statusResp.Content.ReadAsStringAsync());
        var reach = statusDoc.RootElement.GetProperty("masterReachability");
        Assert.Equal("unknown", reach.GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, reach.GetProperty("lastFailedPullAt").ValueKind);
    }

    // Mixed-outcome regression: within the same edge node, one artifact fetch is refused (403)
    // and a sibling artifact fetch succeeds. The refusal must not corrupt the reachability signal
    // that the concurrent successful fetch drives.
    [Fact]
    public async Task MixedBatch_OneRefusedOneSucceeds_SuccessDrivesReachability_RefusalDoesNotDegradeIt()
    {
        await using var f = new DependablyFactory { DeploymentMode = "edge" };

        string refusedName = $"edgerefuse{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string refusedFile = $"{refusedName}-1.0.0.tgz";
        string refusedPath = $"/npm/{refusedName}/-/{refusedFile}";

        string okName = $"edgeok{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        const string okVersion = "1.0.0";
        var (tarball, _, _) = NpmFixtures.BuildTarball(okName, okVersion);
        string okFile = $"{okName}-{okVersion}.tgz";
        string okPath = $"/npm/{okName}/-/{okFile}";

        f.MockUpstream
            .Given(Request.Create().WithPath(refusedPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.Forbidden));
        f.MockUpstream
            .Given(Request.Create().WithPath(okPath)
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBearer(token);

        var refused = await client.GetAsync($"/npm/tarballs/{refusedName}/{refusedFile}");
        Assert.Equal(HttpStatusCode.BadGateway, refused.StatusCode);
        Assert.Equal(1, MasterCalls(f, refusedPath));

        var ok = await client.GetAsync($"/npm/tarballs/{okName}/{okFile}");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        using var statusClient = f.CreateClient();
        var statusResp = await statusClient.GetAsync("/edge/status");
        statusResp.EnsureSuccessStatusCode();
        using var statusDoc = JsonDocument.Parse(await statusResp.Content.ReadAsStringAsync());
        var reach = statusDoc.RootElement.GetProperty("masterReachability");

        // The successful fetch is the only recorded reachability outcome — state reads "ok", not
        // "degraded" from the earlier refusal, and no failure timestamp was ever stamped.
        Assert.Equal("ok", reach.GetProperty("state").GetString());
        Assert.NotEqual(JsonValueKind.Null, reach.GetProperty("lastSuccessfulPullAt").ValueKind);
        Assert.Equal(JsonValueKind.Null, reach.GetProperty("lastFailedPullAt").ValueKind);
    }

    private static int MasterCalls(DependablyFactory f, string path) =>
        f.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));
}
