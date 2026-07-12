using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end for the headless edge deployment mode: a node whose sole upstream for every
/// ecosystem is one central master, authenticated with one reader token. Boots the host with
/// <c>DEPLOYMENT_MODE=edge</c> pointed at the WireMock master, then asserts:
///   1. No admin user or system_admin is created; a single implicit org exists; upstream_registry
///      holds exactly the seeded master rows with the encrypted-at-rest edge token.
///   2. A proxy cache-miss on npm + PyPI + NuGet fetches from the stubbed master WITH the
///      Authorization header attached (the stub only matches when the header is present),
///      verifies the checksum, stores in the cache tier, and a second request is a warm hit that
///      fires no further upstream call.
///
/// Each test uses its own edge factory so the WireMock master URL is pinned into EDGE_MASTER_URL
/// before first boot.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeModeTests
{
    private const string EdgeToken = DependablyFactory.DefaultEdgeToken;

    private static DependablyFactory NewEdgeFactory() => new()
    {
        DeploymentMode = "edge",
        // Envelope-encrypt the seeded edge token at rest (mirrors a production edge with a KEK).
        MasterKey = Convert.ToBase64String(new byte[32]),
    };

    [Fact]
    public async Task EdgeBoot_NoAdminUser_SingleOrg_UpstreamRowsPointAtMasterWithAuth()
    {
        await using var f = NewEdgeFactory();
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM users"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM system_admins"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM orgs"));

        string masterHost = new Uri(f.MockUpstream.Urls[0]).Host;
        var rows = (await conn.QueryAsync<(string Ecosystem, string Url, string AuthType, string? Secret)>(
            "SELECT ecosystem AS Ecosystem, url AS Url, auth_type AS AuthType, secret AS Secret FROM upstream_registry ORDER BY ecosystem")).ToList();

        var ecosystems = rows.Select(r => r.Ecosystem).OrderBy(e => e, StringComparer.Ordinal).ToList();
        Assert.Equal(new[] { "apk", "cargo", "golang", "maven", "npm", "nuget", "oci", "pypi", "rpm" }, ecosystems);
        Assert.All(rows, r =>
        {
            Assert.Contains(masterHost, r.Url);
            // Every seeded row carries the edge token, encrypted at rest (never anonymous/plaintext).
            Assert.NotNull(r.Secret);
            Assert.StartsWith("enc:v1:", r.Secret);
        });
        Assert.Equal("bearer", rows.Single(r => r.Ecosystem == "npm").AuthType);
        Assert.Equal("basic", rows.Single(r => r.Ecosystem == "oci").AuthType);
    }

    [Fact]
    public async Task EdgeProxy_NpmTarballMiss_FetchesFromMasterWithAuth_ThenWarmHit()
    {
        await using var f = NewEdgeFactory();
        string name = $"edgenpm{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string version = "1.0.0";
        var (tarball, sha256, _) = NpmFixtures.BuildTarball(name, version);
        string file = $"{name}-{version}.tgz";
        string masterPath = $"/npm/{name}/-/{file}";

        // Stub the master npm tarball route — ONLY matches when the edge presents the Bearer token,
        // so a successful fetch proves the Authorization header was attached.
        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath)
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBearer(token);

        var miss = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, miss.StatusCode);
        Assert.Equal(tarball, await miss.Content.ReadAsByteArrayAsync());
        Assert.Equal(1, MasterCalls(f, masterPath));

        // Second request is a warm cache hit — no further upstream call.
        var hit = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, hit.StatusCode);
        Assert.Equal(1, MasterCalls(f, masterPath));

        Assert.Contains(sha256, AllCacheShas(f));
    }

    [Fact]
    public async Task EdgeProxy_NuGetFlatContainerMiss_FetchesFromMasterWithAuth_ThenWarmHit()
    {
        await using var f = NewEdgeFactory();
        string id = $"Edge.NuGet.{Guid.NewGuid():N}"[..22];
        string version = "1.0.0";
        var (bytes, sha256) = NuGetFixtures.BuildNupkg(id, version);
        string lower = id.ToLowerInvariant();
        string file = $"{lower}.{version}.nupkg";
        string masterPath = $"/nuget/flatcontainer/{lower}/{version}/{file}";

        f.MockUpstream
            .Given(Request.Create().WithPath(masterPath)
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await f.CreateToken("pull");
        using var client = f.CreateClientWithBasic(token);

        var miss = await client.GetAsync(masterPath);
        Assert.Equal(HttpStatusCode.OK, miss.StatusCode);
        Assert.Equal(bytes, await miss.Content.ReadAsByteArrayAsync());
        Assert.Equal(1, MasterCalls(f, masterPath));

        var hit = await client.GetAsync(masterPath);
        Assert.Equal(HttpStatusCode.OK, hit.StatusCode);
        Assert.Equal(1, MasterCalls(f, masterPath));

        Assert.Contains(sha256, AllCacheShas(f));
    }

    [Fact]
    public async Task EdgeProxy_PyPiWheelMiss_FetchesFromMasterWithAuth_ThenWarmHit()
    {
        await using var f = NewEdgeFactory();
        string name = $"edgepypi{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string version = "1.0.0";
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = PyPiFixtures.BuildWheel(name, version);

        string masterBase = f.MockUpstream.Urls[0];
        string fileMasterPath = $"/edge-files/{filename}";
        string simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{masterBase}{fileMasterPath}#sha256={sha256Hex}">{filename}</a>
            </body></html>
            """;

        // Master simple index and the file download are both gated on the edge Bearer token.
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

        var miss = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, miss.StatusCode);
        Assert.Equal(wheelBytes, await miss.Content.ReadAsByteArrayAsync());
        Assert.Equal(1, MasterCalls(f, fileMasterPath));

        var hit = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, hit.StatusCode);
        // Warm hit serves from cache — no second file download from the master.
        Assert.Equal(1, MasterCalls(f, fileMasterPath));

        Assert.Contains(sha256Hex, AllCacheShas(f));
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private static int MasterCalls(DependablyFactory f, string path) =>
        f.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));

    // The in-memory blob store keys proxy blobs by their content-addressed SHA-256 (last path
    // segment). Returns the stored SHAs so tests can assert a verified cache-tier write.
    private static List<string> AllCacheShas(DependablyFactory f) =>
        f.BlobStore.GetKeys().Select(k => k.Split('/').Last()).ToList();
}
