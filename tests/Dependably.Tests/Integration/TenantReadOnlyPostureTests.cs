using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for the <c>read_only</c> posture: narrower than the full lockout
/// <see cref="TenantSuspensionLockoutTests"/> pins. <c>TenantStatusEnforcementMiddleware</c>
/// admits a safe method (GET/HEAD/OPTIONS) on every plane and any write on the management plane
/// (<c>/api/v1/</c>), refusing only a state-changing protocol-plane request — the per-ecosystem
/// publish/upload/delete/yank routes. Every negative probe is paired with its active-org twin so
/// a gate that refuses nothing (or refuses everything, collapsing back to the suspended shape)
/// fails the assertion rather than passing vacuously.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantReadOnlyPostureTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── Protocol-plane writes refused ───────────────────────────────────────────

    [Fact]
    public async Task ReadOnly_OciBlobUpload_Refused_ActiveTwinSucceeds()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] activeBytes = RandomBytes(256);
        string activeDigest = Digest(activeBytes);
        using (var activeResp = await client.PostAsync(
            $"/v2/ro-oci/blobs/uploads/?digest={activeDigest}", new ByteArrayContent(activeBytes)))
        {
            Assert.Equal(HttpStatusCode.Created, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "read_only");

        byte[] roBytes = RandomBytes(256);
        string roDigest = Digest(roBytes);
        using var roResp = await client.PostAsync(
            $"/v2/ro-oci/blobs/uploads/?digest={roDigest}", new ByteArrayContent(roBytes));

        Assert.Equal(HttpStatusCode.Forbidden, roResp.StatusCode);
        using var doc = JsonDocument.Parse(await roResp.Content.ReadAsStringAsync());
        Assert.Equal("DENIED", doc.RootElement.GetProperty("errors")[0].GetProperty("code").GetString());
    }

    [Fact]
    public async Task ReadOnly_OciManifestPut_Refused()
    {
        // The middleware refuses before the controller ever parses the body, so the manifest
        // content need not be valid to pin the refusal itself.
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        await _factory.SetOrgStatus("default", "read_only");

        using var content = new StringContent("{}", Encoding.UTF8, "application/vnd.oci.image.manifest.v1+json");
        var resp = await client.PutAsync("/v2/ro-oci-manifest/manifests/latest", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("DENIED", doc.RootElement.GetProperty("errors")[0].GetProperty("code").GetString());
    }

    [Fact]
    public async Task ReadOnly_OciManifestDelete_Refused()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);
        await _factory.SetOrgStatus("default", "read_only");

        var resp = await client.DeleteAsync(
            "/v2/ro-oci-manifest/manifests/sha256:" + new string('a', 64));

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ReadOnly_NpmPublish_Refused_ActiveTwinSucceeds()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string activeName = $"ro-npm-active-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        using (var activeResp = await client.PutAsync(
            $"/npm/{activeName}",
            new StringContent(NpmFixtures.BuildPublishBody(activeName, "1.0.0"), Encoding.UTF8, "application/json")))
        {
            Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "read_only");

        string roName = $"ro-npm-blocked-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        var roResp = await client.PutAsync(
            $"/npm/{roName}",
            new StringContent(NpmFixtures.BuildPublishBody(roName, "1.0.0"), Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.Locked, roResp.StatusCode);
        using var doc = JsonDocument.Parse(await roResp.Content.ReadAsStringAsync());
        Assert.Equal("ReadOnlyWrite", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task ReadOnly_NuGetPush_Refused_ActiveTwinSucceeds()
    {
        string token = await _factory.CreateToken("push");

        using (var activeResp = await PushNuGetRawAsync(token, "ro-nuget-active", "1.0.0"))
        {
            Assert.Equal(HttpStatusCode.Created, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "read_only");

        using var roResp = await PushNuGetRawAsync(token, "ro-nuget-blocked", "1.0.0");
        Assert.Equal(HttpStatusCode.Locked, roResp.StatusCode);
    }

    private async Task<HttpResponseMessage> PushNuGetRawAsync(string token, string id, string version)
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", $"{id}.{version}.nupkg");
        return await client.PutAsync("/nuget/publish", content);
    }

    [Fact]
    public async Task ReadOnly_PyPiUpload_Refused_ActiveTwinSucceeds()
    {
        string token = await _factory.CreateToken("push");

        using (var activeResp = await PushPyPiRawAsync(token, "ro-pypi-active", "1.0.0"))
        {
            Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "read_only");

        using var roResp = await PushPyPiRawAsync(token, "ro-pypi-blocked", "1.0.0");
        Assert.Equal(HttpStatusCode.Locked, roResp.StatusCode);
    }

    private async Task<HttpResponseMessage> PushPyPiRawAsync(string token, string name, string version)
    {
        var (bytes, sha256) = PyPiFixtures.BuildWheel(name, version);
        string filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";

        using var client = _factory.CreateClient();
        using var content = new MultipartFormDataContent();
        content.Add(new StringContent("file_upload"), ":action");
        content.Add(new StringContent("2.1"), "metadata_version");
        content.Add(new StringContent(name), "name");
        content.Add(new StringContent(version), "version");
        content.Add(new StringContent(sha256), "sha256_digest");

        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);

        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        return await client.PostAsync("/pypi/legacy/", content);
    }

    [Fact]
    public async Task ReadOnly_MavenPut_Refused_ActiveTwinSucceeds()
    {
        string token = await _factory.CreateToken("push");

        using (var activeResp = await PutMavenRawAsync(token, "ro-active", "1.0"))
        {
            Assert.Equal(HttpStatusCode.Created, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "read_only");

        using var roResp = await PutMavenRawAsync(token, "ro-blocked", "1.0");
        Assert.Equal(HttpStatusCode.Locked, roResp.StatusCode);
    }

    private async Task<HttpResponseMessage> PutMavenRawAsync(string token, string artifactId, string version)
    {
        byte[] bytes = [0x50, 0x4B];
        string filename = $"{artifactId}-{version}.jar";
        string path = $"/maven/com/example/{artifactId}/{version}/{filename}";

        using var client = _factory.CreateClient();
        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        using var content = new ByteArrayContent(bytes);
        return await client.PutAsync(path, content);
    }

    // ── Protocol-plane reads keep working ───────────────────────────────────────

    [Fact]
    public async Task ReadOnly_ArtifactDownload_StaysReachable()
    {
        await _factory.PushNuGetPackage("rodownload", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        await _factory.SetOrgStatus("default", "read_only");

        var resp = await client.GetAsync(
            "/nuget/flatcontainer/rodownload/1.0.0/rodownload.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ReadOnly_ProxyCacheFill_StaysReachable()
    {
        string name = $"ro-proxy-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        const string version = "1.0.0";
        string file = $"{name}-{version}.tgz";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        _factory.MockUpstream.Given(WireMock.RequestBuilders.Request.Create().WithPath($"/{name}/-/{file}").UsingGet())
            .RespondWith(WireMock.ResponseBuilders.Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        await _factory.SetOrgStatus("default", "read_only");

        // A cache-fill GET is not billable hosted storage, so it stays admitted even read-only.
        var resp = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Management plane keeps working, including writes ────────────────────────

    [Fact]
    public async Task ReadOnly_Login_StaysReachable()
    {
        const string password = "ReadOnlyLoginPass12345!";
        string email = $"ro-login-{Guid.NewGuid():N}@example.com";
        await _factory.CreateUser(email, password);

        using var client = _factory.CreateClient();
        await _factory.SetOrgStatus("default", "read_only");

        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ReadOnly_ManagementApiRead_StaysReachable()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);
        await _factory.SetOrgStatus("default", "read_only");

        var resp = await client.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ReadOnly_ManagementApiWrite_StaysReachable()
    {
        // Management-plane writes (token minting here) stay admitted — the narrower posture only
        // refuses the protocol-plane publish/upload surface, not admin actions like managing
        // tokens or members.
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);
        await _factory.SetOrgStatus("default", "read_only");

        var resp = await client.PostAsJsonAsync("/api/v1/tokens", new { capabilities = new[] { "read:*" } });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Exempt operator surfaces stay exempt ────────────────────────────────────

    [Fact]
    public async Task ReadOnly_HealthReadyMetricsVersion_StayReachable()
    {
        using var client = _factory.CreateClient();
        await _factory.SetOrgStatus("default", "read_only");

        foreach (string path in new[] { "/health", "/ready", "/metrics", "/version" })
        {
            var resp = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
