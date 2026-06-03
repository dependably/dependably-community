using System.Net;
using System.Net.Http.Headers;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// The management download endpoint (<c>GET /api/v1/packages/{eco}/{name}/{version}/download</c>)
/// lets a logged-in UI user fetch a single artifact using their session — the protocol download
/// surfaces only accept an Authorization-header token, so the SPA cannot drive them directly.
///
/// These tests cover: an uploaded version (registry tier) round-trips its exact bytes with an
/// attachment Content-Disposition; a proxy-cached version round-trips from the cache tier;
/// missing package/version → 404; a member (not just admin) can download; an unauthenticated
/// request is rejected; and the mixed case where one package name holds both an uploaded and a
/// proxy version, each served from the correct tier.
/// </summary>
[Trait("Category", "Integration")]
public sealed class DownloadVersionTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public DownloadVersionTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        var jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static MultipartFormDataContent OneFile(byte[] bytes, string name)
    {
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var content = new MultipartFormDataContent();
        content.Add(part, "files", name);
        return content;
    }

    private async Task UploadNpm(HttpClient c, string name, string version)
    {
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        using var content = OneFile(bytes, $"{name}-{version}.tgz");
        (await c.PostAsync("/api/v1/admin/upload", content)).EnsureSuccessStatusCode();
    }

    /// <summary>Stubs the upstream tarball and drives a proxy cache MISS so a proxy-origin
    /// version row + cache-tier blob exist for the name/version. Returns the upstream bytes.</summary>
    private async Task<byte[]> SeedProxyVersion(string name, string version)
    {
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        var filename = $"{name}-{version}.tgz";
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return bytes;
    }

    [Fact]
    public async Task DownloadUploadedVersion_Returns200_WithBytesAndAttachment()
    {
        using var c = await AdminClient();
        var name = $"dl-uploaded";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        using var content = OneFile(bytes, $"{name}-1.0.0.tgz");
        (await c.PostAsync("/api/v1/admin/upload", content)).EnsureSuccessStatusCode();

        var resp = await c.GetAsync($"/api/v1/packages/npm/{name}/1.0.0/download");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/octet-stream", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal("attachment", resp.Content.Headers.ContentDisposition?.DispositionType);
        Assert.Equal($"{name}-1.0.0.tgz", resp.Content.Headers.ContentDisposition?.FileName);
        Assert.Equal(bytes, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task DownloadProxyVersion_Returns200_FromCacheTier()
    {
        var name = $"dlproxy{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var bytes = await SeedProxyVersion(name, "1.0.0");

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/packages/npm/{name}/1.0.0/download");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        // The bytes live only in the cache tier — round-tripping them proves the origin-based
        // tier selector reads from .Cache for a proxy version.
        Assert.Equal(bytes, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task DownloadMissingVersion_Returns404()
    {
        using var c = await AdminClient();
        await UploadNpm(c, "dl-missing-ver", "1.0.0");

        var resp = await c.GetAsync("/api/v1/packages/npm/dl-missing-ver/9.9.9/download");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadMissingPackage_Returns404()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/packages/npm/dl-never-existed/1.0.0/download");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Member_CanDownload_Returns200()
    {
        using var admin = await AdminClient();
        await UploadNpm(admin, "dl-member", "1.0.0");

        var userId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "pw", "member");
        var jwt = await _factory.CreateUserJwt(userId, "member");
        using var member = _factory.CreateClient();
        member.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await member.GetAsync("/api/v1/packages/npm/dl-member/1.0.0/download");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Unauthenticated_Returns401()
    {
        using var admin = await AdminClient();
        await UploadNpm(admin, "dl-anon", "1.0.0");

        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync("/api/v1/packages/npm/dl-anon/1.0.0/download");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task MixedOriginPackage_EachVersionServedFromCorrectTier()
    {
        var name = $"dlmixed{Guid.NewGuid():N}"[..18].ToLowerInvariant();

        using var c = await AdminClient();
        var (uploadedBytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        using var content = OneFile(uploadedBytes, $"{name}-1.0.0.tgz");
        (await c.PostAsync("/api/v1/admin/upload", content)).EnsureSuccessStatusCode();

        // A second version of the SAME name fetched from upstream lands as a proxy version.
        var proxyBytes = await SeedProxyVersion(name, "2.0.0");

        var uploaded = await c.GetAsync($"/api/v1/packages/npm/{name}/1.0.0/download");
        Assert.Equal(HttpStatusCode.OK, uploaded.StatusCode);
        Assert.Equal(uploadedBytes, await uploaded.Content.ReadAsByteArrayAsync());

        var proxy = await c.GetAsync($"/api/v1/packages/npm/{name}/2.0.0/download");
        Assert.Equal(HttpStatusCode.OK, proxy.StatusCode);
        Assert.Equal(proxyBytes, await proxy.Content.ReadAsByteArrayAsync());
    }
}
