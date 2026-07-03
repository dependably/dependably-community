using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dependably.Infrastructure.Edge;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Publish fail-closed on an edge node: a cache edge holds no durable registry tier, so every
/// publish/push/import AND every authoritative mutation/delete must fail fast with a 405 carrying
/// the "publish to the master registry" title rather than touch state that can never replicate
/// upstream. Covers npm PUT, NuGet push, PyPI legacy upload, Maven PUT, RPM upload, and OCI
/// upload-initiation on the publish side; and OCI chunk PATCH + manifest DELETE, NuGet unlist
/// DELETE, npm dist-tag PUT/DELETE + unpublish DELETE, and Cargo yank/unyank on the mutation side.
///
/// Every mutation/delete case targets a nonexistent artifact: the guard fires at the top of the
/// action before any lookup, so a 405 (not a 404) proves the guard sits ahead of resolution.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgePublishFailClosedTests
{
    // A push-capable inbound token so requests pass the per-endpoint capability gate and reach
    // the edge publish guard (proving the guard, not an auth failure, is what returns 405).
    private static async Task<(DependablyFactory Factory, HttpClient Bearer, string Token)> NewEdgeAsync()
    {
        var f = new DependablyFactory { DeploymentMode = "edge", EdgeAccessToken = "inbound-tok" };
        using (var boot = f.CreateClient())
        {
            await boot.GetAsync("/health");
        }

        // A push service token in the edge org (slug 'default' in tests) — reader-only inbound
        // token can't publish, but publish is refused for a different reason we want to isolate.
        string push = await f.CreateToken("push");
        return (f, f.CreateClientWithBearer(push), push);
    }

    private static void AssertEdge405(HttpResponseMessage resp, string body)
    {
        Assert.Equal(HttpStatusCode.MethodNotAllowed, resp.StatusCode);
        Assert.Contains(EdgePublishGuard.Title, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Edge_NpmPut_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        string body = NpmFixtures.BuildPublishBody("edge-npm-pub", "1.0.0");
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/edge-npm-pub", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_NuGetPush_405()
    {
        var (f, _, token) = await NewEdgeAsync();
        await using var _f = f;

        var (bytes, _) = NuGetFixtures.BuildNupkg("Edge.NuGet.Pub", "1.0.0");
        using var client = f.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", "edge.nuget.pub.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_PyPiUpload_405()
    {
        var (f, _, token) = await NewEdgeAsync();
        await using var _f = f;

        string name = "edge_pypi_pub";
        var (bytes, sha256) = PyPiFixtures.BuildWheel(name, "1.0.0");
        string filename = $"{name}-1.0.0-py3-none-any.whl";

        using var client = f.CreateClient();
        using var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent("1.0.0"), "version" },
            { new StringContent(sha256), "sha256_digest" },
        };
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}")));

        var resp = await client.PostAsync("/pypi/legacy/", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_MavenPut_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes("dummy-jar-bytes"));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/java-archive");
        var resp = await client.PutAsync("/maven/com/example/edgelib/1.0.0/edgelib-1.0.0.jar", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_RpmUpload_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes("dummy-rpm-bytes"));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-rpm");
        var resp = await client.PutAsync("/rpm/upload", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_OciUploadInit_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // POST /v2/{name}/blobs/uploads/ — the upload-initiation choke point.
        var resp = await client.PostAsync("/v2/edge/repo/blobs/uploads/", new ByteArrayContent([]));

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_OciManifestPut_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        using var content = new StringContent("{}", Encoding.UTF8, "application/vnd.oci.image.manifest.v1+json");
        var resp = await client.PutAsync("/v2/edge/repo/manifests/latest", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    // ── Mutation / delete paths (guard fires ahead of any lookup — 405 beats 404) ──

    [Fact]
    public async Task Edge_OciChunkPatch_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // PATCH /v2/{name}/blobs/uploads/{id} — the chunk-append choke point. The upload session
        // does not exist; a 405 (not 404) proves the guard runs before the session lookup.
        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes("chunk-bytes"));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var req = new HttpRequestMessage(HttpMethod.Patch, "/v2/edge/repo/blobs/uploads/nonexistent-session")
        {
            Content = content,
        };
        var resp = await client.SendAsync(req);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_OciManifestDelete_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // DELETE a manifest that does not exist — the guard fires before the blob lookup.
        var resp = await client.DeleteAsync("/v2/edge/repo/manifests/latest");

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_NuGetUnlistDelete_405()
    {
        var (f, _, token) = await NewEdgeAsync();
        await using var _f = f;

        using var client = f.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        // Unlist a version that does not exist — the guard fires before the package lookup.
        var resp = await client.DeleteAsync("/nuget/publish/Edge.Nonexistent/1.0.0");

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_NpmDistTagPut_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // Set a dist-tag on a package that does not exist — the guard fires before the lookup.
        using var content = new StringContent("\"1.0.0\"", Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/-/package/edge-nonexistent/dist-tags/beta", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_NpmDistTagDelete_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // Delete a non-'latest' dist-tag on a package that does not exist — the guard fires
        // before both the 'latest'-is-protected check and the package lookup.
        var resp = await client.DeleteAsync("/npm/-/package/edge-nonexistent/dist-tags/beta");

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_NpmUnpublishDelete_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // Unpublish a version of a package that does not exist — the guard fires before the lookup.
        var resp = await client.DeleteAsync("/npm/edge-nonexistent/-rev/1.0.0");

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_CargoYankDelete_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // Yank a version of a crate that does not exist — the guard fires before the lookup.
        var resp = await client.DeleteAsync("/cargo/api/v1/crates/edge-nonexistent/1.0.0/yank");

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Edge_CargoUnyankPut_405()
    {
        var (f, client, _) = await NewEdgeAsync();
        await using var _f = f;
        using var _c = client;

        // Unyank a version of a crate that does not exist — the guard fires before the lookup.
        using var content = new ByteArrayContent([]);
        var resp = await client.PutAsync("/cargo/api/v1/crates/edge-nonexistent/1.0.0/unyank", content);

        AssertEdge405(resp, await resp.Content.ReadAsStringAsync());
    }
}
