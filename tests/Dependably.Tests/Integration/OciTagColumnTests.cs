using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that <c>GET /api/v1/packages/oci/{name}</c> surfaces OCI image tags alongside
/// each digest version row. The critical scenario is a single digest mapped to two tags —
/// confirming that both tags are returned in the <c>tags</c> array.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciTagColumnTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyFactory _factory;

    public OciTagColumnTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Pushes a single manifest under two distinct tags (v1.0 and latest), then queries the
    /// management API. The version row for the digest must carry both tags — verifying that
    /// <c>GetOciTagsByDigestAsync</c> aggregates all tags for a digest and the controller
    /// includes them in the response.
    /// </summary>
    [Fact]
    public async Task GetPackage_OciDigestWithTwoTags_ReturnsBothTagsInVersionRow()
    {
        string repo = $"oci-tag-test-{Guid.NewGuid():N}"[..28].ToLowerInvariant();

        // Push blobs + manifest.
        string token = await _factory.CreateToken("push");
        using var pushClient = _factory.CreateClientWithBearer(token);

        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layerBytes = new byte[512];
        RandomNumberGenerator.Fill(layerBytes);
        string configDigest = ComputeDigest(configBytes);
        string layerDigest = ComputeDigest(layerBytes);

        await PushBlobMonolithicAsync(pushClient, repo, configBytes, configDigest);
        await PushBlobMonolithicAsync(pushClient, repo, layerBytes, layerDigest);

        byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = ComputeDigest(manifest);

        // Push the same manifest content under two different tags.
        using (var r = await PutManifestAsync(pushClient, repo, "v1.0", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        }

        using (var r = await PutManifestAsync(pushClient, repo, "latest", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        }

        // Query the management API as an authenticated admin.
        string jwt = await _factory.CreateAdminJwt();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        using var resp = await c.GetAsync($"/api/v1/packages/oci/{Uri.EscapeDataString(repo)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions").EnumerateArray().ToList();

        // Locate the version row whose version equals the manifest digest.
        var row = versions.FirstOrDefault(v =>
            v.GetProperty("version").GetString() == manifestDigest);

        Assert.True(row.ValueKind != JsonValueKind.Undefined,
            $"No version row found for digest {manifestDigest}. Versions: {string.Join(", ", versions.Select(v => v.GetProperty("version").GetString()))}");

        Assert.True(row.TryGetProperty("tags", out var tagsEl),
            "Version row must contain a 'tags' property");

        var tags = tagsEl.EnumerateArray().Select(t => t.GetString()!).ToList();

        // Both tags must appear in the array (sorted by tag per ORDER BY tag).
        Assert.Contains("latest", tags);
        Assert.Contains("v1.0", tags);
        Assert.Equal(2, tags.Count);
    }

    /// <summary>
    /// Pushes a manifest under a single tag and verifies the version row contains exactly
    /// that tag. Baseline correctness check: one digest, one tag, tags array has one element.
    /// </summary>
    [Fact]
    public async Task GetPackage_OciDigestWithOneTag_ReturnsSingleTagInArray()
    {
        string repo = $"oci-one-tag-{Guid.NewGuid():N}"[..24].ToLowerInvariant();

        string token = await _factory.CreateToken("push");
        using var pushClient = _factory.CreateClientWithBearer(token);

        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"arm64","os":"linux"}""");
        byte[] layerBytes = new byte[256];
        RandomNumberGenerator.Fill(layerBytes);
        string configDigest = ComputeDigest(configBytes);
        string layerDigest = ComputeDigest(layerBytes);

        await PushBlobMonolithicAsync(pushClient, repo, configBytes, configDigest);
        await PushBlobMonolithicAsync(pushClient, repo, layerBytes, layerDigest);

        byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = ComputeDigest(manifest);

        using (var r = await PutManifestAsync(pushClient, repo, "release", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        }

        string jwt = await _factory.CreateAdminJwt();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        using var resp = await c.GetAsync($"/api/v1/packages/oci/{Uri.EscapeDataString(repo)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions").EnumerateArray().ToList();
        var row = versions.FirstOrDefault(v =>
            v.GetProperty("version").GetString() == manifestDigest);

        Assert.True(row.ValueKind != JsonValueKind.Undefined,
            $"No version row found for digest {manifestDigest}");

        Assert.True(row.TryGetProperty("tags", out var tagsEl),
            "Version row must contain a 'tags' property");

        var tags = tagsEl.EnumerateArray().Select(t => t.GetString()!).ToList();
        Assert.Equal(["release"], tags);
    }

    /// <summary>
    /// Verifies that non-OCI packages (e.g. npm) include an empty <c>tags</c> array in each
    /// version row — the field must always be present to keep the frontend contract stable.
    /// </summary>
    [Fact]
    public async Task GetPackage_NonOciPackage_ReturnsEmptyTagsArray()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        // Upload a minimal npm package.
        string name = $"oci-tags-npm-{Guid.NewGuid():N}"[..28].ToLowerInvariant();
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var form = new MultipartFormDataContent { { part, "files", $"{name}-1.0.0.tgz" } };
        (await c.PostAsync("/api/v1/admin/upload", form)).EnsureSuccessStatusCode();

        using var resp = await c.GetAsync($"/api/v1/packages/npm/{Uri.EscapeDataString(name)}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions").EnumerateArray().ToList();
        Assert.NotEmpty(versions);

        foreach (var ver in versions)
        {
            Assert.True(ver.TryGetProperty("tags", out var tagsEl),
                "Non-OCI version row must still contain a 'tags' property");
            Assert.Equal(JsonValueKind.Array, tagsEl.ValueKind);
            Assert.Equal(0, tagsEl.GetArrayLength());
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────────

    private static async Task PushBlobMonolithicAsync(HttpClient client, string repo, byte[] bytes, string digest)
    {
        using var resp = await client.PostAsync(
            $"/v2/{repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(
        HttpClient client, string repo, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        return await client.PutAsync($"/v2/{repo}/manifests/{reference}", content);
    }

    private static byte[] BuildImageManifest(string configDigest, long configSize, string layerDigest, long layerSize)
    {
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{ManifestMediaType}}",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{{configDigest}}",
            "size": {{configSize}}
          },
          "layers": [
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "{{layerDigest}}",
              "size": {{layerSize}}
            }
          ]
        }
        """;
        return Encoding.UTF8.GetBytes(json);
    }

    private static string ComputeDigest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
