using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Cross-org refcount integration tests for OCI manifest DELETE.
///
/// OCI blob keys are content-addressed and shared across orgs: two orgs that push the
/// same manifest bytes share one physical blob in the Registry tier. The controller must
/// count remaining <c>oci_blobs</c> references across all orgs before deleting the physical
/// file, so org A's delete must not destroy bytes that org B still references.
///
/// These tests use <see cref="DependablyMultiFactory"/> so each org is a genuine HTTP
/// tenant routed via the <c>Host: slug.localhost</c> subdomain — the same path the
/// controller's refcount query protects.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciSharedBlobRefcountTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyMultiFactory _factory;

    public OciSharedBlobRefcountTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Cross-org shared physical blob ────────────────────────────────────────

    /// <summary>
    /// Org A and org B each independently push an image whose manifest bytes are identical
    /// (same config + layer content → same digest). After org A deletes its manifest:
    /// <list type="bullet">
    ///   <item>Org A gets 404 for the manifest.</item>
    ///   <item>Org B still gets 200 for the manifest and its referenced layer blob.</item>
    ///   <item>The physical blob key is still present in the blob store.</item>
    /// </list>
    /// When org B then deletes its copy, the physical blob is removed.
    /// </summary>
    [Fact]
    public async Task DeleteManifest_SharedDigest_PhysicalBlobSurvivesUntilLastOrgDeletes()
    {
        // ── Provision two tenants ─────────────────────────────────────────────
        string slugA = "ora-" + Guid.NewGuid().ToString("N")[..8];
        string slugB = "orb-" + Guid.NewGuid().ToString("N")[..8];

        using var sysClient = await _factory.CreateSystemAdminClient();
        await CreateTenantAsync(sysClient, slugA);
        await CreateTenantAsync(sysClient, slugB);

        string tokenA = await CreateOciTokenAsync(slugA);
        string tokenB = await CreateOciTokenAsync(slugB);

        // ── Build deterministic image content (same bytes → same digest for both orgs) ──
        // Config and layer are constants so the manifest bytes — and therefore the
        // content-addressed blob key — are identical across both pushes.
        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux","shared":"true"}""");
        byte[] layerBytes = Encoding.UTF8.GetBytes("shared-layer-content-constant");
        string configDigest = Sha256Digest(configBytes);
        string layerDigest = Sha256Digest(layerBytes);
        byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = Sha256Digest(manifest);

        // ── Push from org A ───────────────────────────────────────────────────
        using var clientA = ClientForOrg(slugA, tokenA);
        const string repo = "shared/img";
        await PushBlobAsync(clientA, repo, configBytes, configDigest);
        await PushBlobAsync(clientA, repo, layerBytes, layerDigest);
        using (var put = await PutManifestAsync(clientA, repo, "v1", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        // ── Push from org B (same bytes, same blob key, separate DB rows) ─────
        using var clientB = ClientForOrg(slugB, tokenB);
        await PushBlobAsync(clientB, repo, configBytes, configDigest);
        await PushBlobAsync(clientB, repo, layerBytes, layerDigest);
        using (var put = await PutManifestAsync(clientB, repo, "v1", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        // Derive the physical manifest blob key from the digest.
        string[] parts = manifestDigest.Split(':', 2);
        string manifestBlobKey = $"oci/{parts[0]}/{parts[1]}";
        Assert.True(await _factory.BlobStore.ExistsAsync(manifestBlobKey),
            "Manifest physical blob must exist after both orgs push.");

        // ── Org A deletes its manifest ────────────────────────────────────────
        using (var del = await clientA.SendAsync(
            new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{manifestDigest}")))
        {
            Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);
        }

        // Org A must now get 404 for the manifest.
        using (var get = await clientA.GetAsync($"/v2/{repo}/manifests/{manifestDigest}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
        }

        // Physical blob must still exist — org B still holds a reference.
        Assert.True(await _factory.BlobStore.ExistsAsync(manifestBlobKey),
            "Physical blob must survive org A's delete while org B still references it.");

        // Org B must still get 200 for the manifest.
        using (var get = await clientB.GetAsync($"/v2/{repo}/manifests/{manifestDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        }

        // Org B must still get 200 for the layer blob.
        using (var get = await clientB.GetAsync($"/v2/{repo}/blobs/{layerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        }

        // ── Org B deletes its manifest ────────────────────────────────────────
        using (var del = await clientB.SendAsync(
            new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{manifestDigest}")))
        {
            Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);
        }

        // Now that both orgs have deleted, the physical manifest blob must be gone.
        Assert.False(await _factory.BlobStore.ExistsAsync(manifestBlobKey),
            "Physical blob must be deleted once no org holds a reference.");
    }

    // ── No-upstream tags/list ─────────────────────────────────────────────────

    /// <summary>
    /// When no OCI upstream is configured for an org, tags/list of a locally pushed
    /// repository must return 200 with the local tags — the upstream-fetch path must
    /// degrade gracefully rather than returning an error.
    /// </summary>
    [Fact]
    public async Task TagsList_NoUpstreamConfigured_LocallyPushedTags_Returns200()
    {
        string slug = "notag-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await _factory.CreateSystemAdminClient();
        await CreateTenantAsync(sysClient, slug);
        string token = await CreateOciTokenAsync(slug);

        string repo = "lib/hello";
        using var client = ClientForOrg(slug, token);

        // Push an image with two tags.
        byte[] configBytes = Encoding.UTF8.GetBytes("""{"os":"linux"}""");
        byte[] layerBytes = Encoding.UTF8.GetBytes("layer-payload");
        string configDigest = Sha256Digest(configBytes);
        string layerDigest = Sha256Digest(layerBytes);
        byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);

        await PushBlobAsync(client, repo, configBytes, configDigest);
        await PushBlobAsync(client, repo, layerBytes, layerDigest);

        using (var put = await PutManifestAsync(client, repo, "stable", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }
        using (var put = await PutManifestAsync(client, repo, "latest", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        // List tags — no upstream is configured, must degrade to local-only.
        using var resp = await client.GetAsync($"/v2/{repo}/tags/list");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = System.Text.Json.JsonDocument.Parse(body);
        var tags = doc.RootElement.GetProperty("tags")
            .EnumerateArray()
            .Select(t => t.GetString()!)
            .ToList();

        Assert.Contains("stable", tags);
        Assert.Contains("latest", tags);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static async Task CreateTenantAsync(HttpClient sysClient, string slug)
    {
        var resp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private async Task<string> CreateOciTokenAsync(string slug)
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();

        var org = await orgs.GetBySlugAsync(slug)
            ?? throw new InvalidOperationException($"Org '{slug}' not found.");

        var (raw, _) = await tokens.CreateServiceTokenAsync(
            org.Id,
            $"tok-{Guid.NewGuid():N}"[..16],
            """["publish:oci","read:artifact","read:metadata","yank:oci"]""",
            expiresAt: null);
        return raw;
    }

    private HttpClient ClientForOrg(string slug, string token)
    {
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task PushBlobAsync(HttpClient client, string repo, byte[] bytes, string digest)
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

    private static byte[] BuildImageManifest(
        string configDigest, long configSize, string layerDigest, long layerSize)
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

    private static string Sha256Digest(byte[] bytes)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
