using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration tests for OCI protocol extensions: paginated tag listing, merged
/// upstream tag union, Referrers API (OCI 1.1), protocol-level manifest DELETE
/// (digest and tag forms), blob DELETE 405, auth requirements for DELETE, and
/// cross-org isolation for DELETE.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciProtocolExtendedTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/ext";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
    private const string OciImageIndexMediaType = "application/vnd.oci.image.index.v1+json";

    private readonly DependablyFactory _factory;

    public OciProtocolExtendedTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Tags pagination ────────────────────────────────────────────────────────

    [Fact]
    public async Task TagsList_NoParams_ReturnsSortedTags()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Push three images with tags in deliberately non-lexical order.
        await PushImageAsync(client, "zeta");
        await PushImageAsync(client, "alpha");
        await PushImageAsync(client, "beta");

        using var resp = await client.GetAsync($"/v2/{Repo}/tags/list");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var tags = doc.RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToList();

        // At minimum our three tags must be present and sorted.
        Assert.Contains("alpha", tags);
        Assert.Contains("beta", tags);
        Assert.Contains("zeta", tags);

        var ourTags = tags.Where(t => t is "alpha" or "beta" or "zeta").ToList();
        Assert.Equal(["alpha", "beta", "zeta"], ourTags);
    }

    [Fact]
    public async Task TagsList_WithN_LimitsAndEmitsLinkHeader()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/page-{Guid.NewGuid():N}"[..20];

        // Push 3 tags.
        await PushImageToRepoAsync(client, repo, "tag-a");
        await PushImageToRepoAsync(client, repo, "tag-b");
        await PushImageToRepoAsync(client, repo, "tag-c");

        // Request only 2 per page.
        using var resp = await client.GetAsync($"/v2/{repo}/tags/list?n=2");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var tags = doc.RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()!).ToList();

        Assert.Equal(2, tags.Count);
        Assert.Equal("tag-a", tags[0]);
        Assert.Equal("tag-b", tags[1]);

        // Link header must be present.
        Assert.True(resp.Headers.TryGetValues("Link", out var linkValues));
        string link = Assert.Single(linkValues);
        Assert.Contains("rel=\"next\"", link);
        Assert.Contains($"last=tag-b", link);
        Assert.Contains($"/v2/{repo}/tags/list", link);
    }

    [Fact]
    public async Task TagsList_WithLast_ReturnsContinuationPage()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/cont-{Guid.NewGuid():N}"[..20];

        await PushImageToRepoAsync(client, repo, "tag-a");
        await PushImageToRepoAsync(client, repo, "tag-b");
        await PushImageToRepoAsync(client, repo, "tag-c");

        // Second page: everything after tag-a.
        using var resp = await client.GetAsync($"/v2/{repo}/tags/list?last=tag-a");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var tags = doc.RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()!).ToList();

        // Should return tag-b and tag-c only.
        Assert.Equal(["tag-b", "tag-c"], tags);

        // No more pages — no Link header.
        Assert.False(resp.Headers.Contains("Link"));
    }

    [Fact]
    public async Task TagsList_LastPageExact_NoLinkHeader()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/last-{Guid.NewGuid():N}"[..20];

        await PushImageToRepoAsync(client, repo, "v1");
        await PushImageToRepoAsync(client, repo, "v2");

        // Request exactly 2 — matches tag count.
        using var resp = await client.GetAsync($"/v2/{repo}/tags/list?n=2");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var tags = JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()!).ToList();

        Assert.Equal(2, tags.Count);
        // No Link header when the page exactly fills the available tags.
        Assert.False(resp.Headers.Contains("Link"));
    }

    // ── Tag union (local + upstream) ─────────────────────────────────────────
    // The merge/deduplicate/sort logic is exercised at unit-level in
    // OciControllerProxyTests.ListTags_LocalAndUpstream_ReturnsMergedSortedDeduped,
    // where the upstream can be controlled via an injected IHttpClientFactory.
    // Integration-level coverage requires an OCI upstream configured at factory
    // startup (Oci:Upstreams array config), which this shared fixture does not
    // set. The integration tests below cover the local-only pagination path.


    // ── Referrers API ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Referrers_ManifestWithSubject_IsListed()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/ref-{Guid.NewGuid():N}"[..20];

        // Push base image.
        (string baseManifestDigest, _) = await PushImageToRepoReturnDigestAsync(client, repo, "base");

        // Push a referrer manifest that subjects the base image.
        string sbomContent = """{"schemaVersion":2,"subject_note":"test"}""";
        byte[] sbomBlob = Encoding.UTF8.GetBytes(sbomContent);
        string sbomDigest = ComputeDigest(sbomBlob);
        await PushBlobAsync(client, repo, sbomBlob, sbomDigest);

        byte[] referrerManifest = BuildReferrerManifest(
            sbomDigest, sbomBlob.Length, baseManifestDigest,
            "application/vnd.example.sbom.v1");
        string referrerDigest = ComputeDigest(referrerManifest);

        using (var put = await PutManifestAsync(client, repo, "referrer-tag", referrerManifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }
        _ = referrerDigest; // captured for potential future assertions

        // Query referrers for the base digest.
        using var resp = await client.GetAsync($"/v2/{repo}/referrers/{baseManifestDigest}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(OciImageIndexMediaType, resp.Content.Headers.ContentType?.MediaType);

        string body = await resp.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        var manifests = doc.RootElement.GetProperty("manifests").EnumerateArray().ToList();

        Assert.NotEmpty(manifests);
        // The referrer manifest descriptor must be present.
        Assert.Contains(manifests, m =>
            m.TryGetProperty("artifactType", out var at) &&
            at.GetString() == "application/vnd.example.sbom.v1");
    }

    [Fact]
    public async Task Referrers_ArtifactTypeFilter_OnlyMatchingReturned()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/filt-{Guid.NewGuid():N}"[..20];

        (string baseDigest, _) = await PushImageToRepoReturnDigestAsync(client, repo, "img");

        // Push two referrers with different artifactTypes.
        await PushReferrerManifestAsync(client, repo, baseDigest, "ref-sbom", "application/vnd.example.sbom");
        await PushReferrerManifestAsync(client, repo, baseDigest, "ref-sig", "application/vnd.example.sig");

        // Filter by sbom.
        using var resp = await client.GetAsync(
            $"/v2/{repo}/referrers/{baseDigest}?artifactType=application/vnd.example.sbom");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(resp.Headers.TryGetValues("OCI-Filters-Applied", out var filters));
        Assert.Equal("artifactType", Assert.Single(filters));

        var manifests = JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manifests").EnumerateArray().ToList();

        // Only sbom referrer.
        Assert.All(manifests, m =>
        {
            Assert.True(m.TryGetProperty("artifactType", out var at));
            Assert.Equal("application/vnd.example.sbom", at.GetString());
        });
        Assert.DoesNotContain(manifests, m =>
            m.TryGetProperty("artifactType", out var at) &&
            at.GetString() == "application/vnd.example.sig");
    }

    [Fact]
    public async Task Referrers_NoMatchingManifests_ReturnsEmptyIndex()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/empty-{Guid.NewGuid():N}"[..20];
        (string baseDigest, _) = await PushImageToRepoReturnDigestAsync(client, repo, "lonely");

        // Query referrers — none pushed.
        using var resp = await client.GetAsync($"/v2/{repo}/referrers/{baseDigest}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var manifests = JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("manifests").EnumerateArray().ToList();

        Assert.Empty(manifests);
    }

    // ── DELETE manifest by digest ─────────────────────────────────────────────

    [Fact]
    public async Task DeleteManifest_ByDigest_RemovedFromListing()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/del-{Guid.NewGuid():N}"[..20];
        (string digest, _) = await PushImageToRepoReturnDigestAsync(client, repo, "to-delete");

        // Confirm tag is present.
        using (var tags = await client.GetAsync($"/v2/{repo}/tags/list"))
        {
            Assert.Equal(HttpStatusCode.OK, tags.StatusCode);
            var list = JsonDocument.Parse(await tags.Content.ReadAsStringAsync())
                .RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToList();
            Assert.Contains("to-delete", list);
        }

        // DELETE the manifest by digest.
        using (var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{digest}")))
        {
            Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);
        }

        // Manifest GET by digest must now be 404.
        using (var get = await client.GetAsync($"/v2/{repo}/manifests/{digest}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
        }

        // Tag must also be gone.
        using var tagsAfter = await client.GetAsync($"/v2/{repo}/tags/list");
        // Either 404 (no tags remain) or the tag is absent.
        if (tagsAfter.StatusCode == HttpStatusCode.OK)
        {
            var remaining = JsonDocument.Parse(await tagsAfter.Content.ReadAsStringAsync())
                .RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToList();
            Assert.DoesNotContain("to-delete", remaining);
        }
        else
        {
            Assert.Equal(HttpStatusCode.NotFound, tagsAfter.StatusCode);
        }
    }

    [Fact]
    public async Task DeleteManifest_ByDigest_BlobKeyRemovedFromRegistryTier()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/blkdel-{Guid.NewGuid():N}"[..20];
        (string digest, string blobKey) = await PushImageToRepoReturnDigestAsync(client, repo, "blk");

        // Verify blob key is present in the in-memory blob store before delete.
        Assert.True(await _factory.BlobStore.ExistsAsync(blobKey));

        using var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{digest}"));
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // Blob key must be removed from the registry tier.
        Assert.False(await _factory.BlobStore.ExistsAsync(blobKey));
    }

    // ── DELETE manifest by tag (untag only) ───────────────────────────────────

    [Fact]
    public async Task DeleteManifest_ByTag_UntagsOnly_ManifestBlobRemains()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/untag-{Guid.NewGuid():N}"[..20];
        (string digest, _) = await PushImageToRepoReturnDigestAsync(client, repo, "my-tag");

        // DELETE by tag.
        using (var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/my-tag")))
        {
            Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);
        }

        // Manifest blob must still be accessible by digest.
        using (var get = await client.GetAsync($"/v2/{repo}/manifests/{digest}"))
        {
            Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        }

        // Tag must be gone.
        using var tagsAfter = await client.GetAsync($"/v2/{repo}/tags/list");
        if (tagsAfter.StatusCode == HttpStatusCode.OK)
        {
            var remaining = JsonDocument.Parse(await tagsAfter.Content.ReadAsStringAsync())
                .RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToList();
            Assert.DoesNotContain("my-tag", remaining);
        }
    }

    [Fact]
    public async Task DeleteManifest_ByTag_UnknownTag_Returns404()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/notag-{Guid.NewGuid():N}"[..20];

        using var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/nonexistent-tag"));
        Assert.Equal(HttpStatusCode.NotFound, del.StatusCode);
    }

    // ── DELETE blob → 405 ─────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteBlob_Returns405()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string repo = $"team/blobdel-{Guid.NewGuid():N}"[..20];
        string fakeDigest = $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("fake"))).ToLowerInvariant()}";

        using var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/blobs/{fakeDigest}"));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, del.StatusCode);

        string body = await del.Content.ReadAsStringAsync();
        Assert.Contains("UNSUPPORTED", body);
    }

    // ── Auth required for DELETE ──────────────────────────────────────────────

    [Fact]
    public async Task DeleteManifest_NoToken_Returns401()
    {
        using var client = _factory.CreateClient();
        string repo = $"team/noauth-{Guid.NewGuid():N}"[..20];
        string fakeDigest = $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("x"))).ToLowerInvariant()}";

        using var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{fakeDigest}"));
        Assert.Equal(HttpStatusCode.Unauthorized, del.StatusCode);
        Assert.Equal("Basic", del.Headers.WwwAuthenticate.First().Scheme);
    }

    [Fact]
    public async Task DeleteManifest_PullOnlyToken_Returns403()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        string repo = $"team/pullonly-{Guid.NewGuid():N}"[..20];
        string fakeDigest = $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("x"))).ToLowerInvariant()}";

        using var del = await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{fakeDigest}"));
        Assert.Equal(HttpStatusCode.Forbidden, del.StatusCode);
        Assert.Contains("yank:oci", await del.Content.ReadAsStringAsync());
    }

    // ── Cross-org isolation for DELETE ────────────────────────────────────────

    [Fact]
    public async Task DeleteManifest_CrossOrg_OrgACannotDeleteOrgBManifest()
    {
        // Push a manifest in the default org (org B).
        string pushToken = await _factory.CreateToken("push");
        using var pushClient = _factory.CreateClientWithBearer(pushToken);

        string repo = $"team/xorg-{Guid.NewGuid():N}"[..20];
        (string digest, _) = await PushImageToRepoReturnDigestAsync(pushClient, repo, "shared");

        // Create a token in a second org (org A) with yank:oci.
        string crossToken = await CreateOtherOrgYankTokenAsync();
        using var crossClient = _factory.CreateClientWithBearer(crossToken);

        // Org A's token attempts to delete org B's manifest.
        using var del = await crossClient.SendAsync(new HttpRequestMessage(HttpMethod.Delete, $"/v2/{repo}/manifests/{digest}"));

        // Must be 404 or 401 — the manifest does not exist in org A's namespace.
        Assert.True(del.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized,
            $"Expected 404 or 401 but got {del.StatusCode}");

        // Manifest must still exist in org B.
        using var get = await pushClient.GetAsync($"/v2/{repo}/manifests/{digest}");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static async Task PushImageAsync(HttpClient client, string tag)
        => await PushImageToRepoAsync(client, Repo, tag);

    private static async Task PushImageToRepoAsync(HttpClient client, string repo, string tag)
        => await PushImageToRepoReturnDigestAsync(client, repo, tag);

    private static async Task<(string ManifestDigest, string ManifestBlobKey)> PushImageToRepoReturnDigestAsync(
        HttpClient client, string repo, string tag)
    {
        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layerBytes = RandomBytes(256);
        string configDigest = ComputeDigest(configBytes);
        string layerDigest = ComputeDigest(layerBytes);

        await PushBlobAsync(client, repo, configBytes, configDigest);
        await PushBlobAsync(client, repo, layerBytes, layerDigest);

        byte[] manifest = BuildImageManifest(repo, configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = ComputeDigest(manifest);

        using var put = await PutManifestAsync(client, repo, tag, manifest);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);

        // Derive the blob key for the manifest so callers can assert on blob store state.
        string[] digestParts = manifestDigest.Split(':', 2);
        string blobKey = $"oci/{digestParts[0]}/{digestParts[1]}";
        return (manifestDigest, blobKey);
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

    private static async Task PushReferrerManifestAsync(
        HttpClient client, string repo, string subjectDigest, string tag, string artifactType)
    {
        byte[] payload = Encoding.UTF8.GetBytes($"{{\"note\":\"{artifactType}\"}}");
        string payloadDigest = ComputeDigest(payload);
        await PushBlobAsync(client, repo, payload, payloadDigest);

        byte[] manifest = BuildReferrerManifest(payloadDigest, payload.Length, subjectDigest, artifactType);
        using var put = await PutManifestAsync(client, repo, tag, manifest);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
    }

    private static byte[] BuildImageManifest(string repo, string configDigest, long configSize, string layerDigest, long layerSize)
    {
        _ = repo; // not used in the manifest body itself
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

    private static byte[] BuildReferrerManifest(
        string blobDigest, long blobSize, string subjectDigest, string artifactType)
    {
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{ManifestMediaType}}",
          "artifactType": "{{artifactType}}",
          "config": {
            "mediaType": "{{artifactType}}",
            "digest": "{{blobDigest}}",
            "size": {{blobSize}}
          },
          "layers": [],
          "subject": {
            "mediaType": "{{ManifestMediaType}}",
            "digest": "{{subjectDigest}}",
            "size": 1
          }
        }
        """;
        return Encoding.UTF8.GetBytes(json);
    }

    private static string ComputeDigest(byte[] bytes)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private async Task<string> CreateOtherOrgYankTokenAsync()
    {
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var other = await orgRepo.CreateOrgAsync($"yank-{Guid.NewGuid():N}"[..16]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            other.Id,
            $"yank-tok-{Guid.NewGuid():N}"[..16],
            """["yank:oci","read:artifact","read:metadata"]""",
            expiresAt: null);
        return raw;
    }

}
