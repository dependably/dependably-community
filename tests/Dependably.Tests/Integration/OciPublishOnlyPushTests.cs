using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins a <c>docker push</c> in the shape a real client performs it: a publish-only token
/// (<c>["publish:*"]</c> — exactly what the web token modal's push preset mints) presented over
/// HTTP <b>Basic</b>, driving the full HEAD-probe → upload → manifest sequence.
///
/// <para>
/// Both halves of that shape were previously uncovered. <see cref="OciPushTests"/> mints a token
/// carrying <c>read:artifact</c> alongside <c>publish:*</c>, which satisfies the pull gate on its
/// own, so its probes never reach the <c>allowPushProbe</c> exception that a publish-only client
/// depends on — that suite stays green even with the exception removed. And every OCI test
/// authenticates with Bearer, while docker always sends Basic. The combination a live push
/// actually exercises therefore had no end-to-end coverage at all.
/// </para>
///
/// <para>
/// The negative cases are deliberate twins of the positive ones: the same token that may probe a
/// blob with HEAD must still be refused the blob's bytes on GET and the repository's tag list, so
/// the probe exception cannot decay into a general read licence.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciPublishOnlyPushTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "publish-only/app";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyFactory _factory;

    public OciPublishOnlyPushTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task PublishOnlyTokenOverBasic_CompletesTheFullPushSequence()
    {
        string token = await _factory.CreateToken("publish-only");
        using var client = _factory.CreateClientWithBasic(token);

        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layerBytes = RandomBytes(2048);
        string configDigest = Digest(configBytes);
        string layerDigest = Digest(layerBytes);

        // The docker login probe: /v2/ resolves the credential but performs no capability check.
        using (var ping = await client.GetAsync("/v2/"))
        {
            Assert.Equal(HttpStatusCode.OK, ping.StatusCode);
        }

        // Step 1 — the existence probe docker issues before uploading each layer. A publish-only
        // token reaches this only through the push-probe exception; without it the whole push
        // dies here rather than at the write gate.
        using (var head = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{layerDigest}")))
        {
            Assert.Equal(HttpStatusCode.NotFound, head.StatusCode);
        }

        // Step 2 — the writes.
        await PushBlobChunkedAsync(client, configBytes, configDigest);
        await PushBlobMonolithicAsync(client, layerBytes, layerDigest);

        // Step 3 — the probe repeated after the upload: now the blob exists, so the same HEAD
        // that 404'd must answer 200. This is the request that renders as "Layer already exists".
        using (var head = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{layerDigest}")))
        {
            Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        }

        byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = Digest(manifest);

        // Step 4 — the tag-resolution probe docker makes before pushing a manifest.
        using (var head = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/manifests/1.0.0")))
        {
            Assert.Equal(HttpStatusCode.NotFound, head.StatusCode);
        }

        using var put = await PutManifestAsync(client, "1.0.0", manifest);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        Assert.Equal(manifestDigest, Assert.Single(put.Headers.GetValues("Docker-Content-Digest")));
    }

    [Fact]
    public async Task PublishOnlyToken_IsStillRefusedBlobBytesAndTagList()
    {
        string token = await _factory.CreateToken("publish-only");
        using var client = _factory.CreateClientWithBasic(token);

        byte[] layerBytes = RandomBytes(1024);
        string layerDigest = Digest(layerBytes);
        await PushBlobMonolithicAsync(client, layerBytes, layerDigest);

        // The blob exists and this token pushed it — a GET is still real pull content.
        using (var get = await client.GetAsync($"/v2/{Repo}/blobs/{layerDigest}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, get.StatusCode);
        }

        using var tags = await client.GetAsync($"/v2/{Repo}/tags/list");
        Assert.Equal(HttpStatusCode.Forbidden, tags.StatusCode);
    }

    /// <summary>
    /// The failure an operator actually meets: a read-scoped credential passes <c>docker login</c>
    /// and passes the blob HEAD probes, then is refused at the first write. The denial must
    /// identify <b>which</b> credential was refused — that is what separates "re-scope this token"
    /// from "the client sent a different credential than you minted" — while disclosing nothing
    /// about what that credential can do, since <c>/v2/</c> error bodies travel into CI logs.
    /// </summary>
    [Fact]
    public async Task ReadOnlyToken_PassesProbesThenIsDeniedAtWrite_AndTheDenialIdentifiesTheCredential()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        using (var ping = await client.GetAsync("/v2/"))
        {
            Assert.Equal(HttpStatusCode.OK, ping.StatusCode);
        }

        using (var head = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{Digest(RandomBytes(16))}")))
        {
            Assert.Equal(HttpStatusCode.NotFound, head.StatusCode);
        }

        using var post = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Forbidden, post.StatusCode);

        string body = await post.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var error = doc.RootElement.GetProperty("errors")[0];

        string message = error.GetProperty("message").GetString()!;
        Assert.Contains("publish:oci", message, StringComparison.Ordinal);

        var detail = error.GetProperty("detail");
        Assert.Equal("publish:oci", detail.GetProperty("required").GetString());

        // Identifies the credential: a prefix of the token's id, long enough to tell two
        // credentials apart in a job log and short enough not to republish the whole key.
        string tokenRef = detail.GetProperty("tokenRef").GetString()!;
        Assert.Equal(8, tokenRef.Length);
        Assert.Matches("^[0-9a-f]{8}$", tokenRef);
        Assert.Contains(tokenRef, message, StringComparison.Ordinal);

        // The adversarial twin: the wire must disclose nothing about what the token can do.
        // The granted set is operator-side only — Serilog line and audit row.
        Assert.DoesNotContain("read:artifact", body, StringComparison.Ordinal);
        Assert.DoesNotContain("read:metadata", body, StringComparison.Ordinal);
        Assert.DoesNotContain("granted", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static async Task PushBlobChunkedAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var resp = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        string location = Assert.Single(resp.Headers.GetValues("Location"));

        using (var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location)
        { Content = new ByteArrayContent(bytes) }))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }

        using var put = await client.PutAsync($"{location}?digest={digest}", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
    }

    private static async Task PushBlobMonolithicAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var resp = await client.PostAsync(
            $"/v2/{Repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(
        HttpClient client, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        return await client.PutAsync($"/v2/{Repo}/manifests/{reference}", content);
    }

    private static byte[] BuildImageManifest(
        string configDigest, long configSize, string layerDigest, long layerSize)
    {
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
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

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
