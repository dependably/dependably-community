using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration tests for OCI blob HTTP Range (206 Partial Content) support.
/// Verifies that docker/containerd-style resumable pulls receive correct 206 responses,
/// that Accept-Ranges is present on HEAD and GET, and that edge cases (invalid ranges,
/// past-end ranges, no Range header) return the correct status codes.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciBlobRangeTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/rangetest";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyFactory _factory;

    public OciBlobRangeTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Happy paths ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetBlob_NoRangeHeader_Returns200WithAcceptRanges()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            using var resp = await client.GetAsync($"/v2/{Repo}/blobs/{layerDigest}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.True(resp.Headers.Contains("Accept-Ranges"),
                "Accept-Ranges header must be present on 200 GET.");
            Assert.Equal("bytes", resp.Headers.GetValues("Accept-Ranges").First());

            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(blobBytes, body);
        }
    }

    [Fact]
    public async Task HeadBlob_Returns200WithAcceptRanges()
    {
        var (client, _, _, layerDigest) = await PushLayerAsync();
        using (client)
        {
            using var resp = await client.SendAsync(
                new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{layerDigest}"));
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.True(resp.Headers.Contains("Accept-Ranges"),
                "Accept-Ranges must be present on HEAD.");
            Assert.Equal("bytes", resp.Headers.GetValues("Accept-Ranges").First());
        }
    }

    [Fact]
    public async Task GetBlob_Range_First10Bytes_Returns206WithCorrectBody()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.Range = new RangeHeaderValue(0, 9);

            using var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.PartialContent, resp.StatusCode);

            string contentRange = resp.Content.Headers.ContentRange?.ToString() ?? string.Empty;
            Assert.StartsWith("bytes 0-9/", contentRange);
            Assert.Contains($"/{blobBytes.Length}", contentRange);

            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(10, body.Length);
            Assert.Equal(blobBytes[..10], body);
        }
    }

    [Fact]
    public async Task GetBlob_Range_Last50Bytes_Returns206WithCorrectBody()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            long total = blobBytes.Length;
            long from = total - 50;
            long to = total - 1;

            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.Range = new RangeHeaderValue(from, to);

            using var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.PartialContent, resp.StatusCode);

            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(50, body.Length);
            Assert.Equal(blobBytes[^50..], body);
        }
    }

    [Fact]
    public async Task GetBlob_Range_OpenEnd_Returns206ToEndOfBlob()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            long from = 100;
            // Open-ended range: bytes=100- (no end)
            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.TryAddWithoutValidation("Range", $"bytes={from}-");

            using var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.PartialContent, resp.StatusCode);

            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(blobBytes.Length - (int)from, body.Length);
            Assert.Equal(blobBytes[(int)from..], body);
        }
    }

    [Fact]
    public async Task GetBlob_Range_BeyondEnd_Returns206ForPartialOverlap()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            // Request range that starts within the blob but ends beyond it.
            long from = blobBytes.Length - 10;
            long to = blobBytes.Length + 999_999;

            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.Range = new RangeHeaderValue(from, to);

            using var resp = await client.SendAsync(request);
            // A range that overlaps should still return 206 with what's available.
            Assert.Equal(HttpStatusCode.PartialContent, resp.StatusCode);

            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(10, body.Length);
            Assert.Equal(blobBytes[^10..], body);
        }
    }

    [Fact]
    public async Task GetBlob_Range_StartsExactlyAtEnd_Returns416()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            // Range starts at one byte past the last valid index — unsatisfiable.
            long from = blobBytes.Length;

            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.Range = new RangeHeaderValue(from, from + 9);

            using var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, resp.StatusCode);

            // Content-Range MUST be "bytes */total" on 416 per RFC 7233.
            string contentRange = resp.Content.Headers.ContentRange?.ToString() ?? string.Empty;
            Assert.Contains($"/{blobBytes.Length}", contentRange);
        }
    }

    [Fact]
    public async Task GetBlob_Range_InvertedRange_Returns200FullBody()
    {
        // A syntactically invalid range (from > to) is treated as "no range" by the
        // parser, so the full blob is returned with 200 rather than 416.
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.TryAddWithoutValidation("Range", "bytes=50-10"); // from > to

            using var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            byte[] body = await resp.Content.ReadAsByteArrayAsync();
            Assert.Equal(blobBytes, body);
        }
    }

    [Fact]
    public async Task GetBlob_Range_ContentRangeHeaderCorrect()
    {
        var (client, _, blobBytes, layerDigest) = await PushLayerAsync();
        using (client)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"/v2/{Repo}/blobs/{layerDigest}");
            request.Headers.Range = new RangeHeaderValue(5, 14);

            using var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.PartialContent, resp.StatusCode);

            string contentRange = resp.Content.Headers.ContentRange?.ToString() ?? string.Empty;
            Assert.Equal($"bytes 5-14/{blobBytes.Length}", contentRange);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task<(HttpClient Client, byte[] ConfigBytes, byte[] LayerBytes, string LayerDigest)> PushLayerAsync()
    {
        string token = await _factory.CreateToken("push");
        var client = _factory.CreateClientWithBearer(token);

        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        // Use a fixed-size blob large enough that range requests are interesting (>200 bytes).
        byte[] layerBytes = new byte[512];
        RandomNumberGenerator.Fill(layerBytes);

        string configDigest = Sha256Digest(configBytes);
        string layerDigest = Sha256Digest(layerBytes);

        await PushBlobMonolithicAsync(client, configBytes, configDigest);
        await PushBlobMonolithicAsync(client, layerBytes, layerDigest);

        byte[] manifest = BuildManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = Sha256Digest(manifest);
        await PutManifestAsync(client, manifestDigest, manifest);

        return (client, configBytes, layerBytes, layerDigest);
    }

    private static async Task PushBlobMonolithicAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var resp = await client.PostAsync(
            $"/v2/{Repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    private static async Task PutManifestAsync(HttpClient client, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        using var resp = await client.PutAsync($"/v2/{Repo}/manifests/{reference}", content);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    private static byte[] BuildManifest(string configDigest, long configSize, string layerDigest, long layerSize)
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

    private static string Sha256Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
