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
/// End-to-end coverage for the OCI Distribution Spec push surface: blob upload sessions
/// (monolithic + chunked), manifest puts with referenced-blob validation, and the round-trip
/// back through the existing pull path. Also pins the auth gate (token + publish:oci),
/// digest verification, cumulative size enforcement, and partial-failure cleanup.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciPushTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/app";
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly DependablyFactory _factory;

    public OciPushTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Happy path: push two blobs (chunked + monolithic) + manifest, then pull back ──

    [Fact]
    public async Task Push_FullImage_RoundTripsThroughPullPath()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layerBytes = RandomBytes(4096);
        string configDigest = Digest(configBytes);
        string layerDigest = Digest(layerBytes);

        // Config via chunked upload (POST → PATCH → PUT); layer via monolithic single-POST.
        await PushBlobChunkedAsync(client, configBytes, configDigest);
        await PushBlobMonolithicAsync(client, layerBytes, layerDigest);

        byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
        string manifestDigest = Digest(manifest);

        // PUT the manifest by tag.
        using (var put = await PutManifestAsync(client, "1.0.0", manifest))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
            Assert.Equal(manifestDigest, Assert.Single(put.Headers.GetValues("Docker-Content-Digest")));
            Assert.Equal($"/v2/{Repo}/manifests/{manifestDigest}", Assert.Single(put.Headers.GetValues("Location")));
        }

        // Pull the manifest back by tag — exact bytes.
        using (var get = await client.GetAsync($"/v2/{Repo}/manifests/1.0.0"))
        {
            Assert.Equal(HttpStatusCode.OK, get.StatusCode);
            Assert.Equal(manifestDigest, Assert.Single(get.Headers.GetValues("Docker-Content-Digest")));
            Assert.Equal(manifest, await get.Content.ReadAsByteArrayAsync());
        }

        // Pull a layer blob back by digest — exact bytes.
        using (var get = await client.GetAsync($"/v2/{Repo}/blobs/{layerDigest}"))
        {
            Assert.Equal(HttpStatusCode.OK, get.StatusCode);
            Assert.Equal(layerBytes, await get.Content.ReadAsByteArrayAsync());
        }

        // HEAD the config blob — present.
        using (var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{configDigest}")))
        {
            Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        }

        // Tags list includes the pushed tag.
        using var tags = await client.GetAsync($"/v2/{Repo}/tags/list");
        Assert.Equal(HttpStatusCode.OK, tags.StatusCode);
        using var doc = JsonDocument.Parse(await tags.Content.ReadAsStringAsync());
        var list = doc.RootElement.GetProperty("tags").EnumerateArray().Select(t => t.GetString()).ToList();
        Assert.Contains("1.0.0", list);
    }

    // ── Auth gate ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task UploadInit_NoToken_Returns401()
    {
        using var client = _factory.CreateClient();
        using var resp = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.True(resp.Headers.WwwAuthenticate.Count > 0);
        // Challenge MUST be Basic: a Bearer realm must be a token-endpoint URL we do
        // not serve, so docker/skopeo could not satisfy it. Basic lets them send
        // base64(user:PAT), which ResolveTokenAsync accepts.
        Assert.Equal("Basic", resp.Headers.WwwAuthenticate.First().Scheme);
    }

    [Fact]
    public async Task UploadInit_TokenWithoutPublishOci_Returns403()
    {
        string token = await _factory.CreateToken("pull"); // read-only caps, no publish:oci
        using var client = _factory.CreateClientWithBearer(token);
        using var resp = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Digest verification ──────────────────────────────────────────────────────────

    [Fact]
    public async Task BlobFinalize_DigestMismatch_Returns400AndStoresNothing()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] bytes = RandomBytes(512);
        string wrongDigest = Digest(RandomBytes(512)); // digest of different content

        // Chunked: POST → PATCH (real bytes) → PUT with the WRONG digest.
        string location = await StartUploadAsync(client);
        using (var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location)
        { Content = new ByteArrayContent(bytes) }))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }
        using (var put = await client.PutAsync($"{location}?digest={wrongDigest}", new ByteArrayContent([])))
        {
            Assert.Equal(HttpStatusCode.BadRequest, put.StatusCode);
        }

        // The blob must not be retrievable — the mismatched upload was discarded.
        using var get = await client.GetAsync($"/v2/{Repo}/blobs/{wrongDigest}");
        Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
    }

    // ── Manifest referenced-blob validation ──────────────────────────────────────────

    [Fact]
    public async Task ManifestPut_MissingReferencedBlob_Returns404ManifestBlobUnknown()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Reference a config blob that was never uploaded.
        string missing = Digest(RandomBytes(128));
        byte[] manifest = BuildImageManifest(missing, 128, missing, 128);

        using var put = await PutManifestAsync(client, "broken", manifest);
        Assert.Equal(HttpStatusCode.NotFound, put.StatusCode);
        string body = await put.Content.ReadAsStringAsync();
        Assert.Contains("MANIFEST_BLOB_UNKNOWN", body);
    }

    [Fact]
    public async Task ManifestPut_MalformedJson_Returns400ManifestInvalid()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        using var put = await PutManifestAsync(client, "garbage", Encoding.UTF8.GetBytes("{ not json"));
        Assert.Equal(HttpStatusCode.BadRequest, put.StatusCode);
        Assert.Contains("MANIFEST_INVALID", await put.Content.ReadAsStringAsync());
    }

    // ── Cumulative size enforcement ──────────────────────────────────────────────────

    [Fact]
    public async Task BlobUpload_ExceedsCumulativeOciLimit_Returns413()
    {
        string orgId = await OrgIdAsync();
        await SetOciLimitAsync(orgId, 1024);
        try
        {
            string token = await _factory.CreateToken("push");
            using var client = _factory.CreateClientWithBearer(token);

            byte[] tooBig = RandomBytes(4096); // exceeds the 1 KiB limit
            string location = await StartUploadAsync(client);
            using var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location)
            { Content = new ByteArrayContent(tooBig) });

            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, patch.StatusCode);
        }
        finally
        {
            await SetOciLimitAsync(orgId, null); // restore: unlimited (shared factory)
        }
    }

    // ── Aggregate storage quota enforcement ─────────────────────────────────────────

    [Fact]
    public async Task BlobFinalize_ExceedsStorageQuota_Returns413()
    {
        // Sets the tenant's aggregate storage quota to 50 bytes, then attempts to finalize a
        // 512-byte blob. The finalize PUT must return 413 with SIZE_INVALID — the quota gate
        // fires before the blob is written to the Registry tier.
        string orgId = await OrgIdAsync();
        await SetStorageQuotaAsync(orgId, 50); // tiny cap
        try
        {
            string token = await _factory.CreateToken("push");
            using var client = _factory.CreateClientWithBearer(token);

            byte[] blob = RandomBytes(512);
            string digest = Digest(blob);
            string location = await StartUploadAsync(client);

            // PATCH: chunk the bytes in; the chunk check passes (per-blob upload limit is unset).
            using (var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location)
            { Content = new ByteArrayContent(blob) }))
            {
                Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
            }

            // PUT (finalize): quota gate fires here.
            using var put = await client.PutAsync($"{location}?digest={digest}", new ByteArrayContent([]));
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, put.StatusCode);
            string body = await put.Content.ReadAsStringAsync();
            Assert.Contains("SIZE_INVALID", body);
        }
        finally
        {
            await SetStorageQuotaAsync(orgId, null);
        }
    }

    [Fact]
    public async Task ManifestPut_ExceedsStorageQuota_Returns413()
    {
        // Pushes a config and layer blob successfully under an ample quota, then tightens
        // the quota to exactly the current usage so the manifest PUT cannot fit, and asserts
        // the manifest PUT returns 413.
        string orgId = await OrgIdAsync();
        try
        {
            string token = await _factory.CreateToken("push");
            using var client = _factory.CreateClientWithBearer(token);

            byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
            byte[] layerBytes = RandomBytes(256);
            string configDigest = Digest(configBytes);
            string layerDigest = Digest(layerBytes);

            // Push both blobs successfully (no quota yet).
            await PushBlobMonolithicAsync(client, configBytes, configDigest);
            await PushBlobMonolithicAsync(client, layerBytes, layerDigest);

            // Read current usage and clamp the quota to it, leaving no room for the manifest.
            long used = await ReadStorageUsedBytesAsync(orgId);
            await SetStorageQuotaAsync(orgId, used);

            // Manifest PUT must be rejected.
            byte[] manifest = BuildImageManifest(configDigest, configBytes.Length, layerDigest, layerBytes.Length);
            using var put = await PutManifestAsync(client, "1.0.0", manifest);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, put.StatusCode);
            Assert.Contains("SIZE_INVALID", await put.Content.ReadAsStringAsync());
        }
        finally
        {
            await SetStorageQuotaAsync(orgId, null);
        }
    }

    [Fact]
    public async Task BlobFinalize_MixedScenario_FirstFitsSecondQuotaExceeded()
    {
        // Pushes a first blob (500 bytes) that fits inside the quota budget, then a second
        // blob (400 bytes) whose addition would exceed the budget — asserts the second
        // finalize returns 413 and that the counter reflects only the accepted bytes.
        //
        // The shared factory accumulates data across tests. The quota is set relative to the
        // live usage baseline at the start of this test so other tests' data doesn't affect
        // the arithmetic: baseline + 500 fits, baseline + 500 + 400 does not.
        string orgId = await OrgIdAsync();
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Trigger the backfill so the baseline counter is accurate before we set a quota.
        // (TryReserveStorageAsync backfills from the live SUM on first call when counter = 0.)
        long baseline = await TriggerBackfillAndReadCounterAsync(orgId);
        long quota = baseline + 700; // 500 fits, 500 + 400 = 900 > 700 head-room
        await SetStorageQuotaAsync(orgId, quota);
        try
        {
            // First blob: 500 bytes — baseline + 500 <= baseline + 700 → fits.
            byte[] blob1 = RandomBytes(500);
            string location1 = await StartUploadAsync(client);
            using (var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location1)
            { Content = new ByteArrayContent(blob1) }))
            {
                Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
            }
            using (var put = await client.PutAsync($"{location1}?digest={Digest(blob1)}", new ByteArrayContent([])))
            {
                Assert.Equal(HttpStatusCode.Created, put.StatusCode);
            }

            // Second blob: 400 bytes — baseline + 500 + 400 = baseline + 900 > baseline + 700 → rejected.
            byte[] blob2 = RandomBytes(400);
            string location2 = await StartUploadAsync(client);
            using (var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location2)
            { Content = new ByteArrayContent(blob2) }))
            {
                Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
            }
            using var putFail = await client.PutAsync($"{location2}?digest={Digest(blob2)}", new ByteArrayContent([]));
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, putFail.StatusCode);

            // Counter must be exactly baseline + 500 (the rejected blob must not add to it).
            long counter = await ReadStorageUsedBytesAsync(orgId);
            Assert.Equal(baseline + 500, counter);
        }
        finally
        {
            await SetStorageQuotaAsync(orgId, null);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────────

    private static async Task<string> StartUploadAsync(HttpClient client)
    {
        using var resp = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        return Assert.Single(resp.Headers.GetValues("Location"));
    }

    private static async Task PushBlobChunkedAsync(HttpClient client, byte[] bytes, string digest)
    {
        string location = await StartUploadAsync(client);
        using (var patch = await client.SendAsync(new HttpRequestMessage(HttpMethod.Patch, location)
        { Content = new ByteArrayContent(bytes) }))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }
        using var put = await client.PutAsync($"{location}?digest={digest}", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        Assert.Equal(digest, Assert.Single(put.Headers.GetValues("Docker-Content-Digest")));
    }

    private static async Task PushBlobMonolithicAsync(HttpClient client, byte[] bytes, string digest)
    {
        using var resp = await client.PostAsync(
            $"/v2/{Repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(bytes));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        Assert.Equal(digest, Assert.Single(resp.Headers.GetValues("Docker-Content-Digest")));
    }

    private static async Task<HttpResponseMessage> PutManifestAsync(HttpClient client, string reference, byte[] manifest)
    {
        var content = new ByteArrayContent(manifest);
        content.Headers.ContentType = new MediaTypeHeaderValue(ManifestMediaType);
        return await client.PutAsync($"/v2/{Repo}/manifests/{reference}", content);
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

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private async Task<string> OrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'"))!;
    }

    private async Task SetOciLimitAsync(string orgId, long? bytes)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_upload_bytes_oci = @bytes WHERE org_id = @orgId",
            new { bytes, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetStorageQuotaAsync(string orgId, long? quota)
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        await orgs.SetStorageQuotaBytesAsync(orgId, quota);
    }

    private async Task<long> ReadStorageUsedBytesAsync(string orgId)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(storage_used_bytes, 0) FROM org_settings WHERE org_id = @orgId",
            new { orgId });
    }

    /// <summary>
    /// Forces the quota counter backfill (live SUM of package_versions) that
    /// TryReserveStorageAsync runs on first call when the counter is 0, then returns the
    /// accurate baseline. Without this, a test that sets a quota before any reserve call
    /// would see the counter backfill on the first reserve — potentially invalidating the
    /// expected arithmetic when the backfill value exceeds the test's quota headroom.
    /// </summary>
    private async Task<long> TriggerBackfillAndReadCounterAsync(string orgId)
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        // A reserve-with-null-quota never modifies the counter but still runs the backfill
        // (the UPDATE's WHERE clause succeeds when storage_used_bytes = 0 and quota is null).
        // After this call the counter reflects the live SUM from package_versions.
        await orgs.TryReserveStorageAsync(orgId, delta: 0, quota: null, ct: default);
        return await ReadStorageUsedBytesAsync(orgId);
    }
}
