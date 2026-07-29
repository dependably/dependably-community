using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the staging-continuity precondition on the OCI chunked-upload path.
///
/// The session row lives in the shared database while the staging file is replica-local, so a
/// PATCH routed to a replica that does not own the session still resolves the session. Without a
/// precondition, <c>FileMode.Append</c> creates the missing file, the chunk lands at offset 0, the
/// shared <c>received_bytes</c> is overwritten with the wrong local length, and the client is told
/// 202 — the push failing only at finalize with DIGEST_INVALID after the whole layer streamed.
///
/// A missing staging file is exactly what a mis-routed request looks like from the receiving
/// replica's point of view, so these tests delete or truncate the staging file to reproduce the
/// condition against a single instance.
///
/// Every refusal case is paired with a "must still be accepted" twin, because a continuity check
/// that is too strict breaks correct clients: docker and containerd omit Content-Range entirely,
/// and a resuming client sends one that is legitimately contiguous.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciChunkContinuityTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Repo = "team/continuity";

    private readonly DependablyFactory _factory;

    public OciChunkContinuityTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Mis-routed PATCH: staging file absent on this replica ────────────────────

    [Fact]
    public async Task Patch_StagingFileMissing_Returns416_NotAccepted()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);
        string uploadId = UploadIdFrom(location);

        // First chunk lands normally on the owning replica.
        byte[] first = RandomBytes(2048);
        using (var patch = await PatchAsync(client, location, first, contentRange: null))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }
        Assert.Equal(first.Length, await ReceivedBytesAsync(uploadId));

        // Simulate the mis-route: this replica has no staging file for the session.
        File.Delete(await StagingPathAsync(uploadId));

        byte[] second = RandomBytes(2048);
        using var misrouted = await PatchAsync(client, location, second, contentRange: null);

        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, misrouted.StatusCode);

        // The refusal must tell the client where the upload actually is, so it can resume.
        Assert.Equal($"0-{first.Length - 1}", Assert.Single(misrouted.Headers.GetValues("Range")));
        Assert.Equal(uploadId, Assert.Single(misrouted.Headers.GetValues("Docker-Upload-UUID")));
        Assert.Contains("BLOB_UPLOAD_INVALID", await misrouted.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Patch_StagingFileMissing_DoesNotOverwriteRecordedProgress()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);
        string uploadId = UploadIdFrom(location);

        byte[] first = RandomBytes(4096);
        using (var patch = await PatchAsync(client, location, first, contentRange: null))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }

        File.Delete(await StagingPathAsync(uploadId));

        // A 512-byte chunk on a replica with no staging file is what used to rewrite
        // received_bytes from 4096 down to 512 and return 202.
        using (var misrouted = await PatchAsync(client, location, RandomBytes(512), contentRange: null))
        {
            Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, misrouted.StatusCode);
        }

        Assert.Equal(first.Length, await ReceivedBytesAsync(uploadId));

        // The session survives the refusal — a mis-route is the load balancer's fault, and the
        // upload must stay resumable rather than being torn down under the client.
        Assert.NotNull(await StagingPathAsync(uploadId));
    }

    [Fact]
    public async Task Patch_StagingFileTruncated_Returns416()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);
        string uploadId = UploadIdFrom(location);

        using (var patch = await PatchAsync(client, location, RandomBytes(4096), contentRange: null))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }

        // A present-but-wrong-length staging file is the case a bare File.Exists check would miss.
        string staging = await StagingPathAsync(uploadId);
        using (var fs = new FileStream(staging, FileMode.Open, FileAccess.Write))
        {
            fs.SetLength(1024);
        }

        using var resp = await PatchAsync(client, location, RandomBytes(256), contentRange: null);
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, resp.StatusCode);
        Assert.Equal("0-4095", Assert.Single(resp.Headers.GetValues("Range")));
    }

    // ── Content-Range continuity ─────────────────────────────────────────────────

    [Fact]
    public async Task Patch_ContentRangeOutOfOrder_Returns416()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);
        string uploadId = UploadIdFrom(location);

        using (var patch = await PatchAsync(client, location, RandomBytes(1024), contentRange: "0-1023"))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }

        // Session is at 1024; a chunk claiming to start at 4096 skips a gap.
        using var gapped = await PatchAsync(client, location, RandomBytes(512), contentRange: "4096-4607");
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, gapped.StatusCode);
        Assert.Equal("0-1023", Assert.Single(gapped.Headers.GetValues("Range")));

        // The rejected chunk must not have been written.
        Assert.Equal(1024, await ReceivedBytesAsync(uploadId));
    }

    [Fact]
    public async Task Patch_ContentRangeReplayingAnAlreadyReceivedOffset_Returns416()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);
        string uploadId = UploadIdFrom(location);

        using (var patch = await PatchAsync(client, location, RandomBytes(2048), contentRange: "0-2047"))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }

        // Re-sending the first chunk would duplicate bytes if appended blindly.
        using var replay = await PatchAsync(client, location, RandomBytes(2048), contentRange: "0-2047");
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, replay.StatusCode);
        Assert.Equal(2048, await ReceivedBytesAsync(uploadId));
    }

    // ── Correct clients must keep working ────────────────────────────────────────

    [Fact]
    public async Task Patch_ContiguousContentRange_IsAccepted()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);
        string uploadId = UploadIdFrom(location);

        using (var first = await PatchAsync(client, location, RandomBytes(1024), contentRange: "0-1023"))
        {
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        }

        using (var second = await PatchAsync(client, location, RandomBytes(1024), contentRange: "1024-2047"))
        {
            Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
            Assert.Equal("0-2047", Assert.Single(second.Headers.GetValues("Range")));
        }

        Assert.Equal(2048, await ReceivedBytesAsync(uploadId));
    }

    [Fact]
    public async Task Patch_RfcShapedContentRange_IsAccepted()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        string location = await StartUploadAsync(client);

        using (var first = await PatchAsync(client, location, RandomBytes(1024), contentRange: "bytes 0-1023/2048"))
        {
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        }

        // A client that spells the header the RFC 7233 way rather than the OCI way is being more
        // correct than the spec requires and must not be refused for it.
        using var second = await PatchAsync(client, location, RandomBytes(1024), contentRange: "bytes 1024-2047/2048");
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
    }

    [Fact]
    public async Task ChunkedPush_WithoutContentRange_StillRoundTrips()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // docker and containerd omit Content-Range on PATCH; the continuity check must not have
        // made the header mandatory.
        byte[] blob = RandomBytes(8192);
        string digest = Digest(blob);

        string location = await StartUploadAsync(client);
        using (var patch = await PatchAsync(client, location, blob[..4096], contentRange: null))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }
        using (var patch = await PatchAsync(client, location, blob[4096..], contentRange: null))
        {
            Assert.Equal(HttpStatusCode.Accepted, patch.StatusCode);
        }

        using (var put = await client.PutAsync($"{location}?digest={digest}", new ByteArrayContent([])))
        {
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        using var get = await client.GetAsync($"/v2/{Repo}/blobs/{digest}");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(blob, await get.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task MonolithicPush_IsUnaffectedByTheContinuityCheck()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // A monolithic POST appends to a session whose staging file was just created empty, so
        // the precondition (length 0 == received_bytes 0) must hold on the very first append.
        byte[] blob = RandomBytes(4096);
        string digest = Digest(blob);

        using (var post = await client.PostAsync(
            $"/v2/{Repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(blob)))
        {
            Assert.Equal(HttpStatusCode.Created, post.StatusCode);
        }

        using var get = await client.GetAsync($"/v2/{Repo}/blobs/{digest}");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(blob, await get.Content.ReadAsByteArrayAsync());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private static async Task<string> StartUploadAsync(HttpClient client)
    {
        using var resp = await client.PostAsync($"/v2/{Repo}/blobs/uploads/", new ByteArrayContent([]));
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        return Assert.Single(resp.Headers.GetValues("Location"));
    }

    private static async Task<HttpResponseMessage> PatchAsync(
        HttpClient client, string location, byte[] body, string? contentRange)
    {
        var content = new ByteArrayContent(body);
        if (contentRange is not null)
        {
            content.Headers.TryAddWithoutValidation("Content-Range", contentRange);
        }
        return await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Patch, location) { Content = content });
    }

    private static string UploadIdFrom(string location) => location.Split('/')[^1];

    private async Task<long> ReceivedBytesAsync(string uploadId)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT received_bytes FROM oci_uploads WHERE upload_id = @uploadId", new { uploadId });
    }

    private async Task<string> StagingPathAsync(string uploadId)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        string? path = await conn.ExecuteScalarAsync<string?>(
            "SELECT staging_path FROM oci_uploads WHERE upload_id = @uploadId", new { uploadId });
        return Assert.IsType<string>(path);
    }

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static byte[] RandomBytes(int n)
    {
        byte[] buf = new byte[n];
        RandomNumberGenerator.Fill(buf);
        return buf;
    }
}
