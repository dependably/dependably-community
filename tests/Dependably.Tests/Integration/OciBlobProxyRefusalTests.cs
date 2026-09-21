using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// What the blob proxy answers when it declines to serve a blob the upstream does have.
///
/// <para>
/// Two refusals — a layer over <c>Oci:MaxBlobProxyBytes</c>, and bytes that did not hash to the
/// digest they were requested under — used to leave the fetch path as the same null result, and
/// a null became <c>404 BLOB_UNKNOWN</c>. That is a false statement about content the upstream
/// was in the middle of handing over, and it is the reason a deterministic over-cap layer reads
/// to whoever is debugging it as a corrupted cache entry rather than as a configured limit. So
/// the status is asserted first and separately: not-404 is the defect, and 5xx is the fix.
/// </para>
///
/// <para>
/// Each refusal is then asserted to carry its own marker AND to lack the other's. One shared
/// constant naming neither, or a message naming both, would satisfy a one-sided assertion while
/// leaving an operator unable to tell a number they chose from an integrity event worth alerting
/// on.
/// </para>
///
/// <para>
/// The disclosure half follows the manifest plane's rule (<c>ManifestUnknownAsync</c>): a
/// <c>/v2/</c> blob read is anonymously reachable under <c>anonymous_pull</c>, so the upstream
/// host and the fault are for token-holders only. Both halves of that pair are asserted against
/// one instance — asserting only the absence would pass on an instance that never names an
/// upstream at all.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciBlobProxyRefusalTests
{
    // A host that appears nowhere in the seeded defaults, so finding it in a response body can
    // only mean this org's configured routing leaked into it.
    private const string PrivateUpstreamHost = "mirror.internal.example";

    private const string Repo = "unsloth/unsloth";

    // The smallest cap OciOptionsValidator accepts, so the "over cap" body stays small enough to
    // build in memory while still crossing a real configured ceiling.
    private const long CapBytes = 1024L * 1024;

    /// <summary>Markers that identify each fault, asserted present for one and absent for the other.</summary>
    private const string TooLargeMarker = "per-blob proxy limit";
    private const string MismatchMarker = "does not match the requested digest";

    private static string DigestOf(byte[] data)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>An upstream that serves <paramref name="body"/> for any blob request.</summary>
    private static DependablyFactory UpstreamServing(byte[] body, bool declareLength = true) => new()
    {
        ExtraSettings = new Dictionary<string, string?>
        {
            ["Oci:MaxBlobProxyBytes"] = CapBytes.ToString(),
        },
        OciUpstreamHandler = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = declareLength
                ? new ByteArrayContent(body)
                : new StreamContent(new NonSeekableStream(body)),
        },
    };

    // ── The status code: the defect itself ────────────────────────────────────

    [Fact]
    public async Task OverCapBlob_Returns502_NotTheBlobUnknown404()
    {
        byte[] body = new byte[CapBytes + 4096];
        Random.Shared.NextBytes(body);

        await using var factory = UpstreamServing(body);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/v2/{Repo}/blobs/{DigestOf(body)}");

        // Asserted as its own fact, ahead of any message check: a 404 here is the bug, and a
        // test that only inspected the prose would pass on a better-worded lie.
        Assert.NotEqual(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
    }

    /// <summary>
    /// A chunked upstream declares no Content-Length, so the pre-check cannot catch it and the
    /// cap is enforced mid-stream instead — a separate branch, reaching the same refusal.
    /// </summary>
    [Fact]
    public async Task OverCapBlob_WithNoDeclaredLength_IsRefusedMidStream_NotServedAsAMiss()
    {
        byte[] body = new byte[CapBytes + 4096];
        Random.Shared.NextBytes(body);

        await using var factory = UpstreamServing(body, declareLength: false);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/v2/{Repo}/blobs/{DigestOf(body)}");

        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.Equal("blob_too_large", await ReadFaultAsync(resp));
    }

    // ── The two faults, each distinguished from the other ─────────────────────

    [Fact]
    public async Task OverCapBlob_NamesTheCap_AndNotAnIntegrityFailure()
    {
        byte[] body = new byte[CapBytes + 4096];
        Random.Shared.NextBytes(body);

        await using var factory = UpstreamServing(body);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/v2/{Repo}/blobs/{DigestOf(body)}");

        string message = await ReadMessageAsync(resp);
        Assert.Contains(TooLargeMarker, message, StringComparison.Ordinal);
        Assert.Contains(CapBytes.ToString(), message, StringComparison.Ordinal);
        Assert.Contains("Oci__MaxBlobProxyBytes", message, StringComparison.Ordinal);
        Assert.Equal("blob_too_large", await ReadFaultAsync(resp));

        // The other fault's marker must be absent, or one constant naming every cause passes.
        Assert.DoesNotContain(MismatchMarker, message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DigestMismatch_IsReportedAsIntegrity_AndNotAsTheCap()
    {
        byte[] served = "these are not the bytes you asked for"u8.ToArray();
        byte[] requested = "the bytes that were actually requested"u8.ToArray();

        await using var factory = UpstreamServing(served);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        // Well under the cap, so nothing but the digest check can refuse it.
        var resp = await client.GetAsync($"/v2/{Repo}/blobs/{DigestOf(requested)}");

        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        string message = await ReadMessageAsync(resp);
        Assert.Contains(MismatchMarker, message, StringComparison.Ordinal);
        Assert.Equal("blob_digest_mismatch", await ReadFaultAsync(resp));

        Assert.DoesNotContain(TooLargeMarker, message, StringComparison.Ordinal);
    }

    // ── The happy path still works ────────────────────────────────────────────

    [Fact]
    public async Task UnderCapBlob_WithMatchingDigest_IsProxiedAndServed()
    {
        byte[] body = new byte[64 * 1024];
        Random.Shared.NextBytes(body);

        await using var factory = UpstreamServing(body);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/v2/{Repo}/blobs/{DigestOf(body)}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(body, await resp.Content.ReadAsByteArrayAsync());
    }

    // ── HEAD must not disagree with GET ───────────────────────────────────────

    /// <summary>
    /// Docker HEADs a layer before pulling it. A HEAD that answers 200 for a blob the GET will
    /// refuse sends the client to fetch something this registry has already decided not to
    /// carry, so the refusal lands mid-pull instead of before it.
    /// </summary>
    [Fact]
    public async Task Head_RefusesAnOverCapBlob_JustAsGetDoes()
    {
        byte[] body = new byte[CapBytes + 4096];
        Random.Shared.NextBytes(body);

        await using var factory = UpstreamServing(body);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        using var req = new HttpRequestMessage(HttpMethod.Head, $"/v2/{Repo}/blobs/{DigestOf(body)}");
        var head = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.BadGateway, head.StatusCode);
    }

    // ── Disclosure ────────────────────────────────────────────────────────────

    /// <summary>
    /// The org's upstream list is supply-chain topology, and a blob GET is anonymously reachable
    /// under anonymous pull exactly as a manifest GET is. The status is for everyone — the
    /// unreachable-upstream path on this route already answers 502 anonymously — but the host
    /// and the fault are not.
    /// </summary>
    [Fact]
    public async Task AnonymousCaller_GetsTheStatusButNotTheTopology_WhileAnAuthenticatedOneGetsBoth()
    {
        byte[] body = new byte[CapBytes + 4096];
        Random.Shared.NextBytes(body);
        string digest = DigestOf(body);

        await using var factory = UpstreamServing(body);
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost);
        await EnableAnonymousPullAsync(factory);

        using var anonymous = factory.CreateClient();
        var anonResp = await anonymous.GetAsync($"/v2/{Repo}/blobs/{digest}");

        // The honest status is not a disclosure and is not withheld.
        Assert.Equal(HttpStatusCode.BadGateway, anonResp.StatusCode);

        string anonBody = await anonResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain(PrivateUpstreamHost, anonBody, StringComparison.Ordinal);
        Assert.DoesNotContain(TooLargeMarker, anonBody, StringComparison.Ordinal);
        Assert.Null(await ReadDetailAsync(anonResp));

        // The twin: the same request with a credential must disclose it. Without this the
        // absence assertions above pass on an instance that never names an upstream at all.
        string token = await factory.CreateToken("pull");
        using var authed = factory.CreateClientWithBearer(token);
        var authResp = await authed.GetAsync($"/v2/{Repo}/blobs/{digest}");

        string authMessage = await ReadMessageAsync(authResp);
        Assert.Contains(PrivateUpstreamHost, authMessage, StringComparison.Ordinal);
        Assert.Contains(TooLargeMarker, authMessage, StringComparison.Ordinal);
        Assert.Equal("blob_too_large", await ReadFaultAsync(authResp));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>A stream that refuses to report its length, so StreamContent declares none.</summary>
    private sealed class NonSeekableStream : Stream
    {
        private readonly MemoryStream _inner;
        public NonSeekableStream(byte[] data) => _inner = new MemoryStream(data);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override void Flush() => _inner.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Replaces the org's seeded OCI routing with exactly one upstream, so an assertion about
    /// which host is named cannot be satisfied by a default row.
    /// </summary>
    private static async Task RouteAllToAsync(DependablyFactory factory, string host)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn,
            "DELETE FROM upstream_registry WHERE ecosystem = 'oci'");
        await Dapper.SqlMapper.ExecuteAsync(conn,
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, prefixes)
            SELECT lower(hex(randomblob(16))), id, 'oci', @host, 0, 'anonymous', @prefixes
            FROM orgs
            """,
            new { host, prefixes = JsonSerializer.Serialize(new[] { "" }) });
    }

    private static async Task EnableAnonymousPullAsync(DependablyFactory factory)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn,
            """
            INSERT INTO org_settings (org_id, anonymous_pull)
            SELECT id, 1 FROM orgs
            WHERE true
            ON CONFLICT(org_id) DO UPDATE SET anonymous_pull = 1
            """);
    }

    private static async Task<string> ReadMessageAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("errors")[0].GetProperty("message").GetString() ?? "";
    }

    private static async Task<string?> ReadDetailAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var detail = doc.RootElement.GetProperty("errors")[0].GetProperty("detail");
        return detail.ValueKind == JsonValueKind.Null ? null : detail.GetRawText();
    }

    private static async Task<string?> ReadFaultAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("errors")[0]
            .GetProperty("detail").GetProperty("fault").GetString();
    }
}
