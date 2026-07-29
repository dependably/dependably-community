using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Coverage for <see cref="ApkIndexFetchCoordinator"/>'s <c>APKINDEX.tar.gz</c> server-side
/// signature verification gate. Mirrors the <c>Rpm:VerifyRepomdSignature</c> gating matrix
/// (<see cref="Dependably.Protocol.RpmUpstreamProxy"/>): verification is enabled when the
/// instance override is explicitly set, or otherwise iff the org has a configured apk RSA
/// trust anchor.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ApkIndexFetchCoordinatorTests : IAsyncLifetime
{
    private const string TestOrgId = "test-org";
    private const string Release = "edge";
    private const string Repo = "main";
    private const string Arch = "x86_64";
    private const string IndexFile = "APKINDEX.tar.gz";

    private WireMockServer _server = null!;
    private string _upstream = null!;

    public Task InitializeAsync()
    {
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _server.Stop();
        return Task.CompletedTask;
    }

    // ── gating matrix ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAsync_OverrideTrue_NoAnchors_FailsClosed()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        StubIndex(apkindex);

        var coordinator = BuildCoordinator(verifyFlag: "true");  // no anchor seeded

        await Assert.ThrowsAsync<ApkIndexSignatureVerificationFailedException>(
            () => coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default));
    }

    [Fact]
    public async Task GetAsync_OverrideUnset_NoAnchors_PassesThroughUnverified()
    {
        // Back-compat: an org with no trust anchor and no explicit override gets the raw
        // upstream bytes exactly as before — even bytes that aren't a validly signed index.
        byte[] rawBytes = "fake-index-bytes"u8.ToArray();
        StubIndex(rawBytes);

        var coordinator = BuildCoordinator();

        var result = await coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);

        Assert.NotNull(result);
        Assert.Equal(rawBytes, await ReadAllAsync(result!.Body));
    }

    [Fact]
    public async Task GetAsync_AnchorConfigured_ValidSignature_Verifies()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        StubIndex(apkindex);

        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa), acceptSha1: true);

        var result = await coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);

        Assert.NotNull(result);
        Assert.Equal(apkindex, await ReadAllAsync(result!.Body));
    }

    [Fact]
    public async Task GetAsync_AnchorConfigured_TamperedIndex_RefusesAndDoesNotCache()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        byte[] tampered = (byte[])apkindex.Clone();
        tampered[^1] ^= 0xFF;
        StubIndex(tampered);

        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa), acceptSha1: true);

        await Assert.ThrowsAsync<ApkIndexSignatureVerificationFailedException>(
            () => coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default));

        // Refused bytes must never be cached — a retry after fixing upstream must re-fetch.
        await Assert.ThrowsAsync<ApkIndexSignatureVerificationFailedException>(
            () => coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default));
        Assert.Equal(2, _server.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, $"/{Release}/{Repo}/{Arch}/{IndexFile}", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task GetAsync_AnchorConfigured_UnrelatedKey_Refuses()
    {
        using var signer = RSA.Create(2048);
        using var unrelated = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(signer, "signer@test-deadbeef.rsa.pub");
        StubIndex(apkindex);

        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(unrelated), acceptSha1: true);

        await Assert.ThrowsAsync<ApkIndexSignatureVerificationFailedException>(
            () => coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default));
    }

    // ── SHA-1 index-signature acceptance ──────────────────────────────────────

    /// <summary>
    /// The digest algorithm of an <c>APKINDEX.tar.gz</c> signature is named by the index itself,
    /// so a SHA-1 <c>.SIGN.RSA.*</c> entry lets untrusted input pick the weak arm. With the
    /// opt-in off the index is refused — and refusal must reach the caller as a verification
    /// failure (the index is neither cached nor served), never as a pass.
    /// </summary>
    [Fact]
    public async Task GetAsync_Sha1Signature_OptInOff_FailsClosed()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        StubIndex(apkindex);

        // Correct anchor, cryptographically valid signature — refused on algorithm alone.
        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa), acceptSha1: false);

        await Assert.ThrowsAsync<ApkIndexSignatureVerificationFailedException>(
            () => coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default));

        // And the refused bytes are not cached: a second call re-fetches rather than serving them.
        await Assert.ThrowsAsync<ApkIndexSignatureVerificationFailedException>(
            () => coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default));
        Assert.Equal(2, _server.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, $"/{Release}/{Repo}/{Arch}/{IndexFile}", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Adversarial twin: a SHA-256 index signature is outside the opt-in and verifies with the
    /// SHA-1 switch off, so the refusal above is scoped to the weak algorithm rather than
    /// breaking apk index verification wholesale.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetAsync_Sha256Signature_VerifiesInEitherSha1Posture(bool acceptSha1)
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSha256SignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        StubIndex(apkindex);

        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa), acceptSha1: acceptSha1);

        var result = await coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);

        Assert.NotNull(result);
        Assert.Equal(apkindex, await ReadAllAsync(result!.Body));
    }

    [Fact]
    public async Task GetAsync_OverrideFalse_AnchorConfigured_SkipsVerification()
    {
        // An explicit false override always wins over anchor presence — mirrors
        // Rpm:VerifyRepomdSignature's override semantics exactly.
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        byte[] tampered = (byte[])apkindex.Clone();
        tampered[^1] ^= 0xFF;
        StubIndex(tampered);

        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa), verifyFlag: "false");

        var result = await coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);

        Assert.NotNull(result);
        Assert.Equal(tampered, await ReadAllAsync(result!.Body));
    }

    [Fact]
    public async Task GetAsync_NonIndexFilename_NeverVerified()
    {
        // Only APKINDEX.tar.gz is gated; a raw .SIGN.RSA.* blob (or any other index-adjacent
        // file) passes through exactly like before, even with an anchor configured.
        byte[] rawSignatureBlob = new byte[256];
        RandomNumberGenerator.Fill(rawSignatureBlob);
        const string signatureFile = ".SIGN.RSA.signer@test-deadbeef.rsa.pub";
        _server.Given(Request.Create().WithPath($"/{Release}/{Repo}/{Arch}/{signatureFile}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(rawSignatureBlob));

        using var rsa = RSA.Create(2048);
        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa));

        var result = await coordinator.GetAsync(
            _upstream, Release, Repo, Arch, signatureFile, null, null, TestOrgId, default);

        Assert.NotNull(result);
        Assert.Equal(rawSignatureBlob, await ReadAllAsync(result!.Body));
    }

    [Fact]
    public async Task GetAsync_CacheHit_ReVerifiesOnEveryCall()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(rsa, "signer@test-deadbeef.rsa.pub");
        StubIndex(apkindex);

        var coordinator = BuildCoordinator(rsaPublicKeyPem: ExportPublicPem(rsa), acceptSha1: true);

        var first = await coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);
        var second = await coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);

        Assert.NotNull(first);
        Assert.NotNull(second);
        // Single-flight cache: only one upstream round-trip even though verification re-runs
        // against the caller's anchors on both the miss and the cache-hit path.
        Assert.Equal(1, _server.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, $"/{Release}/{Repo}/{Arch}/{IndexFile}", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task GetAsync_CallerCancelsWhileFetchStillRunning_DoesNotStartDuplicateUpstreamFetch()
    {
        // ABA regression: caller A's own wait detaches (client disconnect/timeout) while the
        // shared upstream fetch it registered is still running. Caller B then joins the same
        // coordinate before the shared fetch resolves. The single-flight in-flight entry must
        // survive A's early detach so B joins the live fetch instead of starting a duplicate one.
        var handler = new GatedHandler();
        var coordinator = BuildCoordinator(handler: handler);

        using var ctsA = new CancellationTokenSource();
        var taskA = coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, ctsA.Token);

        await handler.FirstCallStarted;

        ctsA.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => taskA);

        // Caller B joins for the identical coordinate while the shared fetch is still blocked on
        // the gate. On the buggy unconditional-TryRemove finally, A's cancellation already evicted
        // the in-flight entry, so B would start a second (un-gated, immediately-completing) fetch
        // here instead of joining the still-running one.
        var taskB = coordinator.GetAsync(_upstream, Release, Repo, Arch, IndexFile, null, null, TestOrgId, default);

        var winner = await Task.WhenAny(taskB, Task.Delay(TimeSpan.FromMilliseconds(300)));
        Assert.NotSame(taskB, winner); // B must still be waiting on the shared (gated) fetch
        Assert.Equal(1, handler.CallCount);

        handler.ReleaseFirstCall();
        var resultB = await taskB;

        Assert.NotNull(resultB);
        Assert.Equal(1, handler.CallCount); // still exactly one upstream round-trip
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private void StubIndex(byte[] body) =>
        _server.Given(Request.Create().WithPath($"/{Release}/{Repo}/{Arch}/{IndexFile}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(body));

    private static async Task<byte[]> ReadAllAsync(Stream s)
    {
        using var ms = new MemoryStream();
        await s.CopyToAsync(ms);
        return ms.ToArray();
    }

    private static string ExportPublicPem(RSA rsa) => rsa.ExportSubjectPublicKeyInfoPem();

    // Builds a SHA-1-signed (.SIGN.RSA.<keyname>) index — the variant Alpine ships, and the one
    // that verifies only under the Apk:AcceptSha1IndexSignatures opt-in.
    private static byte[] BuildSignedApkIndex(RSA signingKey, string keyName)
    {
        byte[] member2 = BuildGzipMember("APKINDEX content"u8.ToArray());
        byte[] sig = signingKey.SignData(member2, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        byte[] member1 = BuildGzipTarMember(".SIGN.RSA." + keyName, sig);
        return [.. member1, .. member2];
    }

    private static byte[] BuildSha256SignedApkIndex(RSA signingKey, string keyName)
    {
        byte[] member2 = BuildGzipMember("APKINDEX content"u8.ToArray());
        byte[] sig = signingKey.SignData(member2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] member1 = BuildGzipTarMember(".SIGN.RSA256." + keyName, sig);
        return [.. member1, .. member2];
    }

    private static byte[] BuildGzipTarMember(string entryName, byte[] entryContent)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, entryName) { DataStream = new MemoryStream(entryContent) });
        }
        return ms.ToArray();
    }

    private static byte[] BuildGzipMember(byte[] content)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(content);
        }
        return ms.ToArray();
    }

    private ApkIndexFetchCoordinator BuildCoordinator(
        string? rsaPublicKeyPem = null, string? verifyFlag = null, HttpMessageHandler? handler = null,
        bool acceptSha1 = false)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Apk:IndexTtl"] = "00:05:00",
            [WeakAlgorithmAcceptance.ApkSha1IndexSignatureKey] = acceptSha1 ? "true" : "false",
        };
        if (verifyFlag is not null)
        {
            settings["Apk:VerifyIndexSignature"] = verifyFlag;
        }
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        var trustStore = new StubPerOrgTrustAnchorStore();
        if (rsaPublicKeyPem is not null)
        {
            trustStore.AddAnchor(TestOrgId, "apk", new TrustAnchorMaterial
            {
                Id = "test-anchor",
                AnchorKind = "rsa",
                Material = rsaPublicKeyPem,
                Label = "test-key",
                KeyId = null,
            });
        }

        var httpFactory = new StaticHttpClientFactory(new HttpClient(handler ?? new WireMockHandler(_server)));
        var memCache = new MemoryCache(new MemoryCacheOptions());

        return new ApkIndexFetchCoordinator(
            httpFactory, memCache, new StubAirGapMode(enabled: false), new AllowAllValidator(),
            trustStore, config, NullLogger<ApkIndexFetchCoordinator>.Instance,
            new WeakAlgorithmAcceptance(config, NullLogger<WeakAlgorithmAcceptance>.Instance));
    }

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>Routes HttpClient requests through the WireMock server.</summary>
    private sealed class WireMockHandler : HttpMessageHandler
    {
        private readonly WireMockServer _server;
        public WireMockHandler(WireMockServer server) => _server = server;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
            {
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            using var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }

    /// <summary>
    /// Blocks the first request on a gate the test controls explicitly, so the single-flight
    /// in-flight entry is deterministically still "running" when a second caller joins. Every
    /// subsequent request completes immediately, so a duplicate (un-gated) fetch is observable
    /// as an immediate second completion rather than needing a wall-clock race.
    /// </summary>
    private sealed class GatedHandler : HttpMessageHandler
    {
        private int _callCount;
        private readonly TaskCompletionSource _firstCallStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseFirstCall = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int CallCount => _callCount;
        public Task FirstCallStarted => _firstCallStarted.Task;
        public void ReleaseFirstCall() => _releaseFirstCall.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _callCount) == 1)
            {
                _firstCallStarted.SetResult();
                await _releaseFirstCall.Task;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent("gated-apkindex-body"u8.ToArray()),
            };
        }
    }
}
