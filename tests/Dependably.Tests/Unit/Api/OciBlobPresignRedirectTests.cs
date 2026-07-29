using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Presigned-redirect coverage for the OCI blob read path.
///
/// The behaviour under test is that a digest-addressed blob GET can be answered with a 307 to a
/// short-lived signed URL instead of streaming — but only once every check the streaming path
/// runs has passed. Each positive case therefore has an adversarial twin asserting both that the
/// refusal is unchanged and that no URL was minted: the whole risk of this feature is a presign
/// that happens before the gate, and a refusal that still leaked a URL would look like a pass on
/// status code alone.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciBlobPresignRedirectTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly RecordingPresignBlobStore _cacheBlobs = new();
    private readonly RecordingPresignBlobStore _registryBlobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly OciBlobKeyLock _blobKeyLock = new();
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly CacheAccessRecorder _cacheRecorder;

    private string _orgId = null!;
    private string _otherOrgId = null!;
    private string _closedOrgId = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private OrgRepository _orgs = null!;

    public OciBlobPresignRedirectTests()
    {
        _cacheArtifacts = new CacheArtifactRepository(_db);
        _cacheRecorder = new CacheAccessRecorder(
            _cacheArtifacts, new TenantArtifactAccessRepository(_db),
            NullLogger<CacheAccessRecorder>.Instance, _clock);
    }

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, _clock);
        _audit = new AuditRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "presign-org");
        _otherOrgId = await OrgSeeder.InsertAsync(_db, "presign-other-org");
        _closedOrgId = await OrgSeeder.InsertAsync(_db, "presign-closed-org");

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id IN (@a, @b)",
            new { a = _orgId, b = _otherOrgId });
        // The closed org refuses anonymous pull — the unauthorized-principal twin.
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
            new { orgId = _closedOrgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Positive: the redirect is issued, is a 307, and is short-lived ─────────

    [Fact]
    public async Task BlobGet_PresignDisabled_StreamsExactlyAsBefore()
    {
        string digest = await SeedBlobAsync(RandomBytes(), _orgId);

        var ctl = BuildController(_orgId, presignEnabled: false);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        _ = Assert.IsType<FileStreamResult>(result);
        Assert.Equal("HIT", ctl.Response.Headers["X-Cache"].ToString());
        Assert.False(ctl.Response.Headers.ContainsKey("Location"));
        Assert.Empty(_cacheBlobs.PresignedKeys);
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_ReturnsShortLived307Redirect()
    {
        string digest = await SeedBlobAsync(RandomBytes(), _orgId);

        var ctl = BuildController(_orgId, presignEnabled: true);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.False(redirect.Permanent);
        Assert.True(redirect.PreserveMethod, "A blob redirect must be 307 so a HEAD stays a HEAD.");
        Assert.StartsWith("https://blobs.test/signed/", redirect.Url, StringComparison.Ordinal);

        // Short-lived: exactly the configured TTL past the frozen clock, not an open-ended grant.
        Assert.Equal(
            _clock.GetUtcNow().AddSeconds(PresignedReadOptions.DefaultTtlSeconds),
            Assert.Single(_cacheBlobs.PresignedExpiries));

        // The signed URL is a bearer credential — the redirect carrying it must not be cached.
        Assert.Equal("private, no-store", ctl.Response.Headers.CacheControl.ToString());
        // A 307 carries no body; the pre-set full-size Content-Length must not survive.
        Assert.False(ctl.Response.Headers.ContainsKey("Content-Length"));
    }

    // ── Adversarial twins: a refusal must refuse AND mint nothing ──────────────

    [Fact]
    public async Task BlobGet_PresignEnabled_UnauthorizedPrincipal_Is401_AndMintsNoUrl()
    {
        string digest = await SeedBlobAsync(RandomBytes(), _closedOrgId);

        var ctl = BuildController(_closedOrgId, presignEnabled: true);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, error.StatusCode);
        AssertNoUrlLeaked(ctl);
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_CrossTenantDigest_IsRefused_AndMintsNoUrl()
    {
        // Seeded for _orgId only; _otherOrgId has no oci_blobs row for this digest and no
        // upstream, so the read must not resolve — and must certainly not be signed.
        string digest = await SeedBlobAsync(RandomBytes(), _orgId);

        var ctl = BuildController(_otherOrgId, presignEnabled: true);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status404NotFound, error.StatusCode);
        AssertNoUrlLeaked(ctl);
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_BlockGateDenies_Is403_AndMintsNoUrl()
    {
        string digest = await SeedBlobAsync(RandomBytes(), _orgId, licenseSpdx: "GPL-3.0-only");
        await LicensePolicySeeder.SetModeAsync(_db, _orgId, "block");
        await LicensePolicySeeder.AddBlocklistEntryAsync(_db, _orgId, "GPL-3.0-only");

        var ctl = BuildController(_orgId, presignEnabled: true);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
        AssertNoUrlLeaked(ctl);

        // The block is recorded as a block, not as a download.
        Assert.Equal(1, await CountActivityAsync(_orgId, "blocked_license"));
        Assert.Equal(0, await CountActivityAsync(_orgId, "download"));
    }

    [Fact]
    public async Task BlobGet_PresignDisabled_BlockGateDenies_Is403()
    {
        // The gate is not a redirect-only gate: the streaming path refuses the same content, so
        // the redirect path is not stricter than the path it replaces.
        string digest = await SeedBlobAsync(RandomBytes(), _orgId, licenseSpdx: "GPL-3.0-only");
        await LicensePolicySeeder.SetModeAsync(_db, _orgId, "block");
        await LicensePolicySeeder.AddBlocklistEntryAsync(_db, _orgId, "GPL-3.0-only");

        var ctl = BuildController(_orgId, presignEnabled: false);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, error.StatusCode);
    }

    // ── Backends that cannot sign keep streaming ──────────────────────────────

    [Fact]
    public async Task BlobGet_PresignEnabled_LocalBackend_StillStreams()
    {
        // The local backend does not implement IPresignedReadBlobStore at all, so "unsupported"
        // is a compile-time fact the serve path reads by type test — never an error the client
        // could see.
        Assert.IsNotAssignableFrom<IPresignedReadBlobStore>(new LocalBlobStore(NewTempRoot()));

        var local = new InMemoryBlobStore(_clock);
        string digest = await SeedBlobAsync(RandomBytes(), _orgId, into: local);

        var ctl = BuildController(_orgId, presignEnabled: true, tiers: new TieredBlobStorage(local, local));
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        _ = Assert.IsType<FileStreamResult>(result);
        Assert.False(ctl.Response.Headers.ContainsKey("Location"));
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_StoreCannotSignRightNow_StillStreams()
    {
        _cacheBlobs.CanSign = false;
        string digest = await SeedBlobAsync(RandomBytes(), _orgId);

        var ctl = BuildController(_orgId, presignEnabled: true);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        _ = Assert.IsType<FileStreamResult>(result);
        Assert.Empty(_cacheBlobs.PresignedKeys);
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_RangeRequest_StillStreamsPartialContent()
    {
        // Only full digest-addressed reads redirect; a ranged read keeps its 206 contract.
        string digest = await SeedBlobAsync(RandomBytes(256), _orgId);

        var ctl = BuildController(_orgId, presignEnabled: true);
        ctl.Request.Headers.Range = "bytes=0-15";
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        _ = Assert.IsType<EmptyResult>(result);
        Assert.Equal(StatusCodes.Status206PartialContent, ctl.Response.StatusCode);
        Assert.Empty(_cacheBlobs.PresignedKeys);
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_HeadRequest_IsNotRedirected()
    {
        string digest = await SeedBlobAsync(RandomBytes(), _orgId);

        var ctl = BuildController(_orgId, presignEnabled: true);
        var result = await ctl.Head($"library/ubuntu/blobs/{digest}", default);

        _ = Assert.IsType<OkResult>(result);
        Assert.Empty(_cacheBlobs.PresignedKeys);
    }

    [Fact]
    public async Task BlobGet_PresignEnabled_EvictedBlob_FallsThroughInsteadOfSigningAMissingKey()
    {
        // The row survives an eviction the store does not; the streaming path answers that by
        // falling through to upstream, and the redirect path must not short-circuit it with a
        // URL that would 404 at the object store.
        string digest = await SeedBlobAsync(RandomBytes(), _orgId);
        await _cacheBlobs.DeleteAsync(BlobKeyFor(digest));

        var ctl = BuildController(_orgId, presignEnabled: true);
        var result = await ctl.Get($"library/ubuntu/blobs/{digest}", default);

        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status404NotFound, error.StatusCode);
        AssertNoUrlLeaked(ctl);
    }

    // ── Telemetry parity ──────────────────────────────────────────────────────

    [Fact]
    public async Task BlobGet_RedirectPath_RecordsTheSameDownloadTelemetryAsTheStreamingPath()
    {
        byte[] bytes = RandomBytes();
        string digest = await SeedBlobAsync(bytes, _orgId);
        string purl = $"pkg:oci/library/ubuntu@{digest}";

        var streamed = BuildController(_orgId, presignEnabled: false);
        _ = Assert.IsType<FileStreamResult>(await streamed.Get($"library/ubuntu/blobs/{digest}", default));
        var afterStream = await ReadDownloadRowsAsync(_orgId, purl);

        var redirected = BuildController(_orgId, presignEnabled: true);
        _ = Assert.IsType<RedirectResult>(await redirected.Get($"library/ubuntu/blobs/{digest}", default));
        var afterRedirect = await ReadDownloadRowsAsync(_orgId, purl);

        Assert.Single(afterStream);
        Assert.Equal(2, afterRedirect.Count);
        // Same event type, same PURL, same ecosystem, same actor attribution — the redirect adds
        // one row indistinguishable from the streamed one.
        Assert.Equal(afterStream[0], afterRedirect[1]);
    }

    /// <summary>
    /// An S3-style blob store: byte storage plus the optional presign capability, recording every
    /// key it was asked to sign and the expiry it was handed. The recording is what makes the
    /// adversarial twins meaningful — asserting a 401/403/404 alone would not prove a URL was never
    /// minted, and minting one before the gate is the failure this feature has to be proof against.
    /// </summary>
    private sealed class RecordingPresignBlobStore : IBlobStore, IPresignedReadBlobStore
    {
        private readonly InMemoryBlobStore _inner = new();
        private readonly List<string> _presignedKeys = [];
        private readonly List<DateTimeOffset> _presignedExpiries = [];

        public bool CanSign { get; set; } = true;

        public IReadOnlyList<string> PresignedKeys => _presignedKeys;
        public IReadOnlyList<DateTimeOffset> PresignedExpiries => _presignedExpiries;

        public bool SupportsPresignedReads => CanSign;

        public async Task<Uri?> TryCreatePresignedReadUrlAsync(
            string key, DateTimeOffset expiresAt, CancellationToken ct = default)
        {
            if (!await _inner.ExistsAsync(key, ct))
            {
                return null;
            }

            _presignedKeys.Add(key);
            _presignedExpiries.Add(expiresAt);
            return new Uri($"https://blobs.test/signed/{Uri.EscapeDataString(key)}?expires={expiresAt.ToUnixTimeSeconds()}");
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => _inner.PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void AssertNoUrlLeaked(OciController ctl)
    {
        Assert.Empty(_cacheBlobs.PresignedKeys);
        Assert.Empty(_registryBlobs.PresignedKeys);
        Assert.False(ctl.Response.Headers.ContainsKey("Location"));
    }

    private static string NewTempRoot()
    {
        string root = Path.Combine(Path.GetTempPath(), "dependably-presign-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static byte[] RandomBytes(int n = 128)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static string BlobKeyFor(string digest)
        => BlobKeys.OciBlob("sha256", digest["sha256:".Length..]);

    private async Task<string> SeedBlobAsync(
        byte[] bytes, string orgId, string? licenseSpdx = null, IBlobStore? into = null)
    {
        string sha256 = Sha256Hex(bytes);
        string digest = "sha256:" + sha256;
        string blobKey = BlobKeys.OciBlob("sha256", sha256);

        await (into ?? _cacheBlobs).PutAsync(blobKey, new MemoryStream(bytes), default);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, license_spdx)
            VALUES (@digest, @orgId, 'application/octet-stream', @size, @blobKey, 'proxy', @licenseSpdx)
            ON CONFLICT (digest, org_id) DO NOTHING
            """,
            new { digest, orgId, size = (long)bytes.Length, blobKey, licenseSpdx });

        return digest;
    }

    private async Task<long> CountActivityAsync(string orgId, string eventType)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = @eventType",
            new { orgId, eventType });
    }

    private async Task<List<string>> ReadDownloadRowsAsync(string orgId, string purl)
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<(string Ecosystem, string Purl, string EventType, string? ActorId)>(
            """
            SELECT ecosystem AS Ecosystem, purl AS Purl, event_type AS EventType, actor_id AS ActorId
            FROM activity
            WHERE org_id = @orgId AND purl = @purl AND event_type = 'download'
            """,
            new { orgId, purl });
        return rows.Select(r => $"{r.Ecosystem}|{r.Purl}|{r.EventType}|{r.ActorId ?? "-"}").ToList();
    }

    private OciController BuildController(
        string orgId, bool presignEnabled, TieredBlobStorage? tiers = null)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("presign-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "presign-org");

        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        var blobs = tiers ?? new TieredBlobStorage(_cacheBlobs, _registryBlobs);
        var presign = new BlobPresignService(
            new PresignedReadOptions
            {
                Enabled = presignEnabled,
                Ttl = TimeSpan.FromSeconds(PresignedReadOptions.DefaultTtlSeconds),
            },
            _clock,
            NullLogger<BlobPresignService>.Instance);

        var svc = new OciControllerServices(
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: blobs,
            Db: _db,
            Upstream: BuildResolver(blobs),
            Uploads: BuildUploads(blobs),
            OrphanBlobs: new OciOrphanBlobDeleter(_db, blobs, _blobKeyLock),
            BlockGate: BuildBlockGate(),
            EdgeGuard: TestEdgeMode.DisabledPublishGuard(),
            Packages: new PackageRepository(_db),
            TenantArtifactAccess: new TenantArtifactAccessRepository(_db),
            Presign: presign);

        return new OciController(svc, NullLogger<OciController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private OciUploadService BuildUploads(TieredBlobStorage blobs)
        => new(new OciUploadService.Dependencies(
            _db,
            blobs,
            _orgs,
            new PresignUnlimitedDisk(),
            new StagingOptions(Path.GetTempPath(), FloorBytes: 0),
            new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
            NewLicenseRecorder(blobs),
            _blobKeyLock,
            NullLogger<OciUploadService>.Instance,
            _clock));

    private OciImageLicenseRecorder NewLicenseRecorder(TieredBlobStorage blobs)
        => new(_db, blobs, _clock, NullLogger<OciImageLicenseRecorder>.Instance,
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)));

    private OciUpstreamResolver BuildResolver(TieredBlobStorage blobs)
    {
        var options = Options.Create(new OciOptions { ManifestTagTtl = TimeSpan.FromMinutes(5) });
        var http = new PresignNeverCallFactory();
        var authSvc = new OciUpstreamAuthService(
            http, options, new PresignDisabledAirGap(), NullLogger<OciUpstreamAuthService>.Instance, _clock);
        return new OciUpstreamResolver(
            http, authSvc, options, blobs, _db, new PresignDisabledAirGap(),
            NewLicenseRecorder(blobs), _cacheRecorder, _cacheArtifacts,
            NullLogger<OciUpstreamResolver>.Instance, _clock, TestEnvelope.Unconfigured());
    }

    private BlockGateService BuildBlockGate()
    {
        var normalizer = new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance);
        return new BlockGateService(
            new VulnerabilityRepository(_db, _clock),
            _audit,
            new QuarantineRepository(_db, _clock),
            new Dependably.Infrastructure.Alerts.AlertService(
                new Dependably.Infrastructure.Alerts.AlertRepository(_db, _clock),
                new Dependably.Infrastructure.Alerts.NoOpAlertNotifier(),
                NullLogger<Dependably.Infrastructure.Alerts.AlertService>.Instance),
            new InstallScriptAllowlistService(
                _db,
                new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()),
                _clock),
            new LicenseRepository(_db, _clock, normalizer),
            new StubPerOrgTrustAnchorStore(),
            NullLogger<BlockGateService>.Instance,
            _clock);
    }
}

file sealed class PresignNeverCallFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(new PresignNeverCallHandler());
}

file sealed class PresignNeverCallHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        => throw new InvalidOperationException("No upstream call is expected on a locally cached blob read.");
}

file sealed class PresignDisabledAirGap : IAirGapMode
{
    public bool IsEnabled => false;
    public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
    public bool IsJobDisabled(string jobName) => false;
}

file sealed class PresignUnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}
