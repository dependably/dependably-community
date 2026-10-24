using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The refusal arms of the RPM upstream proxy: an upstream that errors, answers with oversized or
/// malformed repodata, names no usable entry, or whose detached repomd signature is missing,
/// forged or unverifiable. Every one of them yields no metadata (null / empty / a throw) and
/// never a package resolution, and nothing refused is cached. Upstream HTTP is a per-request
/// function, so failures are injected rather than timed.
/// </summary>
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class RpmUpstreamProxyRefusalTests : IAsyncLifetime
{
    private const string Base = "https://mirror.fedoraproject.example/releases/40/Everything/x86_64/os";
    private const string OrgId = "org-rpm";

    private readonly TestMetadataStore _db = new();
    private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new();
    private readonly List<string> _requests = new();
    private readonly List<string?> _ifModifiedSince = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private void Serve(string path, byte[] body, HttpStatusCode status = HttpStatusCode.OK)
        => _routes[$"{Base}/{path}"] = () => new HttpResponseMessage(status) { Content = new ByteArrayContent(body) };

    private void Serve(string path, string body) => Serve(path, Encoding.UTF8.GetBytes(body));

    private void Fail(string path, HttpStatusCode status)
        => _routes[$"{Base}/{path}"] = () => new HttpResponseMessage(status);

    private void Respond(string path, Func<HttpResponseMessage> make) => _routes[$"{Base}/{path}"] = make;

    private (RpmUpstreamProxy Proxy, InMemoryBlobStore Blobs) Build(
        IUpstreamUrlValidator? validator = null,
        bool airGapped = false,
        string? mode = null,
        string? verify = null,
        StubPerOrgTrustAnchorStore? trust = null,
        IBlobStore? blobStore = null)
    {
        var blobs = new InMemoryBlobStore();
        var settings = new Dictionary<string, string?>();
        if (mode is not null)
        {
            settings["Rpm:UpstreamMode"] = mode;
        }

        if (verify is not null)
        {
            settings["Rpm:VerifyRepomdSignature"] = verify;
        }

        settings["Rpm:RepomdTtl"] = "not-a-timespan";
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var effective = blobStore ?? blobs;
        var proxy = new RpmUpstreamProxy(new RpmUpstreamProxyServices(
            new Factory(new Handler(this)),
            new TieredBlobStorage(effective, effective),
            _db,
            new MemoryCache(new MemoryCacheOptions()),
            config,
            new AirGap(airGapped),
            validator ?? new Allow(),
            NullLogger<RpmUpstreamProxy>.Instance,
            TimeProvider.System,
            trust ?? new StubPerOrgTrustAnchorStore(),
            new RpmPrimaryMapCache(RpmPrimaryMapCache.DefaultSizeLimitBytes)));
        return (proxy, blobs);
    }

    // ── mode flags ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, true, false)]
    [InlineData("passthrough", true, false)]
    [InlineData("MERGED", false, true)]
    [InlineData("something-else", false, false)]
    public void TheUpstreamModeSelectors_FollowTheConfiguredValue(string? mode, bool passthrough, bool merged)
    {
        var (proxy, _) = Build(mode: mode);

        Assert.Equal(passthrough, proxy.IsPassthroughModeSelected);
        Assert.Equal(merged, proxy.IsMergedModeSelected);
    }

    // ── repodata routing ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("comps.xml")]
    [InlineData("../../etc/passwd")]
    [InlineData("ABCDEF-primary.xml.gz")]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000primary.xml.gz")]
    public async Task AnUnrecognisedRepodataName_IsRefusedWithoutAnUpstreamRequest(string filename)
    {
        var (proxy, _) = Build();

        Assert.Null(await proxy.GetRepodataAsync(Base, filename, null, null, default));
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task Repomd_404_IsNull_AndNothingIsCached()
    {
        Fail("repodata/repomd.xml", HttpStatusCode.NotFound);
        var (proxy, _) = Build();

        Assert.Null(await proxy.GetRepodataAsync(Base, "repomd.xml", null, null, default));
        Assert.Null(await proxy.GetRepodataAsync(Base, "repomd.xml", null, null, default));

        Assert.Equal(2, _requests.Count);
    }

    [Fact]
    public async Task Repomd_UpstreamError_PropagatesInsteadOfBeingServedAsMetadata()
    {
        Fail("repodata/repomd.xml", HttpStatusCode.BadGateway);
        var (proxy, _) = Build();

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            proxy.GetRepodataAsync(Base, "repomd.xml", null, null, default));
    }

    [Fact]
    public async Task Repomd_BlockedByTheUrlValidator_IsNullWithoutARequest()
    {
        var (proxy, _) = Build(validator: new Block());

        Assert.Null(await proxy.GetRepodataAsync(Base, "repomd.xml", null, null, default));
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task Repomd_OverTheMetadataCap_IsTreatedAsUnavailable_NotBuffered()
    {
        Respond("repodata/repomd.xml", () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[UpstreamClient.MaxMetadataResponseBytes + 1]),
        });
        var (proxy, _) = Build();

        Assert.Null(await proxy.GetRepodataAsync(Base, "repomd.xml", null, null, default));
    }

    [Fact]
    public async Task Repomd_Upstream304WithAnEtag_IsReportedNotModified()
    {
        Respond("repodata/repomd.xml", () =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.NotModified);
            resp.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"v1\"");
            return resp;
        });
        var (proxy, _) = Build();

        var result = await proxy.GetRepodataAsync(Base, "repomd.xml", "\"v1\"", null, default);

        Assert.NotNull(result);
        Assert.True(result!.NotModified);
        Assert.Equal("\"v1\"", result.ETag);
    }

    [Fact]
    public async Task Repomd_CachedCopy_AnswersNotModifiedOnlyForAMatchingEtag()
    {
        Respond("repodata/repomd.xml", () =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Repomd("a", "primary.xml.gz")) };
            resp.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"v7\"");
            return resp;
        });
        var (proxy, _) = Build();
        await proxy.GetRepodataAsync(Base, "repomd.xml", null, null, default);

        var matching = await proxy.GetRepodataAsync(Base, "repomd.xml", "\"v7\"", null, default);
        var stale = await proxy.GetRepodataAsync(Base, "repomd.xml", "\"v6\"", null, default);

        Assert.True(matching!.NotModified);
        Assert.False(stale!.NotModified);
        Assert.Single(_requests);
    }

    // ── hash-prefixed repodata ──────────────────────────────────────────────────

    [Theory]
    [InlineData("-primary.xml.gz", "application/x-gzip")]
    [InlineData("-primary.sqlite.bz2", "application/x-bzip2")]
    [InlineData("-primary.xml.zst", "application/zstd")]
    [InlineData("-modules.yaml", "application/xml")]
    public async Task AVerifiedHashPrefixedFile_IsServedWithTheMatchingContentType_AndCachedByHash(
        string suffix, string contentType)
    {
        byte[] body = Encoding.UTF8.GetBytes("repodata-" + suffix);
        string sha = Sha256(body);
        Serve($"repodata/{sha}{suffix}", body);
        var (proxy, blobs) = Build();

        var result = await proxy.GetRepodataAsync(Base, sha + suffix, null, null, default);

        Assert.Equal(contentType, result!.ContentType);
        Assert.Equal(body, await ReadAsync(result.Body));
        Assert.True(await blobs.ExistsAsync(BlobKeys.RpmRepodataProxy(sha)));
    }

    [Fact]
    public async Task AHashPrefixedFile_TheUpstreamRefuses_IsNull()
    {
        string sha = new('a', 64);
        Fail($"repodata/{sha}-primary.xml.gz", HttpStatusCode.NotFound);
        var (proxy, blobs) = Build();

        Assert.Null(await proxy.GetRepodataAsync(Base, sha + "-primary.xml.gz", null, null, default));
        Assert.False(await blobs.ExistsAsync(BlobKeys.RpmRepodataProxy(sha)));
    }

    [Fact]
    public async Task AHashPrefixedFile_BlockedByTheUrlValidator_IsNull()
    {
        var (proxy, _) = Build(validator: new Block());

        Assert.Null(await proxy.GetRepodataAsync(Base, new string('a', 64) + "-primary.xml.gz", null, null, default));
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task AHashPrefixedFile_AlreadyCached_IsServedWithoutAnUpstreamRequest()
    {
        byte[] body = Encoding.UTF8.GetBytes("cached repodata");
        string sha = Sha256(body);
        var (proxy, blobs) = Build();
        await blobs.PutAsync(BlobKeys.RpmRepodataProxy(sha), new MemoryStream(body));

        var result = await proxy.GetRepodataAsync(Base, sha + "-other.xml.gz", null, null, default);

        Assert.Equal(body, await ReadAsync(result!.Body));
        Assert.Empty(_requests);
    }

    // ── GPG key ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GpgKey_FallsBackToTheSecondPath_WhenTheFirstIsAbsent()
    {
        Fail("RPM-GPG-KEY", HttpStatusCode.NotFound);
        Serve("repodata/repomd.xml.key", "-----BEGIN PGP PUBLIC KEY BLOCK-----");
        var (proxy, _) = Build();

        byte[]? key = await proxy.GetGpgKeyAsync(Base, default);

        Assert.Equal("-----BEGIN PGP PUBLIC KEY BLOCK-----", Encoding.UTF8.GetString(key!));
        Assert.Equal(2, _requests.Count);
    }

    [Fact]
    public async Task GpgKey_WhenNoPathAnswers_IsNull_AndIsNotCached()
    {
        Fail("RPM-GPG-KEY", HttpStatusCode.NotFound);
        Fail("repodata/repomd.xml.key", HttpStatusCode.Forbidden);
        var (proxy, _) = Build();

        Assert.Null(await proxy.GetGpgKeyAsync(Base, default));
        Assert.Null(await proxy.GetGpgKeyAsync(Base, default));

        Assert.Equal(4, _requests.Count);
    }

    [Fact]
    public async Task GpgKey_BlockedByTheUrlValidator_IsNullWithoutARequest()
    {
        var (proxy, _) = Build(validator: new Block());

        Assert.Null(await proxy.GetGpgKeyAsync(Base, default));
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task GpgKey_AnOversizedFirstPath_IsSkipped_AndTheNextPathIsTried()
    {
        Respond("RPM-GPG-KEY", () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[UpstreamClient.MaxMetadataResponseBytes + 1]),
        });
        Serve("repodata/repomd.xml.key", "key-bytes");
        var (proxy, _) = Build();

        byte[]? key = await proxy.GetGpgKeyAsync(Base, default);

        Assert.Equal("key-bytes", Encoding.UTF8.GetString(key!));
    }

    // ── primary / filelists / non-primary entries ───────────────────────────────

    [Fact]
    public async Task Primary_AirGapped_Throws_ForEveryMetadataEntryPoint()
    {
        var (proxy, _) = Build(airGapped: true);

        await Assert.ThrowsAsync<AirGappedException>(() => proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default));
        await Assert.ThrowsAsync<AirGappedException>(() => proxy.GetUpstreamFilelistsXmlGzAsync(OrgId, Base, default));
        await Assert.ThrowsAsync<AirGappedException>(() => proxy.GetUpstreamNonPrimaryRepomdEntriesAsync(OrgId, Base, default));
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task Primary_WhenRepomdIsUnavailable_IsNull_AndFilelistsIsNull_AndNonPrimaryIsEmpty()
    {
        Fail("repodata/repomd.xml", HttpStatusCode.NotFound);
        var (proxy, _) = Build();

        Assert.Null(await proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default));
        Assert.Null(await proxy.GetUpstreamFilelistsXmlGzAsync(OrgId, Base, default));
        Assert.Empty(await proxy.GetUpstreamNonPrimaryRepomdEntriesAsync(OrgId, Base, default));
    }

    [Fact]
    public async Task Primary_FetchedAndVerifiedAgainstTheRepomdChecksum()
    {
        byte[] primaryGz = Gzip("<metadata/>");
        string sha = Sha256(primaryGz);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Serve($"repodata/{sha}-primary.xml.gz", primaryGz);
        var (proxy, _) = Build();

        Assert.Equal(primaryGz, await proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default));
    }

    [Fact]
    public async Task Primary_BodyNotMatchingTheRepomdChecksum_IsRefused_AndNeverCached()
    {
        byte[] genuine = Gzip("<metadata/>");
        string sha = Sha256(genuine);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Serve($"repodata/{sha}-primary.xml.gz", Gzip("<metadata>tampered</metadata>"));
        var (proxy, blobs) = Build();

        Assert.Null(await proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default));
        Assert.False(await blobs.ExistsAsync(BlobKeys.RpmRepodataProxy(sha)));
    }

    [Fact]
    public async Task Primary_RepomdWithNoPrimaryEntry_IsNull_AndNoFilelistsEntryIsNull()
    {
        Serve("repodata/repomd.xml", """<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="other"><location href="repodata/x-other.xml.gz"/><checksum type="sha256">x</checksum></data></repomd>""");
        var (proxy, _) = Build();

        Assert.Null(await proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default));
        Assert.Null(await proxy.GetUpstreamFilelistsXmlGzAsync(OrgId, Base, default));
    }

    [Fact]
    public async Task Filelists_FetchedAndVerified()
    {
        byte[] filelistsGz = Gzip("<filelists/>");
        string sha = Sha256(filelistsGz);
        Serve("repodata/repomd.xml", RepomdWithFilelists(sha, $"{sha}-filelists.xml.gz"));
        Serve($"repodata/{sha}-filelists.xml.gz", filelistsGz);
        var (proxy, _) = Build();

        Assert.Equal(filelistsGz, await proxy.GetUpstreamFilelistsXmlGzAsync(OrgId, Base, default));
    }

    [Fact]
    public async Task NonPrimaryEntries_ListEveryEntryExceptPrimary_AndAMalformedRepomdListsNone()
    {
        Serve("repodata/repomd.xml", RepomdWithFilelists(new string('c', 64), "c-filelists.xml.gz"));
        var (proxy, _) = Build();

        var entries = await proxy.GetUpstreamNonPrimaryRepomdEntriesAsync(OrgId, Base, default);

        Assert.Equal("filelists", (string?)Assert.Single(entries).Attribute("type"));

        Serve("repodata/repomd.xml", "<repomd><data type=");
        var (proxy2, _) = Build();
        Assert.Empty(await proxy2.GetUpstreamNonPrimaryRepomdEntriesAsync(OrgId, Base, default));
    }

    [Fact]
    public async Task Primary_ABlobStoreThatCannotSeek_IsStillReadInFull()
    {
        byte[] primaryGz = Gzip("<metadata/>");
        string sha = Sha256(primaryGz);
        var inner = new InMemoryBlobStore();
        await inner.PutAsync(BlobKeys.RpmRepodataProxy(sha), new MemoryStream(primaryGz));
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        var (proxy, _) = Build(blobStore: new NonSeekableReadBlobStore(inner));

        Assert.Equal(primaryGz, await proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default));
        Assert.Single(_requests);
    }

    // ── package resolution ──────────────────────────────────────────────────────

    [Fact]
    public async Task Resolve_WhenRepomdNamesNoPrimary_IsNull()
    {
        Serve("repodata/repomd.xml", """<repomd xmlns="http://linux.duke.edu/metadata/repo"/>""");
        var (proxy, _) = Build();

        Assert.Null(await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default));
    }

    [Fact]
    public async Task Resolve_WhenPrimaryCannotBeFetched_IsNull()
    {
        string sha = new('d', 64);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Fail($"repodata/{sha}-primary.xml.gz", HttpStatusCode.InternalServerError);
        var (proxy, _) = Build();

        Assert.Null(await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default));
    }

    [Fact]
    public async Task Resolve_SkipsMalformedPackageEntries_AndNormalisesRelativeAndAbsoluteHrefs()
    {
        byte[] primaryGz = Gzip(PrimaryXml());
        string sha = Sha256(primaryGz);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Serve($"repodata/{sha}-primary.xml.gz", primaryGz);
        var (proxy, _) = Build();

        var relative = await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default);
        var absolute = await proxy.ResolvePackageUrlAsync(OrgId, Base, "curl-8.6.0-1.fc40.x86_64.rpm", default);
        var noChecksum = await proxy.ResolvePackageUrlAsync(OrgId, Base, "nochecksum-1.0-1.fc40.noarch.rpm", default);
        var notRpm = await proxy.ResolvePackageUrlAsync(OrgId, Base, "srcpkg-1.0-1.fc40.src.rpm", default);
        var noLocation = await proxy.ResolvePackageUrlAsync(OrgId, Base, "nolocation-1.0-1.fc40.noarch.rpm", default);

        Assert.Equal($"{Base}/Packages/o/openssl-3.2.2-1.fc40.x86_64.rpm", relative!.PackageUrl);
        Assert.Equal(0, relative.Epoch);
        Assert.Equal("https://cdn.fedoraproject.example/curl-8.6.0-1.fc40.x86_64.rpm", absolute!.PackageUrl);
        Assert.Equal(2, absolute.Epoch);
        Assert.Null(noChecksum);
        Assert.Null(notRpm);
        Assert.Null(noLocation);
    }

    // ── repomd signature verification ───────────────────────────────────────────

    [Fact]
    public async Task ForcedVerification_WithNoPinnedKey_FailsClosed_WithoutFetchingPrimary()
    {
        byte[] primaryGz = Gzip(PrimaryXml());
        string sha = Sha256(primaryGz);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Serve($"repodata/{sha}-primary.xml.gz", primaryGz);
        var (proxy, _) = Build(verify: "true");

        Assert.Null(await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default));
        Assert.DoesNotContain(_requests, r => r.EndsWith("-primary.xml.gz", StringComparison.Ordinal));
    }

    [Fact]
    public async Task VerificationDisabledByOverride_SkipsTheSignatureEvenWhenAKeyIsPinned()
    {
        var (_, publicKey) = Pgp();
        byte[] primaryGz = Gzip(PrimaryXml());
        string sha = Sha256(primaryGz);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Serve($"repodata/{sha}-primary.xml.gz", primaryGz);
        var (proxy, _) = Build(verify: "false", trust: Trust(publicKey));

        var resolved = await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default);

        Assert.NotNull(resolved);
        Assert.DoesNotContain(_requests, r => r.EndsWith("repomd.xml.asc", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PinnedKey_WithASignatureTheUpstreamRefuses_FailsClosed()
    {
        var (_, publicKey) = Pgp();
        string sha = new('e', 64);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Fail("repodata/repomd.xml.asc", HttpStatusCode.NotFound);
        var (proxy, _) = Build(trust: Trust(publicKey));

        Assert.Null(await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default));
        Assert.DoesNotContain(_requests, r => r.Contains("-primary.xml.gz", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PinnedKey_WithAnOversizedSignature_FailsClosed()
    {
        var (_, publicKey) = Pgp();
        string sha = new('e', 64);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        Respond("repodata/repomd.xml.asc", () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[UpstreamClient.MaxMetadataResponseBytes + 1]),
        });
        var (proxy, _) = Build(trust: Trust(publicKey));

        Assert.Null(await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default));
    }

    [Fact]
    public async Task PinnedKey_WithASignatureOnABlockedUrl_FailsClosed()
    {
        var (_, publicKey) = Pgp();
        string sha = new('e', 64);
        Serve("repodata/repomd.xml", Repomd(sha, $"{sha}-primary.xml.gz"));
        var (proxy, _) = Build(
            validator: new BlockOnly("repomd.xml.asc"), trust: Trust(publicKey));

        Assert.Null(await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default));
        Assert.DoesNotContain(_requests, r => r.EndsWith("repomd.xml.asc", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PinnedKey_WithAGoodSignature_ResolvesTheSignedRepomd_AndCachesTheSignature()
    {
        var (secret, publicKey) = Pgp();
        byte[] primaryGz = Gzip(PrimaryXml());
        string sha = Sha256(primaryGz);
        byte[] repomd = Encoding.UTF8.GetBytes(Repomd(sha, $"{sha}-primary.xml.gz"));
        Serve("repodata/repomd.xml", repomd);
        Serve("repodata/repomd.xml.asc", SignDetached(secret, repomd));
        Serve($"repodata/{sha}-primary.xml.gz", primaryGz);
        var (proxy, _) = Build(trust: Trust(publicKey));

        var first = await proxy.ResolvePackageUrlAsync(OrgId, Base, "openssl-3.2.2-1.fc40.x86_64.rpm", default);
        byte[]? second = await proxy.GetUpstreamPrimaryXmlGzAsync(OrgId, Base, default);

        Assert.NotNull(first);
        Assert.Equal(primaryGz, second);
        Assert.Single(_requests, r => r.EndsWith("repomd.xml.asc", StringComparison.Ordinal));
    }

    [Fact]
    public void VerifyRepomdSignature_RefusesGarbageAndAnEmptySignature()
    {
        var (_, publicKey) = Pgp();
        var ring = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(new MemoryStream(publicKey)));

        Assert.False(RpmUpstreamProxy.VerifyRepomdSignature([1, 2, 3], "not a signature"u8.ToArray(), ring));
        Assert.False(RpmUpstreamProxy.VerifyRepomdSignature([1, 2, 3], [], ring));
    }

    [Fact]
    public async Task Repomd_ForwardsTheClientsIfModifiedSinceToTheUpstream()
    {
        Serve("repodata/repomd.xml", Repomd("a", "primary.xml.gz"));
        var (proxy, _) = Build();

        await proxy.GetRepodataAsync(Base, "repomd.xml", null, "Mon, 26 May 2025 12:00:00 GMT", default);

        Assert.Equal("Mon, 26 May 2025 12:00:00 GMT", Assert.Single(_ifModifiedSince));
    }

    [Fact]
    public void VerifyRepomdSignature_AcceptsACompressedSignaturePacket_AndRefusesItOverTamperedBytes()
    {
        var (secret, publicKey) = Pgp();
        var ring = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(new MemoryStream(publicKey)));
        byte[] repomd = Encoding.UTF8.GetBytes(Repomd("a", "primary.xml.gz"));
        byte[] asc = SignDetachedCompressed(secret, repomd);

        Assert.True(RpmUpstreamProxy.VerifyRepomdSignature(repomd, asc, ring));
        Assert.False(RpmUpstreamProxy.VerifyRepomdSignature(Encoding.UTF8.GetBytes(Repomd("b", "primary.xml.gz")), asc, ring));
    }

    [Fact]
    public void VerifyRepomdSignature_RefusesAMalformedArmouredBlock()
    {
        var (_, publicKey) = Pgp();
        var ring = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(new MemoryStream(publicKey)));
        byte[] asc = Encoding.ASCII.GetBytes("-----BEGIN PGP SIGNATURE-----\n\n!!!! not base64 !!!!\n-----END PGP SIGNATURE-----\n");

        Assert.False(RpmUpstreamProxy.VerifyRepomdSignature([1, 2, 3], asc, ring));
    }

    [Fact]
    public void AnOpenChecksumRepodataBody_ThatIsNotGzip_CannotSatisfyTheDeclaredChecksum()
    {
        byte[] notGzip = Encoding.UTF8.GetBytes("<metadata/>");

        Assert.False(RpmUpstreamProxy.RepodataBodyMatches(notGzip, Sha256(notGzip), RepodataChecksumKind.Open));
        Assert.True(RpmUpstreamProxy.RepodataBodyMatches(notGzip, Sha256(notGzip), RepodataChecksumKind.Compressed));
    }

    [Fact]
    public void ThePrimaryMapCache_IsDisposable_AndHonoursItsConfiguredBound()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Rpm:PrimaryMapCacheSizeLimitBytes"] = "4096" })
            .Build();
        var cache = new RpmPrimaryMapCache(config);

        cache.Cache.Set("k", "v", new MemoryCacheEntryOptions { Size = 8192 });

        Assert.False(cache.Cache.TryGetValue("k", out string? _));
        cache.Dispose();
    }

    // ── parsing ─────────────────────────────────────────────────────────────────

    [Fact]
    public void RepomdParsing_RefusesAnEntryWithoutALocation_AndSurvivesMalformedXml()
    {
        byte[] noLocation = Encoding.UTF8.GetBytes(
            """<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">x</checksum></data></repomd>""");
        byte[] malformed = Encoding.UTF8.GetBytes("<repomd><data");

        Assert.Null(RpmUpstreamProxy.ParsePrimaryFromRepomd(noLocation).Filename);
        Assert.Null(RpmUpstreamProxy.ParsePrimaryFromRepomd(malformed).Filename);
    }

    [Fact]
    public void RepomdParsing_AnEntryWithNoSha256_YieldsAFilenameAndNoChecksum()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(
            """<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="repodata/abc-primary.xml.gz"/><checksum type="md5">x</checksum></data></repomd>""");

        var (filename, sha, _) = RpmUpstreamProxy.ParsePrimaryFromRepomd(bytes);

        Assert.Equal("abc-primary.xml.gz", filename);
        Assert.Null(sha);
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("short-name.xml.gz", false)]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000-", false)]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000-p", true)]
    [InlineData("000000000000000000000000000000000000000000000000000000000000000G-p", false)]
    [InlineData("00000000000000000000000000000000000000000000000000000000000000000-p", false)]
    public void IsHashPrefixedFilename_RequiresExactly64LowercaseHexThenADashAndAName(string name, bool expected)
        => Assert.Equal(expected, RpmUpstreamProxy.IsHashPrefixedFilename(name));

    // ── helpers ─────────────────────────────────────────────────────────────────

    private static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static async Task<byte[]> ReadAsync(Stream s)
    {
        await using (s)
        {
            using var ms = new MemoryStream();
            await s.CopyToAsync(ms);
            return ms.ToArray();
        }
    }

    private static byte[] Gzip(string content)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        {
            gz.Write(Encoding.UTF8.GetBytes(content));
        }

        return ms.ToArray();
    }

    private static string Repomd(string sha, string filename) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <repomd xmlns="http://linux.duke.edu/metadata/repo">
          <data type="primary"><location href="repodata/{filename}"/><checksum type="sha256">{sha}</checksum></data>
        </repomd>
        """;

    private static string RepomdWithFilelists(string sha, string filename) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <repomd xmlns="http://linux.duke.edu/metadata/repo">
          <data type="primary"><location href="repodata/p.xml.gz"/><checksum type="sha256">{new string('f', 64)}</checksum></data>
          <data type="filelists"><location href="repodata/{filename}"/><checksum type="sha256">{sha}</checksum></data>
        </repomd>
        """;

    private static string PrimaryXml() => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
          <package type="rpm">
            <name>openssl</name><arch>x86_64</arch>
            <version epoch="0" ver="3.2.2" rel="1.fc40"/>
            <checksum type="sha256">{new string('1', 64)}</checksum>
            <summary>Utilities from the general purpose cryptography library</summary>
            <location href="Packages/o/openssl-3.2.2-1.fc40.x86_64.rpm"/>
            <format><rpm:license>Apache-2.0</rpm:license></format>
          </package>
          <package type="rpm">
            <name>curl</name><arch>x86_64</arch>
            <version epoch="2" ver="8.6.0" rel="1.fc40"/>
            <checksum type="sha256">{new string('2', 64)}</checksum>
            <location href="https://cdn.fedoraproject.example/curl-8.6.0-1.fc40.x86_64.rpm"/>
          </package>
          <package type="rpm">
            <name>nochecksum</name><arch>noarch</arch>
            <version epoch="0" ver="1.0" rel="1.fc40"/>
            <location href="Packages/n/nochecksum-1.0-1.fc40.noarch.rpm"/>
          </package>
          <package type="rpm">
            <name>nolocation</name><arch>noarch</arch>
            <version epoch="0" ver="1.0" rel="1.fc40"/>
            <checksum type="sha256">{new string('3', 64)}</checksum>
          </package>
          <package type="source">
            <name>srcpkg</name><arch>src</arch>
            <version epoch="0" ver="1.0" rel="1.fc40"/>
            <checksum type="sha256">{new string('4', 64)}</checksum>
            <location href="Packages/s/srcpkg-1.0-1.fc40.src.rpm"/>
          </package>
        </metadata>
        """;

    private static StubPerOrgTrustAnchorStore Trust(byte[] armoredPublicKey)
    {
        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(OrgId, "rpm", new TrustAnchorMaterial
        {
            Id = "anchor-1",
            AnchorKind = "pgp",
            Material = Encoding.UTF8.GetString(armoredPublicKey),
            Label = "fedora-40",
            KeyId = null,
        });
        return store;
    }

    private static (PgpSecretKey Secret, byte[] ArmoredPublic) Pgp()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 25));
        var kp = gen.GenerateKeyPair();
        var created = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var secret = new PgpSecretKey(
            PgpSignature.DefaultCertification, PublicKeyAlgorithmTag.RsaGeneral,
            kp.Public, kp.Private, created, "releng@fedoraproject.example",
            SymmetricKeyAlgorithmTag.Aes256, Array.Empty<char>(), null, null, new SecureRandom());
        using var ms = new MemoryStream();
        using (var armored = new ArmoredOutputStream(ms))
        {
            secret.PublicKey.Encode(armored);
        }

        return (secret, ms.ToArray());
    }

    private static byte[] SignDetached(PgpSecretKey secret, byte[] data)
    {
        var gen = new PgpSignatureGenerator(secret.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        gen.InitSign(PgpSignature.BinaryDocument, secret.ExtractPrivateKey(Array.Empty<char>()));
        gen.Update(data);
        using var ms = new MemoryStream();
        using (var armored = new ArmoredOutputStream(ms))
        using (var bcpg = new BcpgOutputStream(armored))
        {
            gen.Generate().Encode(bcpg);
        }

        return ms.ToArray();
    }

    private static byte[] SignDetachedCompressed(PgpSecretKey secret, byte[] data)
    {
        var gen = new PgpSignatureGenerator(secret.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        gen.InitSign(PgpSignature.BinaryDocument, secret.ExtractPrivateKey(Array.Empty<char>()));
        gen.Update(data);
        using var ms = new MemoryStream();
        using (var armored = new ArmoredOutputStream(ms))
        {
            var compressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            using var packets = compressor.Open(armored);
            using var bcpg = new BcpgOutputStream(packets);
            gen.Generate().Encode(bcpg);
        }

        return ms.ToArray();
    }

    private sealed class Handler(RpmUpstreamProxyRefusalTests owner) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri!.ToString();
            owner._requests.Add(url);
            owner._ifModifiedSince.Add(request.Headers.TryGetValues("If-Modified-Since", out var values) ? values.Single() : null);
            return Task.FromResult(owner._routes.TryGetValue(url, out var make)
                ? make()
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient _client = new(handler);

        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class Allow : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class Block : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.BlockedRange);
    }

    private sealed class BlockOnly(string suffix) : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(url.EndsWith(suffix, StringComparison.Ordinal) ? UpstreamUrlBlock.BlockedRange : UpstreamUrlBlock.None);
    }

    private sealed class AirGap(bool enabled) : IAirGapMode
    {
        public bool IsEnabled => enabled;

        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();

        public bool IsJobDisabled(string jobName) => enabled;
    }
}
