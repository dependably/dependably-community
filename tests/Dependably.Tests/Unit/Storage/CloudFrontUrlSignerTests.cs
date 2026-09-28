using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// The CloudFront signer: canned-policy signatures that verify against the key pair's public
/// half, a URL and policy in exactly the shape CloudFront reconstructs, an expiry fixed by the
/// injected clock, and the residency rule — only a proxied object whose org's upstreams are all
/// credential-free is signed under the cached prefix; an uploaded object, and a proxied one whose
/// visibility is anything but a successful "public" answer, is signed under the uncached prefix, or
/// by the object store when no uncached prefix is configured. The private key never appears in a
/// message.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CloudFrontUrlSignerTests : IDisposable
{
    private const string Base = "https://d111111abcdef8.cloudfront.net";
    private const string KeyPairId = "K2JCJMDEHXQW5F";
    private const string LayerKey = "oci/sha256/4f6c3b3f4e0f5c1d2a9b8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6b5a4f3";

    private readonly RSA _keyPair = RSA.Create(2048);
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private readonly InMemoryBlobStore _objects;

    public CloudFrontUrlSignerTests()
    {
        _objects = new InMemoryBlobStore(_clock);
        _objects.PutAsync(LayerKey, new MemoryStream([1, 2, 3])).GetAwaiter().GetResult();
    }

    public void Dispose() => _keyPair.Dispose();

    private string PrivatePem => _keyPair.ExportRSAPrivateKeyPem();

    private IConfiguration Config(string? uncachedPrefix = "uploaded", params (string Key, string? Value)[] overrides)
    {
        var values = new Dictionary<string, string?>
        {
            [CloudFrontSignerOptions.SignerKey] = "cloudfront",
            [CloudFrontSignerOptions.UrlBaseKey] = Base + "/",
            [CloudFrontSignerOptions.KeyPairIdKey] = KeyPairId,
            [CloudFrontSignerOptions.PrivateKeyKey] = PrivatePem,
            [CloudFrontSignerOptions.CachedPathPrefixKey] = "/cached/",
            [CloudFrontSignerOptions.UncachedPathPrefixKey] = uncachedPrefix,
            [PresignedReadOptions.EnabledKey] = "true",
            [PresignedReadOptions.TtlSecondsKey] = "45",
        };
        foreach (var (key, value) in overrides)
        {
            values[key] = value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private BlobPresignService Service(IConfiguration config, IProxiedContentVisibility? visibility = null)
        => new(PresignedReadOptions.FromConfiguration(config), _clock, NullLogger<BlobPresignService>.Instance, visibility);

    // ── Signature and shape ───────────────────────────────────────────────────

    [Fact]
    public async Task Signature_VerifiesAgainstThePublicKey_OverTheCannedPolicyCloudFrontReconstructs()
    {
        var url = (await Service(Config()).TryCreateAsync(_objects, LayerKey, BlobVisibility.Public))!.Value.Url;

        var (resource, query) = Split(url);
        long expires = long.Parse(query["Expires"]);
        byte[] signature = FromUrlSafeBase64(query["Signature"]);
        string policy = CloudFrontUrlSigner.CannedPolicy(resource, expires);

        using var publicOnly = RSA.Create();
        publicOnly.ImportRSAPublicKey(_keyPair.ExportRSAPublicKey(), out _);
        Assert.True(publicOnly.VerifyData(Encoding.UTF8.GetBytes(policy), signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));

        // And a signature over anything else does not verify — the check above is not vacuous.
        Assert.False(publicOnly.VerifyData(
            Encoding.UTF8.GetBytes(CloudFrontUrlSigner.CannedPolicy(resource, expires + 1)),
            signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void CannedPolicy_HasCloudFrontsExactShape_WithNoWhitespace()
        => Assert.Equal(
            """{"Statement":[{"Resource":"https://d111111abcdef8.cloudfront.net/cached/a.tgz","Condition":{"DateLessThan":{"AWS:EpochTime":1767225600}}}]}""",
            CloudFrontUrlSigner.CannedPolicy("https://d111111abcdef8.cloudfront.net/cached/a.tgz", 1767225600));

    [Fact]
    public async Task Url_IsResourceThenExpiresSignatureKeyPairId()
    {
        string url = (await Service(Config()).TryCreateAsync(_objects, LayerKey, BlobVisibility.Public))!.Value.Url.AbsoluteUri;

        long expires = _clock.GetUtcNow().AddSeconds(45).ToUnixTimeSeconds();
        Assert.Matches(
            new Regex($@"^{Regex.Escape($"{Base}/cached/{LayerKey}")}\?Expires={expires}&Signature=[A-Za-z0-9\-_~]+&Key-Pair-Id={KeyPairId}$"),
            url);
    }

    [Theory]
    [InlineData(new byte[] { 0xFB, 0xFF }, "-~8_")]
    [InlineData(new byte[] { 0x00 }, "AA__")]
    public void UrlSafeBase64_SwapsPlusEqualsAndSlash(byte[] bytes, string expected)
        => Assert.Equal(expected, CloudFrontUrlSigner.UrlSafeBase64(bytes));

    [Fact]
    public void KeySegments_ArePercentEncoded_SlashesKept()
    {
        var signer = new CloudFrontUrlSigner(CloudFrontSignerOptions.FromConfiguration(Config()));
        Assert.Equal(
            $"{Base}/cached/hosted/org/npm/%40scope%2Bpkg/1.0.0/a%20b.tgz",
            signer.ResourceUrl("cached", "hosted/org/npm/@scope+pkg/1.0.0/a b.tgz"));
    }

    [Fact]
    public async Task RedirectLocation_KeepsTheEscapingTheSignatureCovers()
    {
        // The policy is signed over the escaped resource; a Location header carrying the
        // unescaped form would be a different resource to CloudFront and fail verification.
        const string key = "hosted/org/npm/@scope+pkg/1.0.0/a.tgz";
        await _objects.PutAsync(key, new MemoryStream([1]));
        var result = await Service(Config(overrides: (PresignedReadOptions.EcosystemsKey, "npm")), new FixedVisibility(true))
            .TryRedirectAsync(TenantRequest(), _objects, key, 1, BlobOrigin.Proxied, "npm");

        var redirect = Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(result);
        Assert.StartsWith($"{Base}/cached/hosted/org/npm/%40scope%2Bpkg/1.0.0/a.tgz?Expires=", redirect.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Signing_IsDeterministicForOneKeyAndInstant()
    {
        var service = Service(Config());
        var first = await service.TryCreateAsync(_objects, LayerKey, BlobVisibility.Public);
        var second = await service.TryCreateAsync(_objects, LayerKey, BlobVisibility.Public);
        Assert.Equal(first!.Value.Url, second!.Value.Url);
    }

    // ── Expiry from the injected clock ─────────────────────────────────────────

    [Fact]
    public async Task Expiry_IsTheFrozenClockPlusTheTtl()
    {
        var granted = await Service(Config()).TryCreateAsync(_objects, LayerKey, BlobVisibility.Public);

        var expected = _clock.GetUtcNow().AddSeconds(45);
        Assert.Equal(expected, granted!.Value.ExpiresAt);
        Assert.Equal(expected.ToUnixTimeSeconds().ToString(), Split(granted.Value.Url).Query["Expires"]);

        _clock.Advance(TimeSpan.FromMinutes(3));
        var later = await Service(Config()).TryCreateAsync(_objects, LayerKey, BlobVisibility.Public);
        Assert.Equal(expected.AddMinutes(3).ToUnixTimeSeconds().ToString(), Split(later!.Value.Url).Query["Expires"]);
    }

    // ── Residency: which prefix, and which signer ──────────────────────────────

    [Fact]
    public async Task PublicObject_IsSignedUnderTheCachedPrefix()
    {
        var url = (await Service(Config()).TryCreateAsync(_objects, LayerKey, BlobVisibility.Public))!.Value.Url;
        Assert.StartsWith($"{Base}/cached/{LayerKey}?", url.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateObject_IsSignedUnderTheUncachedPrefix()
    {
        var url = (await Service(Config()).TryCreateAsync(_objects, LayerKey, BlobVisibility.Private))!.Value.Url;
        Assert.StartsWith($"{Base}/uploaded/{LayerKey}?", url.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateOciLayer_WithTheSameDigestAsAPublicOne_TakesItsOwnPrefix()
    {
        // One content-addressed key, two origins: the key cannot say whose bytes these are, so the
        // row's origin decides, and the uploaded one never lands on the edge-cacheable prefix.
        var service = Service(Config());
        string proxied = (await service.TryCreateAsync(_objects, LayerKey, BlobVisibility.Public))!.Value.Url.AbsoluteUri;
        string uploaded = (await service.TryCreateAsync(_objects, LayerKey, BlobVisibility.Private))!.Value.Url.AbsoluteUri;

        Assert.StartsWith($"{Base}/cached/", proxied, StringComparison.Ordinal);
        Assert.StartsWith($"{Base}/uploaded/", uploaded, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UncachedPrefixUnset_PrivateObjectFallsToTheStoreSigner_PublicStillCloudFront()
    {
        var store = new StoreSigned(_objects);
        var service = Service(Config(uncachedPrefix: null));

        string uploaded = (await service.TryCreateAsync(store, LayerKey, BlobVisibility.Private))!.Value.Url.AbsoluteUri;
        string proxied = (await service.TryCreateAsync(store, LayerKey, BlobVisibility.Public))!.Value.Url.AbsoluteUri;

        Assert.StartsWith(StoreSigned.UrlBase, uploaded, StringComparison.Ordinal);
        Assert.StartsWith($"{Base}/cached/", proxied, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UncachedPrefixUnset_PrivateObjectOnAStoreThatCannotSign_Streams()
    {
        // The residency default holds even when the store cannot sign: the object streams rather
        // than being routed through CloudFront after all.
        Assert.Null(await Service(Config(uncachedPrefix: null)).TryCreateAsync(_objects, LayerKey, BlobVisibility.Private));
    }

    // ── Residency: which proxied objects count as public ──────────────────────

    [Fact]
    public async Task ProxiedObject_FromAnOrgWhoseUpstreamsAreCredentialFree_IsSignedUnderTheCachedPrefix()
    {
        var visibility = new FixedVisibility(true);
        string location = await RedirectAsync(Service(NpmConfig(), visibility), BlobOrigin.Proxied);

        Assert.StartsWith($"{Base}/cached/", location, StringComparison.Ordinal);
        Assert.Equal([("org-a", "npm")], visibility.Asked);
    }

    [Fact]
    public async Task ProxiedObject_FromAnOrgWithACredentialedUpstream_IsSignedUnderTheUncachedPrefix()
        => Assert.StartsWith(
            $"{Base}/uploaded/",
            await RedirectAsync(Service(NpmConfig(), new FixedVisibility(false)), BlobOrigin.Proxied),
            StringComparison.Ordinal);

    [Fact]
    public async Task ProxiedObject_WhenTheVisibilityLookupThrows_IsSignedUnderTheUncachedPrefix()
        => Assert.StartsWith(
            $"{Base}/uploaded/",
            await RedirectAsync(Service(NpmConfig(), new ThrowingVisibility()), BlobOrigin.Proxied),
            StringComparison.Ordinal);

    [Fact]
    public async Task ProxiedObject_WithNoVisibilityService_IsSignedUnderTheUncachedPrefix()
        => Assert.StartsWith(
            $"{Base}/uploaded/",
            await RedirectAsync(Service(NpmConfig()), BlobOrigin.Proxied),
            StringComparison.Ordinal);

    [Fact]
    public async Task ProxiedObject_OnARequestWithNoResolvedTenant_IsSignedUnderTheUncachedPrefix()
    {
        var visibility = new FixedVisibility(true);
        var http = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        http.Request.Method = "GET";

        var result = await Service(NpmConfig(), visibility).TryRedirectAsync(http, _objects, LayerKey, 1, BlobOrigin.Proxied, "npm");

        Assert.StartsWith($"{Base}/uploaded/", Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(result).Url, StringComparison.Ordinal);
        Assert.Empty(visibility.Asked);
    }

    [Fact]
    public async Task UploadedObject_IsNeverPublic_AndNeverConsultsTheLookup()
    {
        var visibility = new FixedVisibility(true);
        string location = await RedirectAsync(Service(NpmConfig(), visibility), BlobOrigin.Uploaded);

        Assert.StartsWith($"{Base}/uploaded/", location, StringComparison.Ordinal);
        Assert.Empty(visibility.Asked);
    }

    [Fact]
    public async Task ProxiedObject_WithACredentialedUpstreamAndNoUncachedPrefix_FallsToTheStoreSigner()
    {
        var store = new StoreSigned(_objects);
        var http = TenantRequest();

        var result = await Service(Config(uncachedPrefix: null, (PresignedReadOptions.EcosystemsKey, "npm")), new FixedVisibility(false))
            .TryRedirectAsync(http, store, LayerKey, 1, BlobOrigin.Proxied, "npm");

        Assert.StartsWith(StoreSigned.UrlBase, Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(result).Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingObject_IsNotSigned()
        => Assert.Null(await Service(Config()).TryCreateAsync(_objects, "oci/sha256/" + new string('0', 64), BlobVisibility.Public));

    [Fact]
    public async Task ProbedHit_IsSignedByCloudFront_WithOneExistenceCheck()
    {
        // The CloudFront signer only mints; the probe is the one question the store is asked.
        var store = new StoreSigned(_objects);
        var service = Service(Config(), new FixedVisibility(true));
        var http = TenantRequest();

        var probe = await service.ProbeAsync(http, store, LayerKey, BlobOrigin.Proxied, "oci");
        var result = await service.TryRedirectAsync(http, probe!, 3);

        var redirect = Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(result);
        Assert.StartsWith($"{Base}/cached/", redirect.Url, StringComparison.Ordinal);
        Assert.Equal(1, store.ExistsCalls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ProbedProxiedHit_FromAnOrgWithACredentialedUpstream_IsNotSignedUnderTheCachedPrefix(bool uncachedPrefixSet)
    {
        // The probed overloads reach the signer by a different path from the one-shot redirect;
        // they classify the same way.
        var store = new StoreSigned(_objects);
        var service = Service(Config(uncachedPrefix: uncachedPrefixSet ? "uploaded" : null), new FixedVisibility(false));
        var http = TenantRequest();

        var bound = await service.ProbeAsync(http, store, LayerKey, BlobOrigin.Proxied, "oci");
        var unbound = await service.ProbeAsync(http, store, LayerKey, "oci");
        string viaBound = Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(await service.TryRedirectAsync(http, bound!, 3)).Url;
        string viaUnbound = Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(
            await service.TryRedirectAsync(http, unbound!, 3, BlobOrigin.Proxied)).Url;

        string expected = uncachedPrefixSet ? $"{Base}/uploaded/" : StoreSigned.UrlBase;
        Assert.StartsWith(expected, viaBound, StringComparison.Ordinal);
        Assert.StartsWith(expected, viaUnbound, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OneShotRedirect_ViaCloudFront_AsksTheStoreOnce()
    {
        var store = new StoreSigned(_objects);

        Assert.NotNull(await Service(Config()).TryCreateAsync(store, LayerKey, BlobVisibility.Public));
        Assert.Equal(1, store.ExistsCalls);
    }

    // ── Startup validation and the secret ──────────────────────────────────────

    [Theory]
    [InlineData(CloudFrontSignerOptions.UrlBaseKey)]
    [InlineData(CloudFrontSignerOptions.KeyPairIdKey)]
    [InlineData(CloudFrontSignerOptions.PrivateKeyKey)]
    public void CloudFrontSigner_MissingARequiredSetting_FailsStartupNamingIt(string key)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => PresignedReadOptions.FromConfiguration(Config(overrides: (key, ""))));
        Assert.Contains(key, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CloudFrontSigner_IsValidatedEvenWhilePresignedReadsAreOff()
        => Assert.Throws<InvalidOperationException>(() => PresignedReadOptions.FromConfiguration(
            Config(overrides: [(PresignedReadOptions.EnabledKey, "false"), (CloudFrontSignerOptions.KeyPairIdKey, null)])));

    [Theory]
    [InlineData("http://d111111abcdef8.cloudfront.net")]
    [InlineData("d111111abcdef8.cloudfront.net")]
    [InlineData("https://d111111abcdef8.cloudfront.net/?x=1")]
    public void CloudFrontSigner_UrlBaseMustBeHttpsWithNoQuery(string urlBase)
        => Assert.Throws<InvalidOperationException>(() => PresignedReadOptions.FromConfiguration(
            Config(overrides: (CloudFrontSignerOptions.UrlBaseKey, urlBase))));

    [Fact]
    public void UnknownSigner_FailsStartup()
        => Assert.Throws<InvalidOperationException>(() => PresignedReadOptions.FromConfiguration(
            Config(overrides: (CloudFrontSignerOptions.SignerKey, "akamai"))));

    [Fact]
    public void SignerUnset_IsTheStoreSigner_AndReadsNoCloudFrontSetting()
    {
        var options = PresignedReadOptions.FromConfiguration(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [CloudFrontSignerOptions.PrivateKeyKey] = "not a key" })
            .Build());

        Assert.Equal(PresignedReadSigner.Store, options.Signer);
        Assert.Null(options.CloudFront);
    }

    [Fact]
    public void PrivateKey_AcceptsASingleLinePemWithEscapedNewlines()
    {
        string escaped = PrivatePem.Replace("\n", "\\n", StringComparison.Ordinal);
        var options = PresignedReadOptions.FromConfiguration(Config(overrides: (CloudFrontSignerOptions.PrivateKeyKey, escaped)));
        Assert.NotNull(options.CloudFront);
    }

    [Fact]
    public void MalformedPrivateKey_FailsStartup_WithoutEchoingTheValue()
    {
        const string material = "SECRETMATERIALMUSTNOTLEAK";
        string pem = $"-----BEGIN RSA PRIVATE KEY-----\n{material}\n-----END RSA PRIVATE KEY-----";

        var ex = Assert.Throws<InvalidOperationException>(() => PresignedReadOptions.FromConfiguration(
            Config(overrides: (CloudFrontSignerOptions.PrivateKeyKey, pem))));

        Assert.Contains(CloudFrontSignerOptions.PrivateKeyKey, ex.Message, StringComparison.Ordinal);
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            Assert.DoesNotContain(material, e.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void PublicKeyPem_FailsStartup_BecauseItCannotSign()
        => Assert.Throws<InvalidOperationException>(() => PresignedReadOptions.FromConfiguration(
            Config(overrides: (CloudFrontSignerOptions.PrivateKeyKey, _keyPair.ExportRSAPublicKeyPem()))));

    [Fact]
    public void Options_ToString_NeverIncludesTheKey()
    {
        var options = CloudFrontSignerOptions.FromConfiguration(Config());
        string text = options.ToString();

        Assert.Contains(KeyPairId, text, StringComparison.Ordinal);
        Assert.Contains("[redacted]", text, StringComparison.Ordinal);
        string body = PrivatePem.Split('\n')[1];
        Assert.DoesNotContain(body, text, StringComparison.Ordinal);
    }

    // ── Storage layout the distribution can serve ──────────────────────────────

    [Fact]
    public void StorageLayout_SplitTiers_AreRefused()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => CloudFrontSignerOptions.EnsureStorageSupported(tiersSplit: true, "s3"));
        Assert.Contains("tiers", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("local")]
    [InlineData("azure")]
    public void StorageLayout_NonS3Backend_IsRefused(string? backend)
        => Assert.Throws<InvalidOperationException>(() => CloudFrontSignerOptions.EnsureStorageSupported(tiersSplit: false, backend));

    [Theory]
    [InlineData("s3")]
    [InlineData(" S3 ")]
    public void StorageLayout_OneS3Store_IsAccepted(string backend)
        => Assert.Null(Record.Exception(() => CloudFrontSignerOptions.EnsureStorageSupported(tiersSplit: false, backend)));

    [Theory]
    [InlineData("local", null)]
    [InlineData("s3", "S3_BUCKET_CACHE")]
    [InlineData("s3", "STORAGE_BACKEND_REGISTRY")]
    public void Startup_CloudFrontSignerOnAnUnservableLayout_FailsWhenStorageIsRegistered(string backend, string? tierOverride)
    {
        var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder();
        builder.Configuration.AddConfiguration(Config(overrides: [("STORAGE_BACKEND", backend), ("S3_BUCKET", "b"), ("S3_REGION", "ca-central-1")]));
        if (tierOverride is not null)
        {
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { [tierOverride] = "s3" });
        }

        Assert.Throws<InvalidOperationException>(
            () => Dependably.Infrastructure.Startup.StorageStartupExtensions.AddDependablyBlobStore(builder));
    }

    [Fact]
    public void Startup_CloudFrontSignerOnOneS3Store_Registers()
    {
        var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder();
        builder.Configuration.AddConfiguration(Config(overrides: [("STORAGE_BACKEND", "s3"), ("S3_BUCKET", "b"), ("S3_REGION", "ca-central-1")]));

        Dependably.Infrastructure.Startup.StorageStartupExtensions.AddDependablyBlobStore(builder);

        var registered = Assert.Single(builder.Services, d => d.ServiceType == typeof(PresignedReadOptions));
        Assert.Equal(PresignedReadSigner.CloudFront, Assert.IsType<PresignedReadOptions>(registered.ImplementationInstance).Signer);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private IConfiguration NpmConfig() => Config(overrides: (PresignedReadOptions.EcosystemsKey, "npm"));

    private static Microsoft.AspNetCore.Http.DefaultHttpContext TenantRequest()
    {
        var http = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        http.Request.Method = "GET";
        http.Items[Dependably.Infrastructure.TenantContext.HttpItemsKey] =
            Dependably.Infrastructure.TenantContext.ForTenant("org-a", "org-a");
        return http;
    }

    private async Task<string> RedirectAsync(BlobPresignService service, BlobOrigin origin)
    {
        var result = await service.TryRedirectAsync(TenantRequest(), _objects, LayerKey, 1, origin, "npm");
        return Assert.IsType<Microsoft.AspNetCore.Mvc.RedirectResult>(result).Url;
    }

    private sealed class FixedVisibility(bool isPublic) : IProxiedContentVisibility
    {
        public List<(string OrgId, string Ecosystem)> Asked { get; } = [];

        public Task<bool> IsPublicAsync(string orgId, string ecosystem, CancellationToken ct = default)
        {
            Asked.Add((orgId, ecosystem));
            return Task.FromResult(isPublic);
        }
    }

    private sealed class ThrowingVisibility : IProxiedContentVisibility
    {
        public Task<bool> IsPublicAsync(string orgId, string ecosystem, CancellationToken ct = default)
            => throw new InvalidOperationException("lookup failed");
    }

    private static (string Resource, Dictionary<string, string> Query) Split(Uri url)
    {
        string text = url.AbsoluteUri;
        int q = text.IndexOf('?', StringComparison.Ordinal);
        var query = text[(q + 1)..].Split('&')
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => p[0], p => p[1], StringComparer.Ordinal);
        return (text[..q], query);
    }

    private static byte[] FromUrlSafeBase64(string value)
        => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '=').Replace('~', '/'));

    /// <summary>A store with the store signer's capability, so a fallback to it is visible by URL.</summary>
    private sealed class StoreSigned(IBlobStore inner) : IBlobStore, IPresignedReadBlobStore
    {
        public const string UrlBase = "https://bucket.s3.test/";

        private int _existsCalls;

        public bool SupportsPresignedReads => true;

        /// <summary>How many times the store has been asked whether a blob exists.</summary>
        public int ExistsCalls => _existsCalls;

        public Task<Uri?> TryCreatePresignedReadUrlAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
            => Task.FromResult<Uri?>(new Uri(UrlBase + key));

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => inner.PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _existsCalls);
            return inner.ExistsAsync(key, ct);
        }

        public Task DeleteAsync(string key, CancellationToken ct = default) => inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
    }
}
