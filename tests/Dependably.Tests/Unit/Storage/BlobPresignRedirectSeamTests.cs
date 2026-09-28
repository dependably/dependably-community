using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// <c>BlobPresignService.TryRedirectAsync</c> is the one seam every artefact serve path calls
/// where it would open the blob stream. Each refusal case asserts two things: the seam
/// returned null (the caller streams), and nothing was signed or metered — a refusal that still
/// minted a URL or recorded a redirect would look like a pass on the return value alone.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlobPresignRedirectSeamTests
{
    private const string Key = "hosted/org/npm/left-pad/1.0.0/left-pad-1.0.0.tgz";
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SigningStore _store = new();

    private BlobPresignService Sut(bool enabled = true, params string[] ecosystems)
        => new(
            new PresignedReadOptions
            {
                Enabled = enabled,
                Ttl = TimeSpan.FromSeconds(30),
                Ecosystems = ecosystems.Length == 0
                    ? PresignedReadOptions.DefaultEcosystems
                    : ecosystems.ToHashSet(StringComparer.Ordinal),
            },
            _clock,
            NullLogger<BlobPresignService>.Instance);

    private static DefaultHttpContext Metered(EgressKind kind, string method = "GET")
    {
        var http = new DefaultHttpContext();
        http.Request.Method = method;
        http.Features.Set(new EgressMeteringFeature(kind));
        return http;
    }

    [Fact]
    public async Task EnabledListedArtifactGet_Redirects307_NoStore_AndMetersTheObjectOnce()
    {
        var http = Metered(EgressKind.Artifact);
        http.Response.Headers.ContentLength = 4096;
        http.Response.ContentType = "application/octet-stream";

        var result = await Sut(ecosystems: "npm").TryRedirectAsync(http, _store, Key, 4096, BlobOrigin.Uploaded, "npm");

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.False(redirect.Permanent);
        Assert.True(redirect.PreserveMethod);
        Assert.Equal($"https://signed.test/{Key}", redirect.Url);
        Assert.Equal("private, no-store", http.Response.Headers.CacheControl.ToString());
        Assert.Null(http.Response.ContentLength);
        Assert.Null(http.Response.ContentType);
        Assert.Equal(_clock.GetUtcNow().AddSeconds(30), Assert.Single(_store.Expiries));

        var feature = http.Features.Get<EgressMeteringFeature>()!;
        Assert.Equal(EgressKind.Artifact, feature.Kind);
        Assert.Equal(new RedirectedEgress(4096, Key), feature.Redirect);
    }

    [Theory]
    [InlineData("apk", false)]
    [InlineData("npm", true)]
    [InlineData("oci", true)]
    [InlineData("pypi", true)]
    [InlineData("cargo", true)]
    [InlineData("hex", true)]
    public async Task RedirectStatus_Is302ForApk_And307Elsewhere_WithTheSameMetering(string ecosystem, bool preserveMethod)
    {
        // apk-tools does not follow a 307 but does follow a 302; for a GET the two are the same
        // redirect. The status is the only difference: metering and headers are unchanged.
        // A non-permanent RedirectResult is a 307 when it preserves the method and a 302 when not.
        var http = Metered(EgressKind.Artifact);

        var result = await Sut(ecosystems: ecosystem).TryRedirectAsync(http, _store, Key, 2048, BlobOrigin.Proxied, ecosystem);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.False(redirect.Permanent);
        Assert.Equal(preserveMethod, redirect.PreserveMethod);
        Assert.Equal("private, no-store", http.Response.Headers.CacheControl.ToString());
        Assert.Equal(new RedirectedEgress(2048, Key), http.Features.Get<EgressMeteringFeature>()!.Redirect);
    }

    [Fact]
    public async Task NoMeteringFeature_IsAllowed()
    {
        // An edge build, or a caller outside the metered pipeline: nothing classified the request
        // as metadata, so the redirect proceeds.
        var http = new DefaultHttpContext();
        http.Request.Method = "GET";

        Assert.IsType<RedirectResult>(await Sut(ecosystems: "npm").TryRedirectAsync(http, _store, Key, 10, BlobOrigin.Proxied, "npm"));
    }

    [Fact]
    public async Task Disabled_Streams()
        => await AssertStreamsAsync(Sut(enabled: false, "npm"), Metered(EgressKind.Artifact), "npm");

    [Fact]
    public async Task EcosystemNotListed_Streams()
        => await AssertStreamsAsync(Sut(ecosystems: "oci"), Metered(EgressKind.Artifact), "npm");

    [Fact]
    public async Task DefaultList_RedirectsOciOnly()
    {
        Assert.IsType<RedirectResult>(await Sut().TryRedirectAsync(Metered(EgressKind.Artifact), _store, Key, 10, BlobOrigin.Proxied, "oci"));
        _store.Signed.Clear();
        await AssertStreamsAsync(Sut(), Metered(EgressKind.Artifact), "npm");
    }

    [Fact]
    public async Task RangedRequest_Streams()
    {
        var http = Metered(EgressKind.Artifact);
        http.Request.Headers.Range = "bytes=0-99";
        await AssertStreamsAsync(Sut(ecosystems: "npm"), http, "npm");
    }

    [Fact]
    public async Task Head_Streams()
        => await AssertStreamsAsync(Sut(ecosystems: "npm"), Metered(EgressKind.Artifact, "HEAD"), "npm");

    [Fact]
    public async Task MetadataClassifiedResponse_NeverRedirects()
        => await AssertStreamsAsync(Sut(ecosystems: "npm"), Metered(EgressKind.Metadata), "npm");

    [Fact]
    public async Task UnclassifiedPerResponse_NeverRedirects()
        => await AssertStreamsAsync(Sut(ecosystems: "maven"), Metered(EgressKind.PerResponse), "maven");

    [Fact]
    public async Task UnknownSize_Streams_SoTheTransferIsStillMetered()
    {
        var http = Metered(EgressKind.Artifact);
        Assert.Null(await Sut(ecosystems: "npm").TryRedirectAsync(http, _store, Key, 0, BlobOrigin.Proxied, "npm"));
        Assert.Empty(_store.Signed);
        Assert.Null(http.Features.Get<EgressMeteringFeature>()!.Redirect);
    }

    [Fact]
    public async Task StoreCannotSign_Streams()
    {
        _store.CanSign = false;
        await AssertStreamsAsync(Sut(ecosystems: "npm"), Metered(EgressKind.Artifact), "npm");
    }

    [Fact]
    public async Task ObjectMissingFromTheStore_Streams_AndRecordsNoRedirect()
    {
        _store.Missing = true;
        var http = Metered(EgressKind.Artifact);
        http.Response.Headers.CacheControl = "private, max-age=31536000, immutable";

        Assert.Null(await Sut(ecosystems: "npm").TryRedirectAsync(http, _store, Key, 10, BlobOrigin.Proxied, "npm"));
        Assert.Null(http.Features.Get<EgressMeteringFeature>()!.Redirect);
        // The streaming answer's headers are left as the caller set them.
        Assert.Equal("private, max-age=31536000, immutable", http.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task LocalBackendWithoutTheCapability_Streams()
    {
        var http = Metered(EgressKind.Artifact);
        Assert.Null(await Sut(ecosystems: "npm").TryRedirectAsync(http, new InMemoryBlobStore(_clock), Key, 10, BlobOrigin.Proxied, "npm"));
        Assert.Null(http.Features.Get<EgressMeteringFeature>()!.Redirect);
    }

    // ── Probe, then redirect: one existence check ─────────────────────────────

    [Fact]
    public async Task OneShotRedirect_AsksTheStoreWhetherTheBlobExistsOnce()
    {
        Assert.IsType<RedirectResult>(
            await Sut(ecosystems: "npm").TryRedirectAsync(Metered(EgressKind.Artifact), _store, Key, 10, BlobOrigin.Proxied, "npm"));
        Assert.Equal(1, _store.ExistsCalls);
    }

    [Fact]
    public async Task ProbedHit_Redirects_WithoutAskingTheStoreAgain()
    {
        var sut = Sut(ecosystems: "go");
        var http = Metered(EgressKind.Artifact);

        var probe = await sut.ProbeAsync(http, _store, Key, BlobOrigin.Proxied, "go");
        Assert.True(probe!.Exists);
        var redirect = Assert.IsType<RedirectResult>(await sut.TryRedirectAsync(http, probe, 10));

        Assert.Equal($"https://signed.test/{Key}", redirect.Url);
        Assert.Equal(1, _store.ExistsCalls);
        Assert.Equal([Key], _store.Signed);
        Assert.Equal(new RedirectedEgress(10, Key), http.Features.Get<EgressMeteringFeature>()!.Redirect);
    }

    [Fact]
    public async Task ProbedMiss_IsNeverSigned()
    {
        _store.Missing = true;
        var sut = Sut(ecosystems: "go");
        var http = Metered(EgressKind.Artifact);

        var probe = await sut.ProbeAsync(http, _store, Key, BlobOrigin.Proxied, "go");

        Assert.False(probe!.Exists);
        Assert.Null(await sut.TryRedirectAsync(http, probe, 10));
        Assert.Empty(_store.Signed);
        Assert.Null(http.Features.Get<EgressMeteringFeature>()!.Redirect);
    }

    [Fact]
    public async Task Probe_SignsNothing_SoARefusalAfterItMintsNoUrl()
    {
        // A caller gates between the probe and the redirect; a gate refusal simply never calls
        // TryRedirectAsync, so the probe itself must not have minted anything.
        var probe = await Sut(ecosystems: "go").ProbeAsync(Metered(EgressKind.Artifact), _store, Key, BlobOrigin.Proxied, "go");

        Assert.True(probe!.Exists);
        Assert.Empty(_store.Signed);
    }

    [Fact]
    public async Task Probe_ReturnsNull_WithoutAskingTheStore_WhenTheReadCanNeverRedirect()
    {
        // Not a candidate (HEAD, metadata, not listed), or nothing can sign: the caller opens the
        // stream as it would without presigning, and that open is the only store round-trip.
        Assert.Null(await Sut(ecosystems: "go").ProbeAsync(Metered(EgressKind.Artifact, "HEAD"), _store, Key, BlobOrigin.Proxied, "go"));
        Assert.Null(await Sut(ecosystems: "go").ProbeAsync(Metered(EgressKind.Metadata), _store, Key, BlobOrigin.Proxied, "go"));
        Assert.Null(await Sut(ecosystems: "npm").ProbeAsync(Metered(EgressKind.Artifact), _store, Key, BlobOrigin.Proxied, "go"));
        Assert.Null(await Sut(ecosystems: "go").ProbeAsync(Metered(EgressKind.Artifact), new InMemoryBlobStore(_clock), Key, BlobOrigin.Proxied, "go"));
        _store.CanSign = false;
        Assert.Null(await Sut(ecosystems: "go").ProbeAsync(Metered(EgressKind.Artifact), _store, Key, BlobOrigin.Proxied, "go"));

        Assert.Equal(0, _store.ExistsCalls);
    }

    [Fact]
    public async Task ProbedHit_WithUnknownSize_Streams()
    {
        var sut = Sut(ecosystems: "go");
        var http = Metered(EgressKind.Artifact);
        var probe = await sut.ProbeAsync(http, _store, Key, BlobOrigin.Proxied, "go");

        Assert.Null(await sut.TryRedirectAsync(http, probe!, 0));
        Assert.Empty(_store.Signed);
    }

    [Fact]
    public async Task OriginlessProbe_RedirectsWithTheOriginSuppliedAfterTheGate_AskingTheStoreOnce()
    {
        var sut = Sut(ecosystems: "cargo");
        var http = Metered(EgressKind.Artifact);

        var probe = await sut.ProbeAsync(http, _store, Key, "cargo");
        Assert.True(probe!.Exists);
        Assert.Null(await sut.TryRedirectAsync(http, probe, 10));
        Assert.IsType<RedirectResult>(await sut.TryRedirectAsync(http, probe, 10, BlobOrigin.Uploaded));

        Assert.Equal(1, _store.ExistsCalls);
        Assert.Equal([Key], _store.Signed);
    }

    [Fact]
    public async Task ProbeForOneOrigin_RefusesAnother()
    {
        var sut = Sut(ecosystems: "go");
        var http = Metered(EgressKind.Artifact);
        var probe = await sut.ProbeAsync(http, _store, Key, BlobOrigin.Proxied, "go");

        Assert.Null(await sut.TryRedirectAsync(http, probe!, 10, BlobOrigin.Uploaded));
        Assert.Empty(_store.Signed);
    }

    [Fact]
    public async Task OriginlessProbe_ReturnsNull_WhenNothingCanSign()
    {
        _store.CanSign = false;
        Assert.Null(await Sut(ecosystems: "cargo").ProbeAsync(Metered(EgressKind.Artifact), _store, Key, "cargo"));
        Assert.Equal(0, _store.ExistsCalls);
    }

    // ── Ecosystem list binding ────────────────────────────────────────────────

    [Fact]
    public void EcosystemList_DefaultsToOciAlone()
        => Assert.Equal(["oci"], PresignedReadOptions.FromConfiguration(Config()).Ecosystems.Order());

    [Fact]
    public void EcosystemList_ForgivesCaseAndWhitespace()
        => Assert.Equal(
            ["npm", "oci", "pypi"],
            PresignedReadOptions.FromConfiguration(Config((PresignedReadOptions.EcosystemsKey, " NPM, pypi ,oci,"))).Ecosystems.Order());

    [Fact]
    public void EcosystemList_NamingAnUnknownEcosystem_FailsBoot()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => PresignedReadOptions.FromConfiguration(Config((PresignedReadOptions.EcosystemsKey, "npm,golang"))));
        Assert.Contains("golang", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryRedirectableEcosystem_IsAMeteredSource()
    {
        // The list is spelled as the metered source of each ecosystem's downloads — "go", not
        // "golang" — so an operator reading a usage report and the redirect list sees one name.
        Assert.Equal(
            ["apk", "cargo", "go", "hex", "maven", "npm", "nuget", "oci", "pypi", "rpm", "terraform"],
            PresignedReadOptions.RedirectableEcosystems.Order());
    }

    [Theory]
    [InlineData("proxy", BlobOrigin.Proxied)]
    [InlineData("uploaded", BlobOrigin.Uploaded)]
    [InlineData(null, BlobOrigin.Uploaded)]
    [InlineData("mirror", BlobOrigin.Uploaded)]
    public void UnknownOrigins_ReadAsUploaded(string? column, BlobOrigin expected)
        => Assert.Equal(expected, BlobOrigins.FromColumn(column));

    private async Task AssertStreamsAsync(BlobPresignService sut, HttpContext http, string ecosystem)
    {
        Assert.Null(await sut.TryRedirectAsync(http, _store, Key, 10, BlobOrigin.Proxied, ecosystem));
        Assert.Empty(_store.Signed);
        Assert.Null(http.Features.Get<EgressMeteringFeature>()?.Redirect);
        Assert.False(http.Response.Headers.ContainsKey("Location"));
    }

    private static IConfiguration Config(params (string Key, string Value)[] values)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private sealed class SigningStore : IBlobStore, IPresignedReadBlobStore
    {
        public bool CanSign { get; set; } = true;
        public bool Missing { get; set; }
        public List<string> Signed { get; } = [];
        public List<DateTimeOffset> Expiries { get; } = [];

        public bool SupportsPresignedReads => CanSign;

        public int ExistsCalls { get; private set; }

        public Task<Uri?> TryCreatePresignedReadUrlAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
        {
            Signed.Add(key);
            Expiries.Add(expiresAt);
            return Task.FromResult<Uri?>(new Uri($"https://signed.test/{key}"));
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => Task.CompletedTask;
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => Task.FromResult<Stream?>(null);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
        {
            ExistsCalls++;
            return Task.FromResult(!Missing);
        }
        public Task DeleteAsync(string key, CancellationToken ct = default) => Task.CompletedTask;
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => Task.FromResult(0L);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => Task.FromResult<RangedStream?>(null);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => AsyncEnumerable.Empty<BlobInfo>();
    }
}
