using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// An edge node reads its master's Hex public key from the master itself. The key is filled in only
/// for the master's own keyless row, on an edge, and only when the served body parses as a public
/// key; every other source, and every unusable answer, leaves the source as it was.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexMasterKeyResolverTests : IAsyncLifetime
{
    private const string MasterUrl = "http://master.test";

    private readonly TestMetadataStore _db = new();
    private readonly RSA _masterKey = RSA.Create(2048);
    private Func<HttpRequestMessage, HttpResponseMessage> _route = _ => new HttpResponseMessage(HttpStatusCode.NotFound);
    private readonly List<string> _requests = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        _masterKey.Dispose();
        await _db.DisposeAsync();
    }

    [Fact]
    public async Task WithMasterKey_NotAnEdge_ReturnsTheSourcesUntouchedWithoutRequests()
    {
        var sources = new List<UpstreamSource> { new(MasterUrl, null) };

        var result = await Resolver(TestEdgeMode.Disabled()).WithMasterKeyAsync(sources);

        Assert.Same(sources, result);
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task WithMasterKey_EdgeWithNoSources_ReturnsTheEmptyList()
    {
        var sources = new List<UpstreamSource>();

        var result = await Resolver(TestEdgeMode.Edge(MasterUrl)).WithMasterKeyAsync(sources);

        Assert.Same(sources, result);
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task WithMasterKey_KeylessMaster_GetsTheKeyTheMasterServes()
    {
        string pem = HexRegistrySigner.ExportPublicKeyPem(_masterKey);
        _route = _ => Text(pem);

        var result = await Resolver(TestEdgeMode.Edge(MasterUrl)).WithMasterKeyAsync(
            new List<UpstreamSource> { new(MasterUrl + "/", "Bearer t") });

        Assert.Equal(pem, Assert.Single(result).PublicKeyPem);
        Assert.Equal(new[] { "http://master.test/public_key" }, _requests);
    }

    [Fact]
    public async Task WithMasterKey_MixedSources_KeysOnlyTheKeylessMaster()
    {
        string pem = HexRegistrySigner.ExportPublicKeyPem(_masterKey);
        _route = _ => Text(pem);
        var master = new UpstreamSource(MasterUrl, null);
        var keyedMaster = new UpstreamSource(MasterUrl + "/other", null, PublicKeyPem: "already-configured");
        var elsewhere = new UpstreamSource("http://mirror.test", null);
        var malformedUrl = new UpstreamSource("not a url", null);

        var result = await Resolver(TestEdgeMode.Edge(MasterUrl)).WithMasterKeyAsync(
            new List<UpstreamSource> { master, keyedMaster, elsewhere, malformedUrl });

        Assert.Equal(pem, result[0].PublicKeyPem);
        Assert.Equal("already-configured", result[1].PublicKeyPem);
        Assert.Null(result[2].PublicKeyPem);
        Assert.Null(result[3].PublicKeyPem);
        Assert.Single(_requests);
    }

    [Fact]
    public async Task WithMasterKey_MasterAnswersNonSuccess_LeavesTheSourceKeyless()
    {
        _route = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);

        var result = await Resolver(TestEdgeMode.Edge(MasterUrl)).WithMasterKeyAsync(
            new List<UpstreamSource> { new(MasterUrl, null) });

        Assert.Null(Assert.Single(result).PublicKeyPem);
    }

    [Theory]
    [InlineData("<html>maintenance</html>")]
    [InlineData("-----BEGIN PUBLIC KEY-----\ntruncated")]
    [InlineData("")]
    public async Task WithMasterKey_BodyThatIsNotAPublicKey_LeavesTheSourceKeyless(string body)
    {
        _route = _ => Text(body);

        var result = await Resolver(TestEdgeMode.Edge(MasterUrl)).WithMasterKeyAsync(
            new List<UpstreamSource> { new(MasterUrl, null) });

        Assert.Null(Assert.Single(result).PublicKeyPem);
    }

    [Fact]
    public async Task WithMasterKey_TransportFailure_LeavesTheSourceKeyless()
    {
        _route = _ => throw new HttpRequestException("connection reset");

        var result = await Resolver(TestEdgeMode.Edge(MasterUrl)).WithMasterKeyAsync(
            new List<UpstreamSource> { new(MasterUrl, null) });

        Assert.Null(Assert.Single(result).PublicKeyPem);
    }

    private static HttpResponseMessage Text(string body) =>
        new(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)) };

    private HexMasterKeyResolver Resolver(IEdgeMode edge)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"hex-master-{Guid.NewGuid():N}"),
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var urlValidator = Substitute.For<IUpstreamUrlValidator>();
        urlValidator.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(UpstreamUrlBlock.None));
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(new DelegateHandler(request =>
            {
                _requests.Add(request.RequestUri!.ToString());
                return _route(request);
            })),
            new TieredBlobStorage(blobs, blobs), new AuditRepository(_db), urlValidator, Substitute.For<IAirGapMode>(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()), StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        return new HexMasterKeyResolver(edge, upstream, NullLogger<HexMasterKeyResolver>.Instance);
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(respond(request));
    }

    private sealed class SingleHandlerFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient _client = new(handler);

        public HttpClient CreateClient(string name) => _client;
    }
}
