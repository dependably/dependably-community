using System.Net;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The shared trust rules for reading a package from a Hex upstream: an unkeyed source is skipped,
/// a 404 is a miss, every refusal (non-2xx, forged signature, wrong package or repository name,
/// transport failure) is a fault, and a later source can still answer after an earlier one failed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexUpstreamPackageFetcherTests : IAsyncLifetime
{
    private const string OrgId = "org-1";
    private const string PrimaryUrl = "http://primary.test";
    private const string MirrorUrl = "http://mirror.test";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly RSA _primaryKey = RSA.Create(2048);
    private readonly RSA _mirrorKey = RSA.Create(2048);
    private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new(StringComparer.Ordinal);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn, "INSERT INTO orgs (id, slug) VALUES ('org-1', 'org-1')");
    }

    public async Task DisposeAsync()
    {
        _primaryKey.Dispose();
        _mirrorKey.Dispose();
        await _db.DisposeAsync();
    }

    [Fact]
    public async Task Fetch_NoUpstreamsConfigured_IsAbsent()
    {
        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Absent, result.Outcome);
        Assert.Null(result.Package);
        Assert.Null(result.Source);
    }

    [Fact]
    public async Task Fetch_SourceWithoutAKey_IsSkippedWithoutAnyRequest()
    {
        await AddSourceAsync(PrimaryUrl, key: null);
        int requests = 0;
        _routes["/packages/jason"] = () => { requests++; return Ok("jason", "hexpm", _primaryKey); };

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Absent, result.Outcome);
        Assert.Equal(0, requests);
    }

    [Fact]
    public async Task Fetch_SignedResource_ReturnsTheVerifiedPackageAndItsSource()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        _routes["/packages/jason"] = () => Ok("jason", "hexpm", _primaryKey);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Ok, result.Outcome);
        Assert.Equal("jason", result.Package!.Name);
        Assert.Equal(PrimaryUrl, result.Source!.Url);
        Assert.Equal(new[] { "1.4.1" }, result.Package.Releases.Select(r => r.Version));
    }

    [Fact]
    public async Task Fetch_404FromEverySource_IsAbsentNotFault()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        await AddSourceAsync(MirrorUrl, _mirrorKey);

        var result = await FetchAsync("ghost_pkg");

        Assert.Equal(HexUpstreamOutcome.Absent, result.Outcome);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task Fetch_NonSuccessNon404_IsFault(HttpStatusCode status)
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        _routes["/packages/jason"] = () => new HttpResponseMessage(status);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Fault, result.Outcome);
        Assert.Null(result.Package);
    }

    [Fact]
    public async Task Fetch_ResourceSignedByAnotherKey_IsFault()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        _routes["/packages/jason"] = () => Ok("jason", "hexpm", _mirrorKey);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Fault, result.Outcome);
    }

    [Fact]
    public async Task Fetch_ResourceNamingAnotherPackage_IsFault()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        _routes["/packages/jason"] = () => Ok("poison", "hexpm", _primaryKey);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Fault, result.Outcome);
    }

    [Fact]
    public async Task Fetch_WellKnownHexpmHostServingAnotherRepository_IsFault()
    {
        await AddSourceAsync("https://repo.hex.pm", _primaryKey);
        _routes["/packages/jason"] = () => Ok("jason", "someone_elses_repo", _primaryKey);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Fault, result.Outcome);
    }

    [Fact]
    public async Task Fetch_WellKnownHexpmHostServingHexpm_IsOk()
    {
        await AddSourceAsync("https://repo.hex.pm", _primaryKey);
        _routes["/packages/jason"] = () => Ok("jason", "hexpm", _primaryKey);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Ok, result.Outcome);
    }

    [Fact]
    public async Task Fetch_TransportFailure_IsFault()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        _routes["/packages/jason"] = () => throw new HttpRequestException("connection refused");

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Fault, result.Outcome);
    }

    [Fact]
    public async Task Fetch_FirstSourceFaults_SecondAnswers_ReturnsTheSecond()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey, name: "primary");
        await AddSourceAsync(MirrorUrl, _mirrorKey, name: "mirror");
        _routes["primary.test/packages/jason"] = () => new HttpResponseMessage(HttpStatusCode.BadGateway);
        _routes["mirror.test/packages/jason"] = () => Ok("jason", "hexpm", _mirrorKey);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Ok, result.Outcome);
        Assert.Equal(MirrorUrl, result.Source!.Url);
    }

    [Fact]
    public async Task Fetch_FirstSourceFaults_SecondIs404_StaysFault()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey, name: "primary");
        await AddSourceAsync(MirrorUrl, _mirrorKey, name: "mirror");
        _routes["primary.test/packages/jason"] = () => new HttpResponseMessage(HttpStatusCode.BadGateway);

        var result = await FetchAsync("jason");

        Assert.Equal(HexUpstreamOutcome.Fault, result.Outcome);
    }

    [Fact]
    public async Task Fetch_NameWithReservedUrlCharacters_IsEscapedInTheRequestPath()
    {
        await AddSourceAsync(PrimaryUrl, _primaryKey);
        string? requested = null;
        _routes["/packages/jason"] = () => Ok("jason", "hexpm", _primaryKey);
        _onRequest = uri => requested = uri.AbsoluteUri;

        await FetchAsync("a b/c");

        Assert.Equal("http://primary.test/packages/a%20b%2Fc", requested);
    }

    [Fact]
    public void StableVersionsDescending_DropsPreReleasesAndRetired_AndOrdersNewestFirst()
    {
        static HexRelease Release(string version, HexRetirementStatus? retired = null) =>
            new(version, new byte[32], Array.Empty<HexDependency>(), retired, new byte[32], null, null);
        var package = new HexPackage("plug", "hexpm", new[]
        {
            Release("1.9.0"),
            Release("1.10.0"),
            Release("1.11.0-rc.0"),
            Release("1.12.0", new HexRetirementStatus(HexRetirementReason.Security, "CVE")),
            Release("1.2.0"),
        }, Array.Empty<HexSecurityAdvisory>());

        Assert.Equal(new[] { "1.10.0", "1.9.0", "1.2.0" }, HexUpstreamPackageFetcher.StableVersionsDescending(package));
    }

    [Fact]
    public void AbsentResult_CarriesNoPackageOrSource()
    {
        Assert.Equal(HexUpstreamOutcome.Absent, HexUpstreamPackageResult.Absent.Outcome);
        Assert.Null(HexUpstreamPackageResult.Absent.Package);
        Assert.Null(HexUpstreamPackageResult.Absent.Source);
    }

    private Action<Uri>? _onRequest;

    private static HttpResponseMessage Ok(string name, string repository, RSA signer)
    {
        var package = new HexPackage(name, repository, new[]
        {
            new HexRelease("1.4.1", new byte[32], Array.Empty<HexDependency>(), null, new byte[32], null, null),
        }, Array.Empty<HexSecurityAdvisory>());
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), signer)),
        };
    }

    private async Task AddSourceAsync(string url, RSA? key, string? name = null)
    {
        var repo = new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured());
        await repo.AddAsync(OrgId, new NewUpstreamRegistry(
            "hex", url, Name: name, PublicKeyPem: key is null ? null : HexRegistrySigner.ExportPublicKeyPem(key)));
    }

    private Task<HexUpstreamPackageResult> FetchAsync(string name)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"hex-fetch-{Guid.NewGuid():N}"),
            })
            .Build();
        var blobs = new InMemoryBlobStore();
        var urlValidator = Substitute.For<IUpstreamUrlValidator>();
        urlValidator.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(UpstreamUrlBlock.None));
        var upstream = new UpstreamClient(
            new SingleHandlerFactory(new RoutedHandler(_routes, uri => _onRequest?.Invoke(uri))),
            new TieredBlobStorage(blobs, blobs), new AuditRepository(_db), urlValidator, Substitute.For<IAirGapMode>(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()), StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
        var registries = new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, TestEnvelope.Unconfigured()));
        return HexUpstreamPackageFetcher.FetchAsync(
            upstream, registries, OrgId, name, NullLogger.Instance, masterKeys: null, CancellationToken.None);
    }

    private sealed class RoutedHandler(Dictionary<string, Func<HttpResponseMessage>> routes, Action<Uri> onRequest) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var uri = request.RequestUri!;
            onRequest(uri);
            string hostScoped = $"{uri.Host}{uri.AbsolutePath}";
            return routes.TryGetValue(hostScoped, out var hostRoute)
                ? Task.FromResult(hostRoute())
                : Task.FromResult(routes.TryGetValue(uri.AbsolutePath, out var route)
                ? route()
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class SingleHandlerFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient _client = new(handler);

        public HttpClient CreateClient(string name) => _client;
    }
}
