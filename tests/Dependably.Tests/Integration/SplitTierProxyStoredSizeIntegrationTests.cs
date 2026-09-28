using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// A proxied artefact's recorded size on a split-tier deployment whose cache tier is an object
/// store. The staged stream cannot report its length, so the size comes from one listing of the
/// key — and it must be the cache tier that is listed, since that is where the fetch put the bytes.
/// Listing the registry tier finds nothing and records 0, which the stored-byte reconciliation
/// then reports as 100% drift on the plane.
///
/// <para>
/// The twin runs the same fetches with a seekable cache tier: the size comes from the stream
/// itself, and neither tier is listed at all.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SplitTierProxyStoredSizeIntegrationTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    private readonly ListCountingBlobStore _cache;
    private readonly ListCountingBlobStore _registry;
    private bool _cacheSeekable;
    private string _pullToken = "";

    public SplitTierProxyStoredSizeIntegrationTests()
    {
        _factory = new DependablyFactory
        {
            ServiceOverrides = services =>
            {
                services.RemoveAll<TieredBlobStorage>();
                services.AddSingleton(new TieredBlobStorage(_cache!, _registry!));
            },
        };
        var nonSeekableCache = new NonSeekableReadBlobStore(_factory.CacheBlobStore);
        _cache = new ListCountingBlobStore(() => _cacheSeekable ? _factory.CacheBlobStore : nonSeekableCache);
        _registry = new ListCountingBlobStore(() => _factory.BlobStore);
    }

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        _pullToken = await _factory.CreateToken("pull");
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Theory]
    [InlineData("pypi")]
    [InlineData("go")]
    public async Task UnseekableCacheTier_RecordsTheRealSize_ByListingTheCacheTier(string ecosystem)
    {
        var fx = Arrange(ecosystem);
        _registry.Lists = 0;

        using var client = Client(ecosystem);
        var resp = await client.GetAsync(fx.Url);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(fx.Bytes, await resp.Content.ReadAsByteArrayAsync());
        Assert.Equal(fx.Bytes.LongLength, await RecordedSizeAsync(fx));
        Assert.Equal(0, _registry.Lists);
    }

    [Theory]
    [InlineData("pypi")]
    [InlineData("go")]
    public async Task SeekableCacheTier_RecordsTheStreamLength_WithoutListingEitherTier(string ecosystem)
    {
        _cacheSeekable = true;
        try
        {
            var fx = Arrange(ecosystem);
            _cache.Lists = 0;
            _registry.Lists = 0;

            using var client = Client(ecosystem);
            var resp = await client.GetAsync(fx.Url);

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal(fx.Bytes.LongLength, await RecordedSizeAsync(fx));
            Assert.Equal(0, _cache.Lists);
            Assert.Equal(0, _registry.Lists);
        }
        finally
        {
            _cacheSeekable = false;
        }
    }

    private sealed record Fixture(string Ecosystem, string Url, string Name, byte[] Bytes);

    private Fixture Arrange(string ecosystem)
    {
        string u = "sz" + Guid.NewGuid().ToString("N")[..10];
        if (ecosystem == "pypi")
        {
            string filename = $"{u}-1.0.0-py3-none-any.whl";
            var (wheel, sha) = PyPiFixtures.BuildWheel(u, "1.0.0");
            Stub($"/simple/{u}/", Encoding.UTF8.GetBytes(
                $"<html><body><a href=\"{_factory.MockUpstream.Urls[0]}/files/{filename}#sha256={sha}\">{filename}</a></body></html>"));
            Stub($"/files/{filename}", wheel);
            return new Fixture("pypi", $"/packages/{filename}", u, wheel);
        }

        string module = $"example.com/{u}";
        byte[] zip = RandomNumberGenerator.GetBytes(96);
        Stub($"/{module}/@v/v1.0.0.zip", zip);
        return new Fixture("golang", $"/go/{module}/@v/v1.0.0.zip", module, zip);
    }

    private void Stub(string path, byte[] body) =>
        _factory.MockUpstream
            .Given(Request.Create().WithPath(path).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(body));

    private HttpClient Client(string ecosystem) =>
        ecosystem == "pypi" ? _factory.CreateClientWithBasic(_pullToken) : _factory.CreateClientWithBearer(_pullToken);

    private async Task<long> RecordedSizeAsync(Fixture fx)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        // xtenant: cache_artifact is the instance-wide cache plane; the coordinate is unique to this test.
        return await conn.ExecuteScalarAsync<long>(
            "SELECT size_bytes FROM cache_artifact WHERE ecosystem = @ecosystem AND name = @name",
            new { ecosystem = fx.Ecosystem, name = fx.Name });
    }

    /// <summary>Delegates to the store <paramref name="current"/> names and counts listings.</summary>
    private sealed class ListCountingBlobStore(Func<IBlobStore> current) : IBlobStore
    {
        public int Lists { get; set; }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => current().PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => current().GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => current().ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default) => current().DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => current().GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => current().GetRangeAsync(key, from, to, ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
        {
            Lists++;
            return current().ListAsync(prefix, ct);
        }
    }
}
