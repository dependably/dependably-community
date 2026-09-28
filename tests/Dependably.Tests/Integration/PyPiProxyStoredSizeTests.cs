using System.Net;
using System.Net.Http.Headers;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// A proxied PyPI file records its real size on first fetch even when the store hands back
/// streams that cannot report their length (S3, Azure). The recorded size is what the stored-byte
/// reconciliation sums and what a presigned redirect meters, so an unmeasured 0 reads as drift
/// and keeps the file streaming through this instance forever.
///
/// <para>
/// The store here is forward-only on read, like an object store's response stream, and signs
/// presigned URLs. Both the known-checksum path (the simple index carries <c>#sha256=</c>) and
/// the cold path (it does not) are covered, and a store that cannot list the key falls back to
/// "not measured" and streams rather than redirecting an unmetered transfer.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiProxyStoredSizeTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    private readonly PresigningBlobStore _store;
    private readonly NonSeekableReadBlobStore _nonSeekable;
    private bool _listingHidden;
    private string _pullToken = "";

    public PyPiProxyStoredSizeTests()
    {
        _factory = new DependablyFactory
        {
            ServiceOverrides = services =>
            {
                services.RemoveAll<IBlobStore>();
                services.AddSingleton<IBlobStore>(_store!);
                services.RemoveAll<TieredBlobStorage>();
                services.AddSingleton(new TieredBlobStorage(_store!, _store!));
                services.RemoveAll<BlobPresignService>();
                services.AddScoped(sp => new BlobPresignService(
                    new PresignedReadOptions
                    {
                        Enabled = true,
                        Ttl = TimeSpan.FromSeconds(60),
                        Ecosystems = new HashSet<string>(["pypi"], StringComparer.Ordinal),
                    },
                    sp.GetRequiredService<TimeProvider>(),
                    NullLogger<BlobPresignService>.Instance));
            },
        };
        _nonSeekable = new NonSeekableReadBlobStore(_factory.BlobStore, () => _listingHidden);
        _store = new PresigningBlobStore(_nonSeekable);
    }

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        _pullToken = await _factory.CreateToken("pull");
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ProxiedFile_RecordsItsRealSize_AndRedirectsOnceCached(bool indexCarriesSha256)
    {
        var (name, filename, bytes) = StubWheel(indexCarriesSha256);
        using var client = Client();

        using (var first = await client.GetAsync($"/packages/{filename}"))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal(bytes, await first.Content.ReadAsByteArrayAsync());
        }

        Assert.Equal(bytes.LongLength, await RecordedSizeAsync(name, filename));

        _store.ClearSigned();
        using var second = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, second.StatusCode);
        Assert.StartsWith(PresigningBlobStore.UrlBase, second.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.Single(_store.Signed);
    }

    [Fact]
    public async Task StoreThatCannotListTheKey_RecordsNotMeasured_AndStreams()
    {
        // The fallback is one listing of the exact key; a store that does not list it leaves the
        // size unmeasured, and an unmeasured size never redirects (the transfer would go unbilled).
        var (name, filename, bytes) = StubWheel(indexCarriesSha256: true);
        using var client = Client();

        _listingHidden = true;
        try
        {
            using var first = await client.GetAsync($"/packages/{filename}");
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal(bytes, await first.Content.ReadAsByteArrayAsync());
        }
        finally
        {
            _listingHidden = false;
        }

        Assert.Equal(0, await RecordedSizeAsync(name, filename));

        _store.ClearSigned();
        using var second = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Empty(_store.Signed);
    }

    private (string Name, string Filename, byte[] Bytes) StubWheel(bool indexCarriesSha256)
    {
        string name = $"sz-{Guid.NewGuid():N}"[..16];
        string filename = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";
        var (bytes, sha256Hex) = PyPiFixtures.BuildWheel(name, "1.0.0");
        string mockBase = _factory.MockUpstream.Urls[0];
        string fragment = indexCarriesSha256 ? $"#sha256={sha256Hex}" : "";
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"""<!DOCTYPE html><html><body><a href="{mockBase}/files/{filename}{fragment}">{filename}</a></body></html>"""));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(bytes));
        return (name, filename, bytes);
    }

    private async Task<long> RecordedSizeAsync(string name, string filename)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        // xtenant: cache_artifact is the instance-wide cache plane; the coordinate is unique to this test.
        return await conn.ExecuteScalarAsync<long>(
            "SELECT size_bytes FROM cache_artifact WHERE ecosystem = 'pypi' AND name = @name AND filename = @filename",
            new { name, filename });
    }

    private HttpClient Client()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"user:{_pullToken}")));
        return client;
    }
}
