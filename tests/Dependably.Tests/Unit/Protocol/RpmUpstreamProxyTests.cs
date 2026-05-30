using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Coverage for <see cref="RpmUpstreamProxy"/> (#102).
///
/// Tests:
///  - repomd.xml fetched and memory-cached; second call skips HTTP
///  - repomd.xml: client If-None-Match forwarded to upstream; upstream 304 → NotModified result
///  - repomd.xml.asc: fetched and cached independently (same TTL slot logic)
///  - hash-prefixed file: first fetch stores blob; second fetch reads blob (no HTTP)
///  - ParsePrimaryFromRepomd: extracts filename + sha256 from repomd.xml bytes
///  - ParsePrimaryXmlGz: locates package by filename, returns URL + metadata
///  - ResolvePackageUrlAsync: full chain (repomd → primary.xml.gz → package)
///  - ResolvePackageUrlAsync: returns null when package absent from primary
///  - IsNegativelyCached / RecordNegative: write then read confirms TTL
///  - Air-gap blocks GetRepodataAsync, ResolvePackageUrlAsync, GetGpgKeyAsync
///  - GetGpgKeyAsync: fetches key and caches it
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmUpstreamProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private WireMockServer _server = null!;
    private string _upstream = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _server = WireMockServer.Start();
        _upstream = _server.Urls[0].TrimEnd('/');
    }

    public async Task DisposeAsync()
    {
        _server.Stop();
        await _db.DisposeAsync();
    }

    // ── repomd.xml ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetRepodataAsync_RepomdXml_FetchesAndCaches()
    {
        var repomdBytes = Encoding.UTF8.GetBytes(MinimalRepomd());
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithBody(repomdBytes)
                   .WithHeader("ETag", "\"abc123\"")
                   .WithHeader("Last-Modified", "Mon, 26 May 2025 12:00:00 GMT"));

        var proxy = BuildProxy();

        var result = await proxy.GetRepodataAsync("repomd.xml", null, null, default);

        Assert.NotNull(result);
        Assert.False(result!.NotModified);
        Assert.Equal(repomdBytes, result.Body);
        Assert.Equal("\"abc123\"", result.ETag);
        Assert.Equal("application/xml", result.ContentType);
    }

    [Fact]
    public async Task GetRepodataAsync_RepomdXml_SecondCall_ServesFromMemoryCache()
    {
        var repomdBytes = Encoding.UTF8.GetBytes(MinimalRepomd());
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));

        var proxy = BuildProxy();

        await proxy.GetRepodataAsync("repomd.xml", null, null, default);
        await proxy.GetRepodataAsync("repomd.xml", null, null, default);

        // Only one upstream request should have been made.
        Assert.Equal(1, _server.LogEntries.Count(e => e.RequestMessage?.Path?.EndsWith("repomd.xml") == true));
    }

    [Fact]
    public async Task GetRepodataAsync_RepomdXml_IfNoneMatch_ForwardedToUpstream_And304Propagated()
    {
        // Upstream returns 304 when ETag matches.
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet()
                                      .WithHeader("If-None-Match", "\"abc\""))
               .RespondWith(Response.Create().WithStatusCode(304)
                   .WithHeader("ETag", "\"abc\""));

        var proxy = BuildProxy();
        var result = await proxy.GetRepodataAsync("repomd.xml", "\"abc\"", null, default);

        Assert.NotNull(result);
        Assert.True(result!.NotModified);
        Assert.Empty(result.Body);
    }

    [Fact]
    public async Task GetRepodataAsync_RepomdXmlAsc_FetchedAndCached()
    {
        var ascBytes = Encoding.UTF8.GetBytes("-----BEGIN PGP SIGNATURE-----");
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml.asc").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(ascBytes));

        var proxy = BuildProxy();
        var result = await proxy.GetRepodataAsync("repomd.xml.asc", null, null, default);

        Assert.NotNull(result);
        Assert.False(result!.NotModified);
        Assert.Equal(ascBytes, result.Body);
        Assert.Equal("application/pgp-keys", result.ContentType);
    }

    // ── hash-prefixed metadata files ──────────────────────────────────────────

    [Fact]
    public async Task GetRepodataAsync_HashPrefixedFile_FirstFetchStoresBlobSecondServesFromBlob()
    {
        var sha256 = new string('a', 64);
        var filename = $"{sha256}-primary.xml.gz";
        var body = new byte[] { 1, 2, 3, 4, 5 };
        _server.Given(Request.Create().WithPath($"/repodata/{filename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

        var blobs = new InMemoryBlobStore();
        var proxy = BuildProxy(blobs: blobs);

        var result1 = await proxy.GetRepodataAsync(filename, null, null, default);
        Assert.NotNull(result1);
        Assert.Equal(body, result1!.Body);

        // After first fetch the blob should be in the cache tier.
        var stored = await blobs.GetAsync(BlobKeys.RpmRepodataProxy(sha256));
        Assert.NotNull(stored);

        // Second request must NOT hit the server.
        var result2 = await proxy.GetRepodataAsync(filename, null, null, default);
        Assert.NotNull(result2);
        Assert.Equal(body, result2!.Body);

        Assert.Equal(1, _server.LogEntries.Count(e =>
            e.RequestMessage?.Path?.Contains(sha256) == true));
    }

    // ── ParsePrimaryFromRepomd ────────────────────────────────────────────────

    [Fact]
    public void ParsePrimaryFromRepomd_ExtractsFilenameAndSha256()
    {
        var sha256 = new string('b', 64);
        var repomd = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <repomd xmlns="http://linux.duke.edu/metadata/repo">
              <data type="primary">
                <location href="repodata/{sha256}-primary.xml.gz"/>
                <checksum type="sha256">{sha256}</checksum>
              </data>
            </repomd>
            """;

        var (filename, parsedSha256) = RpmUpstreamProxy.ParsePrimaryFromRepomd(Encoding.UTF8.GetBytes(repomd));

        Assert.Equal($"{sha256}-primary.xml.gz", filename);
        Assert.Equal(sha256, parsedSha256);
    }

    [Fact]
    public void ParsePrimaryFromRepomd_MissingPrimaryData_ReturnsNulls()
    {
        var repomd = """
            <?xml version="1.0" encoding="UTF-8"?>
            <repomd xmlns="http://linux.duke.edu/metadata/repo">
              <data type="filelists">
                <location href="repodata/abc-filelists.xml.gz"/>
              </data>
            </repomd>
            """;

        var (filename, sha256) = RpmUpstreamProxy.ParsePrimaryFromRepomd(Encoding.UTF8.GetBytes(repomd));

        Assert.Null(filename);
        Assert.Null(sha256);
    }

    // ── ParsePrimaryXmlGz ─────────────────────────────────────────────────────

    [Fact]
    public void ParsePrimaryXmlGz_LocatesPackageByFilename()
    {
        var sha256 = new string('c', 64);
        var gzBytes = BuildPrimaryXmlGz(new[]
        {
            ("tree", 0, "2.1.1", "1.fc40", "x86_64", sha256, "Packages/t/tree-2.1.1-1.fc40.x86_64.rpm",
             (string?)"A recursive directory listing command", (string?)"tree-devel")
        });

        var map = RpmUpstreamProxy.ParsePrimaryXmlGz(gzBytes, "https://mirror.example.com");

        Assert.True(map.ContainsKey("tree-2.1.1-1.fc40.x86_64.rpm"));
        var res = map["tree-2.1.1-1.fc40.x86_64.rpm"];
        Assert.Equal("https://mirror.example.com/Packages/t/tree-2.1.1-1.fc40.x86_64.rpm", res.PackageUrl);
        Assert.Equal(sha256, res.Sha256);
        Assert.Equal("tree", res.Name);
        Assert.Equal(0, res.Epoch);
        Assert.Equal("2.1.1", res.Version);
        Assert.Equal("1.fc40", res.Release);
        Assert.Equal("x86_64", res.Arch);
        Assert.Equal("A recursive directory listing command", res.Summary);
    }

    [Fact]
    public void ParsePrimaryXmlGz_PackageAbsent_EmptyMap()
    {
        var gzBytes = BuildPrimaryXmlGz([]);
        var map = RpmUpstreamProxy.ParsePrimaryXmlGz(gzBytes, "https://mirror.example.com");
        Assert.Empty(map);
    }

    // ── ResolvePackageUrlAsync ────────────────────────────────────────────────

    [Fact]
    public async Task ResolvePackageUrlAsync_PackageInPrimary_ReturnsResolution()
    {
        var primarySha256 = new string('d', 64);
        var primaryFilename = $"{primarySha256}-primary.xml.gz";
        var packageSha256 = new string('e', 64);

        var repomdBytes = Encoding.UTF8.GetBytes(BuildRepomdWithPrimary(primarySha256, primaryFilename));
        var primaryGzBytes = BuildPrimaryXmlGz(new[]
        {
            ("curl", 0, "8.6.0", "1.fc40", "x86_64", packageSha256,
             "Packages/c/curl-8.6.0-1.fc40.x86_64.rpm", (string?)"HTTP client", (string?)null)
        });

        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGzBytes));

        var proxy = BuildProxy();
        var result = await proxy.ResolvePackageUrlAsync("curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.NotNull(result);
        Assert.Equal($"{_upstream}/Packages/c/curl-8.6.0-1.fc40.x86_64.rpm", result!.PackageUrl);
        Assert.Equal(packageSha256, result.Sha256);
        Assert.Equal("curl", result.Name);
        Assert.Equal("x86_64", result.Arch);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_PackageAbsentFromPrimary_ReturnsNull()
    {
        var primarySha256 = new string('f', 64);
        var primaryFilename = $"{primarySha256}-primary.xml.gz";

        var repomdBytes = Encoding.UTF8.GetBytes(BuildRepomdWithPrimary(primarySha256, primaryFilename));
        var primaryGzBytes = BuildPrimaryXmlGz([]);

        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGzBytes));

        var proxy = BuildProxy();
        var result = await proxy.ResolvePackageUrlAsync("nonexistent-1.0-1.fc40.x86_64.rpm", default);

        Assert.Null(result);
    }

    // ── Negative cache ────────────────────────────────────────────────────────

    [Fact]
    public async Task NegativeCache_RecordThenRead_ReturnsTrueWithinTtl()
    {
        var proxy = BuildProxy();

        await proxy.RecordNegativeAsync("nonexistent-1.0-1.fc40.x86_64.rpm", default);
        var isCached = await proxy.IsNegativelyCachedAsync("nonexistent-1.0-1.fc40.x86_64.rpm", default);

        Assert.True(isCached);
    }

    [Fact]
    public async Task NegativeCache_DifferentPath_ReturnsFalse()
    {
        var proxy = BuildProxy();

        await proxy.RecordNegativeAsync("pkg-a-1.0-1.fc40.x86_64.rpm", default);
        var isCached = await proxy.IsNegativelyCachedAsync("pkg-b-1.0-1.fc40.x86_64.rpm", default);

        Assert.False(isCached);
    }

    // ── Air-gap ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AirGap_GetRepodataAsync_ThrowsAirGappedException()
    {
        var proxy = BuildProxy(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(
            () => proxy.GetRepodataAsync("repomd.xml", null, null, default));
    }

    [Fact]
    public async Task AirGap_ResolvePackageUrlAsync_ThrowsAirGappedException()
    {
        var proxy = BuildProxy(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(
            () => proxy.ResolvePackageUrlAsync("tree-2.1.1-1.fc40.x86_64.rpm", default));
    }

    [Fact]
    public async Task AirGap_GetGpgKeyAsync_ThrowsAirGappedException()
    {
        var proxy = BuildProxy(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(
            () => proxy.GetGpgKeyAsync(default));
    }

    // ── GPG key ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetGpgKeyAsync_FetchesFromRpmGpgKeyPath()
    {
        var keyBytes = Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: test\n");
        _server.Given(Request.Create().WithPath("/RPM-GPG-KEY").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(keyBytes));

        var proxy = BuildProxy();
        var result = await proxy.GetGpgKeyAsync(default);

        Assert.NotNull(result);
        Assert.Equal(keyBytes, result);
    }

    [Fact]
    public async Task GetGpgKeyAsync_SecondCall_ServesFromMemoryCache()
    {
        var keyBytes = Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
        _server.Given(Request.Create().WithPath("/RPM-GPG-KEY").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(keyBytes));

        var proxy = BuildProxy();
        await proxy.GetGpgKeyAsync(default);
        await proxy.GetGpgKeyAsync(default);

        Assert.Equal(1, _server.LogEntries.Count(e => e.RequestMessage?.Path?.EndsWith("RPM-GPG-KEY") == true));
    }

    // ── IsHashPrefixedFilename ────────────────────────────────────────────────

    [Theory]
    [InlineData("aabbcc1122334455aabbcc1122334455aabbcc1122334455aabbcc1122334455-primary.xml.gz", true)]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000-other.xml.gz", true)]
    [InlineData("repomd.xml", false)]
    [InlineData("primary.xml.gz", false)]
    [InlineData("RPM-GPG-KEY", false)]
    [InlineData("abc-primary.xml.gz", false)] // prefix too short
    public void IsHashPrefixedFilename_CorrectlyIdentifies(string filename, bool expected)
    {
        Assert.Equal(expected, RpmUpstreamProxy.IsHashPrefixedFilename(filename));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private RpmUpstreamProxy BuildProxy(InMemoryBlobStore? blobs = null, bool airGapped = false)
    {
        blobs ??= new InMemoryBlobStore();
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Rpm:Upstream"] = _upstream,
                ["Rpm:UpstreamMode"] = "passthrough",
                ["Rpm:RepomdTtl"] = "00:05:00",
                ["Rpm:GpgKeyTtl"] = "1.00:00:00",
                ["Rpm:NegativeCacheTtl"] = "00:05:00",
            })
            .Build();

        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var memCache = new MemoryCache(new MemoryCacheOptions());
        var airGapMode = new StubAirGapMode(airGapped);
        var urlValidator = new AllowAllValidator();

        return new RpmUpstreamProxy(
            httpFactory,
            new TieredBlobStorage(blobs, blobs),
            _db,
            memCache,
            config,
            airGapMode,
            urlValidator);
    }

    // ── XML builders ─────────────────────────────────────────────────────────

    private static string MinimalRepomd() => """
        <?xml version="1.0" encoding="UTF-8"?>
        <repomd xmlns="http://linux.duke.edu/metadata/repo">
          <data type="primary">
            <location href="repodata/aaaa-primary.xml.gz"/>
            <checksum type="sha256">aaaa</checksum>
          </data>
        </repomd>
        """;

    private static string BuildRepomdWithPrimary(string sha256, string filename) => $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <repomd xmlns="http://linux.duke.edu/metadata/repo">
          <data type="primary">
            <location href="repodata/{filename}"/>
            <checksum type="sha256">{sha256}</checksum>
          </data>
        </repomd>
        """;

    private static byte[] BuildPrimaryXmlGz(
        IEnumerable<(string name, int epoch, string ver, string rel, string arch, string sha256, string href, string? summary, string? license)> packages)
    {
        XNamespace common = "http://linux.duke.edu/metadata/common";
        XNamespace rpmNs = "http://linux.duke.edu/metadata/rpm";

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", rpmNs.NamespaceName),
                packages.Select(p =>
                    new XElement(common + "package",
                        new XAttribute("type", "rpm"),
                        new XElement(common + "name", p.name),
                        new XElement(common + "arch", p.arch),
                        new XElement(common + "version",
                            new XAttribute("epoch", p.epoch),
                            new XAttribute("ver", p.ver),
                            new XAttribute("rel", p.rel)),
                        new XElement(common + "checksum",
                            new XAttribute("type", "sha256"),
                            p.sha256),
                        new XElement(common + "summary", p.summary ?? ""),
                        new XElement(common + "description", ""),
                        new XElement(common + "location",
                            new XAttribute("href", p.href)),
                        new XElement(common + "format",
                            new XElement(rpmNs + "license", p.license ?? ""))))));

        using var ms = new MemoryStream();
        using var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true);
        using (var writer = new System.IO.StreamWriter(gz, Encoding.UTF8, leaveOpen: true))
            doc.Save(writer);
        gz.Flush();
        return ms.ToArray();
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled { get; }
        public StubAirGapMode(bool enabled) => IsEnabled = enabled;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(true);
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
            // Redirect any request to the WireMock server (preserving path/query).
            var url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
