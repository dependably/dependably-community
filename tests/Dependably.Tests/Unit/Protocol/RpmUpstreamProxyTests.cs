using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Coverage for <see cref="RpmUpstreamProxy"/>.
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
        byte[] repomdBytes = Encoding.UTF8.GetBytes(MinimalRepomd());
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200)
                   .WithBody(repomdBytes)
                   .WithHeader("ETag", "\"abc123\"")
                   .WithHeader("Last-Modified", "Mon, 26 May 2025 12:00:00 GMT"));

        var proxy = BuildProxy();

        var result = await proxy.GetRepodataAsync(_upstream, "repomd.xml", null, null, default);

        Assert.NotNull(result);
        Assert.False(result!.NotModified);
        Assert.Equal(repomdBytes, result.Body);
        Assert.Equal("\"abc123\"", result.ETag);
        Assert.Equal("application/xml", result.ContentType);
    }

    [Fact]
    public async Task GetRepodataAsync_RepomdXml_SecondCall_ServesFromMemoryCache()
    {
        byte[] repomdBytes = Encoding.UTF8.GetBytes(MinimalRepomd());
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));

        var proxy = BuildProxy();

        await proxy.GetRepodataAsync(_upstream, "repomd.xml", null, null, default);
        await proxy.GetRepodataAsync(_upstream, "repomd.xml", null, null, default);

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
        var result = await proxy.GetRepodataAsync(_upstream, "repomd.xml", "\"abc\"", null, default);

        Assert.NotNull(result);
        Assert.True(result!.NotModified);
        Assert.Empty(result.Body);
    }

    [Fact]
    public async Task GetRepodataAsync_RepomdXmlAsc_FetchedAndCached()
    {
        byte[] ascBytes = Encoding.UTF8.GetBytes("-----BEGIN PGP SIGNATURE-----");
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml.asc").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(ascBytes));

        var proxy = BuildProxy();
        var result = await proxy.GetRepodataAsync(_upstream, "repomd.xml.asc", null, null, default);

        Assert.NotNull(result);
        Assert.False(result!.NotModified);
        Assert.Equal(ascBytes, result.Body);
        Assert.Equal("application/pgp-keys", result.ContentType);
    }

    // ── hash-prefixed metadata files ──────────────────────────────────────────

    [Fact]
    public async Task GetRepodataAsync_HashPrefixedFile_FirstFetchStoresBlobSecondServesFromBlob()
    {
        byte[] body = new byte[] { 1, 2, 3, 4, 5 };
        string sha256 = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
        string filename = $"{sha256}-primary.xml.gz";
        _server.Given(Request.Create().WithPath($"/repodata/{filename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

        var blobs = new InMemoryBlobStore();
        var proxy = BuildProxy(blobs: blobs);

        var result1 = await proxy.GetRepodataAsync(_upstream, filename, null, null, default);
        Assert.NotNull(result1);
        Assert.Equal(body, result1!.Body);

        // After first fetch the blob should be in the cache tier.
        var stored = await blobs.GetAsync(BlobKeys.RpmRepodataProxy(sha256));
        Assert.NotNull(stored);

        // Second request must NOT hit the server.
        var result2 = await proxy.GetRepodataAsync(_upstream, filename, null, null, default);
        Assert.NotNull(result2);
        Assert.Equal(body, result2!.Body);

        Assert.Equal(1, _server.LogEntries.Count(e =>
            e.RequestMessage?.Path?.Contains(sha256) == true));
    }

    [Fact]
    public async Task GetRepodataAsync_HashPrefixedFile_BodyHashMismatch_RejectedAndNotCached()
    {
        // A poisoned / MITM'd upstream serves bytes that do not hash to the requested prefix.
        string sha256 = new('a', 64);                 // not the hash of `body`
        string filename = $"{sha256}-primary.xml.gz";
        byte[] body = new byte[] { 9, 8, 7 };
        _server.Given(Request.Create().WithPath($"/repodata/{filename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

        var blobs = new InMemoryBlobStore();
        var proxy = BuildProxy(blobs: blobs);

        var result = await proxy.GetRepodataAsync(_upstream, filename, null, null, default);

        Assert.Null(result);                                                  // not served
        Assert.Null(await blobs.GetAsync(BlobKeys.RpmRepodataProxy(sha256)));  // not cached
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_OpenChecksumOnly_NotFalselyRejected()
    {
        // Repos that declare only <open-checksum> name the hash of the DECOMPRESSED primary.xml;
        // the body verification must accept that interpretation, not just the compressed hash.
        string packageSha256 = new('e', 64);
        byte[] primaryGzBytes = BuildPrimaryXmlGz(new[]
        {
            ("curl", 0, "8.6.0", "1.fc40", "x86_64", packageSha256,
             "Packages/c/curl-8.6.0-1.fc40.x86_64.rpm", (string?)"HTTP client", (string?)null)
        });

        byte[] decompressed;
        using (var gz = new GZipStream(new MemoryStream(primaryGzBytes), CompressionMode.Decompress))
        using (var ms = new MemoryStream()) { gz.CopyTo(ms); decompressed = ms.ToArray(); }
        string openSha = Convert.ToHexString(SHA256.HashData(decompressed)).ToLowerInvariant();
        string compressedSha = Convert.ToHexString(SHA256.HashData(primaryGzBytes)).ToLowerInvariant();
        string primaryFilename = $"{compressedSha}-primary.xml.gz";  // DNF names by compressed hash

        string repomd = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <repomd xmlns="http://linux.duke.edu/metadata/repo">
              <data type="primary">
                <location href="repodata/{primaryFilename}"/>
                <open-checksum type="sha256">{openSha}</open-checksum>
              </data>
            </repomd>
            """;

        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(Encoding.UTF8.GetBytes(repomd)));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGzBytes));

        var proxy = BuildProxy();
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.NotNull(result);
        Assert.Equal(packageSha256, result!.Sha256);
    }

    // ── ParsePrimaryFromRepomd ────────────────────────────────────────────────

    [Fact]
    public void ParsePrimaryFromRepomd_ExtractsFilenameAndSha256()
    {
        string sha256 = new('b', 64);
        string repomd = $"""
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
        string repomd = """
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
        string sha256 = new('c', 64);
        byte[] gzBytes = BuildPrimaryXmlGz(new[]
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
        byte[] gzBytes = BuildPrimaryXmlGz([]);
        var map = RpmUpstreamProxy.ParsePrimaryXmlGz(gzBytes, "https://mirror.example.com");
        Assert.Empty(map);
    }

    // ── ResolvePackageUrlAsync ────────────────────────────────────────────────

    [Fact]
    public async Task ResolvePackageUrlAsync_PackageInPrimary_ReturnsResolution()
    {
        string packageSha256 = new('e', 64);

        byte[] primaryGzBytes = BuildPrimaryXmlGz(new[]
        {
            ("curl", 0, "8.6.0", "1.fc40", "x86_64", packageSha256,
             "Packages/c/curl-8.6.0-1.fc40.x86_64.rpm", (string?)"HTTP client", (string?)null)
        });
        // The repomd checksum must be the real hash of the primary.xml.gz, or the proxy's
        // integrity check rejects it before parsing.
        string primarySha256 = Convert.ToHexString(SHA256.HashData(primaryGzBytes)).ToLowerInvariant();
        string primaryFilename = $"{primarySha256}-primary.xml.gz";
        byte[] repomdBytes = Encoding.UTF8.GetBytes(BuildRepomdWithPrimary(primarySha256, primaryFilename));

        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGzBytes));

        var proxy = BuildProxy();
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.NotNull(result);
        Assert.Equal($"{_upstream}/Packages/c/curl-8.6.0-1.fc40.x86_64.rpm", result!.PackageUrl);
        Assert.Equal(packageSha256, result.Sha256);
        Assert.Equal("curl", result.Name);
        Assert.Equal("x86_64", result.Arch);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_PackageAbsentFromPrimary_ReturnsNull()
    {
        byte[] primaryGzBytes = BuildPrimaryXmlGz([]);
        string primarySha256 = Convert.ToHexString(SHA256.HashData(primaryGzBytes)).ToLowerInvariant();
        string primaryFilename = $"{primarySha256}-primary.xml.gz";
        byte[] repomdBytes = Encoding.UTF8.GetBytes(BuildRepomdWithPrimary(primarySha256, primaryFilename));

        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGzBytes));

        var proxy = BuildProxy();
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "nonexistent-1.0-1.fc40.x86_64.rpm", default);

        Assert.Null(result);
    }

    // ── Negative cache ────────────────────────────────────────────────────────

    [Fact]
    public async Task NegativeCache_RecordThenRead_ReturnsTrueWithinTtl()
    {
        var proxy = BuildProxy();

        await proxy.RecordNegativeAsync("nonexistent-1.0-1.fc40.x86_64.rpm", default);
        bool isCached = await proxy.IsNegativelyCachedAsync("nonexistent-1.0-1.fc40.x86_64.rpm", default);

        Assert.True(isCached);
    }

    [Fact]
    public async Task NegativeCache_DifferentPath_ReturnsFalse()
    {
        var proxy = BuildProxy();

        await proxy.RecordNegativeAsync("pkg-a-1.0-1.fc40.x86_64.rpm", default);
        bool isCached = await proxy.IsNegativelyCachedAsync("pkg-b-1.0-1.fc40.x86_64.rpm", default);

        Assert.False(isCached);
    }

    // ── Air-gap ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AirGap_GetRepodataAsync_ThrowsAirGappedException()
    {
        var proxy = BuildProxy(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(
            () => proxy.GetRepodataAsync(_upstream, "repomd.xml", null, null, default));
    }

    [Fact]
    public async Task AirGap_ResolvePackageUrlAsync_ThrowsAirGappedException()
    {
        var proxy = BuildProxy(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(
            () => proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "tree-2.1.1-1.fc40.x86_64.rpm", default));
    }

    [Fact]
    public async Task AirGap_GetGpgKeyAsync_ThrowsAirGappedException()
    {
        var proxy = BuildProxy(airGapped: true);
        await Assert.ThrowsAsync<AirGappedException>(
            () => proxy.GetGpgKeyAsync(_upstream, default));
    }

    // ── GPG key ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetGpgKeyAsync_FetchesFromRpmGpgKeyPath()
    {
        byte[] keyBytes = Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: test\n");
        _server.Given(Request.Create().WithPath("/RPM-GPG-KEY").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(keyBytes));

        var proxy = BuildProxy();
        byte[]? result = await proxy.GetGpgKeyAsync(_upstream, default);

        Assert.NotNull(result);
        Assert.Equal(keyBytes, result);
    }

    [Fact]
    public async Task GetGpgKeyAsync_SecondCall_ServesFromMemoryCache()
    {
        byte[] keyBytes = Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
        _server.Given(Request.Create().WithPath("/RPM-GPG-KEY").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(keyBytes));

        var proxy = BuildProxy();
        await proxy.GetGpgKeyAsync(_upstream, default);
        await proxy.GetGpgKeyAsync(_upstream, default);

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

    // ── repomd.xml GPG signature verification ─────────────────────────────────

    [Fact]
    public async Task ResolvePackageUrlAsync_ValidSignature_TrustedKey_ResolvesPackage()
    {
        var (secret, pubArmored) = GeneratePgpKeyPair();
        var (repomdBytes, primaryFilename, primaryGz) = BuildSignedRepoFixture(packageName: "curl");
        byte[] asc = SignDetached(repomdBytes, secret);

        StubRepo(repomdBytes, asc, primaryFilename, primaryGz);

        var proxy = BuildProxy(gpgKey: Encoding.UTF8.GetString(pubArmored));
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.NotNull(result);
        Assert.Equal("curl", result!.Name);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_TamperedRepomd_ReturnsNull_PrimaryNeverFetched()
    {
        var (secret, pubArmored) = GeneratePgpKeyPair();
        var (repomdBytes, primaryFilename, primaryGz) = BuildSignedRepoFixture(packageName: "curl");
        byte[] asc = SignDetached(repomdBytes, secret);                 // signature over the ORIGINAL bytes

        byte[] tampered = (byte[])repomdBytes.Clone();
        tampered[^5] ^= 0xFF;                                        // flip a byte → signature no longer matches
        StubRepo(tampered, asc, primaryFilename, primaryGz);

        var proxy = BuildProxy(gpgKey: Encoding.UTF8.GetString(pubArmored));
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.Null(result);
        // Fail-before-parse: the primary.xml.gz must never be fetched once repomd fails verification.
        Assert.DoesNotContain(_server.LogEntries, e => e.RequestMessage?.Path?.Contains(primaryFilename) == true);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_SignatureFromUntrustedKey_ReturnsNull()
    {
        var (signingKey, _) = GeneratePgpKeyPair();
        var (_, trustedPubArmored) = GeneratePgpKeyPair();           // a DIFFERENT key is trusted
        var (repomdBytes, primaryFilename, primaryGz) = BuildSignedRepoFixture(packageName: "curl");
        byte[] asc = SignDetached(repomdBytes, signingKey);

        StubRepo(repomdBytes, asc, primaryFilename, primaryGz);

        var proxy = BuildProxy(gpgKey: Encoding.UTF8.GetString(trustedPubArmored));
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_MissingAscFile_ReturnsNull()
    {
        var (_, pubArmored) = GeneratePgpKeyPair();
        var (repomdBytes, primaryFilename, primaryGz) = BuildSignedRepoFixture(packageName: "curl");
        // No repomd.xml.asc stub → 404.
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGz));

        var proxy = BuildProxy(gpgKey: Encoding.UTF8.GetString(pubArmored));
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_NoKeyConfigured_ResolvesWithoutVerification()
    {
        // Back-compat: when no trust anchor is pinned, verification is skipped and resolution
        // proceeds exactly as before — no repomd.xml.asc is required.
        var (repomdBytes, primaryFilename, primaryGz) = BuildSignedRepoFixture(packageName: "curl");
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomdBytes));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGz));

        var proxy = BuildProxy();   // no Rpm:GpgKey
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task ResolvePackageUrlAsync_VerifyForcedButNoKey_ReturnsNull()
    {
        var (repomdBytes, primaryFilename, primaryGz) = BuildSignedRepoFixture(packageName: "curl");
        StubRepo(repomdBytes, SignDetached(GeneratePgpKeyPair().secret, repomdBytes), primaryFilename, primaryGz);

        // Operator demanded enforcement but provided no parseable key → fail closed.
        var proxy = BuildProxy(verifyFlag: "true");
        var result = await proxy.ResolvePackageUrlAsync(TestOrgId, _upstream, "curl-8.6.0-1.fc40.x86_64.rpm", default);

        Assert.Null(result);
    }

    [Fact]
    public void VerifyRepomdSignature_ValidTamperedAndWrongKey()
    {
        var (secret, pubArmored) = GeneratePgpKeyPair();
        var (_, otherPubArmored) = GeneratePgpKeyPair();
        byte[] repomd = Encoding.UTF8.GetBytes("<repomd>trusted</repomd>");
        byte[] asc = SignDetached(repomd, secret);

        var trustedRing = LoadRing(pubArmored);
        var otherRing = LoadRing(otherPubArmored);

        Assert.True(RpmUpstreamProxy.VerifyRepomdSignature(repomd, asc, trustedRing));

        byte[] tampered = (byte[])repomd.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(RpmUpstreamProxy.VerifyRepomdSignature(tampered, asc, trustedRing));

        Assert.False(RpmUpstreamProxy.VerifyRepomdSignature(repomd, asc, otherRing));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static (byte[] Repomd, string PrimaryFilename, byte[] PrimaryGz) BuildSignedRepoFixture(string packageName)
    {
        byte[] primaryGz = BuildPrimaryXmlGz(new[]
        {
            (packageName, 0, "8.6.0", "1.fc40", "x86_64", new string('e', 64),
             $"Packages/c/{packageName}-8.6.0-1.fc40.x86_64.rpm", (string?)"HTTP client", (string?)null)
        });
        // The repomd checksum must be the real hash of the primary.xml.gz, or the proxy's
        // repodata-body integrity check (RepodataBodyMatches) rejects it before parsing.
        string primarySha256 = Convert.ToHexString(SHA256.HashData(primaryGz)).ToLowerInvariant();
        string primaryFilename = $"{primarySha256}-primary.xml.gz";
        byte[] repomd = Encoding.UTF8.GetBytes(BuildRepomdWithPrimary(primarySha256, primaryFilename));
        return (repomd, primaryFilename, primaryGz);
    }

    private void StubRepo(byte[] repomd, byte[] asc, string primaryFilename, byte[] primaryGz)
    {
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(repomd));
        _server.Given(Request.Create().WithPath("/repodata/repomd.xml.asc").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(asc));
        _server.Given(Request.Create().WithPath($"/repodata/{primaryFilename}").UsingGet())
               .RespondWith(Response.Create().WithStatusCode(200).WithBody(primaryGz));
    }

    private static PgpPublicKeyRingBundle LoadRing(byte[] armoredPublicKey)
    {
        using var keyIn = PgpUtilities.GetDecoderStream(new MemoryStream(armoredPublicKey));
        return new PgpPublicKeyRingBundle(keyIn);
    }

    private static (PgpSecretKey secret, byte[] armoredPublicKey) GeneratePgpKeyPair()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 25));
        var kp = gen.GenerateKeyPair();
        // Fixed past instant: the key-creation timestamp is embedded in the key material, and
        // BouncyCastle never compares it to the wall clock (the key has no expiry), so a
        // deterministic past value keeps the fixture stable.
        var keyCreatedAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification, PublicKeyAlgorithmTag.RsaGeneral,
            kp.Public, kp.Private, keyCreatedAt, "test@example.com",
            SymmetricKeyAlgorithmTag.Aes256, System.Array.Empty<char>(), null, null, new SecureRandom());

        using var ms = new MemoryStream();
        using (var armored = new ArmoredOutputStream(ms))
        {
            secretKey.PublicKey.Encode(armored);
        }

        return (secretKey, ms.ToArray());
    }

    private static byte[] SignDetached(PgpSecretKey secretKey, byte[] data) => SignDetached(data, secretKey);

    private static byte[] SignDetached(byte[] data, PgpSecretKey secretKey)
    {
        var privKey = secretKey.ExtractPrivateKey(System.Array.Empty<char>());
        var sigGen = new PgpSignatureGenerator(secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        sigGen.InitSign(PgpSignature.BinaryDocument, privKey);
        sigGen.Update(data);
        var sig = sigGen.Generate();

        using var ms = new MemoryStream();
        using (var armored = new ArmoredOutputStream(ms))
        using (var bcpgOut = new BcpgOutputStream(armored))
        {
            sig.Encode(bcpgOut);
        }

        return ms.ToArray();
    }

    private RpmUpstreamProxy BuildProxy(
        InMemoryBlobStore? blobs = null, bool airGapped = false,
        string? gpgKey = null, string? verifyFlag = null)
    {
        blobs ??= new InMemoryBlobStore();
        var settings = new Dictionary<string, string?>
        {
            ["Rpm:Upstream"] = _upstream,
            ["Rpm:UpstreamMode"] = "passthrough",
            ["Rpm:RepomdTtl"] = "00:05:00",
            ["Rpm:GpgKeyTtl"] = "1.00:00:00",
            ["Rpm:NegativeCacheTtl"] = "00:05:00",
        };

        if (verifyFlag is not null)
        {
            settings["Rpm:VerifyRepomdSignature"] = verifyFlag;
        }

        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        var httpFactory = new StaticHttpClientFactory(new HttpClient(new WireMockHandler(_server)));
        var memCache = new MemoryCache(new MemoryCacheOptions());
        var airGapMode = new StubAirGapMode(airGapped);
        var urlValidator = new AllowAllValidator();

        var trustStore = new StubPerOrgTrustAnchorStore();
        if (gpgKey is not null)
        {
            trustStore.AddAnchor(TestOrgId, "rpm", new TrustAnchorMaterial
            {
                Id = "test-anchor",
                AnchorKind = "pgp",
                Material = gpgKey,
                Label = "test-key",
                KeyId = null,
            });
        }

        return new RpmUpstreamProxy(new RpmUpstreamProxyServices(
            httpFactory,
            new TieredBlobStorage(blobs, blobs),
            _db,
            memCache,
            config,
            airGapMode,
            urlValidator,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<RpmUpstreamProxy>.Instance,
            TimeProvider.System,
            trustStore));
    }

    private const string TestOrgId = "test-org";

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
        {
            doc.Save(writer);
        }

        gz.Flush();
        return ms.ToArray();
    }

    // ── Test doubles ──────────────────────────────────────────────────────────

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
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
            string url = _server.Urls[0] + request.RequestUri!.PathAndQuery;
            using var innerRequest = new HttpRequestMessage(request.Method, url);
            foreach (var h in request.Headers)
            {
                innerRequest.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            var inner = new HttpClient();
            return await inner.SendAsync(innerRequest, ct);
        }
    }
}
