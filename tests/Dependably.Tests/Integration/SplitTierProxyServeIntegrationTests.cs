using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Protocol.Hex;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// A deployment with the cache and registry tiers on separate stores
/// (<see cref="DependablyFactory.SplitTiers"/>): a proxied artefact is written to the cache tier
/// on first fetch, and every later read, probe, and size lookup must find it there. A path that
/// reads the registry tier instead misses its own write, so the second request goes back
/// upstream (or the first one fails outright), the recorded size is wrong, and the weekly
/// stored-byte reconciliation reports drift.
///
/// <para>
/// Each case fetches one artefact twice through the real HTTP pipeline and then asserts: the
/// second response is served locally (one upstream call for the artefact path), the recorded
/// <c>cache_artifact.size_bytes</c> is the artefact's length, the bytes sit in the cache-tier store
/// and NOT in the registry-tier store, and the stored-byte reconciliation finds no drift in any
/// plane. Only proxied fetches run against this fixture, so every plane must balance.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SplitTierProxyServeIntegrationTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        SplitTiers = true,
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    private readonly RSA _hexUpstreamKey = RSA.Create(2048);
    private string _orgId = "";
    private string _pullToken = "";

    private string Upstream => _factory.MockUpstream.Urls[0];

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        _factory.CreateClient().Dispose();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        _orgId = (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
        _pullToken = await _factory.CreateToken("pull");

        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem IN ('hex', 'maven', 'terraform', 'cargo')",
            new { orgId = _orgId });
        await InsertUpstreamAsync(conn, "hex", Upstream, publicKeyPem: HexRegistrySigner.ExportPublicKeyPem(_hexUpstreamKey));
        await InsertUpstreamAsync(conn, "maven", $"{Upstream}/m2");
        await InsertUpstreamAsync(conn, "cargo", Upstream);
        await InsertUpstreamAsync(conn, "terraform", $"{Upstream}/tfmirror", protocol: UpstreamRegistryRepository.MirrorProtocol);
    }

    public async Task DisposeAsync()
    {
        _hexUpstreamKey.Dispose();
        await _factory.DisposeAsync();
    }

    public static TheoryData<string> Ecosystems =>
        new("pypi", "pypi-unknown-checksum", "npm", "nuget", "go", "cargo", "apk", "terraform", "hex", "maven");

    [Theory]
    [MemberData(nameof(Ecosystems))]
    public async Task ProxiedArtefact_FetchedTwice_IsServedFromTheCacheTier(string ecosystem)
    {
        var fx = Arrange(ecosystem);
        using var client = ClientFor(ecosystem);

        var first = await client.GetAsync(fx.Url);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(fx.Bytes, await first.Content.ReadAsByteArrayAsync());

        var second = await client.GetAsync(fx.Url);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(fx.Bytes, await second.Content.ReadAsByteArrayAsync());
        if (fx.SetsXCache)
        {
            Assert.Equal("HIT", second.Headers.GetValues("X-Cache").FirstOrDefault());
        }

        Assert.Equal(1, UpstreamCalls(fx.UpstreamPath));

        if (fx.HasHead)
        {
            using var head = new HttpRequestMessage(HttpMethod.Head, fx.Url);
            var headResp = await client.SendAsync(head);
            Assert.Equal(HttpStatusCode.OK, headResp.StatusCode);
            Assert.Equal(1, UpstreamCalls(fx.UpstreamPath));
        }

        var (sizeBytes, blobKey) = await RecordedAsync(fx);
        Assert.Equal(fx.Bytes.Length, sizeBytes);

        string storeKey = BlobKeys.StoreKey(blobKey);
        Assert.True(await _factory.CacheBlobStore.ExistsAsync(storeKey), $"{storeKey} missing from the cache tier");
        Assert.False(await _factory.BlobStore.ExistsAsync(storeKey), $"{storeKey} was written to the registry tier");

        var report = await _factory.Services.GetRequiredService<StoredByteReconciler>().MeasureAsync(CancellationToken.None);
        Assert.True(report.TiersSplit);
        Assert.Empty(UsageReconciliationService.FindPlaneDrift(report.Planes));
        foreach (var plane in report.Planes)
        {
            Assert.True(plane.StoreBytes == plane.MetadataBytes,
                $"plane {plane.Plane}: store {plane.StoreBytes} vs metadata {plane.MetadataBytes}");
        }
    }

    // ── fixtures ─────────────────────────────────────────────────────────────

    private sealed record Fixture(
        string Ecosystem, string Url, string UpstreamPath, byte[] Bytes, string NameLike, string FileLike,
        bool SetsXCache, bool HasHead);

    private Fixture Arrange(string ecosystem)
    {
        string u = "st" + Guid.NewGuid().ToString("N")[..10];
        switch (ecosystem)
        {
            case "pypi":
            case "pypi-unknown-checksum":
                {
                    string filename = $"{u}-1.0.0-py3-none-any.whl";
                    var (wheel, sha) = PyPiFixtures.BuildWheel(u, "1.0.0");
                    string fragment = ecosystem == "pypi" ? $"#sha256={sha}" : "";
                    Stub($"/simple/{u}/", "text/html",
                        Encoding.UTF8.GetBytes($"<html><body><a href=\"{Upstream}/files/{filename}{fragment}\">{filename}</a></body></html>"));
                    Stub($"/files/{filename}", "application/octet-stream", wheel);
                    return new Fixture("pypi", $"/packages/{filename}", $"/files/{filename}", wheel, u, filename,
                        SetsXCache: true, HasHead: true);
                }

            case "npm":
                {
                    var (tgz, _, _) = NpmFixtures.BuildTarball(u, "1.0.0");
                    string filename = $"{u}-1.0.0.tgz";
                    Stub($"/{u}/-/{filename}", "application/octet-stream", tgz);
                    return new Fixture("npm", $"/npm/tarballs/{u}/{filename}", $"/{u}/-/{filename}", tgz, u, filename,
                        SetsXCache: true, HasHead: true);
                }

            case "nuget":
                {
                    var (nupkg, _) = NuGetFixtures.BuildNupkg(u, "1.0.0");
                    string filename = $"{u}.1.0.0.nupkg";
                    Stub($"/registration5-semver1/{u}/1.0.0.json", "application/json",
                        """{ "published": "2024-01-02T03:04:05+00:00", "listed": true }"""u8.ToArray());
                    Stub($"/flatcontainer/{u}/1.0.0/{filename}", "application/octet-stream", nupkg);
                    return new Fixture("nuget", $"/nuget/flatcontainer/{u}/1.0.0/{filename}",
                        $"/flatcontainer/{u}/1.0.0/{filename}", nupkg, u, filename, SetsXCache: true, HasHead: true);
                }

            case "go":
                {
                    string module = $"example.com/{u}";
                    byte[] zip = RandomNumberGenerator.GetBytes(96);
                    Stub($"/{module}/@v/v1.0.0.zip", "application/zip", zip);
                    return new Fixture("golang", $"/go/{module}/@v/v1.0.0.zip", $"/{module}/@v/v1.0.0.zip", zip,
                        module, "%", SetsXCache: true, HasHead: false);
                }

            case "cargo":
                {
                    byte[] crate = RandomNumberGenerator.GetBytes(80);
                    string cksum = Convert.ToHexString(SHA256.HashData(crate)).ToLowerInvariant();
                    Stub($"/{Dependably.Api.CargoController.IndexPath(u)}", "text/plain", Encoding.UTF8.GetBytes(
                        $$"""{"name":"{{u}}","vers":"1.0.0","deps":[],"cksum":"{{cksum}}","features":{},"yanked":false}"""));
                    Stub($"/api/v1/crates/{u}/1.0.0/download", "application/octet-stream", crate);
                    return new Fixture("cargo", $"/cargo/api/v1/crates/{u}/1.0.0/download",
                        $"/api/v1/crates/{u}/1.0.0/download", crate, u, "%", SetsXCache: false, HasHead: false);
                }

            case "apk":
                {
                    string file = $"{u}-1.0.0-r0.apk";
                    byte[] apk = RandomNumberGenerator.GetBytes(72);
                    Stub($"/v3.22/main/x86_64/{file}", "application/octet-stream", apk);
                    return new Fixture("apk", $"/apk/v3.22/main/x86_64/{file}", $"/v3.22/main/x86_64/{file}", apk,
                        u, "%", SetsXCache: true, HasHead: false);
                }

            case "terraform":
                {
                    string provider = $"registry.terraform.io/{u}/null";
                    byte[] archive = RandomNumberGenerator.GetBytes(88);
                    Stub($"/tfmirror/{provider}/1.0.0.json", "application/json", Encoding.UTF8.GetBytes(
                        """{"archives":{"linux_amd64":{"url":"1.0.0/linux_amd64.zip"}}}"""));
                    Stub($"/tfmirror/{provider}/1.0.0/linux_amd64.zip", "application/zip", archive);
                    return new Fixture("terraform", $"/terraform/{provider}/1.0.0/linux_amd64.zip",
                        $"/tfmirror/{provider}/1.0.0/linux_amd64.zip", archive, u, "%", SetsXCache: false, HasHead: false);
                }

            case "hex":
                {
                    byte[] tarball = StubHexRelease(u, "1.0.0");
                    return new Fixture("hex", $"/hex/tarballs/{u}-1.0.0.tar", $"/tarballs/{u}-1.0.0.tar", tarball,
                        u, $"{u}-1.0.0.tar", SetsXCache: true, HasHead: false);
                }

            case "maven":
                {
                    byte[] jar = RandomNumberGenerator.GetBytes(104);
                    string path = $"com/example/{u}/1.0/{u}-1.0.jar";
                    Stub($"/m2/{path}", "application/java-archive", jar);
                    Stub($"/m2/{path}.sha256", "text/plain",
                        Encoding.UTF8.GetBytes(Convert.ToHexString(SHA256.HashData(jar)).ToLowerInvariant() + "  x.jar\n"));
                    return new Fixture("maven", $"/maven/{path}", $"/m2/{path}", jar, u, $"{u}-1.0.jar",
                        SetsXCache: false, HasHead: false);
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "No fixture for this ecosystem.");
        }
    }

    private byte[] StubHexRelease(string name, string version)
    {
        string metadata =
            $"{{<<\"name\">>,<<\"{name}\">>}}.\n{{<<\"version\">>,<<\"{version}\">>}}.\n{{<<\"app\">>,<<\"{name}\">>}}.\n"
            + "{<<\"licenses\">>,[<<\"MIT\">>]}.\n{<<\"requirements\">>,[]}.\n{<<\"build_tools\">>,[<<\"mix\">>]}.\n";
        using var contents = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(contents, System.IO.Compression.CompressionMode.Compress, leaveOpen: true))
        using (var tw = new System.Formats.Tar.TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "lib/demo.ex")
            {
                DataStream = new MemoryStream("defmodule Demo do end\n"u8.ToArray()),
            });
        }

        byte[] tarball = HexTarball.Build(metadata, contents.ToArray());
        var parsed = HexTarball.Parse(tarball, 64 * 1024 * 1024);
        var package = new HexPackage(name, "upstream-repo", new[]
        {
            new HexRelease(version, parsed.InnerChecksum, Array.Empty<HexDependency>(), null, parsed.OuterChecksum, null, null),
        }, Array.Empty<HexSecurityAdvisory>());
        Stub($"/packages/{name}", "application/octet-stream",
            HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), _hexUpstreamKey));
        Stub($"/tarballs/{name}-{version}.tar", "application/octet-stream", tarball);
        return tarball;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void Stub(string path, string contentType, byte[] body) =>
        _factory.MockUpstream
            .Given(Request.Create().WithPath(path).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", contentType).WithBody(body));

    private int UpstreamCalls(string path) =>
        _factory.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.Ordinal));

    private HttpClient ClientFor(string ecosystem) =>
        ecosystem.StartsWith("pypi", StringComparison.Ordinal) || ecosystem is "nuget" or "maven"
            ? _factory.CreateClientWithBasic(_pullToken)
            : _factory.CreateClientWithBearer(_pullToken);

    private async Task<(long SizeBytes, string BlobKey)> RecordedAsync(Fixture fx)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        var rows = (await conn.QueryAsync<(long SizeBytes, string BlobKey)>(
            """
            SELECT size_bytes AS SizeBytes, blob_key AS BlobKey FROM cache_artifact
            WHERE ecosystem = @ecosystem AND name LIKE @nameLike AND filename LIKE @fileLike
            """,
            new { ecosystem = fx.Ecosystem, nameLike = $"%{fx.NameLike}%", fileLike = fx.FileLike })).ToList();
        return Assert.Single(rows);
    }

    private static Task InsertUpstreamAsync(
        System.Data.Common.DbConnection conn, string ecosystem, string url, string? publicKeyPem = null, string? protocol = null) =>
        conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, public_key_pem, upstream_protocol)
            VALUES (@id, (SELECT id FROM orgs WHERE slug = 'default'), @ecosystem, @url, 0, @publicKeyPem, @protocol)
            """,
            new { id = Guid.NewGuid().ToString("N"), ecosystem, url, publicKeyPem, protocol });
}
