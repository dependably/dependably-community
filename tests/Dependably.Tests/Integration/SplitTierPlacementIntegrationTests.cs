using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol.Hex;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Which tier each serve path reads on a deployment with split tiers
/// (<see cref="DependablyFactory.SplitTiers"/>), pinned from both sides.
///
/// <para>
/// A recorded cache hit is answered from the cache tier, and only from it: the same bytes placed in
/// the registry tier instead are not a hit. And the inversion that a fix pointing everything at the
/// cache tier would produce: a published artefact is written to, and served from, the registry
/// tier, never the cache tier. The hosted tests hold before and after the proxy-tier fix; they
/// exist to catch a fix that moved a hosted path onto the wrong tier.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SplitTierPlacementIntegrationTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        SplitTiers = true,
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    private string _orgId = "";
    private string _pullToken = "";

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        _factory.CreateClient().Dispose();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        _orgId = (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
        _pullToken = await _factory.CreateToken("pull");
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    public static TheoryData<string> SeededEcosystems => new("go", "apk", "terraform", "cargo", "hex");

    [Theory]
    [MemberData(nameof(SeededEcosystems))]
    public async Task RecordedCacheHit_IsServedFromTheCacheTier(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem, _factory.CacheBlobStore);
        int registryKeys = await CountKeysAsync(_factory.BlobStore);
        using var client = _factory.CreateClientWithBearer(_pullToken);

        var resp = await client.GetAsync(seeded.Url);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(seeded.Bytes, await resp.Content.ReadAsByteArrayAsync());
        if (ecosystem is "go" or "apk" or "hex")
        {
            // These paths label a hit. The Go miss path re-opens the same cache-tier key through
            // the upstream client without an upstream call, so the label is what tells a hit from
            // a miss that happened to find the bytes.
            Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        }

        Assert.DoesNotContain(_factory.MockUpstream.LogEntries,
            e => e.RequestMessage?.Path?.Contains(seeded.Marker, StringComparison.Ordinal) == true);
        Assert.Equal(registryKeys, await CountKeysAsync(_factory.BlobStore));
    }

    [Theory]
    [MemberData(nameof(SeededEcosystems))]
    public async Task RecordedCacheHit_IsNeverAnsweredFromTheRegistryTier(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem, _factory.BlobStore);
        using var client = _factory.CreateClientWithBearer(_pullToken);

        var resp = await client.GetAsync(seeded.Url);

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        Assert.False(resp.Headers.TryGetValues("X-Cache", out var cache) && cache.Contains("HIT"),
            $"{ecosystem}: bytes in the registry tier answered a cache hit");
    }

    [Fact]
    public async Task PublishedArtefacts_AreWrittenToAndServedFromTheRegistryTier()
    {
        string u = "hs" + Guid.NewGuid().ToString("N")[..10];
        int cacheKeys = await CountKeysAsync(_factory.CacheBlobStore);

        await _factory.PushNpmPackage(u, "1.0.0");
        await _factory.PushNuGetPackage(u, "1.0.0");
        await _factory.PushPyPiPackage(u, "1.0.0");
        string mavenFile = await _factory.PushMavenArtifact("com.example", u, "1.0.0");

        using var bearer = _factory.CreateClientWithBearer(_pullToken);
        using var basic = _factory.CreateClientWithBasic(_pullToken);
        Assert.Equal(HttpStatusCode.OK, (await bearer.GetAsync($"/npm/tarballs/{u}/{u}-1.0.0.tgz")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await basic.GetAsync($"/nuget/flatcontainer/{u}/1.0.0/{u}.1.0.0.nupkg")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await basic.GetAsync($"/maven/com/example/{u}/1.0.0/{mavenFile}")).StatusCode);
        string index = await basic.GetStringAsync($"/simple/{u}/");
        string href = index.Split("href=\"")[1].Split('"')[0].Split('#')[0];
        Assert.Equal(HttpStatusCode.OK, (await basic.GetAsync(href)).StatusCode);

        using var head = new HttpRequestMessage(HttpMethod.Head, $"/npm/tarballs/{u}/{u}-1.0.0.tgz");
        Assert.Equal(HttpStatusCode.OK, (await bearer.SendAsync(head)).StatusCode);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        var keys = (await conn.QueryAsync<string>(
            """
            SELECT pv.blob_key FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem IN ('npm', 'nuget', 'pypi', 'maven')
              AND (p.name LIKE @like OR p.purl_name LIKE @like)
            """,
            new { orgId = _orgId, like = $"%{u}%" })).ToList();
        Assert.Equal(4, keys.Count);
        foreach (string key in keys)
        {
            Assert.True(await _factory.BlobStore.ExistsAsync(BlobKeys.StoreKey(key)), $"{key} missing from the registry tier");
            Assert.False(await _factory.CacheBlobStore.ExistsAsync(BlobKeys.StoreKey(key)), $"{key} written to the cache tier");
        }

        Assert.Equal(cacheKeys, await CountKeysAsync(_factory.CacheBlobStore));
    }

    [Fact]
    public async Task PublishedHexReleaseAndDocs_AreWrittenToAndServedFromTheRegistryTier()
    {
        string name = $"hexst{Guid.NewGuid():N}"[..14];
        int cacheKeys = await CountKeysAsync(_factory.CacheBlobStore);
        string pushToken = await _factory.CreateToken("push");
        using var push = _factory.CreateClient();
        push.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", pushToken);

        byte[] tarball = HexTarball.Build(HexMetadata(name, "1.0.0"), GzipTar());
        Assert.Equal(HttpStatusCode.Created,
            (await push.PostAsync($"/hex/api/packages/{name}/releases", Octets(tarball))).StatusCode);
        byte[] docs = GzipTar();
        Assert.Equal(HttpStatusCode.Created,
            (await push.PostAsync($"/hex/api/packages/{name}/releases/1.0.0/docs", Octets(docs))).StatusCode);

        using var pull = _factory.CreateClientWithBearer(_pullToken);
        var tarResp = await pull.GetAsync($"/hex/tarballs/{name}-1.0.0.tar");
        Assert.Equal(HttpStatusCode.OK, tarResp.StatusCode);
        Assert.Equal(tarball, await tarResp.Content.ReadAsByteArrayAsync());
        var docsResp = await pull.GetAsync($"/hex/docs/{name}-1.0.0.tar.gz");
        Assert.Equal(HttpStatusCode.OK, docsResp.StatusCode);
        Assert.Equal(docs, await docsResp.Content.ReadAsByteArrayAsync());

        string docsKey = BlobKeys.HexDocs(_orgId, name, "1.0.0");
        Assert.True(await _factory.BlobStore.ExistsAsync(docsKey));
        Assert.False(await _factory.CacheBlobStore.ExistsAsync(docsKey));
        Assert.Equal(cacheKeys, await CountKeysAsync(_factory.CacheBlobStore));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private sealed record Seeded(string Url, string Marker, byte[] Bytes);

    private async Task<Seeded> SeedAsync(string ecosystem, IBlobStore tier)
    {
        string u = "sp" + Guid.NewGuid().ToString("N")[..10];
        switch (ecosystem)
        {
            case "go":
                {
                    string module = $"example.com/{u}";
                    string key = BlobKeys.Go(_orgId, module, "v1.0.0", "zip");
                    byte[] bytes = await SeedCacheHitAsync(tier, "golang", module, "v1.0.0", "v1.0.0.zip", key);
                    return new Seeded($"/go/{module}/@v/v1.0.0.zip", u, bytes);
                }

            case "apk":
                {
                    string file = $"{u}-1.0.0-r0.apk";
                    string key = BlobKeys.Apk(_orgId, "v3.19", "main", "x86_64", file);
                    byte[] bytes = await SeedCacheHitAsync(tier, "apk", u, "1.0.0-r0", $"main/x86_64/{file}", key);
                    return new Seeded($"/apk/v3.19/main/x86_64/{file}", u, bytes);
                }

            case "terraform":
                {
                    string provider = $"registry.terraform.io/{u}/null";
                    string key = BlobKeys.Terraform(_orgId, "registry.terraform.io", u, "null", "1.0.0", "linux_amd64");
                    byte[] bytes = await SeedCacheHitAsync(tier, "terraform", provider, "1.0.0", "linux_amd64.zip", key);
                    return new Seeded($"/terraform/{provider}/1.0.0/linux_amd64.zip", u, bytes);
                }

            case "cargo":
                {
                    string key = BlobKeys.Cargo(_orgId, u, "1.0.0");
                    byte[] bytes = await SeedCacheHitAsync(tier, "cargo", u, "1.0.0", $"{u}-1.0.0.crate", key);
                    return new Seeded($"/cargo/api/v1/crates/{u}/1.0.0/download", u, bytes);
                }

            case "hex":
                {
                    string key = BlobKeys.Hex(_orgId, u, "1.0.0");
                    byte[] bytes = await SeedCacheHitAsync(tier, "hex", u, "1.0.0", $"{u}-1.0.0.tar", key);
                    return new Seeded($"/hex/tarballs/{u}-1.0.0.tar", u, bytes);
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "No seed for this ecosystem.");
        }
    }

    private async Task<byte[]> SeedCacheHitAsync(
        IBlobStore tier, string ecosystem, string name, string version, string filename, string blobKey)
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(64);
        await tier.PutAsync(blobKey, new MemoryStream(bytes));

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            _orgId, ecosystem, name, version, filename,
            Sha256: Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            SizeBytes: bytes.Length, BlobKey: blobKey,
            UpstreamUrl: $"https://upstream.example/{filename}", Origin: CacheAccessOrigin.FirstFetch));
        Assert.NotNull(id);
        return bytes;
    }

    private static async Task<int> CountKeysAsync(IBlobStore store)
    {
        int count = 0;
        await foreach (var _ in store.ListAsync(""))
        {
            count++;
        }

        return count;
    }

    private static string HexMetadata(string name, string version) =>
        $"{{<<\"name\">>,<<\"{name}\">>}}.\n{{<<\"version\">>,<<\"{version}\">>}}.\n{{<<\"app\">>,<<\"{name}\">>}}.\n"
        + "{<<\"description\">>,<<\"A test package\">>}.\n{<<\"licenses\">>,[<<\"MIT\">>]}.\n"
        + "{<<\"requirements\">>,[]}.\n{<<\"build_tools\">>,[<<\"mix\">>]}.\n{<<\"elixir\">>,<<\"~> 1.15\">>}.\n";

    private static byte[] GzipTar()
    {
        using var ms = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress, leaveOpen: true))
        using (var tw = new System.Formats.Tar.TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "lib/demo.ex")
            {
                DataStream = new MemoryStream("defmodule Demo do end\n"u8.ToArray()),
            });
        }

        return ms.ToArray();
    }

    private static ByteArrayContent Octets(byte[] bytes)
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return content;
    }
}
