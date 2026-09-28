using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// SSQP symbol reads on a deployment with split tiers (<see cref="DependablyFactory.SplitTiers"/>).
/// One symbol-index lookup serves two kinds of row: a hosted row points at a pushed
/// <c>.snupkg</c> in the registry tier, and a proxied row at a PDB fetched into the cache tier.
/// Each must be read from its own tier, and neither lookup may write to the other one.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SplitTierNuGetSymbolIntegrationTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new() { SplitTiers = true };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task HostedSymbols_AreServedAndReindexedFromTheRegistryTier()
    {
        string id = $"SplitSym{Guid.NewGuid():N}"[..16];
        const string version = "1.0.0";
        var signature = Guid.NewGuid();
        byte[] pdb = NuGetFixtures.BuildPortablePdb(signature);
        byte[] snupkg = NuGetFixtures.BuildSnupkgWithPdbs(id, version, ($"{id}.pdb", pdb));

        await _factory.PushNuGetPackage(id, version);
        int cacheKeys = await CountKeysAsync(_factory.CacheBlobStore);
        using (var pushClient = _factory.CreateClient())
        {
            pushClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", await _factory.CreateToken("push"));
            using var content = new MultipartFormDataContent();
            var file = new ByteArrayContent(snupkg);
            file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(file, "package", $"{id}.{version}.snupkg");
            Assert.Equal(HttpStatusCode.Created, (await pushClient.PutAsync("/nuget/symbols", content)).StatusCode);
        }

        string ssqp = $"/nuget/symbols/{id}.pdb/{NuGetSymbolKey.PortableKey(signature)}/{id}.pdb";
        using var reader = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        var served = await reader.GetAsync(ssqp);
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal(pdb, await served.Content.ReadAsByteArrayAsync());

        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        var reindex = await admin.PostAsync($"/api/v1/packages/nuget/{id}/{version}/reindex-symbols", content: null);
        Assert.Equal(HttpStatusCode.OK, reindex.StatusCode);
        using (var doc = JsonDocument.Parse(await reindex.Content.ReadAsStringAsync()))
        {
            Assert.Equal(1, doc.RootElement.GetProperty("indexedPdbCount").GetInt32());
        }

        string snupkgKey = await SnupkgBlobKeyAsync(id, version);
        Assert.True(await _factory.BlobStore.ExistsAsync(BlobKeys.StoreKey(snupkgKey)));
        Assert.False(await _factory.CacheBlobStore.ExistsAsync(BlobKeys.StoreKey(snupkgKey)));
        Assert.Equal(cacheKeys, await CountKeysAsync(_factory.CacheBlobStore));
    }

    [Fact]
    public async Task ProxiedSymbol_SecondLookup_IsServedFromTheCacheTier()
    {
        const string pdbName = "splittier.pdb";
        const string key = "fedcba9876543210fedcba9876543210ffffffff";
        string url = $"/nuget/symbols/{pdbName}/{key}/{pdbName}";
        string upstreamPath = $"/symbols/{pdbName}/{key}/{pdbName}";
        byte[] pdb = "split-tier portable pdb bytes"u8.ToArray();
        await SetSymbolServerUrlAsync($"{_factory.MockUpstream.Urls[0]}/symbols");
        _factory.MockUpstream.Given(Request.Create().WithPath(upstreamPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(pdb));
        int registryKeys = await CountKeysAsync(_factory.BlobStore);

        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        var first = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(pdb, await first.Content.ReadAsByteArrayAsync());

        // A second outbound fetch would now fail loudly, so a 200 can only come from the local
        // index and the bytes the first lookup stored.
        _factory.MockUpstream.Reset();
        _factory.MockUpstream.Given(Request.Create().WithPath(upstreamPath).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(500));

        var second = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(pdb, await second.Content.ReadAsByteArrayAsync());
        Assert.Equal(registryKeys, await CountKeysAsync(_factory.BlobStore));
    }

    private async Task<string> SnupkgBlobKeyAsync(string id, string version)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string? key = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT DISTINCT nsi.snupkg_blob_key FROM nuget_symbol_index nsi
            JOIN package_versions pv ON pv.id = nsi.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.purl_name = @purlName AND pv.version = @version
            """,
            new { purlName = id.ToLowerInvariant(), version });
        Assert.NotNull(key);
        return key!;
    }

    private async Task SetSymbolServerUrlAsync(string symbolServerUrl)
    {
        _factory.CreateClient().Dispose();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE upstream_registry SET symbol_server_url = @symbolServerUrl
            WHERE org_id = (SELECT id FROM orgs WHERE slug = 'default') AND ecosystem = 'nuget'
            """,
            new { symbolServerUrl });
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
}
