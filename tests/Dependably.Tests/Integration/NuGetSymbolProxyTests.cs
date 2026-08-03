using System.Net;
using Dapper;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// SSQP forward-on-miss: a debug-id the tenant has not indexed locally is fetched from the org's
/// configured upstream symbol server, recorded on the cache plane, gated, and indexed so the next
/// lookup is a local hit.
///
/// <para>
/// Forward-on-miss is the only shape nuget.org supports — its service index carries
/// <c>SymbolPackagePublish</c> (push only) and no resource for downloading a <c>.snupkg</c>, so
/// there is no whole archive to fetch alongside a proxied package.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetSymbolProxyTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private const string PdbName = "proxied.pdb";
    private const string Key = "0123456789abcdef0123456789abcdef01234567";
    private static string Url => $"/nuget/symbols/{PdbName}/{Key}/{PdbName}";

    [Fact]
    public async Task SsqpMiss_WithNoSymbolServerConfigured_DoesNotFetch_And404s()
    {
        // Fail-closed by omission: an upstream without a symbol_server_url is skipped rather than
        // having its symbol host guessed, so nothing is fetched and nothing is cached.
        await ClearSymbolServerUrlAsync();

        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        var resp = await client.GetAsync(Url);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, await CachedSymbolCountAsync());
    }

    [Fact]
    public async Task SsqpMiss_UpstreamDoesNotHavePdb_Returns404()
    {
        // The ordinary case: most packages publish no symbols at all.
        _factory.MockUpstream.Given(Request.Create().WithPath($"/symbols/{PdbName}/{Key}/{PdbName}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(404));
        await SetSymbolServerUrlAsync($"{_factory.MockUpstream.Urls[0]}/symbols");

        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        var resp = await client.GetAsync(Url);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SsqpMiss_UpstreamServesPdb_IsServedRecordedAndIndexed()
    {
        byte[] pdb = "portable pdb bytes"u8.ToArray();
        _factory.MockUpstream.Given(Request.Create().WithPath($"/symbols/{PdbName}/{Key}/{PdbName}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(pdb));
        await SetSymbolServerUrlAsync($"{_factory.MockUpstream.Urls[0]}/symbols");

        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        var resp = await client.GetAsync(Url);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(pdb, await resp.Content.ReadAsByteArrayAsync());

        // Recorded on the cache plane under its own ecosystem, so it is plane-covered but never
        // appears among the tenant's NuGet packages.
        Assert.Equal(1, await CachedSymbolCountAsync());
        Assert.Equal(0, await CachedNuGetPackageCountAsync(PdbName));

        // And NO catalogue row at all. Asserting only the cache_artifact ecosystem missed the
        // actual leak: the proxy record path created a `packages` row, so the PDB surfaced in the
        // Packages list as a package named 'proxied.pdb' under an ecosystem the UI cannot label.
        Assert.Empty(await CataloguedPackagesAsync());

        // Indexed against the cache artifact, so the second lookup resolves locally.
        Assert.Equal(1, await IndexedProxySymbolCountAsync());
    }

    [Fact]
    public async Task SsqpMiss_SecondLookup_ResolvesLocallyWithoutRefetching()
    {
        byte[] pdb = "portable pdb bytes"u8.ToArray();
        _factory.MockUpstream.Given(Request.Create().WithPath($"/symbols/{PdbName}/{Key}/{PdbName}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(pdb));
        await SetSymbolServerUrlAsync($"{_factory.MockUpstream.Urls[0]}/symbols");

        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(Url)).StatusCode);

        // Point the upstream at a 500 so a second outbound fetch would fail loudly; the request
        // must still succeed, which is only possible from the local index.
        _factory.MockUpstream.Reset();
        _factory.MockUpstream.Given(Request.Create().WithPath($"/symbols/{PdbName}/{Key}/{PdbName}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(500));

        var second = await client.GetAsync(Url);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(pdb, await second.Content.ReadAsByteArrayAsync());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetSymbolServerUrlAsync(string symbolServerUrl)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE upstream_registry SET symbol_server_url = @symbolServerUrl WHERE org_id = @orgId AND ecosystem = 'nuget'",
            new { orgId, symbolServerUrl });
    }

    private async Task ClearSymbolServerUrlAsync()
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE upstream_registry SET symbol_server_url = NULL WHERE org_id = @orgId AND ecosystem = 'nuget'",
            new { orgId });
    }

    private async Task<int> CachedSymbolCountAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = @eco",
            new { eco = NuGetSymbolProxyFetcher.SymbolEcosystem });
    }

    private async Task<int> CachedNuGetPackageCountAsync(string name)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'nuget' AND name = @name",
            new { name });
    }

    // Every packages row for the tenant, as "ecosystem/name". A proxied PDB must contribute none.
    private async Task<IReadOnlyList<string>> CataloguedPackagesAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var rows = await conn.QueryAsync<(string Ecosystem, string Name)>(
            "SELECT ecosystem, name FROM packages");
        return rows.Select(r => $"{r.Ecosystem}/{r.Name}").ToList();
    }

    private async Task<int> IndexedProxySymbolCountAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM nuget_symbol_index WHERE owner_kind = 'cache_artifact'");
    }
}
