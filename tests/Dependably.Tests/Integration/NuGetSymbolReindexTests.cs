using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Symbol indexing at push time is best-effort — the version row is already committed, so a
/// corrupt PDB entry or an I/O blip is logged and swallowed rather than failing the push. That
/// leaves a <c>.snupkg</c> which downloads fine but whose PDBs never resolve by debug-id, and
/// re-pushing the coordinate is itself policy-gated. These cover the repair path that makes that
/// posture recoverable.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetSymbolReindexTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task Reindex_AfterIndexRowsDeleted_RestoresSsqpResolution()
    {
        var seeded = await SeedSymbolPackageAsync();
        string ssqpUrl = $"/nuget/symbols/{seeded.Id}.pdb/{seeded.SsqpKey}/{seeded.Id}.pdb";

        using var reader = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync(ssqpUrl)).StatusCode);

        // Simulate push-time indexing having failed: the archive is stored, the index is not.
        await DeleteIndexRowsAsync(seeded.VersionId);
        Assert.Equal(HttpStatusCode.NotFound, (await reader.GetAsync(ssqpUrl)).StatusCode);

        using var admin = await AdminClientAsync();
        var resp = await admin.PostAsync(ReindexUrl(seeded), content: null);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(1, await IndexedCountFromResponseAsync(resp));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync(ssqpUrl)).StatusCode);
    }

    [Fact]
    public async Task Reindex_RunTwice_ProducesNoDuplicateRows()
    {
        var seeded = await SeedSymbolPackageAsync();
        using var admin = await AdminClientAsync();

        var first = await admin.PostAsync(ReindexUrl(seeded), content: null);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var second = await admin.PostAsync(ReindexUrl(seeded), content: null);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        Assert.Equal(await IndexedCountFromResponseAsync(first), await IndexedCountFromResponseAsync(second));
        // The insert alone is idempotent via ON CONFLICT DO NOTHING; this pins that the replace
        // does not accumulate rows either.
        Assert.Equal(1, await IndexRowCountAsync(seeded.VersionId));
    }

    [Fact]
    public async Task Reindex_ReportsZero_WhenArchiveHoldsNoIndexablePdb()
    {
        // The actionable case an operator could previously only find in the server log: the symbol
        // package stored fine but carries nothing this build can index (native PDBs are skipped).
        var seeded = await SeedSymbolPackageAsync(indexablePdb: false);

        using var admin = await AdminClientAsync();
        var resp = await admin.PostAsync(ReindexUrl(seeded), content: null);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, await IndexedCountFromResponseAsync(resp));
    }

    [Fact]
    public async Task Reindex_WithoutTenantConfigure_IsRefused()
    {
        var seeded = await SeedSymbolPackageAsync();

        // A pull token carries read:artifact/read:metadata but not tenant:configure.
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));
        var resp = await client.PostAsync(ReindexUrl(seeded), content: null);

        Assert.True(
            resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"expected 401/403 for a token without tenant:configure, got {(int)resp.StatusCode}");
    }

    [Fact]
    public async Task Reindex_UnknownCoordinate_Returns404()
    {
        using var admin = await AdminClientAsync();
        var resp = await admin.PostAsync(
            $"/api/v1/packages/nuget/nosuchpkg{Guid.NewGuid():N}/1.0.0/reindex-symbols", content: null);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Reindex_VersionWithNoSymbolPackage_Returns404()
    {
        // A .nupkg-only coordinate has nothing to re-index; that is a 404, not a zero-count OK.
        string id = $"NoSym{Guid.NewGuid():N}"[..16];
        await _factory.PushNuGetPackage(id, "1.0.0");

        using var admin = await AdminClientAsync();
        var resp = await admin.PostAsync(
            $"/api/v1/packages/nuget/{id}/1.0.0/reindex-symbols", content: null);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private sealed record SeededSymbols(string Id, string Version, string VersionId, string SsqpKey);

    private static string ReindexUrl(SeededSymbols s) =>
        $"/api/v1/packages/nuget/{s.Id}/{s.Version}/reindex-symbols";

    private async Task<HttpClient> AdminClientAsync()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        return client;
    }

    private static async Task<int> IndexedCountFromResponseAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("indexedPdbCount").GetInt32();
    }

    private async Task<SeededSymbols> SeedSymbolPackageAsync(bool indexablePdb = true)
    {
        string id = $"Reidx{Guid.NewGuid():N}"[..16];
        const string version = "1.0.0";
        var signature = Guid.NewGuid();
        byte[] pdb = indexablePdb
            ? NuGetFixtures.BuildPortablePdb(signature)
            : "not a portable pdb"u8.ToArray();
        byte[] snupkg = NuGetFixtures.BuildSnupkgWithPdbs(id, version, ($"{id}.pdb", pdb));

        await _factory.PushNuGetPackage(id, version);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", await _factory.CreateToken("push"));
        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(snupkg);
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", $"{id}.{version}.snupkg");
        var push = await client.PutAsync("/nuget/symbols", content);
        Assert.Equal(HttpStatusCode.Created, push.StatusCode);

        return new SeededSymbols(id, version, await VersionIdAsync(id, version),
            NuGetSymbolKey.PortableKey(signature));
    }

    private async Task<string> VersionIdAsync(string id, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? versionId = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.purl_name = @purlName AND pv.version = @version LIMIT 1
            """,
            new { purlName = id.ToLowerInvariant(), version });
        Assert.NotNull(versionId);
        return versionId!;
    }

    private async Task DeleteIndexRowsAsync(string versionId)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM nuget_symbol_index WHERE package_version_id = @versionId",
            new { versionId });
    }

    private async Task<int> IndexRowCountAsync(string versionId)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM nuget_symbol_index WHERE package_version_id = @versionId",
            new { versionId });
    }
}
