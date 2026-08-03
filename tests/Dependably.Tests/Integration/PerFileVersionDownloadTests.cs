using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// A hosted version can hold several artifacts — NuGet's <c>.nupkg</c> + <c>.snupkg</c>, PyPI's
/// sdist + wheels. The management package view lists each of them, and each downloads
/// independently.
///
/// <para>
/// Before this, the view read <c>artifact_inventory</c>, whose hosted arm is one row per VERSION,
/// so a multi-file version rendered as a single row carrying only the primary artifact — the
/// <c>.snupkg</c> was invisible. The download endpoint accepted <c>?file=</c> but honoured it only
/// on the proxy path, so even a correct per-file link returned the primary artifact's bytes.
/// </para>
///
/// <para>
/// The expansion deliberately does NOT live in <c>artifact_inventory</c>: that view also feeds the
/// NuGet registration index, the flatcontainer version list and the npm packument, every one of
/// which is version-level. <see cref="MultiFileVersion_IsListedOnceByVersionLevelRenderers"/> is
/// the guard on that — it is what a naive view change would have broken.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PerFileVersionDownloadTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private async Task<HttpClient> AdminClient()
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        return c;
    }

    // Pushes a .nupkg and its .snupkg to one coordinate and returns (id, nupkgBytes, snupkgBytes).
    private async Task<(string Id, byte[] Nupkg, byte[] Snupkg)> SeedNuGetWithSymbolsAsync()
    {
        string id = $"PerFile{Guid.NewGuid():N}"[..16];
        var (nupkg, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
        byte[] snupkg = NuGetFixtures.BuildSnupkgWithPdbs(
            id, "1.0.0", ($"{id}.pdb", NuGetFixtures.BuildPortablePdb(Guid.NewGuid())));

        using var admin = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(nupkg), "files", $"{id}.1.0.0.nupkg");
        content.Add(new ByteArrayContent(snupkg), "files", $"{id}.1.0.0.snupkg");
        var resp = await admin.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(2, JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("accepted").GetInt32());

        return (id.ToLowerInvariant(), nupkg, snupkg);
    }

    private static async Task<List<JsonElement>> VersionRowsAsync(HttpClient c, string eco, string name)
    {
        var resp = await c.GetAsync($"/api/v1/packages/{eco}/{name}");
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("versions").EnumerateArray()
            .Select(e => e.Clone()).ToList();
    }

    [Fact]
    public async Task NuGetVersionWithSymbols_ListsBothFiles()
    {
        var (id, nupkg, snupkg) = await SeedNuGetWithSymbolsAsync();

        using var admin = await AdminClient();
        var rows = await VersionRowsAsync(admin, "nuget", id);

        Assert.Equal(2, rows.Count);
        var byName = rows.ToDictionary(r => r.GetProperty("filename").GetString()!.ToLowerInvariant());
        string lower = id;

        // Each row carries ITS OWN filename and size, not the version's primary.
        Assert.Equal(nupkg.Length, byName[$"{lower}.1.0.0.nupkg"].GetProperty("sizeBytes").GetInt64());
        Assert.Equal(snupkg.Length, byName[$"{lower}.1.0.0.snupkg"].GetProperty("sizeBytes").GetInt64());

        // Version-level facts are identical across siblings — they belong to the version.
        Assert.Equal(
            byName[$"{lower}.1.0.0.nupkg"].GetProperty("version").GetString(),
            byName[$"{lower}.1.0.0.snupkg"].GetProperty("version").GetString());
        Assert.Equal(
            byName[$"{lower}.1.0.0.snupkg"].GetProperty("status").GetString(),
            byName[$"{lower}.1.0.0.nupkg"].GetProperty("status").GetString());

        // Siblings share the version's id — they ARE one package_versions row — so `id` cannot
        // identify a file. `filename` is what does, and it is what the UI keys its per-file rows
        // on (`fileRowKey`) and what `?file=` addresses. Keying on the repeated id throws
        // Svelte's each_key_duplicate, in production builds as well as dev.
        Assert.Equal(
            byName[$"{lower}.1.0.0.nupkg"].GetProperty("id").GetString(),
            byName[$"{lower}.1.0.0.snupkg"].GetProperty("id").GetString());
        Assert.Equal(2, rows.Select(r => r.GetProperty("filename").GetString()).Distinct().Count());
    }

    [Fact]
    public async Task EachFile_DownloadsItsOwnBytes()
    {
        var (id, nupkg, snupkg) = await SeedNuGetWithSymbolsAsync();
        using var admin = await AdminClient();

        // Use the filenames the LISTING reports, which is exactly what the UI passes back — the
        // import path stores the uploaded casing while the push path lowercases, so a hard-coded
        // name here would test an assumption rather than the round trip.
        var rows = await VersionRowsAsync(admin, "nuget", id);
        string nupkgName = rows.Select(r => r.GetProperty("filename").GetString()!)
            .Single(n => n.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase));
        string snupkgName = rows.Select(r => r.GetProperty("filename").GetString()!)
            .Single(n => n.EndsWith(".snupkg", StringComparison.OrdinalIgnoreCase));

        var pkgResp = await admin.GetAsync(
            $"/api/v1/packages/nuget/{id}/1.0.0/download?file={Uri.EscapeDataString(nupkgName)}");
        Assert.Equal(HttpStatusCode.OK, pkgResp.StatusCode);
        Assert.Equal(nupkg, await pkgResp.Content.ReadAsByteArrayAsync());

        var symResp = await admin.GetAsync(
            $"/api/v1/packages/nuget/{id}/1.0.0/download?file={Uri.EscapeDataString(snupkgName)}");
        Assert.Equal(HttpStatusCode.OK, symResp.StatusCode);
        Assert.Equal(snupkg, await symResp.Content.ReadAsByteArrayAsync());

        // The whole point: the two are different artifacts, not the same bytes twice.
        Assert.NotEqual(nupkg, snupkg);
    }

    [Fact]
    public async Task UnknownFile_Is404_AndDoesNotFallBackToThePrimary()
    {
        var (id, nupkg, _) = await SeedNuGetWithSymbolsAsync();
        using var admin = await AdminClient();

        var resp = await admin.GetAsync(
            $"/api/v1/packages/nuget/{id}/1.0.0/download?file=not-a-real-file.nupkg");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        // Substituting the primary would have "succeeded" while handing back the wrong artifact.
        Assert.NotEqual(nupkg, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task NoFileParam_StillServesThePrimaryArtifact()
    {
        // The row-level download button sends no ?file=; it must keep working unchanged.
        var (id, nupkg, _) = await SeedNuGetWithSymbolsAsync();
        using var admin = await AdminClient();

        var resp = await admin.GetAsync($"/api/v1/packages/nuget/{id}/1.0.0/download");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(nupkg, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task PyPiSdistAndWheel_AlsoListBothFiles()
    {
        // Not a NuGet special case: hosted PyPI had the identical gap.
        string name = $"perfile{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        var (wheel, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
        var (sdist, _) = PyPiFixtures.BuildSdist(name, "1.0.0");

        using var admin = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(wheel), "files", $"{name}-1.0.0-py3-none-any.whl");
        content.Add(new ByteArrayContent(sdist), "files", $"{name}-1.0.0.tar.gz");
        var upload = await admin.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        Assert.Equal(2, JsonDocument.Parse(await upload.Content.ReadAsStringAsync())
            .RootElement.GetProperty("accepted").GetInt32());

        var rows = await VersionRowsAsync(admin, "pypi", name);
        Assert.Equal(2, rows.Count);
        var names = rows.Select(r => r.GetProperty("filename").GetString()).ToList();
        Assert.Contains($"{name}-1.0.0-py3-none-any.whl", names);
        Assert.Contains($"{name}-1.0.0.tar.gz", names);
    }

    [Fact]
    public async Task MultiFileVersion_IsListedOnceByVersionLevelRenderers()
    {
        // The guard on the design constraint: the per-file expansion lives in the management
        // projection, NOT in artifact_inventory, because that view also feeds these renderers.
        // Had it gone into the view, each would list the version twice.
        var (id, _, _) = await SeedNuGetWithSymbolsAsync();
        string lower = id;
        using var pull = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var flat = await pull.GetAsync($"/nuget/flatcontainer/{lower}/index.json");
        Assert.Equal(HttpStatusCode.OK, flat.StatusCode);
        using (var doc = JsonDocument.Parse(await flat.Content.ReadAsStringAsync()))
        {
            var versions = doc.RootElement.GetProperty("versions").EnumerateArray()
                .Select(e => e.GetString()).ToList();
            Assert.Single(versions, v => v == "1.0.0");
        }

        var reg = await pull.GetAsync($"/nuget/registration/{lower}/index.json");
        Assert.Equal(HttpStatusCode.OK, reg.StatusCode);
        using (var doc = JsonDocument.Parse(await reg.Content.ReadAsStringAsync()))
        {
            int occurrences = doc.RootElement.GetProperty("items").EnumerateArray()
                .SelectMany(page => page.TryGetProperty("items", out var leaves)
                    ? leaves.EnumerateArray()
                    : Enumerable.Empty<JsonElement>())
                .Count(leaf => leaf.GetProperty("catalogEntry").GetProperty("version").GetString() == "1.0.0");
            Assert.Equal(1, occurrences);
        }
    }
}
