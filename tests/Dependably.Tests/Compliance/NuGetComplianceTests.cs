using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// NuGet v3 protocol compliance tests.
/// Verifies service index structure, nuspec namespace handling, unlist behaviour,
/// version normalization, and case-insensitive package lookup.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class NuGetComplianceTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NuGetComplianceTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Service index ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ServiceIndex_Version_Is300()
    {
        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var json = await client.GetStringAsync("/nuget/v3/index.json");
        using var doc = JsonDocument.Parse(json);

        Assert.Equal("3.0.0", doc.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public async Task ServiceIndex_HasFiveRequiredResourceTypes()
    {
        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var json = await client.GetStringAsync("/nuget/v3/index.json");
        using var doc = JsonDocument.Parse(json);

        var types = doc.RootElement
            .GetProperty("resources")
            .EnumerateArray()
            .Select(r => r.GetProperty("@type").GetString())
            .ToHashSet();

        Assert.Contains("SearchQueryService", types);
        Assert.Contains("RegistrationsBaseUrl", types);
        Assert.Contains("PackageBaseAddress/3.0.0", types);
        Assert.Contains("PackagePublish/2.0.0", types);
        Assert.Contains("SymbolPackagePublish/4.9.0", types);
    }

    // ── Nuspec namespace validation ───────────────────────────────────────────

    [Theory]
    [InlineData("http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd")]
    [InlineData("http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd")]
    public async Task Push_KnownNuspecNamespace_Returns201(string ns)
    {
        var token = await _factory.CreateToken("push");
        var id = $"NsTest{ns.GetHashCode():X8}";
        var bytes = BuildNupkg(id, "1.0.0", ns);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = BuildPushContent(bytes, $"{id}.1.0.0.nupkg");
        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    [Fact]
    public async Task Push_UnknownNuspecNamespace_Returns422()
    {
        var token = await _factory.CreateToken("push");
        var bytes = BuildNupkg("UnknownNs", "1.0.0", "http://schemas.example.com/unknown/nuspec.xsd");

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = BuildPushContent(bytes, "UnknownNs.1.0.0.nupkg");
        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Unlist (soft-delete) ─────────────────────────────────────────────────

    [Fact]
    public async Task Unlist_Version_ExcludedFromSearch()
    {
        await _factory.PushNuGetPackage("UnlistSearch", "1.0.0");

        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        // Unlist (NuGet DELETE = soft-delete/unlist, not hard-delete)
        var del = await client.DeleteAsync("/nuget/publish/UnlistSearch/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // The version should not appear in search results
        var pullToken = await _factory.CreateToken("pull");
        using var reader = _factory.CreateClientWithBasic(pullToken);
        var json = await reader.GetStringAsync("/nuget/query?q=UnlistSearch");
        using var doc = JsonDocument.Parse(json);

        var hits = doc.RootElement.GetProperty("totalHits").GetInt32();
        Assert.Equal(0, hits);
    }

    [Fact]
    public async Task Unlist_Version_StillDownloadableFromFlatcontainer()
    {
        await _factory.PushNuGetPackage("UnlistDown", "2.0.0");

        var token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var del = await client.DeleteAsync("/nuget/publish/UnlistDown/2.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // Flatcontainer download must still work after unlisting
        var pullToken = await _factory.CreateToken("pull");
        using var reader = _factory.CreateClientWithBasic(pullToken);
        var resp = await reader.GetAsync("/nuget/flatcontainer/unlistdown/2.0.0/unlistdown.2.0.0.nupkg");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Version normalization ─────────────────────────────────────────────────

    [Fact]
    public async Task Push_FourPartZeroRevision_NormalizedInPurl()
    {
        await _factory.PushNuGetPackage("NormalVer", "1.0.0.0");

        // 1.0.0.0 → normalised to 1.0.0 in PURL; the package should be accessible under both
        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Flatcontainer uses the stored normalised version
        var resp = await client.GetAsync(
            "/nuget/flatcontainer/normalver/1.0.0/normalver.1.0.0.nupkg");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Case-insensitive lookup ───────────────────────────────────────────────

    [Fact]
    public async Task Flatcontainer_PackageId_CaseInsensitive()
    {
        await _factory.PushNuGetPackage("CasePkg", "1.0.0");

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // NuGet flatcontainer requires case-insensitive ID lookup
        var lower = await client.GetAsync("/nuget/flatcontainer/casepkg/1.0.0/casepkg.1.0.0.nupkg");
        var upper = await client.GetAsync("/nuget/flatcontainer/CASEPKG/1.0.0/casepkg.1.0.0.nupkg");

        Assert.Equal(HttpStatusCode.OK, lower.StatusCode);
        Assert.Equal(HttpStatusCode.OK, upper.StatusCode);
    }

    // ── Push auth ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Push_NoToken_Returns401()
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg("NoAuthPkg", "1.0.0");
        using var client = _factory.CreateClient();
        using var content = BuildPushContent(bytes, "NoAuthPkg.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Push_PullToken_Returns403()
    {
        var token = await _factory.CreateToken("pull");
        var (bytes, _) = NuGetFixtures.BuildNupkg("ScopePkg", "1.0.0");

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = BuildPushContent(bytes, "ScopePkg.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Push_DuplicateVersion_Returns409()
    {
        await _factory.PushNuGetPackage("DupNuGet", "1.0.0");

        var token = await _factory.CreateToken("push");
        var (bytes, _) = NuGetFixtures.BuildNupkg("DupNuGet", "1.0.0");

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = BuildPushContent(bytes, "DupNuGet.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] BuildNupkg(string id, string version, string nuspecNs)
    {
        var nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="{nuspecNs}">
              <metadata>
                <id>{id}</id>
                <version>{version}</version>
                <authors>dependably-test</authors>
                <description>Compliance test package</description>
              </metadata>
            </package>
            """;

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry($"{id}.nuspec");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write(nuspec);
        }
        return ms.ToArray();
    }

    private static MultipartFormDataContent BuildPushContent(byte[] bytes, string filename)
    {
        var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", filename);
        return content;
    }
}
