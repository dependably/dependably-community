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
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string json = await client.GetStringAsync("/nuget/v3/index.json");
        using var doc = JsonDocument.Parse(json);

        Assert.Equal("3.0.0", doc.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public async Task ServiceIndex_HasRequiredResourceTypes()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string json = await client.GetStringAsync("/nuget/v3/index.json");
        using var doc = JsonDocument.Parse(json);

        var types = doc.RootElement
            .GetProperty("resources")
            .EnumerateArray()
            .Select(r => r.GetProperty("@type").GetString())
            .ToHashSet();

        Assert.Contains("SearchQueryService", types);
        Assert.Contains("RegistrationsBaseUrl", types);
        // SemVer 2-aware clients pick this entry over the unversioned RegistrationsBaseUrl.
        Assert.Contains("RegistrationsBaseUrl/3.6.0", types);
        Assert.Contains("PackageBaseAddress/3.0.0", types);
        Assert.Contains("PackagePublish/2.0.0", types);
        Assert.Contains("SymbolPackagePublish/4.9.0", types);
    }

    /// <summary>
    /// Tooling like xunit.runner.visualstudio probes the registration5-* URL shapes
    /// directly rather than reading the service index. Every variant must dispatch to
    /// the same handler so a hardcoded path doesn't 404. Single push + five probes —
    /// theory'd inline data would 409 on every iteration after the first because the
    /// factory's tenant DB is shared across theory rows.
    /// </summary>
    [Fact]
    public async Task Registration_RouteAliases_AllDispatchToHandler()
    {
        await _factory.PushNuGetPackage("AliasPkg", "1.2.3");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string[] aliases = new[]
        {
            "/nuget/registration/aliaspkg/",
            "/nuget/registration5-semver1/aliaspkg/",
            "/nuget/registration5-gz-semver1/aliaspkg/",
            "/nuget/registration5-semver2/aliaspkg/",
            "/nuget/registration5-gz-semver2/aliaspkg/",
        };

        foreach (string? path in aliases)
        {
            // Upstream WireMock returns 404 for unstubbed paths, which exercises the
            // fall-back-to-local branch — perfect for proving the route reached the handler.
            var resp = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            string json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var versions = doc.RootElement
                .GetProperty("items").EnumerateArray()
                .SelectMany(p => p.GetProperty("items").EnumerateArray())
                .Select(e => e.GetProperty("catalogEntry").GetProperty("version").GetString())
                .ToList();
            Assert.True(versions.Contains("1.2.3"),
                $"Alias {path} did not return the pushed version; got: [{string.Join(",", versions)}]");
        }
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
        string token = await _factory.CreateToken("push");
        string id = $"NsTest{ns.GetHashCode():X8}";
        byte[] bytes = BuildNupkg(id, "1.0.0", ns);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = BuildPushContent(bytes, $"{id}.1.0.0.nupkg");
        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    [Fact]
    public async Task Push_UnknownNuspecNamespace_Returns422()
    {
        string token = await _factory.CreateToken("push");
        byte[] bytes = BuildNupkg("UnknownNs", "1.0.0", "http://schemas.example.com/unknown/nuspec.xsd");

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

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        // Unlist (NuGet DELETE = soft-delete/unlist, not hard-delete)
        var del = await client.DeleteAsync("/nuget/publish/UnlistSearch/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // The version should not appear in search results
        string pullToken = await _factory.CreateToken("pull");
        using var reader = _factory.CreateClientWithBasic(pullToken);
        string json = await reader.GetStringAsync("/nuget/query?q=UnlistSearch");
        using var doc = JsonDocument.Parse(json);

        int hits = doc.RootElement.GetProperty("totalHits").GetInt32();
        Assert.Equal(0, hits);
    }

    [Fact]
    public async Task Unlist_Version_StillDownloadableFromFlatcontainer()
    {
        await _factory.PushNuGetPackage("UnlistDown", "2.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var del = await client.DeleteAsync("/nuget/publish/UnlistDown/2.0.0");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // Flatcontainer download must still work after unlisting
        string pullToken = await _factory.CreateToken("pull");
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
        string token = await _factory.CreateToken("pull");
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

        string token = await _factory.CreateToken("pull");
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
        string token = await _factory.CreateToken("pull");
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

        string token = await _factory.CreateToken("push");
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
        string nuspec = $"""
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
