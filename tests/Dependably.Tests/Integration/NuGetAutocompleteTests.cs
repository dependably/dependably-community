using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration tests for the NuGet v3 autocomplete endpoint
/// (GET /nuget/autocomplete) and the service-index advertisement of
/// SearchAutocompleteService resources.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetAutocompleteTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NuGetAutocompleteTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Service index advertisement ───────────────────────────────────────────

    [Fact]
    public async Task ServiceIndex_AdvertisesSearchAutocompleteService()
    {
        // Both the unversioned and the /3.0.0-beta SearchAutocompleteService @type entries
        // must appear in the service index pointing at /nuget/autocomplete.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string body = await client.GetStringAsync("/nuget/v3/index.json");
        using var doc = JsonDocument.Parse(body);
        var resources = doc.RootElement.GetProperty("resources").EnumerateArray().ToList();

        var autocompleteResources = resources
            .Where(r => r.GetProperty("@type").GetString()!
                .StartsWith("SearchAutocompleteService", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(autocompleteResources.Count >= 2,
            $"Expected at least 2 SearchAutocompleteService entries, got {autocompleteResources.Count}.");

        foreach (var r in autocompleteResources)
        {
            string id = r.GetProperty("@id").GetString()!;
            Assert.Contains("/nuget/autocomplete", id, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ── Anonymous-pull gate ───────────────────────────────────────────────────

    [Fact]
    public async Task Autocomplete_WithoutToken_Returns401()
    {
        // Default org has AnonymousPull=false; autocomplete must honour the same gate as
        // Search — no auth header means 401.
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/autocomplete?q=anything");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task AutocompleteVersions_WithoutToken_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/autocomplete?id=SomePkg");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Id-prefix search form ─────────────────────────────────────────────────

    [Fact]
    public async Task Autocomplete_IdPrefixSearch_ReturnsMatchingIds()
    {
        // Push a package whose name contains a distinctive prefix we can filter on.
        string prefix = $"AcPkg{Guid.NewGuid():N}"[..12];
        string pkgId = $"{prefix}Lib";
        await _factory.PushNuGetPackage(pkgId, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/autocomplete?q={prefix}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);

        int totalHits = doc.RootElement.GetProperty("totalHits").GetInt32();
        Assert.True(totalHits >= 1, "Expected at least one hit.");

        var ids = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.Contains(pkgId, ids, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Autocomplete_EmptyQuery_ReturnsAllPackages()
    {
        // Push a recognisable package, then query with no q= — must appear in data.
        string pkgId = $"AcAllPkg{Guid.NewGuid():N}"[..14];
        await _factory.PushNuGetPackage(pkgId, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync("/nuget/autocomplete");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var ids = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.Contains(pkgId, ids, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Autocomplete_TakeClamp_OversizedTakeNotError()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // take=999999 must be clamped to 100, not cause a 500.
        var resp = await client.GetAsync("/nuget/autocomplete?take=999999");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Autocomplete_NegativeSkip_ClampedNotError()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // skip=-5 must be clamped to 0.
        var resp = await client.GetAsync("/nuget/autocomplete?skip=-5");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Autocomplete_UnlistedPackage_ExcludedFromResults()
    {
        // Push then unlist a package; its id must not appear in autocomplete results
        // because it has no non-yanked versions. Pass the original cased name to
        // SetVersionYanked — packages.name stores the nuspec id as-pushed.
        string pkgId = $"AcYank{Guid.NewGuid():N}"[..14];
        await _factory.PushNuGetPackage(pkgId, "1.0.0");
        await _factory.SetVersionYanked("default", "nuget", pkgId, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/autocomplete?q={pkgId}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var ids = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.DoesNotContain(pkgId, ids, StringComparer.OrdinalIgnoreCase);
    }

    // ── Version enumeration form ──────────────────────────────────────────────

    [Fact]
    public async Task AutocompleteVersions_ReturnsVersionsForKnownPackage()
    {
        string pkgId = $"AcVer{Guid.NewGuid():N}"[..12];
        await _factory.PushNuGetPackage(pkgId, "1.0.0");
        await _factory.PushNuGetPackage(pkgId, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/autocomplete?id={pkgId.ToLowerInvariant()}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var versions = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.Contains("1.0.0", versions);
        Assert.Contains("2.0.0", versions);
    }

    [Fact]
    public async Task AutocompleteVersions_ExcludesUnlistedVersions()
    {
        // Push two versions; unlist one. Only the live version must appear.
        // Pass the original cased name to SetVersionYanked — packages.name stores
        // the nuspec id as-pushed.
        string pkgId = $"AcVerYk{Guid.NewGuid():N}"[..14];
        await _factory.PushNuGetPackage(pkgId, "1.0.0");
        await _factory.PushNuGetPackage(pkgId, "2.0.0");
        await _factory.SetVersionYanked("default", "nuget", pkgId, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/autocomplete?id={pkgId.ToLowerInvariant()}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var versions = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.DoesNotContain("1.0.0", versions);
        Assert.Contains("2.0.0", versions);
    }

    [Fact]
    public async Task AutocompleteVersions_UnknownPackage_ReturnsEmptyData()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/autocomplete?id=ghost-{Guid.NewGuid():N}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var versions = doc.RootElement.GetProperty("data").EnumerateArray().ToList();
        Assert.Empty(versions);
    }

    [Fact]
    public async Task AutocompleteVersions_PrereleaseTrue_IncludesPrereleaseVersions()
    {
        string pkgId = $"AcPre{Guid.NewGuid():N}"[..12];
        await _factory.PushNuGetPackage(pkgId, "1.0.0");
        await _factory.PushNuGetPackage(pkgId, "2.0.0-beta.1");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync(
            $"/nuget/autocomplete?id={pkgId.ToLowerInvariant()}&prerelease=true");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var versions = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.Contains("1.0.0", versions);
        Assert.Contains("2.0.0-beta.1", versions);
    }

    [Fact]
    public async Task AutocompleteVersions_PrereleaseFalse_ExcludesPrereleaseVersions()
    {
        string pkgId = $"AcNoP{Guid.NewGuid():N}"[..12];
        await _factory.PushNuGetPackage(pkgId, "1.0.0");
        await _factory.PushNuGetPackage(pkgId, "2.0.0-alpha.1");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // prerelease defaults to false.
        var resp = await client.GetAsync(
            $"/nuget/autocomplete?id={pkgId.ToLowerInvariant()}&prerelease=false");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var versions = doc.RootElement.GetProperty("data")
            .EnumerateArray()
            .Select(e => e.GetString()!)
            .ToList();

        Assert.Contains("1.0.0", versions);
        Assert.DoesNotContain("2.0.0-alpha.1", versions);
    }

    // ── AnonymousPull enabled ─────────────────────────────────────────────────

    [Fact]
    public async Task Autocomplete_AnonymousPullEnabled_NoTokenAllowed()
    {
        // When AnonymousPull is enabled, unauthenticated requests must succeed.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId", new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/nuget/autocomplete?q=anything");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId", new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }
}
