using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Branch-coverage extension for <see cref="Dependably.Api.NuGetController"/>. Targets paths
/// uncovered by NuGetControllerTests / NuGetComplianceTests / MixedOriginRoutingTests:
/// service-index URL shape (both aliases), anonymous registration + registration upstream
/// failure paths, flatcontainer upstream timeout / malformed JSON, push 413 / 422 path-safety,
/// push symbols happy path, unlist idempotency for missing version, GetSymbols success +
/// missing snupkg blob, and semver1 vs semver2 registration variant dispatch.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetControllerExtendedTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NuGetControllerExtendedTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Service index URL shape ───────────────────────────────────────────────

    [Fact]
    public async Task ServiceIndex_BothRouteAliases_ReturnSameResources()
    {
        // Service index responds at /nuget/v3/index.json AND /nuget/index.json. Both
        // must enumerate the full resource set and reuse BaseUrl() for @id construction.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string v3 = await client.GetStringAsync("/nuget/v3/index.json");
        string unv = await client.GetStringAsync("/nuget/index.json");

        using var d1 = JsonDocument.Parse(v3);
        using var d2 = JsonDocument.Parse(unv);

        Assert.Equal("3.0.0", d1.RootElement.GetProperty("version").GetString());
        Assert.Equal("3.0.0", d2.RootElement.GetProperty("version").GetString());

        // @id values must be absolute and include /nuget under the request host.
        foreach (var doc in new[] { d1, d2 })
        {
            foreach (var r in doc.RootElement.GetProperty("resources").EnumerateArray())
            {
                string id = r.GetProperty("@id").GetString()!;
                Assert.StartsWith("http", id, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("/nuget/", id, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    // ── Registration: anonymous-pull disabled → 401 ───────────────────────────

    [Fact]
    public async Task RegistrationIndex_WithoutToken_AnonymousPullDisabled_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/registration/any-pkg/");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task RegistrationIndexSemVer2_WithoutToken_AnonymousPullDisabled_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/registration5-semver2/any-pkg/");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Registration: passthrough disabled + no local row → 404 ───────────────

    [Fact]
    public async Task RegistrationIndex_PassthroughDisabled_NoLocal_Returns404()
    {
        string unknownId = $"unknownreg{Guid.NewGuid():N}"[..18].ToLowerInvariant();

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/nuget/registration/{unknownId}/");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }

    // ── Registration: upstream success → merged JSON returned ─────────────────

    [Fact]
    public async Task RegistrationIndex_SemVer1_UpstreamSucceedsNoLocal_ReturnsUpstreamPayload()
    {
        // Hits ProxyMergedRegistrationAsync path where upstreamJson != null and pkg is null.
        string id = $"regupok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":1,\"items\":["
            + "{\"@id\":\"x\",\"catalogEntry\":{\"id\":\"X\",\"version\":\"1.2.3\",\"listed\":true}}]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-semver1/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration/{id}/");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("\"1.2.3\"", body);
    }

    [Fact]
    public async Task RegistrationIndexSemVer2_UpstreamSucceedsNoLocal_ReturnsUpstreamPayload()
    {
        // semVer2=true picks the registration5-gz-semver2 upstream variant.
        string id = $"regsv2ok{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":1,\"items\":["
            + "{\"@id\":\"x\",\"catalogEntry\":{\"id\":\"X\",\"version\":\"2.0.0-beta+meta\",\"listed\":true}}]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-gz-semver2/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration5-semver2/{id}/");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("2.0.0-beta+meta", body);
    }

    // Regression (#nuget-registration-index-route): NuGet V3 clients request the registration
    // index at `{base}/{lowerId}/index.json` — not the bare `{base}/{lowerId}/`. The routes
    // originally matched only `{id}/`, so `dotnet restore` / `dotnet tool restore` 404'd on every
    // registration lookup (e.g. "Version X of package cyclonedx is not found"). These assert the
    // `/index.json` form reaches the handler (returns the upstream payload, not a routing 404).
    [Theory]
    [InlineData("registration", "registration5-semver1")]                 // unversioned base → semver1 upstream
    [InlineData("registration5-gz-semver2", "registration5-gz-semver2")]  // SemVer2 base advertised in service index
    public async Task RegistrationIndex_IndexJsonSuffix_RoutesToHandler(string clientBase, string upstreamVariant)
    {
        string id = $"regidx{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":1,\"items\":["
            + "{\"@id\":\"x\",\"catalogEntry\":{\"id\":\"X\",\"version\":\"6.2.0\",\"listed\":true}}]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{upstreamVariant}/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/{clientBase}/{id}/index.json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("\"6.2.0\"", await resp.Content.ReadAsStringAsync());
    }

    // ── Registration: upstream non-success + no local row → 404 ───────────────

    [Fact]
    public async Task RegistrationIndex_UpstreamReturns500_NoLocal_Returns404()
    {
        // Exercises the upstream non-success warning path AND the (pkg is null || count==0) → 404 path.
        string id = $"reg500{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-semver1/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration/{id}/");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Registration: upstream success + local → merged with extra page ───────

    [Fact]
    public async Task RegistrationIndex_UpstreamPlusLocal_MergedResponseAddsLocalPage()
    {
        // Both branches present: upstreamJson != null AND localVersions.Count > 0.
        // MergeLocalIntoUpstreamRegistration appends a local page; verify the splice happened.
        string id = $"regmerge{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "9.9.9");
        // Hosted names are implicit local_only; merging upstream needs the explicit operator opt-in.
        await _factory.SeedMixedClaim("nuget", id);

        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":1,\"items\":["
            + "{\"@id\":\"x\",\"catalogEntry\":{\"id\":\"" + id + "\",\"version\":\"1.0.0\",\"listed\":true}}"
            + "]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-semver1/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration/{id}/");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var versions = doc.RootElement.GetProperty("items").EnumerateArray()
            .SelectMany(p => p.GetProperty("items").EnumerateArray())
            .Select(e => e.GetProperty("catalogEntry").GetProperty("version").GetString()!)
            .ToHashSet();
        Assert.Contains("1.0.0", versions);
        Assert.Contains("9.9.9", versions);
    }

    // ── Registration leaf: {id}/{version}.json ───────────────────────────────

    [Fact]
    public async Task RegistrationLeaf_LocalVersion_ServedFromLocalData()
    {
        // A version with a local row is served as a local leaf; packageContent points at our flatcontainer.
        string id = $"leaflocal{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "9.9.9");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration/{id}/9.9.9.json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("9.9.9", doc.RootElement.GetProperty("catalogEntry").GetProperty("version").GetString());
        Assert.Contains($"/flatcontainer/{id}/9.9.9/{id}.9.9.9.nupkg",
            doc.RootElement.GetProperty("packageContent").GetString());
    }

    [Theory]
    [InlineData("registration", "registration5-semver1")]                 // unversioned base → semver1 upstream
    [InlineData("registration5-gz-semver2", "registration5-gz-semver2")]  // SemVer2 base
    public async Task RegistrationLeaf_NoLocal_ProxiesUpstreamLeaf(string clientBase, string upstreamVariant)
    {
        string id = $"leafup{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string leafJson = "{\"@id\":\"x\",\"@type\":\"Package\","
            + "\"catalogEntry\":{\"id\":\"X\",\"version\":\"6.2.0\",\"listed\":true},"
            + "\"listed\":true,\"packageContent\":\"y\"}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{upstreamVariant}/{id}/6.2.0.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leafJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/{clientBase}/{id}/6.2.0.json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("\"6.2.0\"", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RegistrationLeaf_NoLocal_UpstreamMissing_Returns404()
    {
        string id = $"leaf404{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-semver1/{id}/1.2.3.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration/{id}/1.2.3.json");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task RegistrationIndexJson_OutranksLeafRoute_StillMergesLocal()
    {
        // Route-precedence guard: the literal `index.json` segment must out-rank the `{version}.json`
        // leaf route, so `…/{id}/index.json` reaches the index handler (which merges the local 9.9.9
        // page). A mis-route to the leaf would proxy the bare upstream index and drop the local page.
        string id = $"leafprec{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "9.9.9");
        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":1,\"items\":["
            + "{\"@id\":\"x\",\"catalogEntry\":{\"id\":\"" + id + "\",\"version\":\"1.0.0\",\"listed\":true}}"
            + "]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-semver1/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/registration/{id}/index.json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var versions = JsonDocument.Parse(await resp.Content.ReadAsStringAsync())
            .RootElement.GetProperty("items").EnumerateArray()
            .SelectMany(p => p.GetProperty("items").EnumerateArray())
            .Select(e => e.GetProperty("catalogEntry").GetProperty("version").GetString()!)
            .ToHashSet();
        Assert.Contains("9.9.9", versions);  // local page present → index handler ran, not the leaf
    }

    [Fact]
    public async Task RegistrationIndexAndLeaf_LocalOnlyHostedPackage_EmitJsonLdAtIdAndType()
    {
        // Regression: the local-only registration render must emit JSON-LD "@id"/"@type" keys
        // (with the leading "@"). An anonymous-object property `@id` is a C# verbatim identifier
        // whose name is "id" (no "@"), so anonymous objects silently produce a spec-violating
        // document that crashes `dotnet restore` / `dotnet tool install` with
        // "Value cannot be null or an empty string". No upstream is mocked for this id, so the
        // index and leaf are served by BuildLocalRegistration / BuildLocalLeafResponse.
        string id = $"jsonld{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.1.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var idxResp = await client.GetAsync($"/nuget/registration/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, idxResp.StatusCode);
        var idx = JsonDocument.Parse(await idxResp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(string.IsNullOrEmpty(idx.GetProperty("@id").GetString()));
        Assert.True(idx.TryGetProperty("@type", out _));
        var page = idx.GetProperty("items").EnumerateArray().First();
        Assert.False(string.IsNullOrEmpty(page.GetProperty("@id").GetString()));
        Assert.Equal("catalog:CatalogPage", page.GetProperty("@type").GetString());
        var leafItem = page.GetProperty("items").EnumerateArray().First();
        Assert.Equal("Package", leafItem.GetProperty("@type").GetString());
        Assert.False(string.IsNullOrEmpty(leafItem.GetProperty("@id").GetString()));
        var catalog = leafItem.GetProperty("catalogEntry");
        Assert.False(string.IsNullOrEmpty(catalog.GetProperty("@id").GetString()));
        Assert.Equal("1.1.0", catalog.GetProperty("version").GetString());
        Assert.False(string.IsNullOrEmpty(catalog.GetProperty("packageContent").GetString()));

        var leafResp = await client.GetAsync($"/nuget/registration/{id}/1.1.0.json");
        Assert.Equal(HttpStatusCode.OK, leafResp.StatusCode);
        var leaf = JsonDocument.Parse(await leafResp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("Package", leaf.GetProperty("@type").GetString());
        Assert.False(string.IsNullOrEmpty(leaf.GetProperty("@id").GetString()));
        Assert.False(string.IsNullOrEmpty(leaf.GetProperty("packageContent").GetString()));
        var leafCatalog = leaf.GetProperty("catalogEntry");
        Assert.Equal(id, leafCatalog.GetProperty("id").GetString(), ignoreCase: true);
        Assert.Equal("1.1.0", leafCatalog.GetProperty("version").GetString());
    }

    // ── FlatcontainerVersions: upstream malformed JSON → error header ─────────

    [Fact]
    public async Task FlatcontainerVersions_UpstreamMalformedJson_LocalOnlyReturned_HeaderError()
    {
        // MergeUpstreamVersionsAsync catches JsonException, sets X-Upstream-Status=error,
        // logs warning. Local-only versions still returned.
        string id = $"badjson{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "5.0.0");
        await _factory.SeedMixedClaim("nuget", id);

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("{not json"));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("error", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());

        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("5.0.0", body);
    }

    [Fact]
    public async Task FlatcontainerVersions_UpstreamSuccessMissingVersionsField_HeaderError()
    {
        // JSON parses, but 'versions' key is absent — controller logs warning, marks error.
        string id = $"missingver{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");
        await _factory.SeedMixedClaim("nuget", id);

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("{\"otherkey\":[]}"));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("error", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());
    }

    [Fact]
    public async Task FlatcontainerVersions_UpstreamSuccess_HeaderOk_MergesVersions()
    {
        string id = $"upok{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "7.0.0");
        await _factory.SeedMixedClaim("nuget", id);

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("{\"versions\":[\"1.0.0\",\"2.0.0\"]}"));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("ok", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());
    }

    // ── FlatcontainerVersions: anonymous pull denied without token ─────────────

    [Fact]
    public async Task FlatcontainerVersions_AnonymousPullDisabled_NoToken_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/flatcontainer/something/index.json");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Flatcontainer download: upstream 404 → 404 ────────────────────────────

    [Fact]
    public async Task Flatcontainer_Download_UpstreamNotFound_Returns404()
    {
        // Path: no local pkg, AnonymousPull allowed by token, passthrough enabled, proxy fetch
        // hits upstream 404 → returns NotFound (the upstream success branch is inverted).
        string id = $"missupstream{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Flatcontainer download: passthrough disabled + no pkg → 404 ───────────

    [Fact]
    public async Task Flatcontainer_Download_PassthroughDisabled_NoLocal_Returns404()
    {
        // Passthrough disabled means even with token, an unknown package → 404 (early NotFound
        // before any upstream call).
        string id = $"passoff{Guid.NewGuid():N}"[..18].ToLowerInvariant();

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }

    // ── Flatcontainer download: hosted-version normalised lookup ──────────────

    [Fact]
    public async Task Flatcontainer_Download_HostedVersion_TokenAuth_Succeeds()
    {
        // Verifies ServeHostedVersionAsync 200 path: token resolved, blob streamed, X-Cache HIT.
        string id = $"hostdl{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "3.4.5");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync(
            $"/nuget/flatcontainer/{id}/3.4.5/{id}.3.4.5.nupkg");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
    }

    [Fact]
    public async Task Flatcontainer_Download_HostedVersion_FourPartVersion_NormalizedLookup()
    {
        // Push 1.0.0.0 (stored as normalized "1.0.0"); request also as 1.0.0.0 to exercise
        // NormalizeNuGetVersion's parse-success branch.
        string id = $"normver{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/1.0.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Push: missing X-NuGet-ApiKey header → 401 ─────────────────────────────

    [Fact]
    public async Task Push_NoApiKey_Returns401()
    {
        // [Authorize] enforces auth; no token at all → 401 from auth middleware before the
        // controller's body-shape checks ever run.
        var (bytes, _) = NuGetFixtures.BuildNupkg("NoKey", "1.0.0");
        using var client = _factory.CreateClient();
        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(bytes);
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", "NoKey.1.0.0.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Push: garbage zip body → 422 from ParseNupkg's catch ──────────────────

    [Fact]
    public async Task Push_NotAZip_Returns422()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(Encoding.UTF8.GetBytes("this is not a zip"));
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", "junk.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Push: zip with no .nuspec → 422 "No .nuspec found" ────────────────────

    [Fact]
    public async Task Push_ZipMissingNuspec_Returns422()
    {
        string token = await _factory.CreateToken("push");
        byte[] bytes = BuildZip(("readme.txt", "hello"));

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(bytes);
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", "missing.nupkg");

        var resp = await client.PutAsync("/nuget/publish", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Push: org-level NuGet size limit → 413 ────────────────────────────────

    [Fact]
    public async Task Push_ExceedsOrgNuGetLimit_Returns413()
    {
        // Set the per-org NuGet limit small so a normal-sized nupkg exceeds it.
        await _factory.SetOrgLimit("default", "nuget", bytes: 100);
        try
        {
            string token = await _factory.CreateToken("push");
            string id = $"OverLimit{Guid.NewGuid():N}"[..18];
            var (bytes, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
            // Sanity: fixture is larger than 100 bytes (nuspec alone exceeds that).
            Assert.True(bytes.Length > 100, "Fixture nupkg should be larger than the 100-byte cap.");

            using var client = _factory.CreateClient();
            client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
            using var content = new MultipartFormDataContent();
            var fc = new ByteArrayContent(bytes);
            fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(fc, "package", $"{id}.1.0.0.nupkg");

            var resp = await client.PutAsync("/nuget/publish", content);
            // Could be 413 from controller OR 413 from UploadSizeLimitMiddleware — either is a
            // pass on the size-cap branch. Just assert one of the rejection statuses.
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        }
        finally
        {
            // Restore so subsequent tests aren't blocked by the tiny cap.
            await _factory.SetOrgLimit("default", "nuget", bytes: 500L * 1024 * 1024);
        }
    }

    // ── Push: symbols happy path (.snupkg with .pdb) ──────────────────────────

    [Fact]
    public async Task PushSymbols_ValidSnupkg_Returns201()
    {
        // Push .snupkg for a fresh id+version with no prior .nupkg so the publish pipeline
        // doesn't reject as version_exists. Symbols and packages share the version row in
        // this controller's publish path, so coexistence on the same (id, version) would
        // produce 409 Conflict — that case is exercised by PushSymbols_SnupkgMissingPdb_*.
        string id = $"SymPkg{Guid.NewGuid():N}"[..16];

        // .snupkg = ZIP containing a .nuspec + at least one .pdb.
        byte[] snupkg = BuildSnupkg(id, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(snupkg);
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", $"{id}.1.0.0.snupkg");

        var resp = await client.PutAsync("/nuget/symbols", content);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    [Fact]
    public async Task PushSymbols_SnupkgMissingPdb_Returns422()
    {
        // ParseNupkg(isSymbol:true) returns the "must contain at least one .pdb" failure when
        // the zip has a nuspec but no .pdb entry. Hits the symbol-specific validation branch.
        string nuspec = NuspecXml("NoPdbSym", "1.0.0");
        byte[] bytes = BuildZip(("NoPdbSym.nuspec", nuspec));

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = new MultipartFormDataContent();
        var fc = new ByteArrayContent(bytes);
        fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fc, "package", "NoPdbSym.1.0.0.snupkg");

        var resp = await client.PutAsync("/nuget/symbols", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Unlist: idempotency (re-yank a yanked version still 204) ──────────────

    [Fact]
    public async Task Unlist_AlreadyUnlisted_StillReturnsNoContent()
    {
        // Unlist sets yanked=1. A second DELETE on the same coordinates also returns 204 —
        // the SQL UPDATE is a no-op on a yanked row but still finds it; the handler doesn't
        // care about prior state.
        string id = $"ReUnlist{Guid.NewGuid():N}"[..16];
        await _factory.PushNuGetPackage(id, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var first = await client.DeleteAsync($"/nuget/publish/{id}/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

        var second = await client.DeleteAsync($"/nuget/publish/{id}/1.0.0");
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
    }

    [Fact]
    public async Task Unlist_PackageNotFound_Returns404()
    {
        // Exercises the early `pkg is null` 404 branch.
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var resp = await client.DeleteAsync(
            $"/nuget/publish/ghost{Guid.NewGuid():N}/1.0.0");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Unlist_VersionNotFound_Returns404()
    {
        // Package exists, but the requested version does not — second NotFound branch.
        string id = $"VerMiss{Guid.NewGuid():N}"[..16];
        await _factory.PushNuGetPackage(id, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        var resp = await client.DeleteAsync($"/nuget/publish/{id}/9.9.9");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Unlist_MissingApiKey_Returns401()
    {
        // No X-NuGet-ApiKey at all → token is null at controller, but [Authorize] should also
        // reject. Either way the controller branch (token is null || OrgId mismatch) → 401.
        using var client = _factory.CreateClient();
        var resp = await client.DeleteAsync("/nuget/publish/whatever/1.0.0");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── GetSymbols: success + missing snupkg blob ─────────────────────────────

    [Fact]
    public async Task GetSymbols_AfterSymbolPush_Returns200()
    {
        // Push a fresh symbols package (no prior nupkg on this id to avoid version_exists),
        // then GET /nuget/symbols/{id}/{version}/{file}. The controller filters versions
        // whose BlobKey ends with .snupkg, so a symbols-only row still matches.
        string id = $"GetSym{Guid.NewGuid():N}"[..16];

        byte[] snupkg = BuildSnupkg(id, "1.0.0");
        string pushToken = await _factory.CreateToken("push");
        using (var pushClient = _factory.CreateClient())
        {
            pushClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", pushToken);
            using var pushContent = new MultipartFormDataContent();
            var fc = new ByteArrayContent(snupkg);
            fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            pushContent.Add(fc, "package", $"{id}.1.0.0.snupkg");
            var pushResp = await pushClient.PutAsync("/nuget/symbols", pushContent);
            Assert.Equal(HttpStatusCode.Created, pushResp.StatusCode);
        }

        string pullToken = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(pullToken);
        string lowerId = id.ToLowerInvariant();
        var resp = await client.GetAsync(
            $"/nuget/symbols/{lowerId}/1.0.0/{lowerId}.1.0.0.snupkg");

        // The controller looks up by exact normalised version + .snupkg blob key suffix.
        // 200 OK confirms the success path; 404 here would indicate the symbols push or
        // version lookup didn't land. We expect 200.
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task GetSymbols_NoSnupkgVersionPresent_Returns404()
    {
        // Push only a regular .nupkg (no symbols). GetSymbols filters versions whose BlobKey
        // ends with .snupkg — none exist, so the lookup yields no match → 404.
        string id = $"NoSym{Guid.NewGuid():N}"[..16];
        await _factory.PushNuGetPackage(id, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync(
            $"/nuget/symbols/{id.ToLowerInvariant()}/1.0.0/{id.ToLowerInvariant()}.1.0.0.snupkg");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task GetSymbols_AnonymousPullDisabled_NoToken_Returns401()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/symbols/whatever/1.0.0/whatever.1.0.0.snupkg");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task GetSymbols_UploadedOrigin_AnonymousPullEnabled_NoToken_Returns200()
    {
        // Symbols follow AnonymousPull just like .nupkg: when the org enables anonymous pull,
        // uploaded symbols are served without a token. The first-gate (AnonymousPull=false check)
        // is the only enforced gate; the second uploaded-origin guard has been removed.
        string id = $"PrivSym{Guid.NewGuid():N}"[..14];
        byte[] snupkg = BuildSnupkg(id, "1.0.0");
        string pushToken = await _factory.CreateToken("push");
        using (var pushClient = _factory.CreateClient())
        {
            pushClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", pushToken);
            using var pushContent = new MultipartFormDataContent();
            var fc = new ByteArrayContent(snupkg);
            fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            pushContent.Add(fc, "package", $"{id}.1.0.0.snupkg");
            var pushResp = await pushClient.PutAsync("/nuget/symbols", pushContent);
            Assert.Equal(HttpStatusCode.Created, pushResp.StatusCode);
        }

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId", new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);

        string lowerId = id.ToLowerInvariant();
        string path = $"/nuget/symbols/{lowerId}/1.0.0/{lowerId}.1.0.0.snupkg";
        try
        {
            // Anonymous: served when AnonymousPull is on (symbols follow the same gate as .nupkg).
            using var anon = _factory.CreateClient();
            var anonResp = await anon.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, anonResp.StatusCode);

            // Authenticated: still served.
            string pullToken = await _factory.CreateToken("pull");
            using var authed = _factory.CreateClientWithBasic(pullToken);
            var authResp = await authed.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, authResp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId", new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }

    // ── Registration: upstream merge not poisoned by stale local-only cache ──────
    //
    // Regression: after the caching layer was added, the local-only path and the
    // proxy-merged path shared the same IMemoryCache key. A package pushed before an
    // operator added the mixed claim caused the local-only bytes to be cached; subsequent
    // requests (now on the proxy-merged path after the claim was added) hit that stale
    // entry and returned only the local versions, dropping all upstream history.
    //
    // The fix assigns a distinct IsProxy:true key to the proxy-merged path so the two
    // paths can never collide even when the claim changes between requests.

    [Fact]
    public async Task RegistrationIndex_LocalCacheNotPoisoned_AfterMixedClaimAdded()
    {
        // 1. Push a local version — this creates an uploaded-origin row, making the package
        //    implicitly local_only. The first registration request hits ServeLocalRegistrationAsync
        //    and caches local-only bytes under the local key.
        string id = $"cachepois{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "13.0.3");

        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":2,\"items\":["
            + $"{{\"@id\":\"x\",\"catalogEntry\":{{\"id\":\"{id}\",\"version\":\"3.5.8\",\"listed\":true}}}},"
            + $"{{\"@id\":\"y\",\"catalogEntry\":{{\"id\":\"{id}\",\"version\":\"10.0.0\",\"listed\":true}}}}"
            + "]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/registration5-semver1/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // 2. First request: package is implicitly local_only (uploaded version, no claim).
        //    This populates the local-only cache entry. Only local version 13.0.3 is returned.
        var firstResp = await client.GetAsync($"/nuget/registration/{id}/");
        Assert.Equal(HttpStatusCode.OK, firstResp.StatusCode);
        string firstBody = await firstResp.Content.ReadAsStringAsync();
        var firstVersions = ExtractVersionsFromRegistration(firstBody);
        Assert.Contains("13.0.3", firstVersions);

        // 3. Operator adds an explicit mixed claim, enabling upstream merging.
        await _factory.SeedMixedClaim("nuget", id);

        // 4. Second request: now on the proxy-merged path. Must NOT return the stale
        //    local-only bytes. Upstream versions 3.5.8 and 10.0.0 must appear alongside 13.0.3.
        var secondResp = await client.GetAsync($"/nuget/registration/{id}/");
        Assert.Equal(HttpStatusCode.OK, secondResp.StatusCode);
        string secondBody = await secondResp.Content.ReadAsStringAsync();
        var secondVersions = ExtractVersionsFromRegistration(secondBody);

        Assert.Contains("13.0.3", secondVersions);   // local version still present
        Assert.Contains("3.5.8", secondVersions);    // upstream version — missing before fix
        Assert.Contains("10.0.0", secondVersions);   // upstream version — missing before fix
    }

    // Mixed/partial-failure scenario: all 5 registration alias paths must return the
    // merged catalog after a claim change. Before the fix, the shared cache key meant
    // that whichever alias fired first could poison the cache for the others. Verify
    // that sv1 and sv2 paths independently merge upstream without cross-contamination.
    [Theory]
    [InlineData("registration", "registration5-semver1")]
    [InlineData("registration5-gz-semver2", "registration5-gz-semver2")]
    public async Task RegistrationIndex_AllAliases_MergeUpstreamAfterClaimAdded(
        string clientBase, string upstreamVariant)
    {
        string id = $"aliaspois{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "99.0.0");

        string upstreamJson = "{\"count\":1,\"items\":[{\"count\":1,\"items\":["
            + $"{{\"@id\":\"z\",\"catalogEntry\":{{\"id\":\"{id}\",\"version\":\"1.0.0\",\"listed\":true}}}}"
            + "]}]}";
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{upstreamVariant}/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Prime the local-only cache by issuing a first request before the claim is set.
        // For this id+variant the package is implicitly local_only.
        var primeResp = await client.GetAsync($"/nuget/{clientBase}/{id}/");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);
        var primeVersions = ExtractVersionsFromRegistration(await primeResp.Content.ReadAsStringAsync());
        // Upstream 1.0.0 must NOT be present yet (local_only path, no upstream fetch).
        Assert.DoesNotContain("1.0.0", primeVersions);

        // Operator adds the mixed claim.
        await _factory.SeedMixedClaim("nuget", id);

        // Post-claim: the merged response must include both the local and upstream version.
        var mergedResp = await client.GetAsync($"/nuget/{clientBase}/{id}/");
        Assert.Equal(HttpStatusCode.OK, mergedResp.StatusCode);
        var mergedVersions = ExtractVersionsFromRegistration(await mergedResp.Content.ReadAsStringAsync());

        Assert.Contains("99.0.0", mergedVersions);  // local version
        Assert.Contains("1.0.0", mergedVersions);   // upstream version — poisoned before fix
    }

    private static HashSet<string> ExtractVersionsFromRegistration(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("items").EnumerateArray()
            .SelectMany(p => p.GetProperty("items").EnumerateArray())
            .Select(e => e.GetProperty("catalogEntry").GetProperty("version").GetString()!)
            .ToHashSet();
    }

    // ── Flatcontainer download: proxy cache-hit, AnonymousPull disabled → 401 ──

    /// <summary>
    /// Seeds the proxy cache via an authenticated first fetch, then asserts that a subsequent
    /// tokenless GET of the same .nupkg returns 401 with <c>Basic</c> when the org has
    /// <c>AnonymousPull = false</c>. Validates the cache-hit gate mirrors the HEAD behaviour.
    /// </summary>
    [Fact]
    public async Task Flatcontainer_Download_ProxyCacheHit_AnonymousPullOff_NoToken_Returns401()
    {
        string id = $"cahit401{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string file = $"{id}.1.0.0.nupkg";

        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/flatcontainer/{id}/1.0.0/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(nupkgBytes));

        // Prime the proxy cache with an authenticated request.
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBasic(token);
        var primeResp = await authClient.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{file}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // AnonymousPull is false by default; the tokenless cache-hit must return 401.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{file}");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// Confirms that an org with <c>AnonymousPull = true</c> still serves a proxy cache-hit
    /// to unauthenticated clients — no regression for the allowed-anonymous configuration.
    /// </summary>
    [Fact]
    public async Task Flatcontainer_Download_ProxyCacheHit_AnonymousPullOn_NoToken_Returns200()
    {
        string id = $"cahit200{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string file = $"{id}.1.0.0.nupkg";

        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/flatcontainer/{id}/1.0.0/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(nupkgBytes));

        // Prime the proxy cache with an authenticated request.
        string token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBasic(token);
        var primeResp = await authClient.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{file}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        try
        {
            // AnonymousPull enabled: the cache-hit must be served to unauthenticated clients.
            using var anon = _factory.CreateClient();
            var resp = await anon.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{file}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
                new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }

    // ── Hosted nupkg: AnonymousPull gate for uploaded-origin packages ──────────

    /// <summary>
    /// Pushed (uploaded-origin) .nupkg is served to an anonymous client when
    /// <c>AnonymousPull = true</c>. Verifies the hosted flatcontainer download path respects
    /// the org setting.
    /// </summary>
    [Fact]
    public async Task Flatcontainer_Download_HostedUploaded_AnonymousPullOn_NoToken_Returns200()
    {
        string id = $"hostaon{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");
        string file = $"{id}.1.0.0.nupkg";

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId", new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        try
        {
            using var anon = _factory.CreateClient();
            var resp = await anon.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{file}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId", new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }

    /// <summary>
    /// Pushed (uploaded-origin) .nupkg requires auth when <c>AnonymousPull = false</c>.
    /// </summary>
    [Fact]
    public async Task Flatcontainer_Download_HostedUploaded_AnonymousPullOff_NoToken_Returns401()
    {
        string id = $"hostoff{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");
        string file = $"{id}.1.0.0.nupkg";

        // AnonymousPull is false by default.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{file}");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// Pushed (uploaded-origin) .snupkg (symbols) is served anonymously when
    /// <c>AnonymousPull = true</c>. Symbols follow the same gate as the .nupkg.
    /// </summary>
    [Fact]
    public async Task GetSymbols_UploadedOrigin_AnonymousPullOn_NoToken_Returns200()
    {
        string id = $"symaon{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        byte[] snupkg = BuildSnupkg(id, "1.0.0");
        string pushToken = await _factory.CreateToken("push");
        using (var pushClient = _factory.CreateClient())
        {
            pushClient.DefaultRequestHeaders.Add("X-NuGet-ApiKey", pushToken);
            using var pushContent = new MultipartFormDataContent();
            var fc = new ByteArrayContent(snupkg);
            fc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            pushContent.Add(fc, "package", $"{id}.1.0.0.snupkg");
            var pushResp = await pushClient.PutAsync("/nuget/symbols", pushContent);
            Assert.Equal(HttpStatusCode.Created, pushResp.StatusCode);
        }

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")!;
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId", new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);

        string path = $"/nuget/symbols/{id}/1.0.0/{id}.1.0.0.snupkg";
        try
        {
            using var anon = _factory.CreateClient();
            var anonResp = await anon.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, anonResp.StatusCode);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId", new { orgId });
            _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId!);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static string NuspecXml(string id, string version) => $"""
        <?xml version="1.0" encoding="utf-8"?>
        <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
          <metadata>
            <id>{id}</id>
            <version>{version}</version>
            <authors>dependably-test</authors>
            <description>Extended test package</description>
          </metadata>
        </package>
        """;

    private static byte[] BuildZip(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (n, c) in entries)
            {
                var entry = zip.CreateEntry(n);
                using var w = new StreamWriter(entry.Open(), Encoding.UTF8);
                w.Write(c);
            }
        }
        return ms.ToArray();
    }

    private static byte[] BuildSnupkg(string id, string version)
    {
        string nuspec = NuspecXml(id, version);
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var nuspecEntry = zip.CreateEntry($"{id}.nuspec");
            using (var w = new StreamWriter(nuspecEntry.Open(), Encoding.UTF8))
            {
                w.Write(nuspec);
            }

            var pdbEntry = zip.CreateEntry($"lib/netstandard2.0/{id}.pdb");
            using (var w = new StreamWriter(pdbEntry.Open(), Encoding.UTF8))
            {
                w.Write("synthetic pdb bytes");
            }
        }
        return ms.ToArray();
    }
}
