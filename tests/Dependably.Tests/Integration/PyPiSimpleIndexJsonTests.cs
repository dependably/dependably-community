using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression coverage for PEP 691 JSON Simple API content negotiation on
/// <c>/simple/</c> and <c>/simple/{package}/</c>. Both routes once served PEP 503 HTML
/// unconditionally regardless of the request's Accept header — a client that requires the JSON
/// form (per PEP 691) had no way to get it. The response representation is negotiated from the
/// Accept header, defaulting to HTML when JSON isn't explicitly preferred.
///
/// The JSON form is the path modern pip (>=22.3) and uv take, so it must be a first-class
/// citizen of the serving path rather than a bypass: it is cached under its own
/// representation-keyed entry (proven here by a two-request/one-upstream-fetch assertion), it
/// never collides with the HTML entry for the same URL, and every negotiated response carries
/// <c>Vary: Accept</c> so per-URL HTTP caches key on the representation too.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiSimpleIndexJsonTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PyPiSimpleIndexJsonTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string> DefaultOrgId()
    {
        _factory.CreateClient().Dispose(); // ensure first-boot ran
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetProxyPassthrough(bool enabled)
    {
        string orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task EvictBothRepresentations(string name)
    {
        var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
        string orgId = await DefaultOrgId();
        cache.Evict(new PyPiSimpleIndexKey(orgId, name));
        cache.Evict(new PyPiSimpleIndexKey(orgId, name) { WantsJson = true });
    }

    private async Task BlockVersion(string name, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE package_versions SET manual_block_state = 'blocked'
            WHERE id = (
                SELECT pv.id FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.name = @name AND pv.version = @version LIMIT 1)
            """,
            new { name, version });
    }

    // Stubs an upstream simple index with no file anchors, so the merged index is driven purely
    // by the local plane while the proxy path is still genuinely exercised.
    private void StubEmptyUpstreamIndex(string name) =>
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody("<html><body></body></html>"));

    private static async Task AssertJsonRepresentation(HttpClient client, string name)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/simple/{name}/");
        req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(PyPiSimpleIndexHelper.JsonContentType));
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(PyPiSimpleIndexHelper.JsonContentType, resp.Content.Headers.ContentType?.MediaType);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body); // an HTML body cached under a shared key would throw
        Assert.Equal(name, doc.RootElement.GetProperty("name").GetString());
    }

    private static async Task AssertHtmlRepresentation(HttpClient client, string name)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/simple/{name}/");
        req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("text/html"));
        var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.StartsWith("<!DOCTYPE html>", body.TrimStart()); // a JSON body would fail here
    }

    // The filenames listed by a PEP 691 per-package index document.
    private static List<string?> FileNames(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("files").EnumerateArray()
            .Select(f => f.GetProperty("filename").GetString())
            .ToList();
    }

    private int UpstreamCalls(string path) =>
        _factory.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));

    // ── GET /simple/ — root project list negotiation ──────────────────────────

    [Fact]
    public async Task RootIndex_JsonAccept_ReturnsPep691ProjectList()
    {
        string name = $"jsonroot{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        client.DefaultRequestHeaders.Accept.Clear();
        client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue(PyPiSimpleIndexHelper.JsonContentType));

        var resp = await client.GetAsync("/simple/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(PyPiSimpleIndexHelper.JsonContentType, resp.Content.Headers.ContentType?.MediaType);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("1.0", doc.RootElement.GetProperty("meta").GetProperty("api-version").GetString());
        var names = doc.RootElement.GetProperty("projects").EnumerateArray()
            .Select(p => p.GetProperty("name").GetString())
            .ToList();
        Assert.Contains(name, names);
    }

    [Fact]
    public async Task RootIndex_NoAcceptHeader_StillReturnsHtml()
    {
        // No Accept header at all — the default (back-compat) representation stays HTML.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        client.DefaultRequestHeaders.Accept.Clear();

        var resp = await client.GetAsync("/simple/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
    }

    // ── GET /simple/{package}/ — per-package negotiation + block-gate parity ──

    /// <summary>
    /// Mirrors the pip/uv real-world Accept header
    /// (<c>application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1,
    /// text/html;q=0.01</c>): JSON must win the negotiation. Also a partial-failure (mixed)
    /// scenario — one version manually blocked, the other not — proving the JSON form shares
    /// the same block-gate filter as the HTML form so a client negotiating JSON can never
    /// discover an artifact the download gate would deny with 403.
    /// </summary>
    [Fact]
    public async Task PackageIndex_JsonAccept_ReturnsFilesWithHashesAndHonoursBlockGate()
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"jsonpkg{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");
            await _factory.PushPyPiPackage(name, "2.0.0");

            string underscored = name.Replace('-', '_');
            string blockedFile = $"{underscored}-1.0.0-py3-none-any.whl";
            string allowedFile = $"{underscored}-2.0.0-py3-none-any.whl";

            var store = _factory.Services.GetRequiredService<IMetadataStore>();
            await using (var conn = await store.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    UPDATE package_versions SET manual_block_state = 'blocked'
                    WHERE id = (
                        SELECT pv.id FROM package_versions pv
                        JOIN packages p ON p.id = pv.package_id
                        WHERE p.name = @name AND pv.version = '1.0.0' LIMIT 1)
                    """,
                    new { name });
            }

            // A manual block is not a publish, so nothing evicts the rendered index — drop both
            // negotiated representations so neither serves a stale pre-block entry.
            var cache = _factory.Services.GetRequiredService<RenderedResponseCache<PyPiSimpleIndexKey>>();
            var orgs = _factory.Services.GetRequiredService<OrgRepository>();
            string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
            cache.Evict(new PyPiSimpleIndexKey(orgId, name));
            cache.Evict(new PyPiSimpleIndexKey(orgId, name) { WantsJson = true });

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(PyPiSimpleIndexHelper.JsonContentType));
            client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("application/vnd.pypi.simple.v1+html;q=0.1"));
            client.DefaultRequestHeaders.Accept.Add(MediaTypeWithQualityHeaderValue.Parse("text/html;q=0.01"));

            var resp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal(PyPiSimpleIndexHelper.JsonContentType, resp.Content.Headers.ContentType?.MediaType);

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            Assert.Equal(name, doc.RootElement.GetProperty("name").GetString());
            var files = doc.RootElement.GetProperty("files").EnumerateArray().ToList();
            var filenames = files.Select(f => f.GetProperty("filename").GetString()).ToList();

            Assert.DoesNotContain(blockedFile, filenames);   // blocked version absent (partial-failure: still filtered)
            Assert.Contains(allowedFile, filenames);          // non-blocked version present

            var allowedEntry = files.Single(f => f.GetProperty("filename").GetString() == allowedFile);
            Assert.Equal($"/packages/{allowedFile}", allowedEntry.GetProperty("url").GetString());
            Assert.True(allowedEntry.GetProperty("hashes").TryGetProperty("sha256", out _));
            Assert.False(allowedEntry.GetProperty("yanked").GetBoolean());

            // The download gate is unchanged: the blocked file still 403s.
            var dlResp = await client.GetAsync($"/packages/{blockedFile}");
            Assert.Equal(HttpStatusCode.Forbidden, dlResp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    // ── GET /simple/{package}/ — proxy-enabled JSON (the path modern pip actually takes) ──

    /// <summary>
    /// The JSON representation must be served from the shared rendered-response cache exactly as
    /// the HTML one is. This is the dominant client's path — pip >=22.3 and uv send the PEP 691
    /// media type at q=1 — and an uncached JSON path performs a live upstream fetch on every
    /// <c>/simple/{pkg}/</c> resolve, because the UpstreamClient metadata TTL cache is disabled by
    /// default on a non-edge instance (<c>MetadataCacheOptions</c> positive TTL 0). Two identical
    /// requests must therefore fetch upstream exactly once; single-flight alone does not collapse
    /// sequential requests.
    ///
    /// Mixed by construction: the merged index draws from both planes (an upstream-only file and a
    /// locally-published file) while a third, manually-blocked local version must stay filtered —
    /// so caching is proven on a body that a partial block-gate failure contributes to.
    /// </summary>
    [Fact]
    public async Task PackageIndex_JsonAccept_ProxyEnabled_MergedIndexIsCached_UpstreamFetchedOnce()
    {
        await SetProxyPassthrough(true);
        string name = $"jsonprx{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string upstreamFile = $"{underscored}-9.0.0-py3-none-any.whl";
        string allowedFile = $"{underscored}-1.0.0-py3-none-any.whl";
        string blockedFile = $"{underscored}-2.0.0-py3-none-any.whl";
        string mockBase = _factory.MockUpstream.Urls[0];
        string upstreamSha = new('a', 64);

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{upstreamFile}#sha256={upstreamSha}\">{upstreamFile}</a></body></html>"));

        // Local publishes for the same name — the merged index must carry both planes. A hosted
        // name is implicitly local_only, so the mixed claim is what opts it into upstream merging.
        await _factory.PushPyPiPackage(name, "1.0.0");
        await _factory.PushPyPiPackage(name, "2.0.0");
        await BlockVersion(name, "2.0.0");
        await _factory.SeedMixedClaim("pypi", name);
        await EvictBothRepresentations(name);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        client.DefaultRequestHeaders.Accept.Clear();
        client.DefaultRequestHeaders.Accept.Add(
            MediaTypeWithQualityHeaderValue.Parse(PyPiSimpleIndexHelper.JsonContentType));

        int before = UpstreamCalls($"/simple/{name}/");

        var first = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(PyPiSimpleIndexHelper.JsonContentType, first.Content.Headers.ContentType?.MediaType);
        var firstNames = FileNames(await first.Content.ReadAsStringAsync());
        Assert.Contains(upstreamFile, firstNames);        // upstream plane
        Assert.Contains(allowedFile, firstNames);         // local plane
        Assert.DoesNotContain(blockedFile, firstNames);   // blocked local version stays filtered

        var second = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(PyPiSimpleIndexHelper.JsonContentType, second.Content.Headers.ContentType?.MediaType);
        Assert.Equal(firstNames, FileNames(await second.Content.ReadAsStringAsync()));

        // The regression pin: two JSON requests, one upstream fetch. Before the fix the JSON
        // path bypassed the byte cache and this was 2 — a live upstream hit per resolve.
        Assert.Equal(1, UpstreamCalls($"/simple/{name}/") - before);
    }

    /// <summary>
    /// One URL, two representations: whichever is cached first must never be served to a client
    /// negotiating the other. Exercised in both orders (JSON-then-HTML and HTML-then-JSON) so a
    /// cache key that ignored the representation would fail whichever way it collided.
    /// </summary>
    [Fact]
    public async Task PackageIndex_JsonAndHtml_ShareUrlButNotCacheEntry()
    {
        await SetProxyPassthrough(true);
        string jsonFirst = $"jsonfrst{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string htmlFirst = $"htmlfrst{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        foreach (string name in new[] { jsonFirst, htmlFirst })
        {
            StubEmptyUpstreamIndex(name);
            await _factory.PushPyPiPackage(name, "1.0.0");
            await _factory.SeedMixedClaim("pypi", name); // opt the hosted name into the proxy path
        }

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // JSON first, then HTML for the same URL.
        await AssertJsonRepresentation(client, jsonFirst);
        await AssertHtmlRepresentation(client, jsonFirst);

        // HTML first, then JSON for the same URL.
        await AssertHtmlRepresentation(client, htmlFirst);
        await AssertJsonRepresentation(client, htmlFirst);
    }

    /// <summary>
    /// Upstream unreachable on a proxy-enabled org: the JSON path must fall back to the local
    /// versions it already has, not 404 the client out of a package it can serve.
    /// </summary>
    [Fact]
    public async Task PackageIndex_JsonAccept_ProxyEnabled_UpstreamDown_FallsBackToLocalJson()
    {
        await SetProxyPassthrough(true);
        string name = $"jsondown{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        string localFile = $"{name.Replace('-', '_')}-1.0.0-py3-none-any.whl";

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        await _factory.PushPyPiPackage(name, "1.0.0");
        await _factory.SeedMixedClaim("pypi", name); // opt the hosted name into the proxy path

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        client.DefaultRequestHeaders.Accept.Clear();
        client.DefaultRequestHeaders.Accept.Add(
            MediaTypeWithQualityHeaderValue.Parse(PyPiSimpleIndexHelper.JsonContentType));

        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(PyPiSimpleIndexHelper.JsonContentType, resp.Content.Headers.ContentType?.MediaType);
        Assert.Contains(localFile, FileNames(await resp.Content.ReadAsStringAsync()));
        Assert.True(UpstreamCalls($"/simple/{name}/") > 0, "the proxy path must genuinely be exercised");
    }

    /// <summary>
    /// The same URL serves two representations under an ETag and Cache-Control, so every
    /// negotiated response must carry Vary: Accept — without it a per-URL HTTP cache (pip's own
    /// cache, an intermediary proxy, a CDN) can hand a JSON client a stored HTML body.
    /// </summary>
    [Fact]
    public async Task SimpleIndexRoutes_NegotiatedResponses_CarryVaryAccept()
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"jsonvary{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            foreach (string accept in new[] { PyPiSimpleIndexHelper.JsonContentType, "text/html" })
            {
                foreach (string path in new[] { "/simple/", $"/simple/{name}/" })
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, path);
                    req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(accept));
                    var resp = await client.SendAsync(req);

                    Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
                    Assert.Contains("Accept", resp.Headers.Vary, StringComparer.OrdinalIgnoreCase);
                }
            }
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    /// <summary>
    /// A client that expresses no preference between the two representations must receive the
    /// PEP 503 HTML one. A bare <c>*/*</c> is what requests-default scrapers and generic HTTP
    /// clients send; answering them with PEP 691 JSON would swap the representation under
    /// clients that only parse HTML. JSON is served only when explicitly preferred, which is
    /// exactly what the negotiator documents.
    /// </summary>
    [Theory]
    [InlineData("*/*")]                 // generic client, no preference — must not get JSON
    [InlineData("text/html, */*")]      // HTML plus a catch-all
    [InlineData("text/*")]              // any text type
    public async Task PackageIndex_NoRepresentationPreference_ReturnsHtml(string accept)
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"jsonwild{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            using var req = new HttpRequestMessage(HttpMethod.Get, $"/simple/{name}/");
            foreach (string entry in accept.Split(','))
            {
                req.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(entry.Trim()));
            }

            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task PackageIndex_HtmlOnlyAccept_StillReturnsHtml()
    {
        await SetProxyPassthrough(false);
        try
        {
            string name = $"jsonhtml{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));

            var resp = await client.GetAsync($"/simple/{name}/");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }
}
