using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the dependency-confusion guard: a hosted name with no explicit
/// claim is implicitly local_only (no upstream merge, no proxy fetch — silent 404 semantics),
/// and operator-reserved namespace patterns shut upstream off for matching names while hosted
/// content keeps serving. Also covers the /api/v1/reserved-namespaces CRUD surface.
/// </summary>
[Trait("Category", "Integration")]
public sealed class DepConfusionGuardTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public DepConfusionGuardTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"dcg-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    private void StubUpstreamPackument(string name, string version)
    {
        string upstreamJson = $$"""
        {
          "_id": "{{name}}",
          "name": "{{name}}",
          "dist-tags": {"latest":"{{version}}"},
          "versions": {
            "{{version}}": {
              "name": "{{name}}",
              "version": "{{version}}",
              "dist": {"tarball":"https://registry.npmjs.org/{{name}}/-/{{name}}-{{version}}.tgz","shasum":"deadbeef"}
            }
          }
        }
        """;
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));
    }

    // ── implicit local_only for hosted names ──────────────────────────────────

    [Fact]
    public async Task HostedName_NoClaim_DoesNotMergeUpstream_AndRefusesProxyFetch()
    {
        // The dependency-confusion hole this guard closes: a HIGHER version published
        // publicly under an internal name must not win resolution or be fetchable.
        string name = $"internal{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "1.0.0");
        StubUpstreamPackument(name, "99.9.9");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var versions = doc.RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty("1.0.0", out _), "hosted version must serve");
        Assert.False(versions.TryGetProperty("99.9.9", out _), "upstream version must not be merged");

        // Proxy fetch of the upstream version: silent 404, same as a local_only claim —
        // not a 403, which would confirm the name's existence to anonymous probes.
        var tarball = await client.GetAsync($"/npm/tarballs/{name}/{name}-99.9.9.tgz");
        Assert.Equal(HttpStatusCode.NotFound, tarball.StatusCode);
    }

    // ── reserved namespaces ───────────────────────────────────────────────────

    [Fact]
    public async Task ReservedPattern_NeverConsultsUpstream_HostedStillServes()
    {
        string stem = $"rsvd{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        using var admin = await AdminClient();
        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "npm", pattern = $"{stem}*" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        // A never-pushed name under the reserved pattern: upstream has it, but the proxy
        // must not even ask — 404 without consulting the (stubbed) upstream.
        string upstreamOnly = $"{stem}-public";
        StubUpstreamPackument(upstreamOnly, "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{upstreamOnly}");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);

        // Hosted content under the reserved pattern serves normally.
        string hosted = $"{stem}-app";
        await _factory.PushNpmPackage(hosted, "2.0.0");
        var hostedResp = await client.GetAsync($"/npm/{hosted}");
        Assert.Equal(HttpStatusCode.OK, hostedResp.StatusCode);
        using var doc = JsonDocument.Parse(await hostedResp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("versions").TryGetProperty("2.0.0", out _));
    }

    // ── reserved namespaces: PyPI JSON API ───────────────────────────────────

    private void StubUpstreamPyPiJson(string path)
    {
        _factory.MockUpstream.Given(
                Request.Create().WithPath(path).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("""{"info":{"name":"x","version":"9.9.9"},"releases":{},"urls":[]}"""));
    }

    private int UpstreamHits(string path) =>
        _factory.MockUpstream.LogEntries.Count(e => e.RequestMessage?.Path == path);

    private async Task ReservePyPi(string pattern)
    {
        using var admin = await AdminClient();
        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "pypi", pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PyPiJsonApi_ReservedName_NeverConsultsUpstream(bool versioned)
    {
        string stem = $"rsvj{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await ReservePyPi($"{stem}-*");

        // The request spelling differs from the reserved pattern (case + underscore); PEP 503
        // normalization must still match it, exactly as the simple index and download paths do.
        string requested = $"{stem.ToUpperInvariant()}_Public";
        string normalized = $"{stem}-public";
        string suffix = versioned ? "/1.0.0/json" : "/json";
        string upstreamPath = $"/pypi/{normalized}{suffix}";
        StubUpstreamPyPiJson(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{requested}{suffix}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, UpstreamHits(upstreamPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PyPiJsonApi_UnreservedTwin_ProxiesUpstreamOnce(bool versioned)
    {
        string stem = $"rsvj{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await ReservePyPi($"{stem}-*");

        // Same stem, but outside the reserved pattern (no dash after the stem).
        string name = $"{stem}public";
        string suffix = versioned ? "/1.0.0/json" : "/json";
        string upstreamPath = $"/pypi/{name}{suffix}";
        StubUpstreamPyPiJson(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}{suffix}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(1, UpstreamHits(upstreamPath));
    }

    [Fact]
    public async Task PyPiJsonApi_ReservedName_HostedVersionsStillServe()
    {
        string stem = $"rsvj{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await ReservePyPi($"{stem}-*");

        string hosted = $"{stem}-app";
        await _factory.PushPyPiPackage(hosted, "2.0.0");
        string upstreamPath = $"/pypi/{hosted}/json";
        StubUpstreamPyPiJson(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/pypi/{hosted}/json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("2.0.0", doc.RootElement.GetProperty("info").GetProperty("version").GetString());
        Assert.True(doc.RootElement.GetProperty("releases").TryGetProperty("2.0.0", out _));

        var versioned = await client.GetAsync($"/pypi/{hosted}/2.0.0/json");
        Assert.Equal(HttpStatusCode.OK, versioned.StatusCode);

        Assert.Equal(0, UpstreamHits(upstreamPath));
    }

    // ── reserved namespaces: Go checksum-database lookup ─────────────────────

    // The test host points Go:SumDb at the WireMock root, so the configured sumdb name is the
    // mock's host and /go/sumdb/{name}/{path} proxies to {mock}/{path}.
    private string SumDbName => new Uri(_factory.MockUpstream.Urls[0]).Host;

    private const string SumDbBody = "sumdb-record\n";

    // WireMock form-decodes '+' to a space in the request path it matches on, though the request
    // on the wire carries '+' (as in a +incompatible version), so the stub names the decoded form.
    private void StubSumDb(string path)
    {
        _factory.MockUpstream.Given(
                Request.Create().WithPath(path.Replace('+', ' ')).UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain; charset=utf-8")
                .WithBody(SumDbBody));
    }

    // Paths are read from the raw request URL rather than WireMock's decoded Path, so '+' is
    // compared as sent.
    private IEnumerable<string> SumDbRequestPaths() =>
        _factory.MockUpstream.LogEntries
            .Select(e => e.RequestMessage?.Url)
            .OfType<string>()
            .Select(u => new Uri(u).AbsolutePath);

    // Every request upstream saw whose path names the fragment, under any route, so a reserved
    // name reaching upstream through some rewritten path still counts.
    private int SumDbHits(string fragment) =>
        SumDbRequestPaths().Count(p => p.Contains(fragment, StringComparison.Ordinal));

    private int SumDbPathHits(string path) =>
        SumDbRequestPaths().Count(p => p == path);

    private async Task<string> ReserveGo(string pattern)
    {
        using var admin = await AdminClient();
        var add = await admin.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "golang", pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        using var doc = JsonDocument.Parse(await add.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetString()!;
    }

    private static string GoStem() => $"corp{Guid.NewGuid():N}"[..16] + ".example";

    // {0} is a per-test host stem, so neither reservations nor the shared metadata cache carry
    // over between cases. Each pair is (reserved pattern, lookup path after lookup/).
    [Theory]
    // Plain prefix reservation.
    [InlineData("{0}/internal/*", "{0}/internal/tool@v1.0.0")]
    // Bang-encoded request against a pattern written in the decoded, case-significant form:
    // the decode has to run before the match.
    [InlineData("{0}/internal/Tool", "{0}/internal/!tool@v1.0.0")]
    [InlineData("{0}/BurntSushi", "{0}/!burnt!sushi/toml@v1.0.0")]
    // +incompatible is part of the version, after the only '@'.
    [InlineData("{0}/internal/*", "{0}/internal/tool@v2.0.0+incompatible")]
    // A second '@' leaves the module part holding '@', which no module path contains: refused
    // rather than matched as "tool@x" against an exact reservation it would slip past.
    [InlineData("{0}/internal/tool", "{0}/internal/tool@x@v1.0.0")]
    public async Task GoSumDbLookup_ReservedModule_Returns404_AndNeverConsultsUpstream(
        string patternTemplate, string lookupTemplate)
    {
        string stem = GoStem();
        await ReserveGo(string.Format(patternTemplate, stem));
        string upstreamPath = "/lookup/" + string.Format(lookupTemplate, stem);
        StubSumDb(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}{upstreamPath}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.DoesNotContain(SumDbBody, await resp.Content.ReadAsStringAsync());
        Assert.Equal(0, SumDbHits(stem));
    }

    // The literal case named for the check: github.com/!burnt!sushi decodes to
    // github.com/BurntSushi, which is reserved. Its unreserved twin (all lowercase, so it encodes
    // without '!') is a different module and still proxies.
    [Fact]
    public async Task GoSumDbLookup_BangEncodedGitHubPath_ReservedRefused_LowercaseTwinProxied()
    {
        await ReserveGo("github.com/BurntSushi");
        const string reservedPath = "/lookup/github.com/!burnt!sushi/toml@v1.0.0";
        const string twinPath = "/lookup/github.com/burntsushi/toml@v1.0.0";
        StubSumDb(reservedPath);
        StubSumDb(twinPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var reserved = await client.GetAsync($"/go/sumdb/{SumDbName}{reservedPath}");
        Assert.Equal(HttpStatusCode.NotFound, reserved.StatusCode);
        Assert.Equal(0, SumDbHits("!burnt!sushi"));

        var twin = await client.GetAsync($"/go/sumdb/{SumDbName}{twinPath}");
        Assert.Equal(HttpStatusCode.OK, twin.StatusCode);
        Assert.Equal(SumDbBody, await twin.Content.ReadAsStringAsync());
        Assert.Equal(1, SumDbPathHits(twinPath));
    }

    // Unreserved lookups are unchanged: proxied verbatim, exactly once.
    [Theory]
    // Shares the reserved prefix but not its '/' boundary.
    [InlineData("{0}/internalx/tool@v1.0.0")]
    // A module outside the reservation, with a +incompatible version.
    [InlineData("{0}/public/tool@v2.0.0+incompatible")]
    // Bang-encoded but outside the reservation.
    [InlineData("{0}/public/!tool@v1.0.0")]
    public async Task GoSumDbLookup_UnreservedTwin_ProxiesUpstreamOnce(string lookupTemplate)
    {
        string stem = GoStem();
        await ReserveGo($"{stem}/internal/*");
        string upstreamPath = "/lookup/" + string.Format(lookupTemplate, stem);
        StubSumDb(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}{upstreamPath}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(SumDbBody, await resp.Content.ReadAsStringAsync());
        Assert.Equal(1, SumDbPathHits(upstreamPath));
    }

    // A '!' that is not valid bang-encoding names no module the reservation check can match, so
    // the lookup fails closed even with no reservation covering it.
    [Theory]
    [InlineData("{0}/!!tool@v1.0.0")]
    [InlineData("{0}/!Tool@v1.0.0")]
    [InlineData("{0}/!1tool@v1.0.0")]
    [InlineData("{0}/tool!@v1.0.0")]
    public async Task GoSumDbLookup_InvalidBangEscape_Returns404_AndNeverConsultsUpstream(string lookupTemplate)
    {
        string stem = GoStem();
        string upstreamPath = "/lookup/" + string.Format(lookupTemplate, stem);
        StubSumDb(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}{upstreamPath}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, SumDbHits(stem));
    }

    // The org without the reservation reaches upstream: removing the reservation lets the same
    // lookup through on the next request. That it reaches upstream exactly once also shows the
    // refused request left nothing in the metadata cache to answer from.
    [Fact]
    public async Task GoSumDbLookup_Unreserving_RestoresUpstream_AndRefusalCachedNothing()
    {
        string stem = GoStem();
        string id = await ReserveGo($"{stem}/internal/*");
        string upstreamPath = $"/lookup/{stem}/internal/tool@v1.0.0";
        StubSumDb(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var refused = await client.GetAsync($"/go/sumdb/{SumDbName}{upstreamPath}");
        Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);
        Assert.Equal(0, SumDbHits(stem));

        using (var admin = await AdminClient())
        {
            var remove = await admin.DeleteAsync($"/api/v1/reserved-namespaces/{id}");
            Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);
        }

        var proxied = await client.GetAsync($"/go/sumdb/{SumDbName}{upstreamPath}");
        Assert.Equal(HttpStatusCode.OK, proxied.StatusCode);
        Assert.Equal(SumDbBody, await proxied.Content.ReadAsStringAsync());
        Assert.Equal(1, SumDbPathHits(upstreamPath));
    }

    // ── dot segments ahead of the reservation check ──────────────────────────

    // HttpClient and the TestServer request translation both collapse '.' segments before the
    // app sees them, so a raw path is set on the request directly. The app then composes it into
    // an upstream URL, and Uri collapses it there instead: a check run on the uncollapsed name
    // would decide about a different module than the one upstream is asked for.
    private async Task<int> SendRawPathAsync(string rawPath, string token)
    {
        var ctx = await _factory.Server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = new PathString(rawPath);
            c.Request.Headers.Authorization = $"Bearer {token}";
        });
        return ctx.Response.StatusCode;
    }

    // Each template is a request path; {0} is the per-test host stem, {1} the sumdb name. The
    // exact reservation {0}/acme/x matches the collapsed name but not the uncollapsed one.
    [Theory]
    [InlineData("/go/sumdb/{1}/./lookup/{0}/acme/x@v1.0.0")]
    [InlineData("/go/sumdb/{1}/lookup/{0}/acme/./x@v1.0.0")]
    [InlineData("/go/{0}/acme/./x/@v/v1.0.0.info")]
    [InlineData("/go/{0}/acme/./x/@v/v1.0.0.mod")]
    [InlineData("/go/{0}/acme/./x/@v/v1.0.0.zip")]
    [InlineData("/go/{0}/acme/./x/@latest")]
    [InlineData("/go/{0}/acme/./x/@v/list")]
    public async Task GoRoutes_DotSegmentAroundReservedModule_Returns400_AndNeverConsultsUpstream(string template)
    {
        string stem = GoStem();
        await ReserveGo($"{stem}/acme/x");
        string token = await _factory.CreateToken("pull");

        int status = await SendRawPathAsync(string.Format(template, stem, SumDbName), token);

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Equal(0, SumDbHits(stem));
    }

    // The twin that shows the raw-path request reaches the handler intact: the same lookup with
    // no '.' segment and no reservation is proxied once.
    [Fact]
    public async Task GoSumDbLookup_RawPathWithoutDotSegment_Unreserved_ProxiesOnce()
    {
        string stem = GoStem();
        string upstreamPath = $"/lookup/{stem}/acme/x@v1.0.0";
        StubSumDb(upstreamPath);
        string token = await _factory.CreateToken("pull");

        int status = await SendRawPathAsync($"/go/sumdb/{SumDbName}{upstreamPath}", token);

        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal(1, SumDbPathHits(upstreamPath));
    }

    // latest and tile paths carry no module name, so a reservation does not touch them. Only this
    // test requests these paths on this fixture, so the metadata cache holds nothing for them.
    [Fact]
    public async Task GoSumDbTileAndLatest_UnderReservation_StillProxy()
    {
        string stem = GoStem();
        await ReserveGo($"{stem}/internal/*");
        const string tilePath = "/tile/8/0/x001/234";
        StubSumDb(tilePath);
        StubSumDb("/latest");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var tile = await client.GetAsync($"/go/sumdb/{SumDbName}{tilePath}");
        Assert.Equal(HttpStatusCode.OK, tile.StatusCode);
        Assert.Equal(SumDbBody, await tile.Content.ReadAsStringAsync());
        Assert.Equal(1, SumDbPathHits(tilePath));

        var latest = await client.GetAsync($"/go/sumdb/{SumDbName}/latest");
        Assert.Equal(HttpStatusCode.OK, latest.StatusCode);
        Assert.Equal(SumDbBody, await latest.Content.ReadAsStringAsync());
        Assert.Equal(1, SumDbPathHits("/latest"));
    }

    // ── sumdb path allowlist ─────────────────────────────────────────────────

    // Paths the Go client never sends, each carrying a reserved module name. Only supported,
    // lookup/{module}@{version}, latest and canonical tile paths are forwarded; the reservation
    // check reads a module name only out of a lookup, so any other shape must not reach upstream.
    // {0} is the per-test host stem; the reservation is {0}/internal/*.
    [Theory]
    [InlineData("/lookupx/{0}/internal/tool@v1.0.0")]
    [InlineData("/foo/{0}/internal/tool")]
    [InlineData("/{0}/internal/tool@v1.0.0")]
    [InlineData("/latest/{0}/internal/tool")]
    [InlineData("/tile/8/0/{0}/internal/tool")]
    [InlineData("/tile/8/data/{0}/internal/tool@v1.0.0")]
    [InlineData("/Lookup/{0}/internal/tool@v1.0.0")]
    [InlineData("/lookup/{0}/internal/tool@latest")]
    public async Task GoSumDbUnknownPath_NamingReservedModule_Returns404_AndNeverConsultsUpstream(string template)
    {
        string stem = GoStem();
        await ReserveGo($"{stem}/internal/*");
        string upstreamPath = string.Format(template, stem);
        StubSumDb(upstreamPath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}{upstreamPath}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.DoesNotContain(SumDbBody, await resp.Content.ReadAsStringAsync());
        Assert.Equal(0, SumDbHits(stem));
    }

    // Tile paths outside the canonical form golang.org/x/mod/sumdb/tlog.ParseTilePath accepts are
    // refused, reservation or not. Each path is requested only here, so a zero count is not a
    // cache artefact.
    [Theory]
    [InlineData("/tile/8/0/x01/911")]          // index group not three digits
    [InlineData("/tile/8/0/1911")]             // last group four digits
    [InlineData("/tile/8/0/x000/912")]         // leading zero group
    [InlineData("/tile/8/0/913/x001")]         // x on the last group
    [InlineData("/tile/8/0/x001/914/x002")]    // x missing on a middle group
    [InlineData("/tile/0/0/915")]              // height below 1
    [InlineData("/tile/31/0/916")]             // height above 30
    [InlineData("/tile/08/0/917")]             // height with a leading zero
    [InlineData("/tile/8/00/918")]             // level with a leading zero
    [InlineData("/tile/8/64/919")]             // level deeper than an int64 tree
    [InlineData("/tile/8/Data/920")]           // data is case-sensitive
    [InlineData("/tile/8/0/921.p/256")]        // partial width equal to 2^H
    [InlineData("/tile/8/0/922.p/0")]          // partial width zero
    [InlineData("/tile/8/0/923.p/07")]         // partial width with a leading zero
    [InlineData("/tile/8/0/924.p")]            // partial marker with no width
    [InlineData("/tile/8/0")]                  // no index
    [InlineData("/tile/8/0/abc")]              // index not a number
    [InlineData("/tile/8/0/x001/x002/x003/x004/x005/x006/x007/925")] // more groups than an int64 index
    public async Task GoSumDbMalformedTile_Returns404_AndNeverConsultsUpstream(string tilePath)
    {
        StubSumDb(tilePath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}{tilePath}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, SumDbPathHits(tilePath));
    }

    // Every canonical tile shape the Go client requests still forwards under a reservation:
    // hash tiles at several levels, a partial tile, and data tiles, full and partial.
    [Theory]
    [InlineData("/tile/8/1/931")]
    [InlineData("/tile/8/2/x002/x000/932")]
    [InlineData("/tile/8/0/x003/933.p/7")]
    [InlineData("/tile/8/data/x004/934")]
    [InlineData("/tile/8/data/935.p/255")]
    [InlineData("/tile/30/63/936")]
    public async Task GoSumDbCanonicalTile_UnderReservation_ProxiesOnce(string tilePath)
    {
        string stem = GoStem();
        await ReserveGo($"{stem}/internal/*");
        StubSumDb(tilePath);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}{tilePath}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(SumDbBody, await resp.Content.ReadAsStringAsync());
        Assert.Equal(1, SumDbPathHits(tilePath));
    }

    // The supported probe stays a local answer: 200 under a reservation, no upstream request.
    [Fact]
    public async Task GoSumDbSupported_UnderReservation_Returns200_WithoutUpstream()
    {
        string stem = GoStem();
        await ReserveGo($"{stem}/internal/*");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}/supported");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, SumDbPathHits("/supported"));
    }

    // The sumdb name in the path selects nothing: only the configured Go:SumDb is proxied, and
    // the upstream host comes from configuration. A request naming any other host, including the
    // configured host with a port or as a subdomain, answers 404 on every allowed shape without
    // an upstream request. {0} is the configured name, {1} the per-test stem.
    [Theory]
    [InlineData("evil.example.com", "/lookup/{1}/public/tool@v1.0.0")]
    [InlineData("{0}:1", "/lookup/{1}/public/tool@v1.0.0")]
    [InlineData("{0}.evil.example.com", "/lookup/{1}/public/tool@v1.0.0")]
    [InlineData("evil.example.com", "/tile/8/0/{1}")]
    [InlineData("evil.example.com", "/latest")]
    [InlineData("evil.example.com", "/supported")]
    public async Task GoSumDbOtherHost_Returns404_AndNeverConsultsUpstream(string hostTemplate, string pathTemplate)
    {
        string stem = GoStem();
        string host = string.Format(hostTemplate, SumDbName);
        int before = SumDbRequestPaths().Count();

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/go/sumdb/{host}{string.Format(pathTemplate, SumDbName, stem)}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, SumDbHits(stem));
        Assert.Equal(0, SumDbHits(host));
        Assert.Equal(before, SumDbRequestPaths().Count());
    }

    // ── CRUD surface ──────────────────────────────────────────────────────────

    [Fact]
    public async Task ReservedNamespaces_AddListDelete_RoundTrip()
    {
        using var c = await AdminClient();
        string pattern = $"@crud{Guid.NewGuid():N}/*";

        var add = await c.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "npm", pattern });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        var created = await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync());
        string? id = created.RootElement.GetProperty("id").GetString();
        Assert.False(string.IsNullOrEmpty(id));

        var list = await c.GetAsync("/api/v1/reserved-namespaces");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.Contains(items.EnumerateArray(), e => e.GetProperty("pattern").GetString() == pattern);

        var remove = await c.DeleteAsync($"/api/v1/reserved-namespaces/{id}");
        Assert.Equal(HttpStatusCode.NoContent, remove.StatusCode);

        // Idempotent delete (unknown id) — same shape as the allowlist surface.
        var again = await c.DeleteAsync($"/api/v1/reserved-namespaces/{id}");
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
    }

    [Theory]
    [InlineData("docker", "lib*")]   // unsupported ecosystem
    [InlineData("npm", "")]          // empty pattern
    [InlineData("npm", "a*b")]       // non-trailing glob
    public async Task ReservedNamespaces_InvalidInput_Returns422(string ecosystem, string pattern)
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/reserved-namespaces", new { ecosystem, pattern });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Theory]
    [InlineData("cargo", "serde-*")]              // flat crate-name prefix
    [InlineData("golang", "github.com/acme/*")]   // module-path prefix
    [InlineData("apk", "acme-*")]                 // flat package-name prefix
    public async Task ReservedNamespaces_AcceptsCargoAndGo(string ecosystem, string pattern)
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/reserved-namespaces", new { ecosystem, pattern });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
    }

    [Fact]
    public async Task ReservedNamespaces_AddByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/reserved-namespaces",
            new { ecosystem = "npm", pattern = "@nope/*" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }
}
