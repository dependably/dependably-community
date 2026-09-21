using System.Net;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// What an OCI manifest 404 tells the caller, and what it refuses to tell them.
///
/// <para>
/// Two unrelated faults arrive at the same place — no upstream in this org claims the
/// repository name, and an upstream claimed it and answered 404 — and they have different
/// owners: the first is an operator's routing gap, the second a wrong name or tag. A 404 that
/// cannot separate them leaves the caller with nothing to do but repeat the request, which is
/// how a mistyped registry path turns into a debugging session. So each fault is asserted to
/// carry its own marker AND to lack the other's; a message that named both, or a constant that
/// named neither, would pass a one-sided assertion.
/// </para>
///
/// <para>
/// The disclosure half is the same assertion run twice against one instance: anonymous must not
/// learn the org's upstream host, authenticated must. Asserting only the absence would pass on
/// an instance where the host never appears at all — a test that cannot fail. The pair is what
/// makes it mean anything.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciManifestUnknownDiagnosticTests
{
    // A host that appears nowhere in the seeded defaults, so finding it in a response body can
    // only mean this org's configured routing leaked into it.
    private const string PrivateUpstreamHost = "mirror.internal.example";

    private const string TwoSegmentRepo = "unsloth/unsloth";
    private const string SingleSegmentRepo = "alpine";

    /// <summary>An upstream that claims everything and has nothing.</summary>
    private static DependablyFactory NotFoundUpstreamFactory() => new()
    {
        OciUpstreamHandler = _ => new HttpResponseMessage(HttpStatusCode.NotFound),
    };

    [Fact]
    public async Task UpstreamAsked_AndMissed_NamesThatUpstream_AndNotTheRoutingGap()
    {
        await using var factory = NotFoundUpstreamFactory();
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost, prefix: "");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        string message = await ReadMessageAsync(resp);

        Assert.Contains(PrivateUpstreamHost, message, StringComparison.Ordinal);
        Assert.Equal("upstream_miss", await ReadFaultAsync(resp));

        // The other fault's marker must be absent — otherwise a message naming both faults, or
        // one constant carrying every hint, satisfies this test without distinguishing anything.
        Assert.DoesNotContain("No upstream registry", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoUpstreamClaimsTheName_SaysSo_AndNamesNoUpstream()
    {
        await using var factory = NotFoundUpstreamFactory();
        await factory.InitializeAsync();

        // The only route claims a prefix the requested repository does not start with, so
        // routing declines before any upstream is contacted.
        await RouteAllToAsync(factory, PrivateUpstreamHost, prefix: "dotnet/");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        string message = await ReadMessageAsync(resp);

        Assert.Contains("No upstream registry", message, StringComparison.Ordinal);
        Assert.Equal("no_upstream_route", await ReadFaultAsync(resp));

        // Nothing was asked, so nothing may be named as having been asked.
        Assert.DoesNotContain(PrivateUpstreamHost, message, StringComparison.Ordinal);
    }

    /// <summary>
    /// HEAD and GET take separate paths to the same 404 (HEAD never downloads a body), and a fix
    /// applied to one is invisible from the other.
    /// </summary>
    [Fact]
    public async Task Head_CarriesTheSameDiagnosisAsGet()
    {
        await using var factory = NotFoundUpstreamFactory();
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost, prefix: "");

        string token = await factory.CreateToken("pull");
        using var client = factory.CreateClientWithBearer(token);

        using var req = new HttpRequestMessage(HttpMethod.Head, $"/v2/{TwoSegmentRepo}/manifests/v1");
        var head = await client.SendAsync(req);
        var get = await client.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1");

        Assert.Equal(HttpStatusCode.NotFound, head.StatusCode);
        Assert.Equal(await ReadMessageAsync(get), await ReadMessageAsync(head));
    }

    /// <summary>
    /// The org's upstream list is supply-chain topology. <c>/v2/</c> is reachable without a
    /// credential whenever anonymous pull is on, and its error bodies outlive the request, so an
    /// unauthenticated prober must not be able to enumerate where this org fetches from.
    /// </summary>
    [Fact]
    public async Task AnonymousCaller_LearnsNothingAboutTheUpstream_WhileAnAuthenticatedOneDoes()
    {
        await using var factory = NotFoundUpstreamFactory();
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost, prefix: "");
        await EnableAnonymousPullAsync(factory);

        using var anonymous = factory.CreateClient();
        var anonResp = await anonymous.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1");
        Assert.Equal(HttpStatusCode.NotFound, anonResp.StatusCode);

        string anonBody = await anonResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain(PrivateUpstreamHost, anonBody, StringComparison.Ordinal);
        Assert.DoesNotContain("No upstream registry", anonBody, StringComparison.Ordinal);
        Assert.Null(await ReadDetailAsync(anonResp));

        // The twin: the same request with a credential must disclose it. Without this the
        // absence assertion above passes on an instance that never names an upstream at all.
        string token = await factory.CreateToken("pull");
        using var authed = factory.CreateClientWithBearer(token);
        var authResp = await authed.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1");

        Assert.Contains(PrivateUpstreamHost, await ReadMessageAsync(authResp), StringComparison.Ordinal);
    }

    /// <summary>
    /// The naming facts are not topology, so they are said to everyone — but only where they
    /// apply. Docker expands the implicit <c>library/</c> namespace for docker.io alone, which is
    /// why <c>docker pull alpine</c> resolves and <c>docker pull host/alpine</c> does not; a name
    /// that already carries a namespace has no such trap and must not collect the advice.
    /// </summary>
    [Fact]
    public async Task SingleSegmentName_GetsTheLibraryHint_AndATwoSegmentNameDoesNot()
    {
        await using var factory = NotFoundUpstreamFactory();
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost, prefix: "");
        await EnableAnonymousPullAsync(factory);

        using var client = factory.CreateClient();

        string single = await ReadMessageAsync(
            await client.GetAsync($"/v2/{SingleSegmentRepo}/manifests/v1"));
        string twoSegment = await ReadMessageAsync(
            await client.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1"));

        Assert.Contains($"library/{SingleSegmentRepo}", single, StringComparison.Ordinal);
        Assert.DoesNotContain("library/", twoSegment, StringComparison.Ordinal);
    }

    /// <summary>A digest reference is reported as <c>name@digest</c>, a tag as <c>name:tag</c>.</summary>
    [Fact]
    public async Task Message_NamesTheRepository_NotJustTheReference()
    {
        await using var factory = NotFoundUpstreamFactory();
        await factory.InitializeAsync();
        await RouteAllToAsync(factory, PrivateUpstreamHost, prefix: "");
        await EnableAnonymousPullAsync(factory);

        using var client = factory.CreateClient();
        string message = await ReadMessageAsync(
            await client.GetAsync($"/v2/{TwoSegmentRepo}/manifests/v1"));

        Assert.Contains($"{TwoSegmentRepo}:v1", message, StringComparison.Ordinal);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Replaces the org's seeded OCI routing with exactly one upstream, so an assertion about
    /// which host is named cannot be satisfied by a default row.
    /// </summary>
    private static async Task RouteAllToAsync(DependablyFactory factory, string host, string prefix)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn,
            "DELETE FROM upstream_registry WHERE ecosystem = 'oci'");
        await Dapper.SqlMapper.ExecuteAsync(conn,
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, prefixes)
            SELECT lower(hex(randomblob(16))), id, 'oci', @host, 0, 'anonymous', @prefixes
            FROM orgs
            """,
            new { host, prefixes = JsonSerializer.Serialize(new[] { prefix }) });
    }

    private static async Task EnableAnonymousPullAsync(DependablyFactory factory)
    {
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await Dapper.SqlMapper.ExecuteAsync(conn,
            """
            INSERT INTO org_settings (org_id, anonymous_pull)
            SELECT id, 1 FROM orgs
            WHERE true
            ON CONFLICT(org_id) DO UPDATE SET anonymous_pull = 1
            """);
    }

    private static async Task<string> ReadMessageAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("errors")[0].GetProperty("message").GetString() ?? "";
    }

    private static async Task<string?> ReadDetailAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var detail = doc.RootElement.GetProperty("errors")[0].GetProperty("detail");
        return detail.ValueKind == JsonValueKind.Null ? null : detail.GetRawText();
    }

    private static async Task<string?> ReadFaultAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("errors")[0]
            .GetProperty("detail").GetProperty("fault").GetString();
    }
}
