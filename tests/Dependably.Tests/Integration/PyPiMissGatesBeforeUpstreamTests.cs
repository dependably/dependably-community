using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// A PyPI file download that misses the cache resolves the artefact URL by fetching the
/// upstream's simple index for the package name, with the upstream credential. Every refusal
/// gate (anonymous pull, allowlist/blocklist, passthrough, reserved namespace, local_only claim)
/// must therefore run before that fetch: a refused request must send nothing upstream, or the
/// name of an internal package is disclosed to every configured upstream.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiMissGatesBeforeUpstreamTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public PyPiMissGatesBeforeUpstreamTests(DependablyFactory factory) => _factory = factory;

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetPassthroughAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private static string NewName(string stem) => $"{stem}{Guid.NewGuid():N}"[..20].ToLowerInvariant();

    private static string WheelName(string name) => $"{name}-1.0.0-py3-none-any.whl";

    // Stubs an upstream that advertises the wheel, so a request that reaches it would succeed.
    private void StubUpstreamIndex(string name)
    {
        string file = WheelName(name);
        string mockBase = _factory.MockUpstream.Urls[0];
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{file}\">{file}</a></body></html>"));
        var (bytes, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));
    }

    private int UpstreamRequests(string name) =>
        _factory.MockUpstream.LogEntries.Count(e =>
            e.RequestMessage?.Path?.Contains(name, StringComparison.OrdinalIgnoreCase) == true);

    [Fact]
    public async Task Download_ControlUnrestrictedName_ReachesUpstreamAndServes()
    {
        string name = NewName("ctl");
        StubUpstreamIndex(name);
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var resp = await client.GetAsync($"/packages/{WheelName(name)}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(UpstreamRequests(name) >= 2);
    }

    [Fact]
    public async Task Download_ReservedName_Returns404_AndSendsNothingUpstream()
    {
        string name = NewName("resv");
        StubUpstreamIndex(name);
        string orgId = await DefaultOrgIdAsync();
        await _factory.Services.GetRequiredService<ReservedNamespaceService>()
            .AddAsync(orgId, "pypi", name, createdBy: null);
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var resp = await client.GetAsync($"/packages/{WheelName(name)}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, UpstreamRequests(name));
    }

    [Fact]
    public async Task Download_LocalOnlyClaim_Returns404_AndSendsNothingUpstream()
    {
        string name = NewName("lonly");
        StubUpstreamIndex(name);
        string orgId = await DefaultOrgIdAsync();
        await _factory.Services.GetRequiredService<ClaimRepository>().ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString("D"),
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = orgId,
            Ecosystem = "pypi",
            Name = name,
            PriorState = null,
            NewState = ClaimStateMachine.LocalOnly,
            Reason = "miss-path gate ordering test",
            ActorId = null,
            OccurredAt = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow(),
            PurgedCount = 0,
        });
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var resp = await client.GetAsync($"/packages/{WheelName(name)}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, UpstreamRequests(name));
    }

    [Fact]
    public async Task Download_PassthroughDisabled_Returns404_AndSendsNothingUpstream()
    {
        string name = NewName("nopass");
        StubUpstreamIndex(name);
        await SetPassthroughAsync(false);
        try
        {
            using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

            var resp = await client.GetAsync($"/packages/{WheelName(name)}");

            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
            Assert.Equal(0, UpstreamRequests(name));
        }
        finally
        {
            await SetPassthroughAsync(true);
        }
    }

    [Fact]
    public async Task Download_BlocklistedName_Returns403_AndSendsNothingUpstream()
    {
        string name = NewName("blk");
        StubUpstreamIndex(name);
        string orgId = await DefaultOrgIdAsync();
        await _factory.Services.GetRequiredService<BlocklistRepository>().AddAsync(orgId, $"pkg:pypi/{name}");
        using var client = _factory.CreateClientWithBasic(await _factory.CreateToken("pull"));

        var resp = await client.GetAsync($"/packages/{WheelName(name)}");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Equal(0, UpstreamRequests(name));
    }

    [Fact]
    public async Task Download_AnonymousPullOff_NoToken_Returns401_AndSendsNothingUpstream()
    {
        string name = NewName("anon");
        StubUpstreamIndex(name);
        await SetAnonymousPullAsync(false);
        try
        {
            using var client = _factory.CreateClient();

            var resp = await client.GetAsync($"/packages/{WheelName(name)}");

            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
            Assert.Equal(0, UpstreamRequests(name));

            using var headReq = new HttpRequestMessage(HttpMethod.Head, $"/packages/{WheelName(name)}");
            var head = await client.SendAsync(headReq);
            Assert.Equal(HttpStatusCode.Unauthorized, head.StatusCode);
            Assert.Equal(0, UpstreamRequests(name));
        }
        finally
        {
            await SetAnonymousPullAsync(true);
        }
    }
}
