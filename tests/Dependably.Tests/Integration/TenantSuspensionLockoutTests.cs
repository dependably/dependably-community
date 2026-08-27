using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for the full-lockout contract: <c>orgs.status != 'active'</c> refuses
/// every tenant-bound request — protocol plane, management API, and login alike — at
/// <c>TenantStatusEnforcementMiddleware</c>, before it reaches a controller. Every negative probe
/// is paired with its active-org twin in the same test so a broken gate (one that refuses
/// nothing, or refuses everything) fails the assertion rather than passing vacuously.
///
/// <para>
/// Single-mode tests (<see cref="DependablyFactory"/>) exercise the shared gate directly — it
/// runs identically regardless of which <c>ITenantResolver</c> strategy resolved the tenant, so
/// pinning it once per surface here is sufficient; it does not need re-pinning per resolver
/// strategy. <see cref="Suspend_TenantSubdomain_RefusedImmediately_ThenRestoreResumesService"/>
/// uses the multi-mode factory instead, because only multi mode exercises what single mode
/// cannot: subdomain-cache invalidation on a status flip, and the system admin (apex) plane
/// staying reachable while a tenant under it is locked out.
/// </para>
///
/// <para>
/// One exception to "every negative probe pins the fix":
/// <see cref="Suspended_HostedPublish_Refused_ActiveTwinSucceeds"/> already refused on the
/// pre-fix code, because hosted publish was one of the three call sites
/// <c>GlobalTenantStorageResolver.GetRegistryAsync</c> already gated. It stays as defence-in-depth
/// coverage of that pre-existing gate rather than as a regression pin for this change.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantSuspensionLockoutTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── OCI push ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Suspended_OciPush_Refused_ActiveTwinSucceeds_WithOciShapedError()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        byte[] activeBytes = RandomBytes(256);
        string activeDigest = Digest(activeBytes);
        using (var activeResp = await client.PostAsync(
            $"/v2/suspend-oci/blobs/uploads/?digest={activeDigest}", new ByteArrayContent(activeBytes)))
        {
            Assert.Equal(HttpStatusCode.Created, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "suspended");

        byte[] suspendedBytes = RandomBytes(256);
        string suspendedDigest = Digest(suspendedBytes);
        using var suspendedResp = await client.PostAsync(
            $"/v2/suspend-oci/blobs/uploads/?digest={suspendedDigest}", new ByteArrayContent(suspendedBytes));

        // OCI does not read RFC 7807 problem+json — the OCI Distribution Spec error envelope
        // applies here instead of the 423 problem-JSON every other surface gets.
        Assert.Equal(HttpStatusCode.Forbidden, suspendedResp.StatusCode);
        Assert.Equal("application/json", suspendedResp.Content.Headers.ContentType?.MediaType);

        // Response.Clear() must not drop the headers SecurityHeadersMiddleware set on the way in.
        Assert.Equal("nosniff", Assert.Single(suspendedResp.Headers.GetValues("X-Content-Type-Options")));

        using var doc = JsonDocument.Parse(await suspendedResp.Content.ReadAsStringAsync());
        Assert.Equal(
            "DENIED",
            doc.RootElement.GetProperty("errors")[0].GetProperty("code").GetString());

        // No internal org id or precise lifecycle state on the wire — a fixed, generic message.
        string message = doc.RootElement.GetProperty("errors")[0].GetProperty("message").GetString()!;
        Assert.DoesNotContain("suspend", message, StringComparison.OrdinalIgnoreCase);
    }

    // ── Proxy cache-fill ─────────────────────────────────────────────────────

    [Fact]
    public async Task Suspended_ProxyCacheFill_Refused_ActiveTwinSucceeds_AndUpstreamNeverCalled()
    {
        string activeName = $"susp-active-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string blockedName = $"susp-block-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        const string version = "1.0.0";
        string activeFile = $"{activeName}-{version}.tgz";
        string blockedFile = $"{blockedName}-{version}.tgz";
        var (activeBytes, _, _) = NpmFixtures.BuildTarball(activeName, version);
        var (blockedBytes, _, _) = NpmFixtures.BuildTarball(blockedName, version);
        StubTarball(activeName, activeFile, activeBytes);
        StubTarball(blockedName, blockedFile, blockedBytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var activeResp = await client.GetAsync($"/npm/tarballs/{activeName}/{activeFile}");
        Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);

        await _factory.SetOrgStatus("default", "suspended");

        var blockedResp = await client.GetAsync($"/npm/tarballs/{blockedName}/{blockedFile}");
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);

        // The refusal happens before ProxyFetchService ever runs — the operator's egress for
        // this artifact was never spent, which is the whole point of gating suspension here
        // rather than after a cache miss has already dialed upstream.
        int upstreamHits = _factory.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, $"/{blockedName}/-/{blockedFile}", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, upstreamHits);
    }

    private void StubTarball(string name, string file, byte[] bytes)
        => _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

    // ── Hosted publish ───────────────────────────────────────────────────────

    [Fact]
    public async Task Suspended_HostedPublish_Refused_ActiveTwinSucceeds()
    {
        string token = await _factory.CreateToken("push");

        using (var activeResp = await PushNuGetRawAsync(token, "suspend-nuget-active", "1.0.0"))
        {
            Assert.Equal(HttpStatusCode.Created, activeResp.StatusCode);
        }

        await _factory.SetOrgStatus("default", "suspended");

        using var blockedResp = await PushNuGetRawAsync(token, "suspend-nuget-blocked", "1.0.0");
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);
    }

    private async Task<HttpResponseMessage> PushNuGetRawAsync(string token, string id, string version)
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", $"{id}.{version}.nupkg");
        return await client.PutAsync("/nuget/publish", content);
    }

    // ── Artifact download ────────────────────────────────────────────────────

    [Fact]
    public async Task Suspended_ArtifactDownload_Refused_ActiveTwinSucceeds()
    {
        await _factory.PushNuGetPackage("suspenddownload", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var activeResp = await client.GetAsync(
            "/nuget/flatcontainer/suspenddownload/1.0.0/suspenddownload.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);

        await _factory.SetOrgStatus("default", "suspended");

        var blockedResp = await client.GetAsync(
            "/nuget/flatcontainer/suspenddownload/1.0.0/suspenddownload.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);
    }

    // ── Login ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Suspended_Login_Refused_ActiveTwinSucceeds()
    {
        const string password = "SuspendLoginPass12345!";
        string email = $"suspend-login-{Guid.NewGuid():N}@example.com";
        await _factory.CreateUser(email, password);

        using var client = _factory.CreateClient();

        var activeLogin = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, activeLogin.StatusCode);

        await _factory.SetOrgStatus("default", "suspended");

        var blockedLogin = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.Locked, blockedLogin.StatusCode);
    }

    // ── Management API ───────────────────────────────────────────────────────

    [Fact]
    public async Task Suspended_ManagementApi_Refused_ActiveTwinSucceeds()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);

        var activeResp = await client.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);

        await _factory.SetOrgStatus("default", "suspended");

        var blockedResp = await client.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);

        // Response.Clear() (needed to overwrite whatever the controller might already have
        // started writing) must not drop the headers SecurityHeadersMiddleware set on the way in.
        Assert.Equal("nosniff", Assert.Single(blockedResp.Headers.GetValues("X-Content-Type-Options")));

        using var doc = JsonDocument.Parse(await blockedResp.Content.ReadAsStringAsync());
        Assert.Equal("StatusInactive", doc.RootElement.GetProperty("reason").GetString());

        // The gate runs before this caller's credential is meaningfully distinguishable from an
        // anonymous probe on some surfaces, so the body must not hand out the org's internal id
        // or its exact lifecycle state.
        Assert.False(doc.RootElement.TryGetProperty("tenantId", out _));
        Assert.False(doc.RootElement.TryGetProperty("detail", out _));
    }

    // ── Operator/observability surfaces are exempt from the lockout ────────────

    [Fact]
    public async Task Suspended_HealthReadyMetricsVersion_StayReachable_WhileManagementApiStill423s()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);

        await _factory.SetOrgStatus("default", "suspended");

        // A tenant-bound surface still refuses...
        var statsResp = await client.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.Locked, statsResp.StatusCode);

        // ...but the exact operator/observability allowlist stays reachable. Single mode (the
        // default) resolves every request — a liveness probe included — against the one org, so
        // without this exemption suspending a tenant would 423 its own health checks into a
        // crash loop.
        foreach (string path in new[] { "/health", "/ready", "/metrics", "/version" })
        {
            var resp = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
    }

    [Fact]
    public async Task Suspended_OperatorAllowlist_ExemptsTrailingSlash_ButNotANearMissPrefix()
    {
        await _factory.SetOrgStatus("default", "suspended");
        using var client = _factory.CreateClient();

        // ASP.NET Core routing drops a trailing empty segment, so GET /ready/ reaches the same
        // /ready endpoint as GET /ready — a k8s livenessProbe.httpGet.path or a load balancer
        // health check commonly carries that trailing slash. The allowlist must match on the
        // same basis the router does, or a trailing-slash probe config 423s the instant the
        // operator suspends the tenant it is trying to check on.
        foreach (string path in new[] { "/health/", "/ready/", "/metrics/", "/version/" })
        {
            var resp = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        // Exactness cuts the other way too: a path that merely starts with an exempt name is
        // not a prefix match and must still refuse — a suspended tenant's lockout must not leak
        // through a route that happens to share a leading segment with an operator surface.
        foreach (string path in new[] { "/healthy", "/readyz", "/metrics-extra", "/versions" })
        {
            var resp = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Locked, resp.StatusCode);
        }
    }

    [Fact]
    public async Task Suspended_EdgeStatus_StaysReachable()
    {
        // /edge/status is in the same operator/observability class as /metrics and /version
        // (same MetricsAccessConfig IP allowlist, no tenant data in the payload), so it carries
        // the same exemption. Only mapped when DEPLOYMENT_MODE=edge.
        await using var edge = new DependablyFactory { DeploymentMode = "edge" };
        await edge.InitializeAsync();
        await edge.SetOrgStatus("default", "suspended");

        using var client = edge.CreateClient();
        var resp = await client.GetAsync("/edge/status");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── archived / deleting: same gate as suspended ─────────────────────────

    [Theory]
    [InlineData("archived")]
    [InlineData("deleting")]
    public async Task NonSuspendedInactiveStatuses_AlsoRefused_ActiveTwinSucceeds(string status)
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClientWithBearer(jwt);

        var activeResp = await client.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.OK, activeResp.StatusCode);

        await _factory.SetOrgStatus("default", status);

        var blockedResp = await client.GetAsync("/api/v1/stats");
        Assert.Equal(HttpStatusCode.Locked, blockedResp.StatusCode);
    }

    // ── Rate limiting is not bypassed for a suspended tenant ────────────────

    [Fact]
    public async Task Suspended_StillRateLimited_NotExemptFromThrottle()
    {
        // Dedicated factory with a tight login budget — the shared _factory (like every other
        // DependablyFactory) pins every rate-limit policy to 100000+ so unrelated test classes
        // don't self-throttle, which would make a 429 unobservable here.
        await using var factory = new DependablyFactory
        {
            ExtraSettings = new Dictionary<string, string?> { ["LOGIN_RATE_LIMIT_PERMITS"] = "2" },
        };
        await factory.InitializeAsync();
        await factory.SetOrgStatus("default", "suspended");

        using var client = factory.CreateClient();

        // Under budget: refused for suspension, not yet rate-limited.
        for (int i = 0; i < 2; i++)
        {
            var resp = await client.PostAsJsonAsync(
                "/api/v1/auth/login", new { email = "irrelevant@example.com", password = "irrelevant" });
            Assert.Equal(HttpStatusCode.Locked, resp.StatusCode);
        }

        // Over budget: UseRateLimiter runs before TenantStatusEnforcementMiddleware, so a
        // suspended tenant's requests are throttled exactly like an active tenant's — suspension
        // narrows what the request can reach, not the budget it costs an attacker to try.
        var throttled = await client.PostAsJsonAsync(
            "/api/v1/auth/login", new { email = "irrelevant@example.com", password = "irrelevant" });
        Assert.Equal(HttpStatusCode.TooManyRequests, throttled.StatusCode);
    }

    // ── Operator plane + cache invalidation (multi mode) ────────────────────

    [Fact]
    public async Task Suspend_TenantSubdomain_RefusedImmediately_ThenRestoreResumesService()
    {
        await using var multi = new DependablyMultiFactory();
        await multi.InitializeAsync();

        string slug = "susp-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await multi.CreateSystemAdminClient();
        var createResp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, createResp.StatusCode);

        using var tenantClient = multi.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");

        // Active: the tenant subdomain resolves and serves normally.
        var preResp = await tenantClient.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, preResp.StatusCode);

        var suspendResp = await sys.PatchAsJsonAsync(
            $"/api/v1/system/tenants/{slug}/status", new { status = "suspended" });
        Assert.Equal(HttpStatusCode.NoContent, suspendResp.StatusCode);

        // Refused on the very next request, with no wait for the 5-second slug-cache TTL —
        // proves SetTenantStatus's InvalidateSlug call actually evicts the cached resolution
        // instead of leaving a suspended tenant reachable until the TTL expires.
        var lockedResp = await tenantClient.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.Locked, lockedResp.StatusCode);
        using (var doc = JsonDocument.Parse(await lockedResp.Content.ReadAsStringAsync()))
        {
            Assert.Equal("StatusInactive", doc.RootElement.GetProperty("reason").GetString());
        }

        // The operator (apex) plane is unaffected by this tenant's suspension: system admin can
        // still reach SystemController and see the tenant's current status.
        var listResp = await sys.GetAsync("/api/v1/system/tenants?limit=200");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        using (var listDoc = JsonDocument.Parse(await listResp.Content.ReadAsStringAsync()))
        {
            var match = listDoc.RootElement.GetProperty("items").EnumerateArray()
                .First(i => i.GetProperty("slug").GetString() == slug);
            Assert.Equal("suspended", match.GetProperty("status").GetString());
        }

        // Restore via the operator plane — service resumes without a restart.
        var restoreResp = await sys.PatchAsJsonAsync(
            $"/api/v1/system/tenants/{slug}/status", new { status = "active" });
        Assert.Equal(HttpStatusCode.NoContent, restoreResp.StatusCode);

        var resumedResp = await tenantClient.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, resumedResp.StatusCode);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
