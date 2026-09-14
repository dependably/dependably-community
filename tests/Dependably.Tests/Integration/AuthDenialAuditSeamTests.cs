using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the protocol-plane credential and capability denial family through the
/// real pipeline, where the two traps that make this change dangerous actually live.
///
/// <para>
/// <b>The dual-scheme trap.</b> Sixty-one management actions carry
/// <c>[Authorize(AuthenticationSchemes = "Bearer,ApiToken")]</c>. For a JWT-session caller ASP.NET
/// runs both schemes: the token handler reads the same <c>Authorization: Bearer &lt;jwt&gt;</c>
/// header, resolves nothing, and fails — while the request succeeds on the Bearer scheme.
/// Recording a rejection at that failure would write one on every single SPA request, which is
/// both a false security signal and an audit write on the product's busiest path. The refusal is
/// therefore recorded in the challenge handler, reached only when the request really does end
/// unauthorized, and the pair of tests below is what tells those two situations apart: the
/// negative alone would pass on an implementation that records nothing at all.
/// </para>
///
/// <para>
/// <b>The cross-tenant trap.</b> Tenant A's live credential aimed at tenant B produces a denial
/// that belongs in B's feed — and B's row must name neither A's token id nor A's operator-chosen
/// token name, which is free text and so leaks more than an opaque id would.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class AuthDenialAuditSeamTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public AuthDenialAuditSeamTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>A route that carries the dual-scheme Authorize attribute.</summary>
    private const string DualSchemeRoute = "/api/v1/activity";

    private AuthDenialAuditCoalescer Accumulator =>
        _factory.Services.GetRequiredService<AuthDenialAuditCoalescer>();

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    /// <summary>
    /// Empties the open window so a test reads only the denials its own request produced. The
    /// accumulator is a process-wide singleton and the fixture is shared.
    /// </summary>
    private void ResetWindow() => Accumulator.DrainWindow();

    private static bool IsRejection(AuthDenialTally tally) =>
        tally.Key.Action == AuthDenialRecorder.TokenRejectedAction;

    /// <summary>
    /// THE regression test for the dual-scheme trap. A JWT-session request that succeeds must
    /// leave the denial accumulator empty — the token scheme failed on the very same header and
    /// that failure is not a rejection.
    /// </summary>
    [Fact]
    public async Task JwtSessionRequestOnADualSchemeRouteEmitsNoTokenRejection()
    {
        string jwt = await _factory.CreateAdminJwt();
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var resp = await client.GetAsync(DualSchemeRoute);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.DoesNotContain(Accumulator.DrainWindow().Entries, IsRejection);
    }

    /// <summary>
    /// The adversarial twin of the test above, on the same route. Without it the negative proves
    /// nothing: an implementation that never records anywhere would pass it just as happily as
    /// the correct one.
    /// </summary>
    [Fact]
    public async Task AnUnresolvableCredentialOnTheSameRouteIsRecorded()
    {
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "definitely-not-a-real-token");
        var resp = await client.GetAsync(DualSchemeRoute);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        var tally = Assert.Single(Accumulator.DrainWindow().Entries, IsRejection);
        Assert.Equal(AuthDenialRecorder.ReasonInvalid, tally.Key.Reason);
        // The route template, which for a management route has no tenant data in it either way —
        // but the derivation is the same one the package planes depend on.
        Assert.Equal("/api/v1/activity", tally.Key.Route);
    }

    /// <summary>
    /// A request with no credential at all ends 401 through the same challenge handler. It is not
    /// a rejection: nothing was presented, and counting it would make the family a measure of
    /// anonymous traffic rather than of credential misuse.
    /// </summary>
    [Fact]
    public async Task AnUnauthenticatedRequestWithNoCredentialIsNotARejection()
    {
        ResetWindow();

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync(DualSchemeRoute);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.DoesNotContain(Accumulator.DrainWindow().Entries, IsRejection);
    }

    /// <summary>
    /// A credential presented on an anonymous-pull protocol route that does not resolve is a
    /// rejection even though the request is served 200. This is the leaked-PAT case: the client
    /// is refused as a credential and served as an anonymous caller, and a definition written as
    /// "a 401 was produced" would see none of it.
    /// </summary>
    [Fact]
    public async Task AnUnresolvableCredentialIsRecordedEvenWhenTheRequestSucceedsAnonymously()
    {
        string name = $"denial-anon-{Guid.NewGuid():N}"[..20];
        await _factory.PushNpmPackage(name, "1.0.0");

        await SetAnonymousPullAsync(true);
        try
        {
            ResetWindow();

            using var client = _factory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", "revoked-token-still-in-a-ci-job");
            var resp = await client.GetAsync($"/npm/{name}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var tally = Assert.Single(Accumulator.DrainWindow().Entries, IsRejection);
            Assert.Equal(AuthDenialRecorder.ReasonInvalid, tally.Key.Reason);
            Assert.Equal("npm", tally.Key.Ecosystem);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var org = await orgs.GetBySlugAsync("default");
        Assert.NotNull(org);

        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId = org.Id });
        orgs.InvalidateSettingsCache(org.Id);
    }

    /// <summary>
    /// The BOLA case, all the way to the row a SIEM collector reads. Tenant A's token is
    /// presented against tenant B's package; the flushed row is B's, is actor-less, and contains
    /// no trace of A's org, token id or token name — in the audit row's own columns or in the
    /// feed the pull API renders from them.
    /// </summary>
    [Fact]
    public async Task ACrossTenantCredentialNeverPutsTheOtherTenantsIdentityInThisTenantsFeed()
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var audit = _factory.Services.GetRequiredService<AuditRepository>();
        var time = _factory.Services.GetRequiredService<TimeProvider>();

        var target = await orgs.GetBySlugAsync("default");
        Assert.NotNull(target);

        var presenting = await orgs.CreateOrgAsync($"probe-{Guid.NewGuid():N}"[..14]);
        string presentingTokenName = $"leaky-name-{Guid.NewGuid():N}"[..22];
        var (raw, presentingToken) = await tokens.CreateServiceTokenAsync(
            presenting.Id,
            presentingTokenName,
            """["read:artifact","read:metadata"]""",
            expiresAt: null);

        string name = $"denial-bola-{Guid.NewGuid():N}"[..20];
        await _factory.PushNpmPackage(name, "1.0.0");
        ResetWindow();

        using (var client = _factory.CreateClient())
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
            var resp = await client.GetAsync($"/npm/{name}");
            Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        }

        var flusher = _factory.Services.GetRequiredService<AuthDenialAuditFlushService>();
        await flusher.FlushWindowAsync(CancellationToken.None);

        var now = time.GetUtcNow();
        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            since: now.AddHours(-1),
            until: now.AddHours(1),
            orgId: target.Id,
            actionFilter: null,
            limit: 200,
            afterCursor: null);

        // Reachable on the DEFAULT action set — a collector that never sends action= must see
        // this family, otherwise the event exists and nobody ingests it.
        var rejection = Assert.Single(
            items, i => i.Action == AuthDenialRecorder.TokenRejectedAction);
        Assert.Contains(AuthDenialRecorder.ReasonTenantMismatch, rejection.Detail);

        // Actor-less under the target tenant: no id and, correspondingly, no fabricated kind.
        Assert.Null(rejection.ActorId);

        string rendered = string.Join('', items.Select(i =>
            string.Join('', i.Action, i.OrgId, i.ActorId, i.Detail, i.SourceIp, i.Purl)));
        Assert.DoesNotContain(presenting.Id, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(presentingToken.Id, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(presentingTokenName, rendered, StringComparison.Ordinal);

        // And the denormalized label column, which the feed does not render but the audit page
        // does, carries nothing either.
        await using var conn = await Db.OpenAsync();
        var labels = await conn.QueryAsync<string?>(
            """
            SELECT actor_label FROM audit_log
            WHERE action = @action AND org_id = @orgId
            """,
            new { action = AuthDenialRecorder.TokenRejectedAction, orgId = target.Id });
        Assert.All(labels, Assert.Null);
    }

    /// <summary>
    /// A capability refusal on an inline <c>HasCapability</c> gate reaches the same family, with
    /// the required-versus-granted pair that makes it actionable. Before this change only OCI
    /// recorded anything at all on that gate.
    /// </summary>
    [Fact]
    public async Task AnInlineCapabilityGateRecordsRequiredAndGranted()
    {
        string name = $"denial-cap-{Guid.NewGuid():N}"[..20];
        await _factory.PushNpmPackage(name, "1.0.0");

        // publish-only: exactly what the product's own "push" token preset mints — no read
        // capability at all, so the tarball read gate refuses it.
        string publishOnly = await _factory.CreateToken("publish-only");
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", publishOnly);
        var resp = await client.GetAsync($"/npm/{name}/-/{name}-1.0.0.tgz");

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        var tally = Assert.Single(
            Accumulator.DrainWindow().Entries,
            t => t.Key.Action == AuthDenialRecorder.CapabilityDeniedAction);
        Assert.Equal(Capabilities.ReadArtifact, tally.Key.Required);
        Assert.Equal("publish:*", tally.Key.Granted);
        Assert.Equal("npm", tally.Key.Ecosystem);
        // The partition namespace the inline gates use. The attribute path emits ip: instead,
        // because its principal carries the token OWNER's id, not the token's.
        Assert.StartsWith("token:", tally.Key.Partition, StringComparison.Ordinal);
    }

    // ── The hosted-write plane ───────────────────────────────────────────────
    //
    // These paths resolve the credential WITHOUT a tenant and then make their own
    // token.OrgId != orgId decision, because a publish path wants a 401 with a challenge header
    // rather than the read paths' coerce-to-null. Wiring the shared resolver alone does not reach
    // them: a live credential from another tenant resolves, no recorder runs, and the request is
    // refused with no event — across npm publish and dist-tags, PyPI publish, NuGet
    // push/symbols/unlist and the whole Hex plane, which is the surface a cross-tenant credential
    // probe actually targets. One test per plane, and an in-tenant twin so the assertion cannot
    // be satisfied by a recorder that fires on every publish.

    /// <summary>Creates a live push credential bound to a second real org.</summary>
    private async Task<string> OtherOrgPushTokenAsync()
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var other = await orgs.CreateOrgAsync($"probe-{Guid.NewGuid():N}"[..14]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            other.Id,
            $"probe-{Guid.NewGuid():N}"[..16],
            """["publish:*","read:artifact","read:metadata","yank:*"]""",
            expiresAt: null);
        return raw;
    }

    private AuthDenialTally SingleTenantMismatch(string expectedEcosystem)
    {
        var tally = Assert.Single(
            Accumulator.DrainWindow().Entries,
            t => t.Key.Action == AuthDenialRecorder.TokenRejectedAction
                 && t.Key.Reason == AuthDenialRecorder.ReasonTenantMismatch);
        Assert.Equal(expectedEcosystem, tally.Key.Ecosystem);
        // Naming an address rather than the presenting credential: the row belongs to the target
        // tenant, and the presenting tenant's token identity must not reach it.
        Assert.StartsWith("ip:", tally.Key.Partition, StringComparison.Ordinal);
        return tally;
    }

    [Fact]
    public async Task ACrossTenantCredentialOnNpmPublishEmitsATenantMismatchEvent()
    {
        string raw = await OtherOrgPushTokenAsync();
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        using var body = new StringContent("{}", Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/xtenant-{Guid.NewGuid():N}"[..26], body);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        SingleTenantMismatch("npm");
    }

    /// <summary>
    /// The twin. An in-tenant publish credential on the same route is not a denial — without it,
    /// a recorder that fired on every publish would satisfy the test above just as well.
    /// </summary>
    [Fact]
    public async Task AnInTenantCredentialOnNpmPublishEmitsNoRejection()
    {
        string push = await _factory.CreateToken("push");
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", push);
        using var body = new StringContent("{}", Encoding.UTF8, "application/json");
        await client.PutAsync($"/npm/intenant-{Guid.NewGuid():N}"[..26], body);

        Assert.DoesNotContain(Accumulator.DrainWindow().Entries, IsRejection);
    }

    [Fact]
    public async Task ACrossTenantCredentialOnNpmDistTagsEmitsATenantMismatchEvent()
    {
        string name = $"xtag-{Guid.NewGuid():N}"[..18];
        await _factory.PushNpmPackage(name, "1.0.0");
        string raw = await OtherOrgPushTokenAsync();
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        using var body = new StringContent("\"1.0.0\"", Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/-/package/{name}/dist-tags/beta", body);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        SingleTenantMismatch("npm");
    }

    [Fact]
    public async Task ACrossTenantCredentialOnPyPiPublishEmitsATenantMismatchEvent()
    {
        string raw = await OtherOrgPushTokenAsync();
        ResetWindow();

        using var client = _factory.CreateClient();
        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{raw}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        using var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
        };
        var resp = await client.PostAsync("/pypi/legacy/", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        SingleTenantMismatch("pypi");
    }

    /// <summary>
    /// NuGet push resolves its credential from <c>X-NuGet-ApiKey</c> directly rather than through
    /// the shared helper, so this plane bypassed the seam twice over.
    /// </summary>
    [Fact]
    public async Task ACrossTenantCredentialOnNuGetPushEmitsATenantMismatchEvent()
    {
        string raw = await OtherOrgPushTokenAsync();
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", raw);
        using var content = new MultipartFormDataContent
        {
            { new ByteArrayContent([1, 2, 3]), "package", "package.nupkg" },
        };
        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        SingleTenantMismatch("nuget");
    }

    [Fact]
    public async Task ACrossTenantCredentialOnTheHexPlaneEmitsATenantMismatchEvent()
    {
        string raw = await OtherOrgPushTokenAsync();
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        var resp = await client.GetAsync("/hex/names");

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        SingleTenantMismatch("hex");
    }

    /// <summary>
    /// The Hex API plane resolves through its own <c>ResolveHexTokenAsync</c>, which coerces a
    /// cross-tenant token to null the same way the read paths do.
    /// </summary>
    [Fact]
    public async Task ACrossTenantCredentialOnTheHexApiPlaneEmitsATenantMismatchEvent()
    {
        string raw = await OtherOrgPushTokenAsync();
        ResetWindow();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        var resp = await client.GetAsync("/hex/api/users/me");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        SingleTenantMismatch("hex");
    }
}
