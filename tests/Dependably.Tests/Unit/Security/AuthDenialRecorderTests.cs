using System.Net;
using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The shared seam every credential and capability refusal goes through. Three of its decisions
/// are load-bearing and none of them are visible from a call site, which is exactly why they are
/// made in one place and pinned here:
///
/// <list type="number">
///   <item>the route is the endpoint <b>template</b>, so an attacker-controlled request cannot
///         write a package name (tenant data) into an audit row, nor mint one coalescing key per
///         package and push the accumulator to its cap;</item>
///   <item>a rejection's partition is the rate-limit IP form and never a token reference, which
///         is what keeps the cross-tenant case from naming the presenting tenant's credential in
///         the target tenant's feed;</item>
///   <item>a capability denial carries required <em>and</em> granted, the pair that tells an
///         operator whether to re-mint the token or stop the caller.</item>
/// </list>
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuthDenialRecorderTests
{
    private static (HttpContext Context, AuthDenialAuditCoalescer Coalescer) Build(
        string routeTemplate,
        string requestPath,
        string? tenantId = "org-1",
        string remoteIp = "198.51.100.7",
        IEnumerable<string>? caps = null,
        string? requiredCapability = null)
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());
        var services = new ServiceCollection();
        services.AddSingleton(coalescer);

        var ctx = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
        };
        ctx.Request.Path = requestPath;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);

        if (tenantId is not null)
        {
            ctx.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(tenantId, "slug");
        }

        var metadata = requiredCapability is null
            ? new EndpointMetadataCollection()
            : new EndpointMetadataCollection(new RequireCapabilityAttribute(requiredCapability));

        ctx.SetEndpoint(new RouteEndpoint(
            _ => Task.CompletedTask,
            RoutePatternFactory.Parse(routeTemplate),
            order: 0,
            metadata,
            displayName: routeTemplate));

        if (caps is not null)
        {
            var identity = new ClaimsIdentity(
                caps.Select(c => new Claim("cap", c)), TokenAuthenticationDefaults.Scheme);
            ctx.User = new ClaimsPrincipal(identity);
        }

        return (ctx, coalescer);
    }

    private static AuthDenialTally Single(AuthDenialAuditCoalescer coalescer) =>
        Assert.Single(coalescer.DrainWindow().Entries);

    /// <summary>
    /// The route template, not the request path. A raw npm tarball path names a scope and a
    /// package — tenant data an unauthenticated caller chooses — so recording it would both
    /// publish that name into the audit trail and give the coalescing key one value per package.
    /// </summary>
    [Fact]
    public void TokenRejectionKeysOnTheRouteTemplateNotTheRequestPath()
    {
        var (ctx, coalescer) = Build(
            routeTemplate: "/npm/{*path}",
            requestPath: "/npm/@acme/private-thing/-/private-thing-1.0.0.tgz");

        AuthDenialRecorder.RecordTokenRejected(ctx, reason: AuthDenialRecorder.ReasonInvalid);

        var tally = Single(coalescer);
        Assert.Equal("/npm/{*path}", tally.Key.Route);
        Assert.DoesNotContain("private-thing", tally.Key.Route, StringComparison.Ordinal);
    }

    /// <summary>
    /// A denial raised with no endpoint selected still must not fall back to the request path —
    /// the fallback carries the same tenant data and the same unbounded cardinality the happy
    /// path is protected from.
    /// </summary>
    [Fact]
    public void WithNoSelectedEndpointTheRouteIsAPlaceholderNotThePath()
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());
        var services = new ServiceCollection();
        services.AddSingleton(coalescer);
        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Path = "/npm/@acme/private-thing";

        AuthDenialRecorder.RecordTokenRejected(ctx, reason: AuthDenialRecorder.ReasonInvalid);

        Assert.Equal("unknown", Single(coalescer).Key.Route);
    }

    /// <summary>
    /// The partition aggregates an IPv6 allocation to its <c>/64</c> so a caller cannot mint a
    /// fresh key from each address in their own routed prefix, while the row's <c>source_ip</c>
    /// keeps the full address for forensics. The two are deliberately different derivations.
    /// </summary>
    [Fact]
    public void PartitionIsTheRateLimitFormWhileSourceIpKeepsTheFullAddress()
    {
        var (ctx, coalescer) = Build("/simple/{name}", "/simple/requests/", remoteIp: "2001:db8:1:2:3:4:5:6");

        AuthDenialRecorder.RecordTokenRejected(ctx, reason: AuthDenialRecorder.ReasonInvalid);

        var tally = Single(coalescer);
        Assert.Equal("ip:2001:db8:1:2::/64", tally.Key.Partition);
        Assert.Equal("2001:db8:1:2:3:4:5:6", tally.SourceIp);
    }

    /// <summary>
    /// The ecosystem lands in its own key field (and so in the audit row's own column), because
    /// the personal-data sweep nulls <c>detail</c> at its horizon and a row whose only meaning
    /// lived in the payload reads afterwards as a denial of nothing in particular.
    /// </summary>
    [Theory]
    [InlineData("/simple/{name}", "pypi")]
    [InlineData("/npm/{*path}", "npm")]
    [InlineData("/v2/{*rest}", "oci")]
    [InlineData("/cargo/api/v1/crates/new", "cargo")]
    [InlineData("/hex/api/packages/{name}", "hex")]
    [InlineData("/api/v1/lookup", null)]
    public void EcosystemIsDerivedFromTheRouteTemplate(string route, string? expected)
    {
        var (ctx, coalescer) = Build(route, route);

        AuthDenialRecorder.RecordTokenRejected(ctx, reason: AuthDenialRecorder.ReasonInvalid);

        Assert.Equal(expected, Single(coalescer).Key.Ecosystem);
    }

    /// <summary>
    /// Required versus granted, the <c>oci.scope_denied</c> payload generalized to every plane.
    /// The granted set is rendered in a stable order so two denials by one credential fold into
    /// one key instead of two.
    /// </summary>
    [Fact]
    public void CapabilityDenialCarriesRequiredAndGranted()
    {
        var (ctx, coalescer) = Build("/cargo/api/v1/crates/new", "/cargo/api/v1/crates/new");
        var token = TokenFor("tok-abcdef0123456789", "org-1", """["read:metadata","read:artifact"]""");

        AuthDenialRecorder.RecordCapabilityDenied(
            ctx, token, required: Capabilities.PublishCargo, ecosystem: "cargo", orgId: "org-1");

        var tally = Single(coalescer);
        Assert.Equal(AuthDenialRecorder.CapabilityDeniedAction, tally.Key.Action);
        Assert.Equal(AuthDenialRecorder.ReasonInsufficientCapability, tally.Key.Reason);
        Assert.Equal(Capabilities.PublishCargo, tally.Key.Required);
        Assert.Equal("read:artifact, read:metadata", tally.Key.Granted);
        // The credential is named by a truncated database key, never the secret and never a
        // whole internal id.
        Assert.Equal("token:tok-abcd", tally.Key.Partition);
    }

    /// <summary>A credential carrying nothing renders as a word, not as an empty string.</summary>
    [Fact]
    public void CapabilityDenialRendersAnEmptyGrantSetExplicitly()
    {
        var (ctx, coalescer) = Build("/v2/{*rest}", "/v2/acme/app/manifests/latest");
        var token = TokenFor("tok-1", "org-1", "[]");

        AuthDenialRecorder.RecordCapabilityDenied(ctx, token, required: Capabilities.PullOci);

        Assert.Equal("none", Single(coalescer).Key.Granted);
    }

    /// <summary>
    /// The attribute path's forbid handler reads both sides off the request: the required
    /// capability from the endpoint's own metadata, the granted set from the principal's
    /// <c>cap</c> claims.
    /// </summary>
    [Fact]
    public void SchemeForbidReadsRequiredFromEndpointMetadataAndGrantedFromClaims()
    {
        var (ctx, coalescer) = Build(
            "/nuget/v3/package",
            "/nuget/v3/package",
            caps: ["read:metadata"],
            requiredCapability: Capabilities.PublishNuget);

        AuthDenialRecorder.RecordCapabilityDeniedForScheme(ctx, TokenAuthenticationDefaults.Scheme);

        var tally = Single(coalescer);
        Assert.Equal(Capabilities.PublishNuget, tally.Key.Required);
        Assert.Equal("read:metadata", tally.Key.Granted);
        Assert.Equal("nuget", tally.Key.Ecosystem);
    }

    /// <summary>
    /// The dual-scheme guard at the recorder level: a principal this scheme did not issue is not
    /// its business. Both management routes and the protocol plane forbid every scheme in the
    /// policy, so without this a JWT-session refusal would be filed as a protocol-token refusal.
    /// </summary>
    [Fact]
    public void SchemeForbidIgnoresAPrincipalIssuedByAnotherScheme()
    {
        var (ctx, coalescer) = Build("/api/v1/activity", "/api/v1/activity");
        ctx.User = new ClaimsPrincipal(
            new ClaimsIdentity([new Claim("cap", "read:audit")], authenticationType: "Bearer"));

        AuthDenialRecorder.RecordCapabilityDeniedForScheme(ctx, TokenAuthenticationDefaults.Scheme);

        Assert.Empty(coalescer.DrainWindow().Entries);
    }

    /// <summary>
    /// An apex/system-scope request has no tenant, and the key leaves the org null rather than
    /// borrowing one — the flusher turns that into a system-scope row, which is readable, where a
    /// tenant-scope row with a NULL org is readable from nowhere.
    /// </summary>
    [Fact]
    public void ARequestWithNoResolvedTenantRecordsNoOrg()
    {
        var (ctx, coalescer) = Build("/npm/{*path}", "/npm/left-pad", tenantId: null);

        AuthDenialRecorder.RecordTokenRejected(ctx, reason: AuthDenialRecorder.ReasonInvalid);

        Assert.Null(Single(coalescer).Key.OrgId);
    }

    /// <summary>
    /// The recorder is best-effort by contract. A composition root without the accumulator — or a
    /// unit-test context with no service provider at all — must not turn a correct refusal into a
    /// 500 the client reads as a server fault worth retrying.
    /// </summary>
    [Fact]
    public void RecordingWithoutTheAccumulatorRegisteredIsANoOp()
    {
        var bare = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().BuildServiceProvider(),
        };

        // The contract under test is "does not throw", asserted explicitly so a regression fails
        // the test rather than passing vacuously on an empty body.
        Assert.Null(Record.Exception(() =>
        {
            AuthDenialRecorder.RecordTokenRejected(bare, reason: AuthDenialRecorder.ReasonInvalid);
            AuthDenialRecorder.RecordTokenRejected(null, reason: AuthDenialRecorder.ReasonInvalid);
            AuthDenialRecorder.RecordCapabilityDenied(null, null, required: Capabilities.PullOci);
            AuthDenialRecorder.RecordCapabilityDeniedForScheme(null, TokenAuthenticationDefaults.Scheme);
        }));
    }

    /// <summary>
    /// The flag the token scheme sets on an unresolved credential is single-use: a request that
    /// challenges twice must not count one refusal twice.
    /// </summary>
    [Fact]
    public void TheUnresolvedCredentialFlagIsConsumedOnce()
    {
        var ctx = new DefaultHttpContext();

        Assert.False(AuthDenialRecorder.ConsumeUnresolvedCredential(ctx));

        AuthDenialRecorder.FlagUnresolvedCredential(ctx);
        Assert.True(AuthDenialRecorder.ConsumeUnresolvedCredential(ctx));
        Assert.False(AuthDenialRecorder.ConsumeUnresolvedCredential(ctx));
    }

    private static TokenRecord TokenFor(string id, string orgId, string capabilities) =>
        new()
        {
            Id = id,
            OrgId = orgId,
            UserId = null,
            Name = "ci-token",
            Capabilities = capabilities,
            Source = TokenSource.Service,
        };
}
