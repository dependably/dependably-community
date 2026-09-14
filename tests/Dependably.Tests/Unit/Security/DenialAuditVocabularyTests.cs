using System.Net;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Two independent writers fold denials into the same accumulator and therefore into the same two
/// audit columns: <see cref="AuthDenialRecorder"/> for credential and capability refusals, and
/// <c>RateLimitDenialAuditRecorder</c> for rate-limit rejections. Nothing in the type system makes
/// them spell <c>ecosystem</c> and <c>route</c> the same way, and each spelled one of them
/// differently on arrival — a private route-prefix table writing Go's route segment
/// (<c>"go"</c>) instead of its backend id (<c>"golang"</c>), and a raw
/// <c>RoutePattern.RawText</c> read that keeps whichever leading-slash form the action happened to
/// declare.
///
/// <para>
/// Both defects are invisible to every other gate: the rows write, the feeds serve, and a SOC
/// filtering <c>ecosystem = 'golang'</c> or grouping by <c>route</c> simply sees a fraction of the
/// denials with no indication the rest exist. These tests pin the two vocabularies as one, by
/// driving both writers over the same request and asserting they agree — not by asserting each
/// one's output in isolation, which is how they drifted.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class DenialAuditVocabularyTests
{
    private const int Ipv6Prefix = IpAddressExtensions.DefaultIpv6PartitionPrefixBits;

    private static (HttpContext Context, AuthDenialAuditCoalescer Coalescer) Build(
        string routeTemplate, string requestPath)
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());
        var services = new ServiceCollection();
        services.AddSingleton(coalescer);

        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Path = requestPath;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
        ctx.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("org-1", "slug");
        ctx.SetEndpoint(new RouteEndpoint(
            _ => Task.CompletedTask,
            RoutePatternFactory.Parse(routeTemplate),
            order: 0,
            new EndpointMetadataCollection(),
            displayName: routeTemplate));

        return (ctx, coalescer);
    }

    private static AuthDenialKey CredentialDenialKey(string routeTemplate, string requestPath)
    {
        var (ctx, coalescer) = Build(routeTemplate, requestPath);
        AuthDenialRecorder.RecordTokenRejected(ctx, AuthDenialRecorder.ReasonInvalid);
        return Assert.Single(coalescer.DrainWindow().Entries).Key;
    }

    private static AuthDenialKey RateLimitDenialKey(string routeTemplate, string requestPath)
    {
        var (ctx, coalescer) = Build(routeTemplate, requestPath);
        RateLimitDenialAuditRecorder.Record(ctx, "download", Ipv6Prefix, useRedis: false);
        return Assert.Single(coalescer.DrainWindow().Entries).Key;
    }

    /// <summary>
    /// Go is the case the two writers actually disagreed on, because it is the one ecosystem whose
    /// protocol route segment (<c>/go/</c>) is not its backend id (<c>golang</c>) — the id
    /// <c>PurlNormalizer</c>, the package tables and the dashboard filter all use, and the one
    /// <c>EcosystemHardcodedListComplianceTests</c> pins. OCI is the mirror case in the other
    /// direction (<c>/v2/</c> per the Distribution Spec), so it is asserted alongside.
    /// </summary>
    [Theory]
    [InlineData("/go/{*path}", "/go/github.com/acme/widget/@v/list", "golang")]
    [InlineData("/v2/{*rest}", "/v2/acme/widget/manifests/1.0.0", "oci")]
    [InlineData("/npm/{*path}", "/npm/left-pad", "npm")]
    [InlineData("/simple/{*path}", "/simple/requests/", "pypi")]
    [InlineData("/api/v1/orgs", "/api/v1/orgs", null)]
    public void BothDenialWritersRecordTheSameEcosystemId(
        string routeTemplate, string requestPath, string? expected)
    {
        Assert.Equal(expected, CredentialDenialKey(routeTemplate, requestPath).Ecosystem);
        Assert.Equal(expected, RateLimitDenialKey(routeTemplate, requestPath).Ecosystem);
    }

    /// <summary>
    /// Attribute routes are declared both ways in this codebase — <c>[HttpGet("/npm/{*path}")]</c>
    /// and <c>[HttpGet("npm/{*path}")]</c> — and <c>RoutePattern.RawText</c> keeps whichever was
    /// written. Left unnormalised, one route yields two accumulator keys, two flushed rows, and a
    /// grouping that splits one route's denials in half.
    /// </summary>
    [Theory]
    [InlineData("npm/{*path}")]
    [InlineData("/npm/{*path}")]
    public void BothDenialWritersRecordTheSameSlashNormalisedRouteTemplate(string routeTemplate)
    {
        Assert.Equal("/npm/{*path}", CredentialDenialKey(routeTemplate, "/npm/left-pad").Route);
        Assert.Equal("/npm/{*path}", RateLimitDenialKey(routeTemplate, "/npm/left-pad").Route);
    }

    /// <summary>
    /// With no endpoint selected there is no template to record, and neither writer may fall back
    /// to the request path: it carries a package name (tenant data, attacker-chosen) and would
    /// give the coalescing key one value per package.
    /// </summary>
    [Fact]
    public void BothDenialWritersFallBackToTheSameUnknownRouteWithNoEndpoint()
    {
        var coalescer = new AuthDenialAuditCoalescer(TestTime.Frozen());
        var services = new ServiceCollection();
        services.AddSingleton(coalescer);
        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Path = "/npm/@acme/private-thing";
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");

        AuthDenialRecorder.RecordTokenRejected(ctx, AuthDenialRecorder.ReasonInvalid);
        RateLimitDenialAuditRecorder.Record(ctx, "download", Ipv6Prefix, useRedis: false);

        string[] routes = [.. coalescer.DrainWindow().Entries.Select(e => e.Key.Route).Distinct()];
        Assert.Equal(["unknown"], routes);
    }
}
