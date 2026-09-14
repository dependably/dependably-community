using System.Net;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The inline resolution seam — the one every protocol plane except OCI's attribute path runs
/// through. Two properties matter more than the happy path here.
///
/// <para>
/// <b>A rejection is not a 401.</b> With <c>AnonymousPull</c> on, an unresolved credential is
/// served 200 as anonymous; the event still has to fire, because a revoked PAT still being
/// retried by somebody's CI is precisely the thing an operator is trying to see, and it produces
/// no error status at all.
/// </para>
///
/// <para>
/// <b>A cross-tenant presentation is recorded under the target tenant, actor-less.</b> The
/// presenting tenant's token id and service-token name must not appear in the target tenant's
/// audit trail or SIEM feed — the name is operator-chosen free text, so leaking it leaks more
/// than an opaque id would.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class TokenAuthExtensionsDenialTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly AuthDenialAuditCoalescer _coalescer = new(TestTime.Frozen());
    private TokenRepository _tokens = null!;
    private OrgRepository _orgs = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _tokens = new TokenRepository(_db, TestTime.Frozen());
        _orgs = new OrgRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private HttpRequest Request(string? authorization, string tenantId)
    {
        var services = new ServiceCollection();
        services.AddSingleton(_coalescer);

        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Path = "/npm/@acme/private-thing";
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.9");
        ctx.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(tenantId, "slug");
        ctx.SetEndpoint(new RouteEndpoint(
            _ => Task.CompletedTask,
            RoutePatternFactory.Parse("/npm/{*path}"),
            order: 0,
            new EndpointMetadataCollection(),
            displayName: "npm"));

        if (authorization is not null)
        {
            ctx.Request.Headers.Authorization = authorization;
        }

        return ctx.Request;
    }

    /// <summary>What a seeded tenant's credential is known by, for the leak assertions.</summary>
    private sealed record SeededToken(string OrgId, string Raw, string TokenId, string Name);

    private async Task<SeededToken> SeedTokenAsync(
        string slug, string capabilities = """["read:metadata","read:artifact"]""")
    {
        var org = await _orgs.CreateOrgAsync(slug);
        string name = $"ci-{slug}";
        var (raw, record) = await _tokens.CreateServiceTokenAsync(
            org.Id, name, capabilities, expiresAt: null);
        return new SeededToken(org.Id, raw, record.Id, name);
    }

    [Fact]
    public async Task AnUnresolvableCredentialIsRecordedAsInvalid()
    {
        var result = await Request("Bearer nope-not-a-real-token", "org-target")
            .ResolveTokenAsync(_tokens);

        Assert.Null(result);
        var tally = Assert.Single(_coalescer.DrainWindow().Entries);
        Assert.Equal(AuthDenialRecorder.TokenRejectedAction, tally.Key.Action);
        Assert.Equal(AuthDenialRecorder.ReasonInvalid, tally.Key.Reason);
        Assert.Equal("org-target", tally.Key.OrgId);
        Assert.Equal("npm", tally.Key.Ecosystem);
        Assert.Equal("/npm/{*path}", tally.Key.Route);
        Assert.Equal("198.51.100.9", tally.SourceIp);
    }

    /// <summary>
    /// A malformed Basic payload is still a presented credential, and it is the shape a spraying
    /// client produces most often. It counts under the same reason the meter already counts it as.
    /// </summary>
    [Fact]
    public async Task AMalformedBasicCredentialIsRecordedAsInvalid()
    {
        var result = await Request("Basic !!!not-base64!!!", "org-target").ResolveTokenAsync(_tokens);

        Assert.Null(result);
        Assert.Equal(
            AuthDenialRecorder.ReasonInvalid,
            Assert.Single(_coalescer.DrainWindow().Entries).Key.Reason);
    }

    /// <summary>
    /// The adversarial twin for every test above: anonymous traffic is the overwhelming majority
    /// of a public registry's requests, and recording it would drown the signal in the one table
    /// this whole mechanism exists to keep readable.
    /// </summary>
    [Fact]
    public async Task ARequestPresentingNoCredentialRecordsNothing()
    {
        Assert.Null(await Request(authorization: null, "org-target").ResolveTokenAsync(_tokens));

        Assert.Empty(_coalescer.DrainWindow().Entries);
    }

    /// <summary>The other twin: a credential that resolves is not a denial.</summary>
    [Fact]
    public async Task AResolvingInTenantCredentialRecordsNothing()
    {
        var seeded = await SeedTokenAsync("tenant-a");

        var result = await Request($"Bearer {seeded.Raw}", seeded.OrgId)
            .ResolveTokenAsync(_tokens, seeded.OrgId);

        Assert.NotNull(result);
        Assert.Empty(_coalescer.DrainWindow().Entries);
    }

    /// <summary>
    /// Tenant A's live credential aimed at tenant B. The denial belongs to B — it is B being
    /// probed — and B's row must name neither A's token id nor A's operator-chosen token name.
    /// The partition is the presenting address, which is B's to see, not A's identity.
    /// </summary>
    [Fact]
    public async Task ACrossTenantCredentialIsRecordedUnderTheTargetOrgAndNamesNoToken()
    {
        var a = await SeedTokenAsync("tenant-a");
        var b = await SeedTokenAsync("tenant-b");

        var result = await Request($"Bearer {a.Raw}", b.OrgId).ResolveTokenAsync(_tokens, b.OrgId);

        Assert.Null(result);
        var tally = Assert.Single(_coalescer.DrainWindow().Entries);
        Assert.Equal(AuthDenialRecorder.ReasonTenantMismatch, tally.Key.Reason);
        Assert.Equal(b.OrgId, tally.Key.OrgId);

        // Nothing anywhere in the key identifies the presenting tenant or its credential.
        string flattened = string.Join(
            "",
            tally.Key.Action, tally.Key.OrgId, tally.Key.Partition, tally.Key.Ecosystem,
            tally.Key.Policy, tally.Key.Reason, tally.Key.Required, tally.Key.Granted,
            tally.Key.Route, tally.SourceIp);
        Assert.DoesNotContain(a.OrgId, flattened, StringComparison.Ordinal);
        Assert.DoesNotContain(a.TokenId, flattened, StringComparison.Ordinal);
        Assert.DoesNotContain(a.Name, flattened, StringComparison.Ordinal);
        Assert.Equal("ip:198.51.100.9", tally.Key.Partition);
    }

    /// <summary>
    /// One presentation, one count. The org-scoped overload delegates to the unscoped one, so a
    /// careless wiring records the same refusal twice — once as invalid on the way through and
    /// once as tenant_mismatch — and doubles every count a SOC rule thresholds on.
    /// </summary>
    [Fact]
    public async Task ACrossTenantCredentialIsCountedOnceNotTwice()
    {
        var a = await SeedTokenAsync("tenant-a");
        var b = await SeedTokenAsync("tenant-b");

        await Request($"Bearer {a.Raw}", b.OrgId).ResolveTokenAsync(_tokens, b.OrgId);

        var tally = Assert.Single(_coalescer.DrainWindow().Entries);
        Assert.Equal(1, tally.Count);
    }

    /// <summary>
    /// Repetition is the signal. A client looping with a revoked credential writes one row per
    /// window carrying the loop's size, not one row per attempt and not a single suppressed fact.
    /// </summary>
    [Fact]
    public async Task ARetryingCredentialIsCoalescedIntoOneCountedKey()
    {
        string credential = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("user:revoked-tok"));
        for (int i = 0; i < 25; i++)
        {
            await Request(credential, "org-target").ResolveTokenAsync(_tokens);
        }

        var tally = Assert.Single(_coalescer.DrainWindow().Entries);
        Assert.Equal(25, tally.Count);
    }
}
