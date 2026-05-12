using System.Security.Claims;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers <see cref="OrgAccessGuard.AuthorizeCapAsync"/> and
/// <see cref="OrgAccessGuard.CheckCapAsync"/> — the capability-driven variants added in PR-1
/// of the role→capability migration. The 404-on-stranger invariant (BOLA / slug enumeration
/// closure) must hold the same way the role-based path enforces it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgAccessGuardTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private OrgAccessGuard _guard = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _guard = new OrgAccessGuard(_db);

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme'), ('o2','other')");
        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES
                ('u-member',  'o1', 'm@example.com', '', 'member'),
                ('u-admin',   'o1', 'a@example.com', '', 'admin'),
                ('u-owner',   'o1', 'o@example.com', '', 'owner'),
                ('u-auditor', 'o1', 'au@example.com', '', 'auditor'),
                ('u-other',   'o2', 's@example.com', '', 'admin')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static ClaimsPrincipal Principal(string userId, params (string Type, string Value)[] extraClaims)
    {
        var claims = new List<Claim> { new("sub", userId) };
        claims.AddRange(extraClaims.Select(c => new Claim(c.Type, c.Value)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private static DefaultHttpContext HttpContextFor(string tenantId, string slug = "acme")
    {
        var ctx = new DefaultHttpContext();
        ctx.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(tenantId, slug);
        return ctx;
    }

    // ── CheckCapAsync ───────────────────────────────────────────────────────────

    [Fact]
    public async Task CheckCapAsync_MemberHasReadMetadata_Allowed()
    {
        var result = await _guard.CheckCapAsync(
            Principal("u-member"), "u-member", "o1", Capabilities.ReadMetadata);
        Assert.Equal(OrgAccessGuard.AccessResult.Allowed, result);
    }

    [Fact]
    public async Task CheckCapAsync_MemberLacksTenantConfigure_Forbidden()
    {
        var result = await _guard.CheckCapAsync(
            Principal("u-member"), "u-member", "o1", Capabilities.TenantConfigure);
        Assert.Equal(OrgAccessGuard.AccessResult.Forbidden, result);
    }

    [Fact]
    public async Task CheckCapAsync_AdminHasTenantConfigureAndReadAudit_Allowed()
    {
        var configure = await _guard.CheckCapAsync(
            Principal("u-admin"), "u-admin", "o1", Capabilities.TenantConfigure);
        var audit = await _guard.CheckCapAsync(
            Principal("u-admin"), "u-admin", "o1", Capabilities.ReadAudit);
        Assert.Equal(OrgAccessGuard.AccessResult.Allowed, configure);
        Assert.Equal(OrgAccessGuard.AccessResult.Allowed, audit);
    }

    [Fact]
    public async Task CheckCapAsync_AdminLacksTenantAdmin_Forbidden()
    {
        // tenant:admin stays owner-only — the only owner-distinguishing capability.
        var result = await _guard.CheckCapAsync(
            Principal("u-admin"), "u-admin", "o1", Capabilities.TenantAdmin);
        Assert.Equal(OrgAccessGuard.AccessResult.Forbidden, result);
    }

    [Fact]
    public async Task CheckCapAsync_OwnerHasTenantAdmin_Allowed()
    {
        var result = await _guard.CheckCapAsync(
            Principal("u-owner"), "u-owner", "o1", Capabilities.TenantAdmin);
        Assert.Equal(OrgAccessGuard.AccessResult.Allowed, result);
    }

    [Fact]
    public async Task CheckCapAsync_AuditorReadsAuditButNotPublish()
    {
        var audit = await _guard.CheckCapAsync(
            Principal("u-auditor"), "u-auditor", "o1", Capabilities.ReadAudit);
        var publish = await _guard.CheckCapAsync(
            Principal("u-auditor"), "u-auditor", "o1", Capabilities.PublishNpm);
        Assert.Equal(OrgAccessGuard.AccessResult.Allowed, audit);
        Assert.Equal(OrgAccessGuard.AccessResult.Forbidden, publish);
    }

    [Fact]
    public async Task CheckCapAsync_CrossTenant_NotFound()
    {
        // u-other is a member of o2, not o1. Calling against o1 must 404 (not 403) so the
        // slug isn't enumerable.
        var result = await _guard.CheckCapAsync(
            Principal("u-other"), "u-other", "o1", Capabilities.ReadMetadata);
        Assert.Equal(OrgAccessGuard.AccessResult.NotFound, result);
    }

    [Fact]
    public async Task CheckCapAsync_UnknownUser_NotFound()
    {
        var result = await _guard.CheckCapAsync(
            Principal("ghost"), "ghost", "o1", Capabilities.ReadMetadata);
        Assert.Equal(OrgAccessGuard.AccessResult.NotFound, result);
    }

    [Fact]
    public async Task CheckCapAsync_ExplicitCapClaims_NarrowBelowRole()
    {
        // u-admin's role would grant publish:* via ForRole, but the principal also carries
        // explicit cap claims that narrow to read:artifact only. The explicit set must win.
        var principal = Principal("u-admin",
            ("cap", Capabilities.ReadArtifact));
        var canRead = await _guard.CheckCapAsync(
            principal, "u-admin", "o1", Capabilities.ReadArtifact);
        var canPublish = await _guard.CheckCapAsync(
            principal, "u-admin", "o1", Capabilities.PublishNpm);
        Assert.Equal(OrgAccessGuard.AccessResult.Allowed, canRead);
        Assert.Equal(OrgAccessGuard.AccessResult.Forbidden, canPublish);
    }

    // ── AuthorizeCapAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task AuthorizeCapAsync_AdminWithTenantConfigure_AllowsNull()
    {
        var http = HttpContextFor("o1");
        var result = await _guard.AuthorizeCapAsync(
            Principal("u-admin"), http, Capabilities.TenantConfigure);
        Assert.Null(result);
    }

    [Fact]
    public async Task AuthorizeCapAsync_MemberAttemptsTenantConfigure_Forbid()
    {
        var http = HttpContextFor("o1");
        var result = await _guard.AuthorizeCapAsync(
            Principal("u-member"), http, Capabilities.TenantConfigure);
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task AuthorizeCapAsync_CrossTenantUser_NotFound()
    {
        var http = HttpContextFor("o1");
        var result = await _guard.AuthorizeCapAsync(
            Principal("u-other"), http, Capabilities.ReadMetadata);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task AuthorizeCapAsync_MissingTenantContext_NotFound()
    {
        // Apex / uninitialized / missing context routes return 404 rather than 403 —
        // the guard refuses to authorize a request that hasn't been tenant-resolved.
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.Apex;
        var result = await _guard.AuthorizeCapAsync(
            Principal("u-admin"), http, Capabilities.ReadMetadata);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task AuthorizeCapAsync_NoSubjectClaim_Unauthorized()
    {
        var http = HttpContextFor("o1");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(Array.Empty<Claim>(), "test"));
        var result = await _guard.AuthorizeCapAsync(
            principal, http, Capabilities.ReadMetadata);
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task AuthorizeCapAsync_OwnerOps_TenantAdmin_AllowsOwner()
    {
        var http = HttpContextFor("o1");
        var result = await _guard.AuthorizeCapAsync(
            Principal("u-owner"), http, Capabilities.TenantAdmin);
        Assert.Null(result);
    }

    [Fact]
    public async Task AuthorizeCapAsync_OwnerOps_TenantAdmin_ForbidsAdmin()
    {
        // Owner-distinguishing operations (modifying owners, granting owner role) require
        // tenant:admin. Admin has tenant:configure for the rest of PatchMemberRole/RemoveUser
        // but must 403 here. The endpoint runs tenant:configure first, then this stricter
        // check inside the handler when the target/grant touches an owner.
        var http = HttpContextFor("o1");
        var result = await _guard.AuthorizeCapAsync(
            Principal("u-admin"), http, Capabilities.TenantAdmin);
        Assert.IsType<ForbidResult>(result);
    }
}
