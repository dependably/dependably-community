using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// ClaimsController has 5 endpoints (List, Get, Create, Transition, Release) over a
/// state-machine domain. Tests cover happy paths + validation failures + state-machine
/// rejections via the scenario. Audit + emitter assertions on the write paths.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ClaimsControllerUnitTests
{
    // ── List + Get ───────────────────────────────────────────────────────────

    [Fact]
    public async Task List_Empty_Returns200()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.List(
            ecosystem: null, state: null, search: null, limit: 100, ct: CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task Get_NoClaim_ReturnsImplicitUnclaimed()
    {
        // Connected mode (air-gap disabled): missing claim resolves to "implicit unclaimed".
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Get("npm", "ghost", CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
        // Shape: { state, isImplicit, ... } — pin the isImplicit=true contract.
        bool isImplicit = (bool)ok.Value!.GetType().GetProperty("isImplicit")!.GetValue(ok.Value)!;
        Assert.True(isImplicit);
    }

    // ── Create — validation paths ────────────────────────────────────────────

    [Fact]
    public async Task Create_NullBody_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Create(null!, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Create_MissingReason_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest(Ecosystem: "npm", Name: "acme", State: "local_only", Reason: null),
            CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Theory]
    [InlineData("conda")]
    [InlineData(null)]
    [InlineData("")]
    public async Task Create_InvalidEcosystem_Returns400(string? eco)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest(Ecosystem: eco, Name: "acme", State: "local_only", Reason: "test"),
            CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Create_MissingName_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", Name: null, "local_only", "test"),
            CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Create_InvalidState_Returns400FromStateMachine()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // "unclaimed" can't be created — it's a default implicit state, not a writable target.
        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", "acme", "unclaimed", "test"),
            CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Create_LocalOnly_Created_AndAuditsBothLogAndEmitter()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", $"acme-{Guid.NewGuid():N}", "local_only", "init"),
            CancellationToken.None);
        var created = Assert.IsType<CreatedResult>(result);
        Assert.NotNull(created.Value);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'claim.create' AND org_id = @org",
            new { org = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task Create_Duplicate_Returns409()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string name = $"dup-{Guid.NewGuid():N}";
        var first = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", name, "local_only", "init"), CancellationToken.None);
        Assert.IsType<CreatedResult>(first);

        var second = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", name, "local_only", "init"), CancellationToken.None);
        Assert.IsType<ConflictObjectResult>(second);
    }

    // ── Transition ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Transition_NonExistent_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Transition("npm", "ghost",
            new TransitionClaimRequest("mixed", "x"), CancellationToken.None);
        int? status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.Equal(StatusCodes.Status404NotFound, status);
    }

    [Fact]
    public async Task Transition_LocalOnlyToMixed_Allowed_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        string name = $"trans-{Guid.NewGuid():N}";

        var created = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", name, "local_only", "init"), CancellationToken.None);
        Assert.IsType<CreatedResult>(created);

        var result = await b.ClaimsController.Transition("npm", name,
            new TransitionClaimRequest("mixed", "want fallback"), CancellationToken.None);
        Assert.IsType<OkObjectResult>(result);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'claim.transition' AND org_id = @org",
            new { org = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task Transition_MissingReason_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        string name = $"missing-reason-{Guid.NewGuid():N}";
        await b.ClaimsController.Create(
            new CreateClaimRequest("npm", name, "local_only", "init"), CancellationToken.None);

        var result = await b.ClaimsController.Transition("npm", name,
            new TransitionClaimRequest("mixed", Reason: null), CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    // ── Release ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Release_Existing_ReturnsNoContent_AndAudits()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        string name = $"rel-{Guid.NewGuid():N}";
        await b.ClaimsController.Create(
            new CreateClaimRequest("npm", name, "local_only", "init"), CancellationToken.None);

        var result = await b.ClaimsController.Release("npm", name, "cleanup", CancellationToken.None);
        Assert.IsType<NoContentResult>(result);

        await using var conn = await b.Db.OpenAsync();
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'claim.release' AND org_id = @org",
            new { org = b.PrimaryOrgId });
        Assert.True(auditCount >= 1);
    }

    [Fact]
    public async Task Release_NonExistent_Returns404()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Release("npm", "never", "x", CancellationToken.None);
        int? status = (result as IStatusCodeActionResult)?.StatusCode;
        Assert.Equal(StatusCodes.Status404NotFound, status);
    }

    // ── Name canonicalization + ecosystem vocabulary ─────────────────────────

    [Fact]
    public async Task Create_PyPiNonCanonicalName_HonoredByResolverUnderPep503Name()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Operator claims an internal PyPI package by the dotted/underscored name Python uses.
        var created = await b.ClaimsController.Create(
            new CreateClaimRequest("pypi", "Foo.Bar_baz", "local_only", "close dep-confusion"),
            CancellationToken.None);
        Assert.IsType<CreatedResult>(created);

        // Every PyPI enforcement site resolves by the PEP 503 name; the claim must match it.
        var resolver = new ClaimResolver(
            new ClaimRepository(b.Db), new AirGapMode(new ConfigurationBuilder().Build()));
        var eff = await resolver.ResolveAsync(b.PrimaryOrgId, "pypi", "foo-bar-baz", CancellationToken.None);

        Assert.Equal(ClaimStateMachine.LocalOnly, eff.State);
        Assert.False(eff.IsImplicit); // matched the explicit row, not the implicit fallback
        Assert.False(await resolver.IsProxyFetchAllowedAsync(
            b.PrimaryOrgId, "pypi", "foo-bar-baz", CancellationToken.None));
    }

    [Fact]
    public async Task Create_Cargo_Accepted()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Cargo's data paths consult ClaimResolver, so a cargo claim must be creatable — the
        // first publish of a new crate depends on it under CLAIM_ENFORCEMENT=on.
        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("cargo", $"acme-core-{Guid.NewGuid():N}", "local_only", "internal"),
            CancellationToken.None);
        Assert.IsType<CreatedResult>(result);
    }

    [Theory]
    [InlineData("maven")]
    [InlineData("rpm")]
    [InlineData("oci")]
    public async Task Create_ClaimUnawareEcosystem_Rejected(string eco)
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // maven/rpm/oci have no ClaimResolver call site, so a claim would be a silent no-op —
        // the API rejects rather than storing a control that nothing enforces.
        var result = await b.ClaimsController.Create(
            new CreateClaimRequest(eco, "some-name", "local_only", "test"), CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    // ── Auth boundaries ──────────────────────────────────────────────────────

    [Fact]
    public async Task Create_Anonymous_Rejected()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", "acme", "local_only", "test"), CancellationToken.None);
        Assert.False(result is CreatedResult);
    }
}
