using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Cover for the management-plane field bounds added alongside #636 (F8).
///
/// <para>
/// No request DTO in <c>src/Dependably.Management/Api/</c> uses DataAnnotations, so
/// <c>[ApiController]</c>'s automatic <c>ModelState</c> 400 validates JSON shape and nothing about
/// values. Validation is hand-written guard clauses per action — a legitimate decision under
/// <c>InputValidationDecisionComplianceTests</c>, whose own doc states it cannot prove a check is
/// "correct, complete (covers every field), or that it runs before the parameter is used". These
/// are that documented blind spot: fields whose own siblings on the same request were capped while
/// they were not.
/// </para>
///
/// <para>
/// SQLite ignores <c>VARCHAR(n)</c> entirely, so the column is never the backstop — the guard clause
/// is the only bound that exists.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ManagementFieldBoundsTests
{
    private static async Task<ControllerScenarioResult> AdminAsync()
    {
        var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "admin");
        return await s.BuildAsync();
    }

    private static string Long(int n) => new('a', n);

    /// <summary>
    /// A minimal valid capability set. Required: without one the request is refused with "At least
    /// one capability is required" BEFORE the name checks run, so every assertion below would be
    /// measuring the capability guard rather than the bound under test.
    /// </summary>
    private static readonly string[] Caps = ["read:packages"];

    /// <summary>
    /// A refused write is <c>ObjectResult</c> with status 422 (ProblemResults.ValidationErrorAction).
    /// Asserted explicitly rather than as "not the success type": the success results here are
    /// <c>CreatedAtActionResult</c> and <c>NoContentResult</c>, so a negative assertion against
    /// <c>OkObjectResult</c> would pass whether or not the bound fired.
    /// </summary>
    private static void AssertRefused(IActionResult result)
    {
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
    }

    // The allowlist was the only one of OrgListsController's four lists with no length cap; the
    // blocklist, reserved-namespace and install-script arms all had one.
    [Fact]
    public async Task Allowlist_OverlongPurlPattern_Refused()
    {
        await using var b = await AdminAsync();

        var result = await b.OrgListsController.AddAllowlist(
            new AllowlistRequest("pkg:npm/" + Long(600)), CancellationToken.None);

        AssertRefused(result);
    }

    [Fact]
    public async Task Allowlist_OrdinaryPattern_StillAccepted()
    {
        await using var b = await AdminAsync();

        var result = await b.OrgListsController.AddAllowlist(
            new AllowlistRequest("pkg:npm/left-pad@1.3.0"), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
    }

    // Name sits beside Description, which TryNormalizeDescription already caps at 200 and screens
    // for control characters — with a comment explaining that operators read this string in a table
    // and \r\n breaks the row. Name is the more visible field and had neither check.
    [Fact]
    public async Task ServiceToken_OverlongName_Refused()
    {
        await using var b = await AdminAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest(Long(500), null, Caps), CancellationToken.None);

        AssertRefused(result);
    }

    [Theory]
    [InlineData("ci\ntoken")]
    [InlineData("ci\rtoken")]
    [InlineData("ci\ttoken")]
    public async Task ServiceToken_ControlCharacterInName_Refused(string name)
    {
        await using var b = await AdminAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest(name, null, Caps), CancellationToken.None);

        AssertRefused(result);
    }

    [Fact]
    public async Task ServiceToken_OrdinaryName_StillAccepted()
    {
        await using var b = await AdminAsync();

        var result = await b.OrgTokensController.CreateServiceToken(
            new CreateServiceTokenRequest("ci-publisher", null, Caps), CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
    }

    // ReorderAsync does a full O(n) pass over this list before filtering it to the org's own
    // registries, so every id past the real set is work spent on input that is then discarded.
    [Fact]
    public async Task UpstreamReorder_OverlongIdList_Refused()
    {
        await using var b = await AdminAsync();

        var result = await b.UpstreamRegistryController.Reorder(
            "npm",
            new ReorderUpstreamRegistryRequest(Enumerable.Range(0, 5_000).Select(i => $"id-{i}").ToList()),
            CancellationToken.None);

        AssertRefused(result);
    }

    [Fact]
    public async Task UpstreamReorder_OrdinaryIdList_StillAccepted()
    {
        await using var b = await AdminAsync();

        var result = await b.UpstreamRegistryController.Reorder(
            "npm", new ReorderUpstreamRegistryRequest(["id-1", "id-2"]), CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }
}
