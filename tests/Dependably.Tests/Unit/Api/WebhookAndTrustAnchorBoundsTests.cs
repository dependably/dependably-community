using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Cover for the two field bounds that shipped in #636 (F8) without tests, because
/// <see cref="ControllerScenario"/> exposed neither controller at the time:
/// <c>WebhookRequest.Description</c> and <c>AddTrustAnchorRequest.Material</c>/<c>Label</c>.
///
/// <para>
/// Both bounds were argued by analogy to the four that were covered. Analogy is a reason to expect
/// a thing works, not evidence that it does — which is what #638 exists to close.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class WebhookAndTrustAnchorBoundsTests
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
    /// A refused write is <c>ObjectResult</c> with status 422. Asserted explicitly rather than as
    /// "not the success type": both handlers return <c>CreatedAtActionResult</c> on success, so a
    /// negative assertion against <c>OkObjectResult</c> would pass whether or not the bound fired.
    /// </summary>
    private static ProblemDetails AssertRefused(IActionResult result)
    {
        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, obj.StatusCode);
        return Assert.IsAssignableFrom<ProblemDetails>(obj.Value);
    }

    private static WebhookRequest Hook(string? description = null) => new()
    {
        Url = "https://hooks.example.com/dependably",
        EventTypes = ["package.publish"],
        Description = description,
    };

    // ── Webhook description ──────────────────────────────────────────────────

    [Fact]
    public async Task Webhook_OverlongDescription_Refused()
    {
        await using var b = await AdminAsync();

        var result = await b.WebhookController.Add(Hook(Long(2000)), CancellationToken.None);

        var problem = AssertRefused(result);
        Assert.Contains("Description", problem.Detail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Webhook_OrdinaryDescription_StillAccepted()
    {
        await using var b = await AdminAsync();

        var result = await b.WebhookController.Add(
            Hook("Publishes to the release channel."), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task Webhook_NoDescription_StillAccepted()
    {
        await using var b = await AdminAsync();

        var result = await b.WebhookController.Add(Hook(), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);
    }

    // The same bound applies on update, which takes the same DTO through the same validator.
    [Fact]
    public async Task Webhook_OverlongDescriptionOnUpdate_Refused()
    {
        await using var b = await AdminAsync();
        var created = Assert.IsType<CreatedAtActionResult>(
            await b.WebhookController.Add(Hook("initial"), CancellationToken.None));
        string id = created.RouteValues!["id"]!.ToString()!;

        var result = await b.WebhookController.Update(id, Hook(Long(2000)), CancellationToken.None);

        AssertRefused(result);
    }

    // ── Trust-anchor material and label ──────────────────────────────────────

    // rpm/pgp is a registered pair, so the request gets past the pair gate and reaches the length
    // checks. The material is not valid PGP — deliberately: the point is that the LENGTH check
    // refuses it before the parser ever sees it, which is the whole reason the bound exists.
    [Fact]
    public async Task TrustAnchor_OverlongMaterial_Refused()
    {
        await using var b = await AdminAsync();

        var result = await b.TrustAnchorController.Add(
            new AddTrustAnchorRequest("rpm", "pgp", Long(70 * 1024)), CancellationToken.None);

        var problem = AssertRefused(result);
        Assert.Contains("Material", problem.Detail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TrustAnchor_OverlongLabel_Refused()
    {
        await using var b = await AdminAsync();

        var result = await b.TrustAnchorController.Add(
            new AddTrustAnchorRequest("rpm", "pgp", "-----BEGIN PGP PUBLIC KEY BLOCK-----", Long(500)),
            CancellationToken.None);

        var problem = AssertRefused(result);
        Assert.Contains("Label", problem.Detail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // Discriminates the length check from every other refusal on this path: short-but-invalid
    // material is still refused, but for a different stated reason. Without this, a test asserting
    // only "422" would pass even if the length check were deleted, because the parser refuses the
    // material anyway.
    [Fact]
    public async Task TrustAnchor_ShortInvalidMaterial_RefusedForADifferentReason()
    {
        await using var b = await AdminAsync();

        var result = await b.TrustAnchorController.Add(
            new AddTrustAnchorRequest("rpm", "pgp", "not-a-key"), CancellationToken.None);

        var problem = AssertRefused(result);
        Assert.DoesNotContain("characters or fewer", problem.Detail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TrustAnchor_UnregisteredPair_RefusedBeforeTheLengthChecks()
    {
        await using var b = await AdminAsync();

        var result = await b.TrustAnchorController.Add(
            new AddTrustAnchorRequest("rpm", "x509", Long(70 * 1024)), CancellationToken.None);

        var problem = AssertRefused(result);
        Assert.DoesNotContain("characters or fewer", problem.Detail ?? "", StringComparison.OrdinalIgnoreCase);
    }
}
