using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Covers the <c>protocol</c> field on <see cref="UpstreamRegistryController.Add"/> — the
/// management-plane write/read path for <c>upstream_registry.upstream_protocol</c>, which is
/// Terraform-only (see <c>ADR-terraform-provider-network-mirror</c>).
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamRegistryControllerProtocolTests
{
    private static AddUpstreamRegistryRequest Terraform(string? protocol) => new(
        Ecosystem: "terraform", Url: "https://mirror.example/terraform", Protocol: protocol);

    [Fact]
    public async Task UnsupportedProtocolValue_Returns422_AndPersistsNothing()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Terraform("registry"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
        var list = Assert.IsType<OkObjectResult>(await b.UpstreamRegistryController.List(CancellationToken.None));
        Assert.Empty(Assert.IsAssignableFrom<IReadOnlyList<UpstreamRegistryEntry>>(list.Value));
    }

    [Fact]
    public async Task ProtocolOnNonTerraformEcosystem_Returns422()
    {
        // Every other ecosystem serves the same protocol it fetches, so the field has nothing to
        // discriminate; accepting it silently would be a no-op that reads as configuration.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var req = new AddUpstreamRegistryRequest(
            Ecosystem: "npm", Url: "https://cache.example/npm", Protocol: "mirror");
        var result = await b.UpstreamRegistryController.Add(req, CancellationToken.None);

        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task MirrorProtocol_Terraform_Persists201_AndRoundTripsThroughList()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var added = Assert.IsType<CreatedAtActionResult>(
            await b.UpstreamRegistryController.Add(Terraform("mirror"), CancellationToken.None));
        var entry = Assert.IsType<UpstreamRegistryEntry>(added.Value);
        Assert.Equal("mirror", entry.Protocol);

        var list = Assert.IsType<OkObjectResult>(await b.UpstreamRegistryController.List(CancellationToken.None));
        var entries = Assert.IsAssignableFrom<IReadOnlyList<UpstreamRegistryEntry>>(list.Value);
        var listed = Assert.Single(entries, e => e.Ecosystem == "terraform");
        Assert.Equal("mirror", listed.Protocol);
    }

    [Fact]
    public async Task NoProtocol_Terraform_Persists201_WithNullProtocol()
    {
        // The default (Provider Registry Protocol) is the unset column — must not be coerced to
        // some non-null sentinel that a later comparison could misread as "mirror".
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var added = Assert.IsType<CreatedAtActionResult>(
            await b.UpstreamRegistryController.Add(Terraform(null), CancellationToken.None));
        var entry = Assert.IsType<UpstreamRegistryEntry>(added.Value);
        Assert.Null(entry.Protocol);

        var list = Assert.IsType<OkObjectResult>(await b.UpstreamRegistryController.List(CancellationToken.None));
        var entries = Assert.IsAssignableFrom<IReadOnlyList<UpstreamRegistryEntry>>(list.Value);
        Assert.Null(Assert.Single(entries, e => e.Ecosystem == "terraform").Protocol);
    }
}
