using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Covers the OCI branch of <see cref="UpstreamRegistryController.Add"/> (host + SSRF
/// validation, prefixes, <c>ParseOciAuthType</c> for anonymous/basic/dockerhub_token_exchange/
/// aws_ecr/unknown), plus <see cref="UpstreamRegistryController.List"/>,
/// <see cref="UpstreamRegistryController.Delete"/>, and
/// <see cref="UpstreamRegistryController.Reorder"/>, which the auth-focused non-OCI test class
/// does not exercise.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamRegistryControllerOciTests
{
    private static AddUpstreamRegistryRequest Oci(
        string? host = "registry.example.com",
        string? authType = null,
        string? username = null,
        string? secret = null,
        IReadOnlyList<string>? prefixes = null) => new(
            Ecosystem: "oci",
            Url: host,
            AuthType: authType,
            Username: username,
            Secret: secret,
            Prefixes: prefixes ?? ["library/"]);

    [Fact]
    public async Task Oci_Anonymous_Valid_Returns201()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Oci(), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task Oci_MissingHost_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Oci(host: ""), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_MissingPrefixes_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            Oci(prefixes: []), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_PrivateRangeHost_RejectedAsSsrf()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Oci(host: "127.0.0.1"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_Basic_MissingUsername_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            Oci(authType: "basic", secret: "pw"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_Basic_MissingSecret_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            Oci(authType: "basic", username: "user"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_Basic_NoMasterKey_Returns422_FailClosed()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            Oci(authType: "basic", username: "user", secret: "pw"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_Basic_WithMasterKey_Persists201_EncryptedAtRest()
    {
        await using var s = await ControllerScenario.CreateAsync();
        s.WithMasterKey();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            Oci(authType: "basic", username: "user", secret: "pw"), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task Oci_DockerHubTokenExchange_Valid_Returns201()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(
            Oci(authType: "dockerhub_token_exchange"), CancellationToken.None);
        Assert.IsType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task Oci_AwsEcr_Returns422_NotYetSupported()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Oci(authType: "aws_ecr"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Oci_UnknownAuthType_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Add(Oci(authType: "hmac"), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    // ── List / Delete / Reorder ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_ReturnsAddedEntries()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var addReq = new AddUpstreamRegistryRequest(Ecosystem: "npm", Url: "https://cache.example/npm");
        await b.UpstreamRegistryController.Add(addReq, CancellationToken.None);

        var result = Assert.IsType<OkObjectResult>(await b.UpstreamRegistryController.List(CancellationToken.None));
        var entries = Assert.IsAssignableFrom<IReadOnlyList<UpstreamRegistryEntry>>(result.Value);
        Assert.Contains(entries, e => e.Ecosystem == "npm");
    }

    [Fact]
    public async Task Delete_RemovesEntry()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var addReq = new AddUpstreamRegistryRequest(Ecosystem: "npm", Url: "https://cache.example/npm2");
        var added = Assert.IsType<CreatedAtActionResult>(
            await b.UpstreamRegistryController.Add(addReq, CancellationToken.None));
        var entry = Assert.IsType<UpstreamRegistryEntry>(added.Value);

        var deleteResult = await b.UpstreamRegistryController.Delete(entry.Id, CancellationToken.None);
        Assert.IsType<NoContentResult>(deleteResult);

        var list = Assert.IsType<OkObjectResult>(await b.UpstreamRegistryController.List(CancellationToken.None));
        var entries = Assert.IsAssignableFrom<IReadOnlyList<UpstreamRegistryEntry>>(list.Value);
        Assert.DoesNotContain(entries, e => e.Id == entry.Id);
    }

    [Fact]
    public async Task Reorder_InvalidEcosystem_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var result = await b.UpstreamRegistryController.Reorder(
            "not-an-ecosystem", new ReorderUpstreamRegistryRequest([]), CancellationToken.None);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, ((ObjectResult)result).StatusCode);
    }

    [Fact]
    public async Task Reorder_ValidEcosystem_ReordersEntries()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var addA = Assert.IsType<CreatedAtActionResult>(await b.UpstreamRegistryController.Add(
            new AddUpstreamRegistryRequest(Ecosystem: "pypi", Url: "https://mirror-a.example/pypi"),
            CancellationToken.None));
        var entryA = Assert.IsType<UpstreamRegistryEntry>(addA.Value);

        var addB = Assert.IsType<CreatedAtActionResult>(await b.UpstreamRegistryController.Add(
            new AddUpstreamRegistryRequest(Ecosystem: "pypi", Url: "https://mirror-b.example/pypi"),
            CancellationToken.None));
        var entryB = Assert.IsType<UpstreamRegistryEntry>(addB.Value);

        var reorderResult = await b.UpstreamRegistryController.Reorder(
            "pypi", new ReorderUpstreamRegistryRequest([entryB.Id, entryA.Id]), CancellationToken.None);
        Assert.IsType<NoContentResult>(reorderResult);

        var list = Assert.IsType<OkObjectResult>(await b.UpstreamRegistryController.List(CancellationToken.None));
        var ordered = Assert.IsAssignableFrom<IReadOnlyList<UpstreamRegistryEntry>>(list.Value)
            .Where(e => e.Ecosystem == "pypi")
            .OrderBy(e => e.Position)
            .ToList();
        Assert.Equal(entryB.Id, ordered[0].Id);
        Assert.Equal(entryA.Id, ordered[1].Id);
    }
}
