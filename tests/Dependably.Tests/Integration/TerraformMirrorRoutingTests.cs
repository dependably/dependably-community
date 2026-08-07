using System.Net;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Routing-level behaviour of the Terraform mirror's catch-all, which only surfaces once model
/// binding and the <c>[ApiController]</c> filters have run — below the level a controller-object
/// test reaches.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TerraformMirrorRoutingTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public TerraformMirrorRoutingTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    // The bare base URL — what an operator probes first when checking a mirror is reachable, and
    // what a client sees if a `.terraformrc` names the base with no provider beneath it. The
    // trailing-slash form binds an empty path rather than a missing one and must answer the same.
    [InlineData("/terraform")]
    [InlineData("/terraform/")]
    public async Task TheBareBaseUrl_Returns404(string path)
    {
        // A catch-all `{**path}` matches zero segments, so the bare base reaches this action rather
        // than the SPA fallback. With a non-nullable parameter the [ApiController] model-state
        // filter answers 400 "The path field is required" before the action body runs — an answer
        // that says nothing useful to a client probing the base, and one that leaves the action's
        // own empty-path guard unreachable. 404 is the protocol's answer for "not mirrored here".
        using var client = _factory.CreateClient();
        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
