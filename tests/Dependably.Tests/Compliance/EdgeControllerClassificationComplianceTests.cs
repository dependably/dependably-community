using Dependably.Infrastructure.Edge;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the headless edge surface. Every non-abstract controller in the
/// application assembly MUST be explicitly classified Protocol or Management in
/// <see cref="EdgeSurfaceRegistry"/>. An unclassified controller fails the build with its name —
/// this converts the "management plane absent on an edge" guarantee from a fail-open denylist
/// (a new route reachable-by-default on every edge) into a fail-closed compile-time fact.
///
/// It also asserts the two families are disjoint and that the known protocol/management anchors
/// land on the right side, so a mis-move (classifying a protocol surface as management, which
/// would 404 real package pulls on an edge) is caught too.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class EdgeControllerClassificationComplianceTests
{
    private readonly ITestOutputHelper _output;
    public EdgeControllerClassificationComplianceTests(ITestOutputHelper output) => _output = output;

    private static IEnumerable<Type> AllControllers() =>
        typeof(Dependably.Api.PyPiController).Assembly
            .GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal));

    [Fact]
    public void EveryControllerIsExplicitlyClassified()
    {
        var unclassified = AllControllers()
            .Where(t => EdgeSurfaceRegistry.Classify(t) is null)
            .Select(t => t.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        if (unclassified.Count > 0)
        {
            _output.WriteLine("Unclassified controllers (add each to EdgeSurfaceRegistry):");
            unclassified.ForEach(_output.WriteLine);
        }

        Assert.True(
            unclassified.Count == 0,
            $"{unclassified.Count} controller(s) are not classified Protocol/Management in "
            + "EdgeSurfaceRegistry. A new controller must be placed on the correct edge surface — "
            + "Protocol (kept on an edge) or Management (stripped): "
            + string.Join(", ", unclassified));
    }

    [Fact]
    public void ProtocolAndManagementAnchorsAreClassifiedCorrectly()
    {
        // Sanity anchors: a mis-classification (protocol → management) would 404 real package
        // pulls on an edge, and (management → protocol) would leak the admin plane onto one.
        Assert.Equal(EdgeSurface.Protocol, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.NpmController)));
        Assert.Equal(EdgeSurface.Protocol, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.OciController)));
        Assert.Equal(EdgeSurface.Protocol, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.CargoController)));
        Assert.Equal(EdgeSurface.Management, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.OrgController)));
        Assert.Equal(EdgeSurface.Management, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.AuthController)));
        Assert.Equal(EdgeSurface.Management, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.SamlController)));
        Assert.Equal(EdgeSurface.Management, EdgeSurfaceRegistry.Classify(typeof(Dependably.Api.SystemController)));
    }

    [Fact]
    public void UnknownControllerFailsClosed_SelfTest()
    {
        // The gate's contract: an unknown controller type returns null (unclassified) and the
        // stripping convention treats null as non-protocol (stripped). This pins the fail-closed
        // default so a future refactor of Classify can't silently flip it open.
        Assert.Null(EdgeSurfaceRegistry.Classify(typeof(EdgeControllerClassificationComplianceTests)));
        Assert.False(EdgeSurfaceRegistry.IsProtocol(typeof(EdgeControllerClassificationComplianceTests)));
    }
}
