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

    // Protocol controllers live in Dependably.Core (anchored on a moved protocol controller);
    // management controllers live in Dependably.Management beside EdgeSurfaceRegistry. Enumerate
    // both so the classification gate sees every controller regardless of which assembly owns it.
    private static readonly System.Reflection.Assembly CoreAssembly =
        typeof(Dependably.Api.PyPiController).Assembly;

    private static readonly System.Reflection.Assembly ManagementAssembly =
        typeof(EdgeSurfaceRegistry).Assembly;

    // The composition-root assembly (Dependably), anchored on Program. It hosts no controllers —
    // they all live in the two class libraries — which the RootAssembly test below pins.
    private static readonly System.Reflection.Assembly RootAssembly =
        typeof(Program).Assembly;

    // The edge composition root (Dependably.Edge). Like the full root it is a thin bootstrap: the
    // protocol controllers it serves come from Dependably.Core as an application part, so the edge
    // ASSEMBLY itself hosts zero controllers. Loaded by name from the test output dir (a plain
    // reference by name keeps this gate independent of the extern alias the integration tests use).
    private static readonly System.Reflection.Assembly EdgeRootAssembly =
        System.Reflection.Assembly.Load("Dependably.Edge");

    private static IEnumerable<Type> ControllersIn(System.Reflection.Assembly assembly) =>
        assembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal));

    private static IEnumerable<Type> AllControllers() =>
        new[] { CoreAssembly, ManagementAssembly }
            .Distinct()
            .SelectMany(ControllersIn);

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
    public void ClassifiedControllersLiveInTheirSurfaceAssembly()
    {
        // Per-surface assembly invariant: Protocol-classified controllers live in Dependably.Core
        // (the edge image references Core, so they ship on an edge), and Management-classified
        // controllers live in the root assembly that defines EdgeSurfaceRegistry (stripped from the
        // edge closure). A mis-move — a protocol controller left in root, or a management controller
        // that drifted into Core — is a strayed classification and fails here. Each EdgeSurface value
        // maps to exactly one owning assembly.
        var allowedBySurface = new Dictionary<EdgeSurface, System.Reflection.Assembly>
        {
            [EdgeSurface.Protocol] = CoreAssembly,
            [EdgeSurface.Management] = ManagementAssembly,
        };

        var classified = AllControllers()
            .Select(t => (Type: t, Surface: EdgeSurfaceRegistry.Classify(t)))
            .Where(x => x.Surface is not null)
            .ToList();

        Assert.NotEmpty(classified);

        var strays = classified
            .Where(x => x.Type.Assembly != allowedBySurface[x.Surface!.Value])
            .Select(x =>
                $"{x.Type.FullName} classified {x.Surface} lives in {x.Type.Assembly.GetName().Name} "
                + $"(expected {allowedBySurface[x.Surface!.Value].GetName().Name})")
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        if (strays.Count > 0)
        {
            _output.WriteLine("Controllers not in their surface's owning assembly:");
            strays.ForEach(_output.WriteLine);
        }

        Assert.True(
            strays.Count == 0,
            $"{strays.Count} controller(s) do not live in their edge surface's owning assembly "
            + $"(Protocol => {CoreAssembly.GetName().Name}, Management => {ManagementAssembly.GetName().Name}).");
    }

    [Fact]
    public void RootCompositionAssemblyHostsNoControllers()
    {
        // The two-assembly invariant's third leg: after the management extraction, the composition
        // root (Dependably) is a thin bootstrap that owns only Program — every controller lives in
        // Dependably.Core (protocol) or Dependably.Management (management). A controller drifting
        // back into the root would ship in both the community and the edge image regardless of its
        // edge surface, defeating the reference-graph attack-surface reduction. Pin zero here.
        var rootControllers = ControllersIn(RootAssembly)
            .Select(t => t.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        if (rootControllers.Count > 0)
        {
            _output.WriteLine("Controllers found in the root composition assembly (move to Core or Management):");
            rootControllers.ForEach(_output.WriteLine);
        }

        Assert.True(
            rootControllers.Count == 0,
            $"{rootControllers.Count} controller(s) live in the composition-root assembly "
            + $"({RootAssembly.GetName().Name}); controllers must live in Dependably.Core (protocol) "
            + $"or Dependably.Management (management): {string.Join(", ", rootControllers)}");
    }

    [Fact]
    public void EdgeCompositionAssemblyHostsNoControllers()
    {
        // The edge composition root serves protocol controllers via a Dependably.Core application
        // part; the edge assembly itself defines none. A controller drifting into the edge assembly
        // would be a controller that ships ONLY on the edge image — outside the two-assembly
        // classification the gate enumerates — so pin zero here to keep the enumeration exhaustive.
        var edgeControllers = ControllersIn(EdgeRootAssembly)
            .Select(t => t.FullName!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        if (edgeControllers.Count > 0)
        {
            _output.WriteLine("Controllers found in the edge composition assembly (move to Core):");
            edgeControllers.ForEach(_output.WriteLine);
        }

        Assert.True(
            edgeControllers.Count == 0,
            $"{edgeControllers.Count} controller(s) live in the edge composition assembly "
            + $"({EdgeRootAssembly.GetName().Name}); the edge serves protocol controllers from "
            + $"Dependably.Core as an application part and defines none of its own: "
            + string.Join(", ", edgeControllers));
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
