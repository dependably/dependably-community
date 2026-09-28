using System.Reflection;
using System.Text.RegularExpressions;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Usage;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every routed GET on a protocol controller declares whether its response bodies are metered as
/// egress: it carries <see cref="MeteredEgressAttribute"/> (on the action or its controller), or an
/// <c>// egress-ok: &lt;reason&gt;</c> marker in the five lines above its declaration naming why it
/// is not billed.
///
/// Egress is the metered dimension that scales with a tenant's traffic, and a protocol GET that
/// quietly carries no attribute is bytes served and never billed — an absence no reviewer sees in
/// a diff. So the decision has to be written down per action, the same fail-closed shape as the
/// rate-limit gate.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class MeteredEgressComplianceTests
{
    private readonly ITestOutputHelper _output;
    public MeteredEgressComplianceTests(ITestOutputHelper output) => _output = output;

    private const string Marker = "egress-ok:";
    private const int MarkerWindow = 5;

    private static readonly Assembly CoreAssembly = typeof(Dependably.Api.PyPiController).Assembly;

    [Fact]
    public void EveryProtocolGetDeclaresItsEgressMetering()
    {
        var controllers = ProtocolControllers().ToList();
        Assert.True(controllers.Count >= 9, $"only {controllers.Count} protocol controllers found");

        int gets = 0;
        var violations = new List<string>();
        foreach (var controller in controllers)
        {
            string[] source = SourceLinesFor(controller);
            foreach (var action in RoutedGetsOf(controller))
            {
                gets++;
                string? violation = ViolationFor(controller, action, source);
                if (violation is not null)
                {
                    violations.Add(violation);
                }
            }
        }

        Assert.True(gets >= 40, $"only {gets} protocol GET actions found — inventory is broken");

        if (violations.Count > 0)
        {
            violations.Sort(StringComparer.Ordinal);
            violations.ForEach(_output.WriteLine);
            Assert.Fail($"{violations.Count} protocol GET action(s) declare no egress metering. See test output.");
        }
    }

    [Theory]
    [InlineData(nameof(Fixture.Unmetered), "    public IActionResult Unmetered() => Ok();", true)]
    [InlineData(nameof(Fixture.Unmetered), "    // egress-ok: liveness ping, a fixed few bytes\n    public IActionResult Unmetered() => Ok();", false)]
    [InlineData(nameof(Fixture.Metered), "    public IActionResult Metered() => Ok();", false)]
    public void Gate_FailsOnUndecidedAction_AndPassesOnceDecided(string actionName, string source, bool expectViolation)
    {
        var action = typeof(Fixture).GetMethod(actionName)!;
        Assert.Equal(expectViolation, ViolationFor(typeof(Fixture), action, source.Split('\n')) is not null);
    }

    private static IEnumerable<Type> ProtocolControllers() =>
        CoreAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal)
                        && EdgeSurfaceRegistry.Classify(t) == EdgeSurface.Protocol)
            .OrderBy(t => t.FullName, StringComparer.Ordinal);

    private static IEnumerable<MethodInfo> RoutedGetsOf(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.DeclaringType is not null
                        && m.DeclaringType != typeof(object)
                        && m.DeclaringType != typeof(ControllerBase)
                        && !m.IsSpecialName
                        && m.GetCustomAttributes<HttpGetAttribute>(inherit: true).Any())
            .OrderBy(m => m.Name, StringComparer.Ordinal);

    private static string? ViolationFor(Type controller, MethodInfo action, string[] source)
    {
        bool attributed = action.GetCustomAttributes<MeteredEgressAttribute>(inherit: true).Any()
                          || action.DeclaringType!.GetCustomAttributes<MeteredEgressAttribute>(inherit: true).Any();
        return attributed || SourceCarriesMarkerFor(source, action.Name)
            ? null
            : $"{controller.Name}.{action.Name}: no [MeteredEgress(…)] and no `// {Marker} <reason>` marker.";
    }

    private static bool SourceCarriesMarkerFor(string[] source, string actionName)
    {
        for (int i = 0; i < source.Length; i++)
        {
            if (source[i].Contains($" {actionName}(", StringComparison.Ordinal))
            {
                for (int probe = Math.Max(0, i - MarkerWindow); probe <= i; probe++)
                {
                    if (source[probe].Contains(Marker, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static string[] SourceLinesFor(Type controller)
    {
        var lines = new List<string>();
        var declaration = new Regex($@"\bclass\s+{Regex.Escape(controller.Name)}\b");
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] fileLines = File.ReadAllLines(file);
            if (fileLines.Any(l => declaration.IsMatch(l)))
            {
                lines.AddRange(fileLines);
            }
        }

        return [.. lines];
    }

    private sealed class Fixture : ControllerBase
    {
        [HttpGet("/fixture/unmetered")]
        public OkResult Unmetered() => Ok();

        [HttpGet("/fixture/metered")]
        [MeteredEgress(EgressKind.Artifact, "npm")]
        public OkResult Metered() => Ok();
    }
}
