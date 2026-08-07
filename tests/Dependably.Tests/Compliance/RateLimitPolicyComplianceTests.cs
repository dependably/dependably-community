using System.Reflection;
using System.Text.RegularExpressions;
using Dependably.Infrastructure.Edge;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.RateLimiting;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the rate-limit-coverage invariant: no routed protocol action ships without
/// an explicit rate-limit decision.
///
/// <para>
/// The GlobalLimiter now applies a default-deny protocol limit to any surface with no endpoint
/// policy (see <c>RateLimitPartitions.ClassifyGlobalScope</c>), so a forgotten attribute is no
/// longer entirely unbounded. But "the default caught it" is not a substitute for a deliberate
/// choice: the hot protocol routes (packument re-parse, catalogue scan, upstream-fetch
/// amplification) need a policy sized for their real cost, and a reviewer must pick it. This gate
/// converts "we reviewed every protocol route" into "no protocol route can ship without a policy or
/// a written-down reason the default is acceptable".
/// </para>
///
/// <para>An action satisfies the gate with, in resolution order:</para>
/// <list type="number">
///   <item>an <c>[EnableRateLimiting("…")]</c> on the action or its controller (and no action-level
///   <c>[DisableRateLimiting]</c> overriding it);</item>
///   <item>otherwise a <c>// <see cref="Marker"/> &lt;reason&gt;</c> justification marker above the
///   action (or its class), documenting that the default-deny global limit is deliberately what
///   this route relies on — the same shape a bare <c>[DisableRateLimiting]</c> must also carry.</item>
/// </list>
///
/// <para>
/// Known limitation: the gate proves a policy was CHOSEN, not that the policy is correctly sized.
/// It works at reflection granularity over <see cref="HttpMethodAttribute"/>-bearing actions.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class RateLimitPolicyComplianceTests
{
    private readonly ITestOutputHelper _output;
    public RateLimitPolicyComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>The marker that documents a deliberate reliance on the default-deny global limit.</summary>
    private const string Marker = "ratelimit-ok:";

    /// <summary>How far above a declaration the marker may sit, matching the family convention.</summary>
    private const int MarkerWindow = 5;

    private static readonly Assembly CoreAssembly = typeof(Dependably.Api.PyPiController).Assembly;

    // ── The invariant ────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every routed action on a Protocol-classified controller carries an explicit rate-limit
    /// decision. A new protocol route that forgets both an <c>[EnableRateLimiting]</c> attribute and
    /// the justification marker fails here rather than shipping to lean solely on the default-deny
    /// backstop — which is the whole point: the default is a safety net, not an excuse to leave a
    /// hot route unclassified.
    /// </summary>
    [Fact]
    public void EveryProtocolActionCarriesAnExplicitRateLimitDecision()
    {
        var controllers = ProtocolControllers().ToList();

        // A reflection or classification regression that emptied this list would make the gate
        // green-but-blind. Pin a floor well below the real protocol-controller count.
        Assert.True(controllers.Count >= 9, $"only {controllers.Count} protocol controllers found");

        var violations = new List<string>();
        foreach (var controller in controllers)
        {
            string[] source = SourceLinesFor(controller);
            var actions = RoutedActionsOf(controller).ToList();
            Assert.True(actions.Count > 0, $"{controller.FullName} exposes no routed actions — inventory is broken");

            foreach (var action in actions)
            {
                string? violation = ViolationFor(controller, action, source);
                if (violation is not null)
                {
                    violations.Add(violation);
                }
            }
        }

        Report(violations, "protocol action(s) carry no explicit rate-limit decision");
    }

    // ── Self-tests ───────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Pins the attribute resolution the gate depends on: an <c>[EnableRateLimiting]</c> on the
    /// action or inherited from the controller counts, an action-level <c>[DisableRateLimiting]</c>
    /// overrides an inherited enable, and a bare action with neither counts as undecided.
    /// </summary>
    [Fact]
    public void AttributeDecision_ResolvesActionOverClass_SelfTest()
    {
        Assert.True(HasExplicitPolicy(typeof(FixtureActionLimited).GetMethod(nameof(FixtureActionLimited.Get))!));
        Assert.True(HasExplicitPolicy(typeof(FixtureClassLimited).GetMethod(nameof(FixtureClassLimited.Get))!));
        Assert.False(HasExplicitPolicy(typeof(FixtureClassLimited).GetMethod(nameof(FixtureClassLimited.OptedOut))!));
        Assert.False(HasExplicitPolicy(typeof(FixtureUnlimited).GetMethod(nameof(FixtureUnlimited.Get))!));
    }

    /// <summary>
    /// End-to-end fixture proof: the gate FAILS on a routed action with no policy and no marker, and
    /// PASSES once the same action is given a policy attribute, or the documented opt-out marker.
    /// The known-bad/known-good pair is what keeps a future refactor from quietly reopening the hole
    /// (the scanner self-test the compliance-gate family convention requires).
    /// </summary>
    [Theory]
    // No attribute and no marker in the source → violation.
    [InlineData(typeof(FixtureUnlimited), nameof(FixtureUnlimited.Get), "    public IActionResult Get() => Ok();", true)]
    // Same action, marker above the declaration → no violation.
    [InlineData(typeof(FixtureUnlimited), nameof(FixtureUnlimited.Get),
        "    // ratelimit-ok: default-deny global limit is sufficient for this cold route\n    public IActionResult Get() => Ok();", false)]
    // [EnableRateLimiting] on the action needs no marker.
    [InlineData(typeof(FixtureActionLimited), nameof(FixtureActionLimited.Get), "    public IActionResult Get() => Ok();", false)]
    // Action-level [DisableRateLimiting] over a class-level enable → violation without a marker…
    [InlineData(typeof(FixtureClassLimited), nameof(FixtureClassLimited.OptedOut), "    public IActionResult OptedOut() => Ok();", true)]
    // …and passes once the reason is written down.
    [InlineData(typeof(FixtureClassLimited), nameof(FixtureClassLimited.OptedOut),
        "    // ratelimit-ok: streams a fixed static asset, no amplification\n    public IActionResult OptedOut() => Ok();", false)]
    public void Gate_FailsOnUnlimitedAction_AndPassesOnceDecided(
        Type controller, string actionName, string source, bool expectViolation)
    {
        var action = controller.GetMethod(actionName)!;
        string? violation = ViolationFor(controller, action, source.Split('\n'));

        Assert.Equal(expectViolation, violation is not null);
    }

    /// <summary>Pins the marker window: inside it counts, one line beyond it does not.</summary>
    [Fact]
    public void MarkerWindow_IsBounded_SelfTest()
    {
        var justInside = new List<string> { $"// {Marker} reason" };
        justInside.AddRange(Enumerable.Repeat("", MarkerWindow - 1));
        justInside.Add("public IActionResult Get() => Ok();");
        Assert.True(HasMarkerAbove([.. justInside], justInside.Count - 1));

        var justOutside = new List<string> { $"// {Marker} reason" };
        justOutside.AddRange(Enumerable.Repeat("", MarkerWindow));
        justOutside.Add("public IActionResult Get() => Ok();");
        Assert.False(HasMarkerAbove([.. justOutside], justOutside.Count - 1));
    }

    // ── Gate internals ───────────────────────────────────────────────────────────────────────

    private static IEnumerable<Type> ProtocolControllers() =>
        CoreAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal)
                        && EdgeSurfaceRegistry.Classify(t) == EdgeSurface.Protocol)
            .OrderBy(t => t.FullName, StringComparer.Ordinal);

    /// <summary>
    /// The routed-action inventory: public instance methods that carry an HTTP-method attribute
    /// (<c>[HttpGet]</c>/<c>[HttpPost]</c>/…), which is exactly the set of reachable endpoints a
    /// rate-limit policy must cover. Helper methods with no route attribute are not endpoints and
    /// are excluded, so the gate never flags a private computation as an unmetered route.
    /// </summary>
    private static IEnumerable<MethodInfo> RoutedActionsOf(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.DeclaringType is not null
                        && m.DeclaringType != typeof(object)
                        && m.DeclaringType != typeof(ControllerBase)
                        && !m.IsSpecialName
                        && m.GetCustomAttributes<HttpMethodAttribute>(inherit: true).Any())
            .OrderBy(m => m.Name, StringComparer.Ordinal);

    /// <summary>
    /// True when the action has an effective <c>[EnableRateLimiting]</c> policy: one on the action
    /// or inherited from the controller, and no action-level <c>[DisableRateLimiting]</c> turning it
    /// back off (ASP.NET's own precedence — an action-level disable beats a class-level enable).
    /// </summary>
    private static bool HasExplicitPolicy(MethodInfo action)
    {
        return !action.GetCustomAttributes<DisableRateLimitingAttribute>(inherit: false).Any()
               && (action.GetCustomAttributes<EnableRateLimitingAttribute>(inherit: true).Any()
                   || action.DeclaringType!.GetCustomAttributes<EnableRateLimitingAttribute>(inherit: true).Any());
    }

    private static string? ViolationFor(Type controller, MethodInfo action, string[] source)
    {
        return HasExplicitPolicy(action) || SourceCarriesMarkerFor(source, action.Name)
            ? null
            : $"{controller.Name}.{action.Name}: no [EnableRateLimiting(\"…\")] policy and no "
              + $"`// {Marker} <reason>` marker documenting deliberate reliance on the default-deny limit.";
    }

    // A deliberate opt-out is justified either per action (marker above the method declaration) or
    // for the controller as a whole (marker above the class declaration).
    private static bool SourceCarriesMarkerFor(string[] source, string actionName)
    {
        for (int i = 0; i < source.Length; i++)
        {
            bool declaration = source[i].Contains($" {actionName}(", StringComparison.Ordinal)
                               || ClassDeclarationRegex().IsMatch(source[i]);
            if (declaration && HasMarkerAbove(source, i))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasMarkerAbove(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - MarkerWindow); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains(Marker, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Every source line of every file declaring <paramref name="controller"/> — partials included,
    /// so a controller split across companion files (OciController.*.cs) is judged whole.
    /// </summary>
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

    private void Report(List<string> violations, string what)
    {
        if (violations.Count == 0)
        {
            return;
        }

        violations.Sort(StringComparer.Ordinal);
        violations.ForEach(_output.WriteLine);
        Assert.Fail($"{violations.Count} {what}. See test output for the full list.");
    }

    [GeneratedRegex(@"\bclass\s+\w*Controller\b")]
    private static partial Regex ClassDeclarationRegex();

    // ── Fixtures ─────────────────────────────────────────────────────────────────────────────
    // Deliberately-shaped controllers the self-tests drive the gate with. Nested private types in
    // the test assembly, so they never enter the real protocol inventory (which enumerates the Core
    // assembly) — they exist only to prove the gate fails on a known-bad input and passes on a
    // known-good one.

    private sealed class FixtureActionLimited : ControllerBase
    {
        [HttpGet("/fixture/action-limited")]
        [EnableRateLimiting("metadata")]
        public OkResult Get() => Ok();
    }

    [EnableRateLimiting("metadata")]
    private sealed class FixtureClassLimited : ControllerBase
    {
        [HttpGet("/fixture/class-limited")]
        public OkResult Get() => Ok();

        [HttpGet("/fixture/class-limited/opted-out")]
        [DisableRateLimiting]
        public OkResult OptedOut() => Ok();
    }

    private sealed class FixtureUnlimited : ControllerBase
    {
        [HttpGet("/fixture/unlimited")]
        public OkResult Get() => Ok();
    }
}
