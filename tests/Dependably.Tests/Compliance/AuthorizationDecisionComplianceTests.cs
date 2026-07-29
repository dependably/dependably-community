using System.Reflection;
using System.Text.RegularExpressions;
using Dependably.Infrastructure.Edge;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the authorization invariant: no endpoint ships without an explicit
/// authorization decision.
///
/// <para>
/// There is no <c>FallbackPolicy</c> on this instance, and there deliberately cannot be one:
/// <c>RouteScopeFilter</c> lets unauthenticated requests through (it checks realm consistency for
/// principals that are already authenticated, nothing more), and the protocol plane authenticates
/// outside ASP.NET authorization entirely — per-ecosystem token schemes resolved in the action
/// body via <c>TokenAuthExtensions.ResolveTokenAsync</c>. A blanket
/// <c>RequireAuthenticatedUser()</c> fallback would break both. So the backstop is this gate
/// rather than a policy.
/// </para>
///
/// <para>The three decisions a management action may carry, in the order they are resolved:</para>
/// <list type="number">
///   <item><c>[Authorize]</c> / <c>[RequireCapability]</c> on the action or its controller.</item>
///   <item><c>[AllowAnonymous]</c> on the action or its controller — which must in turn carry an
///   <c>// authz-ok: &lt;reason&gt;</c> justification marker, or the attribute is decorative.</item>
///   <item>Neither, i.e. auth resolved by hand in the body (the <c>SiemController</c> shape) —
///   which must carry the same <c>// authz-ok:</c> marker above the action or its class.</item>
/// </list>
///
/// <para>
/// Known limitation: the gate proves a decision was MADE, not that the decision is correct. It
/// cannot tell <c>[Authorize]</c> from the <c>[RequireCapability]</c> the action actually needed,
/// and on the protocol plane it works at controller granularity (below) rather than per action.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class AuthorizationDecisionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public AuthorizationDecisionComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>The marker that documents a deliberate anonymous or hand-rolled authorization decision.</summary>
    private const string Marker = "authz-ok:";

    /// <summary>How far above a declaration the marker may sit, matching the family convention.</summary>
    private const int MarkerWindow = 5;

    private static readonly Assembly ManagementAssembly = typeof(EdgeSurfaceRegistry).Assembly;
    private static readonly Assembly CoreAssembly = typeof(Dependably.Api.PyPiController).Assembly;

    private enum AttributeDecision { Authorize, Anonymous, None }

    // ── Management plane ─────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every action on a Management-classified controller carries one of the three decisions.
    /// A new controller that forgets both an attribute and a manual check fails here rather than
    /// shipping live — which is the whole point: this converts "we reviewed every controller"
    /// into "no controller can ship without a decision".
    /// </summary>
    [Fact]
    public void EveryManagementActionCarriesAnExplicitAuthorizationDecision()
    {
        var controllers = ManagementControllers().ToList();

        // A reflection or classification regression that emptied this list would make the gate
        // green-but-blind. Pin a floor well below the real count.
        Assert.True(controllers.Count >= 20, $"only {controllers.Count} management controllers found");

        var violations = new List<string>();
        foreach (var controller in controllers)
        {
            string[] source = SourceLinesFor(controller);
            var actions = ActionsOf(controller).ToList();
            Assert.True(actions.Count > 0, $"{controller.FullName} exposes no actions — inventory is broken");

            foreach (var action in actions)
            {
                string? violation = ViolationFor(controller, action, source);
                if (violation is not null)
                {
                    violations.Add(violation);
                }
            }
        }

        Report(violations, "management action(s) carry no explicit authorization decision");
    }

    /// <summary>
    /// Adversarial twin: an <c>[AllowAnonymous]</c> without a justification marker is decorative,
    /// and an anonymous endpoint is the one place a reviewer most needs the reason written down.
    /// Scans every source root, so an anonymous endpoint added anywhere is covered.
    /// </summary>
    [Fact]
    public void EveryAllowAnonymousAttributeCarriesAJustificationMarker()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (!AllowAnonymousAttributeRegex().IsMatch(lines[i]) || HasMarkerAbove(lines, i))
                {
                    continue;
                }

                violations.Add(
                    $"{Path.GetRelativePath(SourceRoots.OwningRoot(file), file)}:{i + 1}: "
                    + $"[AllowAnonymous] without a `// {Marker} <reason>` justification.");
            }
        }

        Report(violations, "[AllowAnonymous] attribute(s) carry no justification marker");
    }

    // ── Protocol plane ───────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The protocol plane cannot use ASP.NET authorization — npm/PyPI/NuGet/Maven/RPM/OCI/Cargo/
    /// Go/apk each authenticate with their ecosystem's own token scheme, resolved in the action
    /// body. So the invariant here is the weaker but still fail-closed one: every
    /// Protocol-classified controller must show token resolution somewhere in its own source
    /// (partials included), or declare itself anonymous with a marker. A brand-new protocol
    /// controller with no authorization call anywhere in it is a red build.
    /// </summary>
    [Fact]
    public void EveryProtocolControllerResolvesAuthorizationSomewhereInItsSource()
    {
        var controllers = ProtocolControllers().ToList();
        Assert.True(controllers.Count >= 9, $"only {controllers.Count} protocol controllers found");

        var violations = new List<string>();
        foreach (var controller in controllers)
        {
            string source = string.Join('\n', SourceLinesFor(controller));
            if (source.Length == 0)
            {
                violations.Add($"{controller.FullName}: no source file declares this controller.");
            }
            else if (!ProtocolAuthCallRegex().IsMatch(source) && !source.Contains(Marker, StringComparison.Ordinal))
            {
                violations.Add(
                    $"{controller.FullName}: no ResolveTokenAsync / HasCapability / RequireCapability "
                    + $"call and no `// {Marker} <reason>` marker anywhere in its source.");
            }
        }

        Report(violations, "protocol controller(s) resolve no authorization at all");
    }

    // ── Self-tests ───────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Pins the attribute resolution the gate depends on, including inheritance from the
    /// controller to its actions and action-level <c>[AllowAnonymous]</c> beating a class-level
    /// <c>[Authorize]</c> — the precedence ASP.NET itself applies.
    /// </summary>
    [Fact]
    public void AttributeDecision_ResolvesActionOverClass_SelfTest()
    {
        Assert.Equal(AttributeDecision.Authorize, DecisionFor(typeof(FixtureAuthorized), nameof(FixtureAuthorized.Get)));
        Assert.Equal(AttributeDecision.Authorize, DecisionFor(typeof(FixtureCapability), nameof(FixtureCapability.Get)));
        Assert.Equal(AttributeDecision.Anonymous, DecisionFor(typeof(FixtureAnonymousClass), nameof(FixtureAnonymousClass.Get)));
        Assert.Equal(AttributeDecision.Anonymous, DecisionFor(typeof(FixtureAuthorized), nameof(FixtureAuthorized.OpenAction)));
        Assert.Equal(AttributeDecision.None, DecisionFor(typeof(FixtureUndecided), nameof(FixtureUndecided.Get)));
    }

    /// <summary>
    /// End-to-end fixture proof: the gate FAILS on a controller action with no decision, and
    /// PASSES once the same action is given one — an attribute, or the documented manual-auth
    /// marker. The known-bad/known-good pair is what keeps a future refactor from quietly
    /// reopening the hole.
    /// </summary>
    [Theory]
    // No attribute and no marker in the source → violation.
    [InlineData(typeof(FixtureUndecided), nameof(FixtureUndecided.Get), "    public IActionResult Get() => Ok();", true)]
    // Same action, marker above the declaration (the manual-auth shape) → no violation.
    [InlineData(typeof(FixtureUndecided), nameof(FixtureUndecided.Get),
        "    // authz-ok: resolves auth manually in the body\n    public IActionResult Get() => Ok();", false)]
    // [Authorize] needs no marker.
    [InlineData(typeof(FixtureAuthorized), nameof(FixtureAuthorized.Get), "    public IActionResult Get() => Ok();", false)]
    // [AllowAnonymous] with no marker anywhere → violation, even though a decision "exists".
    [InlineData(typeof(FixtureAnonymousClass), nameof(FixtureAnonymousClass.Get), "    public IActionResult Get() => Ok();", true)]
    // …and the same action passes once the reason is written down.
    [InlineData(typeof(FixtureAnonymousClass), nameof(FixtureAnonymousClass.Get),
        "    // authz-ok: serves tenant-identical static content\n    public IActionResult Get() => Ok();", false)]
    public void Gate_FailsOnUndecidedAction_AndPassesOnceDecided(
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

    private static IEnumerable<Type> ManagementControllers() =>
        ControllersIn(ManagementAssembly).Where(t => EdgeSurfaceRegistry.Classify(t) == EdgeSurface.Management);

    private static IEnumerable<Type> ProtocolControllers() =>
        ControllersIn(CoreAssembly).Where(t => EdgeSurfaceRegistry.Classify(t) == EdgeSurface.Protocol);

    private static IEnumerable<Type> ControllersIn(Assembly assembly) =>
        assembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal))
            .OrderBy(t => t.FullName, StringComparer.Ordinal);

    /// <summary>
    /// The MVC action inventory: public instance methods declared on the controller or any of its
    /// non-framework bases, excluding property accessors and <c>[NonAction]</c> helpers. Walking
    /// the bases matters — an action inherited from a shared controller base is just as reachable
    /// as one declared inline.
    /// </summary>
    private static IEnumerable<MethodInfo> ActionsOf(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.DeclaringType is not null
                        && m.DeclaringType != typeof(object)
                        && m.DeclaringType != typeof(ControllerBase)
                        && !m.IsSpecialName
                        && m.GetCustomAttribute<NonActionAttribute>() is null)
            .OrderBy(m => m.Name, StringComparer.Ordinal);

    private static AttributeDecision DecisionFor(Type controller, string actionName) =>
        DecisionFor(controller.GetMethod(actionName)!);

    /// <summary>
    /// Resolves the attribute-borne decision. Action-level <c>[AllowAnonymous]</c> beats a
    /// class-level <c>[Authorize]</c>, matching ASP.NET's own precedence; otherwise an
    /// <c>[Authorize]</c> anywhere in the chain (including <c>[RequireCapability]</c>, which
    /// derives from it) is the decision.
    /// </summary>
    private static AttributeDecision DecisionFor(MethodInfo action)
    {
        if (action.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any())
        {
            return AttributeDecision.Anonymous;
        }

        if (action.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any())
        {
            return AttributeDecision.Authorize;
        }

        var controller = action.DeclaringType!;
        return controller.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any()
            ? AttributeDecision.Authorize
            : controller.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any()
            ? AttributeDecision.Anonymous
            : AttributeDecision.None;
    }

    private static string? ViolationFor(Type controller, MethodInfo action, string[] source)
    {
        string where = $"{controller.Name}.{action.Name}";
        switch (DecisionFor(action))
        {
            case AttributeDecision.Authorize:
                return null;

            case AttributeDecision.Anonymous:
                return SourceCarriesMarker(source)
                    ? null
                    : $"{where}: [AllowAnonymous] with no `// {Marker} <reason>` justification.";

            default:
                return SourceCarriesMarkerFor(source, action.Name)
                    ? null
                    : $"{where}: no [Authorize]/[RequireCapability], no [AllowAnonymous], and no "
                      + $"`// {Marker} <reason>` marker documenting a hand-rolled check.";
        }
    }

    private static bool SourceCarriesMarker(string[] source) =>
        source.Any(l => l.Contains(Marker, StringComparison.Ordinal));

    // A hand-rolled check is justified either per action (marker above the method declaration) or
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
    /// Every source line of every file declaring <paramref name="controller"/> — partials
    /// included, so a controller split across companion files is judged whole. Matching on the
    /// class declaration rather than the file name is what makes the partial case work.
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

    [GeneratedRegex(@"^\s*\[\s*AllowAnonymous\s*\]")]
    private static partial Regex AllowAnonymousAttributeRegex();

    [GeneratedRegex(@"\b(?:ResolveTokenAsync|HasCapability|RequireCapability)\b")]
    private static partial Regex ProtocolAuthCallRegex();

    [GeneratedRegex(@"\bclass\s+\w*Controller\b")]
    private static partial Regex ClassDeclarationRegex();

    // ── Fixtures ─────────────────────────────────────────────────────────────────────────────
    // Deliberately-shaped controllers the self-tests drive the gate with. They are nested private
    // types in the test assembly, so they never enter the real inventory (which enumerates the
    // Core and Management assemblies) — they exist only to prove the gate fails on a known-bad
    // input and passes on a known-good one.

    [Authorize]
    private sealed class FixtureAuthorized : ControllerBase
    {
        public IActionResult Get() => Ok();

        [AllowAnonymous]
        public IActionResult OpenAction() => Ok();
    }

    [Dependably.Security.RequireCapability("read:audit")]
    private sealed class FixtureCapability : ControllerBase
    {
        public IActionResult Get() => Ok();
    }

    [AllowAnonymous]
    private sealed class FixtureAnonymousClass : ControllerBase
    {
        public IActionResult Get() => Ok();
    }

    private sealed class FixtureUndecided : ControllerBase
    {
        public IActionResult Get() => Ok();
    }
}
