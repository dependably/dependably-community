using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text.RegularExpressions;
using Dependably.Infrastructure.Edge;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the input-validation invariant: no management-plane controller action ships
/// with caller-controlled input and no visible validation decision.
///
/// <para>
/// Raised by the <c>owasp-proactive</c> lens (C03), which rated the control PARTIAL: a small
/// minority of Management controllers use <c>ModelState</c>/DataAnnotations/FluentValidation, the
/// majority use ad-hoc manual checks, and nothing stopped a new controller from doing neither. This
/// gate does <em>not</em> mandate a mechanism — an ad-hoc manual check is exactly as valid a decision
/// as DataAnnotations, matching how <see cref="AuthorizationDecisionComplianceTests"/> treats a
/// hand-rolled auth check as equal to <c>[Authorize]</c>. It only requires that a decision be visible
/// in source for anything the caller controls.
/// </para>
///
/// <para><b>Scope decision — what counts as "caller-controlled input":</b> only parameters bound as a
/// structured payload (a request body/form/query <em>object</em> — <c>class</c> or <c>record</c>
/// parameters, the shape DataAnnotations/FluentValidation/<c>ModelState</c> actually validate).
/// Scalar route/query parameters (an <c>id</c>, a page size, a search string) are deliberately out of
/// scope: every one of them observed in this codebase is either threaded straight into a
/// parameterized, org-scoped lookup that 404s on a miss (covered by <c>OrgIdFilteringComplianceTests</c>
/// / the BOLA posture — a different invariant), or is a bare paging/filter primitive with no
/// injection-relevant shape to enforce. Treating every scalar as "needs a decision" would flag the
/// entire codebase and drown the real gap in noise — the classic rubber-stamp failure mode.
/// <see cref="Microsoft.AspNetCore.Mvc.FromServicesAttribute"/> parameters, <see cref="CancellationToken"/>,
/// and framework plumbing (<see cref="HttpContext"/>, <c>ClaimsPrincipal</c>, <see cref="IFormFile"/>,
/// <c>Stream</c>) are excluded outright — they are not caller-controlled.
/// </para>
///
/// <para>An action with at least one qualifying parameter satisfies the gate, in resolution order:</para>
/// <list type="number">
///   <item>a qualifying parameter's type carries a <see cref="ValidationAttribute"/> on any property
///   and the controller is <c>[ApiController]</c> — the automatic-400-on-invalid-<c>ModelState</c>
///   behaviour that attribute triggers is itself the decision, with no inline check required;</item>
///   <item>the action's own body (or, when extraction fails, the whole controller) contains a line
///   that both names a qualifying parameter (by local name or by its type's name — the latter is what
///   makes a delegated <c>private IActionResult? ValidateFoo(FooRequest req)</c> helper call count,
///   since the call site itself names the parameter) and looks like a validation/comparison construct
///   (<c>IsNullOrWhiteSpace</c>, <c>TryParse</c>, <c>ModelState</c>, <c>Validate…(</c>, a comparison
///   operator, a null check, …) — the ad-hoc manual-check shape that is the actual majority pattern
///   here;</item>
///   <item>an explicit <c>// <see cref="Marker"/> &lt;reason&gt;</c> justification above the action or
///   its class, for a payload that genuinely needs no validation (e.g. every field is optional and
///   any value is acceptable) — mirroring the <c>xtenant:</c>/<c>rawsql:</c>/<c>authz-ok:</c>
///   convention. A bare marker with no reason is malformed and is never honoured — see
///   <see cref="EveryInputValidationOkMarkerCarriesAStatedReason"/>.</item>
/// </list>
///
/// <para>
/// <b>Known limitations, stated plainly:</b> this gate proves a validation-<em>shaped</em> construct
/// exists and mentions the parameter — it cannot prove the check is correct, complete (covers every
/// field), or that it runs before the parameter is used. The manual-check detection is a fixed
/// vocabulary of textual signals, not a control-flow analysis; a legitimate check written in an
/// unrecognised idiom false-flags as a violation (fails closed — it surfaces for review rather than
/// hiding a gap, the same trade the family already makes) and, conversely, a parameter name that
/// coincidentally collides with unrelated code on a matching line could false-pass. Action-body
/// extraction is a brace-counting heuristic keyed off <c>public … &lt;ActionName&gt;(</c>; if it can't
/// find the declaration it falls back to scanning the whole controller, which reopens the
/// same-local-name collision risk across sibling actions (e.g. two actions both naming their
/// parameter <c>req</c>) for that action only. And like <see cref="AuthorizationDecisionComplianceTests"/>,
/// it works at reflection/source-scan granularity: a manual check that lives in a shared, generically
/// named private helper the gate's vocabulary doesn't recognise as validation would need a marker.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class InputValidationDecisionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public InputValidationDecisionComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>The marker that documents a deliberate "no validation needed" decision.</summary>
    private const string Marker = "input-validation-ok:";

    /// <summary>How far above a declaration the marker may sit, matching the family convention.</summary>
    private const int MarkerWindow = 5;

    private static readonly Assembly ManagementAssembly = typeof(EdgeSurfaceRegistry).Assembly;

    /// <summary>Framework/DI types that are never caller-controlled regardless of binding source.</summary>
    private static readonly HashSet<Type> ExcludedTypes =
    [
        typeof(CancellationToken),
        typeof(HttpContext),
        typeof(System.Security.Claims.ClaimsPrincipal),
        typeof(IFormFile),
        typeof(IFormFileCollection),
        typeof(Stream),
    ];

    // ── The invariant ────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every action on a Management-classified controller that binds a structured request payload
    /// carries one of the three decisions above. A new controller that binds a body and validates
    /// nothing fails here rather than shipping live — converting "we reviewed every controller" into
    /// "no controller can ship a payload-binding action without a decision".
    /// </summary>
    [Fact]
    public void EveryManagementActionWithCallerControlledPayloadCarriesAnExplicitValidationDecision()
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

        Report(violations, "management action(s) bind caller-controlled input with no explicit validation decision");
    }

    /// <summary>
    /// Adversarial twin: an <c>// input-validation-ok:</c> marker that names no reason is malformed
    /// and must never be honoured — the reason is what makes the decision reviewable, matching the
    /// <c>backcompat-ok:</c> family precedent (a marker with an object but no reason is rejected, not
    /// silently accepted).
    /// </summary>
    [Fact]
    public void EveryInputValidationOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string text = File.ReadAllText(file);
            foreach (Match m in MarkerReasonRegex().Matches(text))
            {
                string reason = m.Groups["reason"].Value.Trim().TrimStart(':', ' ').Trim();
                if (reason.Length > 0)
                {
                    continue;
                }

                int line = text[..m.Index].Count(c => c == '\n') + 1;
                violations.Add(
                    $"{Path.GetRelativePath(SourceRoots.OwningRoot(file), file)}:{line}: "
                    + $"`// {Marker}` with no stated reason.");
            }
        }

        Report(violations, "input-validation-ok marker(s) give no reason");
    }

    // ── Self-tests ───────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// End-to-end fixture proof: the gate FAILS on an action binding a payload with no validation
    /// anywhere, and PASSES once the same action gets a manual check, a marker, or DataAnnotations —
    /// and does NOT false-positive on an action with no qualifying (complex/record) parameter at all.
    /// </summary>
    [Theory]
    // [FromBody] payload, no check anywhere, no marker → violation.
    [InlineData(typeof(FixtureUndecided), nameof(FixtureUndecided.Post),
        "    public IActionResult Post([FromBody] FixtureRequest req)\n    {\n        return Ok();\n    }",
        true)]
    // Same action, inline manual check referencing the parameter → no violation.
    [InlineData(typeof(FixtureUndecided), nameof(FixtureUndecided.Post),
        "    public IActionResult Post([FromBody] FixtureRequest req)\n    {\n"
        + "        if (string.IsNullOrWhiteSpace(req.Name)) return BadRequest();\n        return Ok();\n    }",
        false)]
    // Same action, delegated to a private helper named after the parameter's type → no violation
    // (the call site itself names the parameter alongside "Validate").
    [InlineData(typeof(FixtureUndecided), nameof(FixtureUndecided.Post),
        "    public IActionResult Post([FromBody] FixtureRequest req)\n    {\n"
        + "        var error = ValidateFixtureRequest(req);\n        if (error is not null) return error;\n        return Ok();\n    }",
        false)]
    // Same action, marker above the declaration → no violation even with an empty body.
    [InlineData(typeof(FixtureUndecided), nameof(FixtureUndecided.Post),
        "    // input-validation-ok: every field is optional and any value is accepted\n"
        + "    public IActionResult Post([FromBody] FixtureRequest req)\n    {\n        return Ok();\n    }",
        false)]
    // No qualifying (complex/record) parameter — a scalar route id and a CancellationToken — needs
    // nothing.
    [InlineData(typeof(FixtureScalarOnly), nameof(FixtureScalarOnly.Get),
        "    public IActionResult Get(string id, CancellationToken ct) => Ok();",
        false)]
    // A DataAnnotations-carrying payload on an [ApiController] needs no inline check.
    [InlineData(typeof(FixtureDataAnnotations), nameof(FixtureDataAnnotations.Post),
        "    public IActionResult Post([FromBody] FixtureValidatedRequest req) => Ok();",
        false)]
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

    /// <summary>Pins the reasonless-marker detection the compliance fact above relies on.</summary>
    [Theory]
    [InlineData("// input-validation-ok: query filters accept any value, none are enforced", false)]
    [InlineData("// input-validation-ok:", true)]
    [InlineData("// input-validation-ok:    ", true)]
    public void MarkerReasonRegex_DetectsMissingReason_SelfTest(string line, bool malformed)
    {
        var match = MarkerReasonRegex().Match(line);
        Assert.True(match.Success);
        string reason = match.Groups["reason"].Value.Trim().TrimStart(':', ' ').Trim();
        Assert.Equal(malformed, reason.Length == 0);
    }

    // ── Gate internals ───────────────────────────────────────────────────────────────────────

    private static IEnumerable<Type> ManagementControllers() =>
        ManagementAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t)
                        && !t.IsAbstract
                        && t.Name.EndsWith("Controller", StringComparison.Ordinal)
                        && EdgeSurfaceRegistry.Classify(t) == EdgeSurface.Management)
            .OrderBy(t => t.FullName, StringComparer.Ordinal);

    /// <summary>
    /// The MVC action inventory, matching <see cref="AuthorizationDecisionComplianceTests"/>: public
    /// instance methods declared on the controller or a non-framework base, excluding property
    /// accessors and <c>[NonAction]</c> helpers.
    /// </summary>
    private static IEnumerable<MethodInfo> ActionsOf(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.DeclaringType is not null
                        && m.DeclaringType != typeof(object)
                        && m.DeclaringType != typeof(ControllerBase)
                        && !m.IsSpecialName
                        && m.GetCustomAttribute<NonActionAttribute>() is null)
            .OrderBy(m => m.Name, StringComparer.Ordinal);

    /// <summary>
    /// True when <paramref name="parameter"/> is a structured payload the action binds from the
    /// caller — the scope this gate covers. See the type-level doc comment for why scalar route/query
    /// parameters are deliberately excluded.
    /// </summary>
    private static bool RequiresValidationDecision(ParameterInfo parameter)
    {
        if (parameter.GetCustomAttribute<FromServicesAttribute>() is not null)
        {
            return false;
        }

        var type = Nullable.GetUnderlyingType(parameter.ParameterType) ?? parameter.ParameterType;
        return !ExcludedTypes.Contains(type)
            && !type.IsPrimitive && !type.IsEnum
            && type != typeof(string) && type != typeof(Guid) && type != typeof(decimal)
            && type != typeof(DateTime) && type != typeof(DateTimeOffset) && type != typeof(TimeSpan);
    }

    /// <summary>
    /// True when <paramref name="parameter"/>'s type carries a <see cref="ValidationAttribute"/> on
    /// any property and the controller is <c>[ApiController]</c> — the automatic invalid-ModelState
    /// 400 that attribute triggers is the decision, with no inline check required.
    /// </summary>
    private static bool HasDataAnnotationsDecision(Type controller, ParameterInfo parameter) =>
        controller.GetCustomAttributes<ApiControllerAttribute>(inherit: true).Any()
        && parameter.ParameterType
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Any(p => p.GetCustomAttributes(inherit: true).OfType<ValidationAttribute>().Any());

    private static string? ViolationFor(Type controller, MethodInfo action, string[] source)
    {
        var qualifying = action.GetParameters().Where(RequiresValidationDecision).ToList();
        if (qualifying.Count == 0)
        {
            return null;
        }

        if (qualifying.Any(p => HasDataAnnotationsDecision(controller, p)))
        {
            return null;
        }

        string body = ExtractActionBody(source, action.Name);
        if (qualifying.Any(p => ReferencedInValidationConstruct(body, p)))
        {
            return null;
        }

        if (SourceCarriesMarkerFor(source, action.Name))
        {
            return null;
        }

        string parms = string.Join(", ", qualifying.Select(p => $"{p.ParameterType.Name} {p.Name}"));
        return $"{controller.Name}.{action.Name}({parms}): binds caller-controlled input but shows no "
             + "ModelState/DataAnnotations/FluentValidation decision, no manual check referencing its "
             + $"parameter(s), and no `// {Marker} <reason>` marker.";
    }

    /// <summary>
    /// True when a single <em>statement</em> in <paramref name="body"/> both names
    /// <paramref name="parameter"/> (by local name or by its type's name — the latter is what makes
    /// a delegated <c>ValidateFoo(FooRequest req)</c> helper call count) and looks like a
    /// validation/comparison construct. "Statement" rather than "line" is deliberate: this codebase
    /// routinely spreads one call across several physical lines (<c>UpsertRetentionAsync(orgId,
    /// req.KeepVersions, req.KeepDays, …)</c>), and a same-line requirement would miss it — but
    /// "line" is also too loose: an unrelated guard clause a few lines above (<c>if (result is not
    /// null)</c>) must not count as validating a completely different parameter. Splitting on
    /// <c>;</c>/<c>{</c>/<c>}</c> approximates a statement boundary without a real parser, closing
    /// that gap while still spanning a multi-line argument list.
    /// </summary>
    private static bool ReferencedInValidationConstruct(string body, ParameterInfo parameter)
    {
        var nameRegex = new Regex($@"\b{Regex.Escape(parameter.Name!)}\b");
        var typeRegex = new Regex($@"\b{Regex.Escape(parameter.ParameterType.Name)}\b");

        foreach (string statement in StatementSplitRegex().Split(body))
        {
            if (ValidationSignalRegex().IsMatch(statement)
                && (nameRegex.IsMatch(statement) || typeRegex.IsMatch(statement)))
            {
                return true;
            }
        }

        return IteratedAndValidatedPerElement(body, parameter);
    }

    /// <summary>
    /// True when the body contains a <c>foreach</c> loop iterating <paramref name="parameter"/> (or
    /// a member access rooted at it, e.g. <c>settings.Keys</c>) whose loop body separately contains a
    /// validation-shaped construct. The statement-scoped check above requires the parameter's own
    /// identifier in the same statement as the check, which a per-element loop never satisfies — the
    /// check runs against the loop variable, not the parameter — so a per-element allowlist check
    /// (<c>foreach (var key in settings.Keys) { if (!Allowed.Contains(key)) … }</c>, the actual shape
    /// <c>InstanceController</c>/<c>SystemController</c> use to validate a settings dictionary) needs
    /// this second, narrower tier: the loop header must name the parameter, not just any identifier.
    /// </summary>
    private static bool IteratedAndValidatedPerElement(string body, ParameterInfo parameter)
    {
        foreach (Match header in ForeachHeaderRegex().Matches(body))
        {
            if (!string.Equals(header.Groups["src"].Value, parameter.Name, StringComparison.Ordinal))
            {
                continue;
            }

            int braceStart = body.IndexOf('{', header.Index + header.Length);
            if (braceStart < 0)
            {
                continue;
            }

            int depth = 0;
            int j = braceStart;
            for (; j < body.Length; j++)
            {
                if (body[j] == '{')
                {
                    depth++;
                }
                else if (body[j] == '}')
                {
                    depth--;
                    if (depth == 0)
                    {
                        j++;
                        break;
                    }
                }
            }

            if (ValidationSignalRegex().IsMatch(body[braceStart..j]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts the source text of the action named <paramref name="actionName"/> out of
    /// <paramref name="source"/> by brace-counting from its declaration. Falls back to the whole
    /// source when the declaration can't be located (see the type-level doc comment for the
    /// consequence of that fallback).
    /// </summary>
    private static string ExtractActionBody(string[] source, string actionName)
    {
        string text = string.Join('\n', source);
        var decl = Regex.Match(text, $@"public\s(?:[^\n{{;]*\s)?{Regex.Escape(actionName)}\s*\(");
        if (!decl.Success)
        {
            return text;
        }

        int parenStart = text.IndexOf('(', decl.Index);
        if (parenStart < 0)
        {
            return text;
        }

        int depth = 0;
        int i = parenStart;
        for (; i < text.Length; i++)
        {
            if (text[i] == '(')
            {
                depth++;
            }
            else if (text[i] == ')')
            {
                depth--;
                if (depth == 0)
                {
                    i++;
                    break;
                }
            }
        }

        int braceStart = text.IndexOf('{', i);
        int arrowStart = text.IndexOf("=>", i, StringComparison.Ordinal);

        if (braceStart >= 0 && (arrowStart < 0 || braceStart < arrowStart))
        {
            int bdepth = 0;
            int j = braceStart;
            for (; j < text.Length; j++)
            {
                if (text[j] == '{')
                {
                    bdepth++;
                }
                else if (text[j] == '}')
                {
                    bdepth--;
                    if (bdepth == 0)
                    {
                        j++;
                        break;
                    }
                }
            }

            return text[braceStart..j];
        }

        if (arrowStart >= 0)
        {
            int semi = text.IndexOf(';', arrowStart);
            return semi >= 0 ? text[arrowStart..(semi + 1)] : text[arrowStart..];
        }

        return text;
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
    /// so a controller split across companion files (<c>SystemController.*.cs</c>) is judged whole.
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

    // "Validate…(" alone misses the credential-verification idiom this codebase actually uses
    // (VerifyTotpAsync, CheckPasswordAsync, RedeemRecoveryCodeAsync — a caller-supplied value
    // checked against a stored secret, rejected on mismatch is exactly a validation decision, and
    // arguably a stronger one than a format check) — Verify…(/Check…(/Redeem…( are recognised too.
    // "\bis\b" (not just "is null"/"is not null") is what catches C# pattern matching against a
    // literal set (`req.Decision is not ("approved" or "denied" or "pending")`), the idiom this
    // codebase actually uses for an enum-shaped string field.
    [GeneratedRegex(
        @"IsNullOrWhiteSpace|IsNullOrEmpty|TryParse|\.Length\b|\.Count\b|\.Contains\(|\.Any\(|\.All\("
        + @"|IsMatch\(|Regex\.|ModelState|IsValid\b|\b(?:Validate|Verify|Check|Redeem)\w*\(|throw new|\?\?"
        + @"|\bis\b|==|!=|<=|>=|(?<![=!<>])[<>](?!=)")]
    private static partial Regex ValidationSignalRegex();

    [GeneratedRegex(@"input-validation-ok:(?<reason>[^\r\n]*)")]
    private static partial Regex MarkerReasonRegex();

    [GeneratedRegex(@"[{};]")]
    private static partial Regex StatementSplitRegex();

    [GeneratedRegex(@"foreach\s*\(\s*[\w?<>\[\],. ]+\s+\w+\s+in\s+(?<src>\w+)\b[^)]*\)")]
    private static partial Regex ForeachHeaderRegex();

    [GeneratedRegex(@"\bclass\s+\w*Controller\b")]
    private static partial Regex ClassDeclarationRegex();

    // ── Fixtures ─────────────────────────────────────────────────────────────────────────────
    // Deliberately-shaped controllers/DTOs the self-tests drive the gate with. Nested private types
    // in the test assembly, so they never enter the real inventory (which enumerates the Management
    // assembly) — they exist only to prove the gate fails on a known-bad input and passes on a
    // known-good one.

    private sealed class FixtureRequest
    {
        public string? Name { get; set; }
    }

    private sealed class FixtureValidatedRequest
    {
        [Required]
        public string? Name { get; set; }
    }

    // These fixture actions exist only for their reflection shape (parameter types/attributes) —
    // the self-tests drive ViolationFor with synthetic source text, never these bodies.
#pragma warning disable IDE0060 // unused parameter — shape only, see above
    [ApiController]
    private sealed class FixtureUndecided : ControllerBase
    {
        public IActionResult Post([FromBody] FixtureRequest req) => Ok();
    }

    [ApiController]
    private sealed class FixtureDataAnnotations : ControllerBase
    {
        public IActionResult Post([FromBody] FixtureValidatedRequest req) => Ok();
    }

    [ApiController]
    private sealed class FixtureScalarOnly : ControllerBase
    {
        public IActionResult Get(string id, CancellationToken ct) => Ok();
    }
#pragma warning restore IDE0060
}
