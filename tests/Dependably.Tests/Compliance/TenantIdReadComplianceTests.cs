using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for how a request's tenant id is read: code that needs "the current tenant's
/// id, which must exist" calls <c>HttpContext.RequireTenantId()</c> (or
/// <c>OrgScopedControllerBase.CurrentTenantId()</c>, which wraps it), never a null-forgiving read
/// of <c>TenantContext.TenantId</c>.
///
/// <para>
/// <c>TenantContext.TenantId</c> is null for the apex and uninitialized surfaces. A management
/// action that reads it as <c>((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!</c>
/// is safe only because <c>OrgAccessGuard.AuthorizeCapAsync</c> has already 404'd a non-tenant
/// request; the <c>!</c> silences the compiler rather than checking anything. If a future route
/// skips the guard, the null travels into a repository's <c>orgId</c> argument or a cache key
/// instead of failing. <c>RequireTenantId()</c> throws at the read, so a broken ordering surfaces
/// as an error rather than as a query scoped to no tenant.
/// </para>
///
/// <para>
/// Two shapes are banned outside <c>TenantContextHttpExtensions.cs</c>:
/// <list type="number">
///   <item>a hard cast <c>(TenantContext)x</c> or <c>(TenantContext?)x</c> — it throws a bare
///   <c>NullReferenceException</c> / <c>InvalidCastException</c> on a missing context and invites
///   the <c>.TenantId!</c> that follows; code that tolerates a missing context uses <c>as</c> or a pattern match;</item>
///   <item>a null-defeating read — <c>.TenantId!</c>, or a <c>??</c> fallback to a string
///   literal (<c>""</c> included), <c>string.Empty</c>, <c>default!</c> or <c>null!</c>, each of
///   which sends a fabricated org id into a query — on a receiver this file binds to
///   <c>TenantContext</c> (a declaration, parameter, pattern variable, <c>as</c>/cast result, or
///   the result of a method declared in the same file to return <c>TenantContext</c>), or directly
///   on an inline <c>(… as TenantContext)</c>.</item>
/// </list>
/// Reads that legitimately handle a non-tenant context stay legal because they never need
/// <c>!</c>: <c>is TenantContext { IsTenant: true, TenantId: { } id }</c> pattern matches,
/// <c>(… as TenantContext)?.TenantId</c> nullable flows, and Apex/system-admin branches.
/// </para>
///
/// <para>
/// A deliberate exception opts out with <c>// tenantid-ok: &lt;reason&gt;</c> in the 5 lines
/// above, matching the <c>// xtenant:</c> / <c>// rawsql:</c> / <c>// blobkey-ok:</c> convention. A
/// bare marker with no stated reason is malformed and is never honoured.
/// </para>
///
/// <para>
/// <b>Known limitations, stated plainly:</b> a per-file source scan with no type information.
/// A <c>TenantContext</c> reached through a property chain (<c>holder.Tenant.TenantId!</c>), a
/// receiver produced by a method declared in another file, or a <c>TenantId</c> extracted by a
/// property pattern and then null-forgiven under a new name is not seen. <c>.TenantId!</c> on a
/// type other than <c>TenantContext</c> (a login first-factor result) is out of scope and passes.
/// Receiver names are collected per file, so the same local name bound to a different type in
/// another method of a file that also binds it to <c>TenantContext</c> is a false positive; the
/// marker handles that. A <c>??</c> fallback to anything other than a literal, <c>string.Empty</c>
/// or a forgiven <c>default</c>/<c>null</c> (a variable, a method call, a constant), and a
/// conditional such as <c>ctx.TenantId is null ? "" : ctx.TenantId</c> or
/// <c>string.IsNullOrEmpty(…) ? … : …</c>, is not detected: telling a legitimate fallback from a
/// fabricated id there needs data flow.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class TenantIdReadComplianceTests
{
    private const string Marker = "tenantid-ok:";
    private const int MarkerWindow = 5;

    /// <summary>The single file permitted to read <c>TenantContext.TenantId</c> as required.</summary>
    private const string HelperFileName = "TenantContextHttpExtensions.cs";

    private const string TypeName = @"(?:global::)?(?:Dependably\.)?(?:Infrastructure\.)?TenantContext";

    // A read of TenantId that turns "no tenant" into a value instead of failing: the
    // null-forgiving `!` (but not `!=`), or a `??` fallback to a string literal (including ""),
    // string.Empty, or a forgiven default!/null!.
    private const string NullDefeat =
        @"\s*(?:!(?!=)|\?\?\s*(?:[$@]{0,2}""[^""]*""|(?:string|String)\s*\.\s*Empty\b|(?:default|null)\s*!))";

    // (TenantContext)expr and (TenantContext?)expr — excludes typeof(TenantContext)/nameof(...)
    // via the lookbehind and requires an operand after the closing paren.
    [GeneratedRegex(@"(?<![\w>])\(\s*" + TypeName + @"\s*\??\s*\)\s*[\w(@]")]
    private static partial Regex HardCast();

    // Declarations, parameters, and pattern variables: `TenantContext ctx`, `TenantContext? ctx`,
    // `is TenantContext ctx`. A following `(` is a method declaration, collected separately.
    [GeneratedRegex(@"\b" + TypeName + @"\??\s+(@?[A-Za-z_]\w*)\b(?!\s*[(<])")]
    private static partial Regex TypedName();

    [GeneratedRegex(@"\bvar\s+(@?[A-Za-z_]\w*)\s*=[^;]*?\bas\s+" + TypeName + @"\b")]
    private static partial Regex VarAs();

    [GeneratedRegex(@"\bvar\s+(@?[A-Za-z_]\w*)\s*=\s*\(\s*" + TypeName + @"\s*\??\s*\)")]
    private static partial Regex VarCast();

    [GeneratedRegex(@"\b" + TypeName + @"\??\s+([A-Za-z_]\w*)\s*\(")]
    private static partial Regex MethodReturningTenantContext();

    // (x as TenantContext).TenantId! / (x as TenantContext)?.TenantId ?? ""
    [GeneratedRegex(@"\bas\s+" + TypeName + @"\s*\)\s*\??\s*\.\s*TenantId" + NullDefeat)]
    private static partial Regex InlineAsForgiven();

    private readonly ITestOutputHelper _output;
    public TenantIdReadComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void TenantIdIsReadOnlyThroughRequireTenantId()
    {
        var violations = new List<string>();
        bool helperSeen = false;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (Path.GetFileName(file).Equals(HelperFileName, StringComparison.Ordinal))
            {
                helperSeen = true;
                continue;
            }

            string text = File.ReadAllText(file);
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);

            foreach (var (index, what) in Scan(text))
            {
                if (HasMarkerAbove(text, index))
                {
                    continue;
                }

                violations.Add(
                    $"{rel}:{LineOf(text, index)}: {what} — use HttpContext.RequireTenantId() (or " +
                    "CurrentTenantId() on an OrgScopedControllerBase), which throws instead of " +
                    "letting a null tenant id reach a query when the tenant gate is skipped.");
            }
        }

        Assert.True(helperSeen,
            $"{HelperFileName} was not found under any source root; the gate's single sanctioned " +
            "reader has moved or been renamed, so update HelperFileName.");
        Assert.True(violations.Count == 0, Report(violations,
            "Null-forgiving TenantContext tenant-id read(s) bypassing RequireTenantId"));
    }

    [Fact]
    public void EveryTenantIdOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
                if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length == 0)
                {
                    violations.Add($"{rel}:{i + 1}: bare '{Marker}' marker with no stated reason.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations, "Malformed tenantid-ok marker(s)"));
    }

    [Theory]
    [InlineData("string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;")]
    [InlineData("var ctx = (TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!;")]
    [InlineData("var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;\nFoo(ctx.TenantId!);")]
    [InlineData("if (HttpContext.Items[TenantContext.HttpItemsKey] is not TenantContext ctx) return;\nFoo(ctx.TenantId!);")]
    [InlineData("string id = (HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext)?.TenantId!;")]
    [InlineData("private TenantContext? Resolve() => null;\nvoid M() { var t = Resolve(); Foo(t!.TenantId!); }")]
    [InlineData("private TenantContext? Resolve() => null;\nvoid M() { var t = Resolve(); Foo(t?.TenantId!); }")]
    [InlineData("var ca = (TenantContext?)HttpContext.Items[TenantContext.HttpItemsKey];\nreturn ca!.TenantId!;")]
    [InlineData("string orgId = (HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext)?.TenantId ?? \"\";")]
    [InlineData("string orgId = (HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext)?.TenantId ?? string.Empty;")]
    [InlineData("var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;\nFoo(ctx?.TenantId ?? \"default\");")]
    [InlineData("if (HttpContext.Items[TenantContext.HttpItemsKey] is TenantContext ctx) Foo(ctx.TenantId ?? null!);")]
    public void DetectorFlagsRawReads(string snippet) =>
        Assert.NotEmpty(Scan(snippet));

    [Theory]
    [InlineData("string orgId = HttpContext.RequireTenantId();")]
    [InlineData("if (HttpContext.Items[TenantContext.HttpItemsKey] is TenantContext { IsTenant: true, TenantId: { } id }) Foo(id);")]
    [InlineData("string? id = (HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext)?.TenantId;")]
    [InlineData("var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;\nif (ctx.TenantId != null) Foo(ctx.TenantId);")]
    [InlineData("var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;\nbool b = ctx.TenantId!= null;")]
    [InlineData("var ff = await BeginLoginAsync();\nFoo(ff.TenantId!);")]
    [InlineData("Type t = typeof(TenantContext);")]
    [InlineData("string id = (HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext)?.TenantId ?? throw new InvalidOperationException();")]
    [InlineData("var ff = await BeginLoginAsync();\nFoo(ff.TenantId ?? \"\");")]
    public void DetectorPassesSanctionedReads(string snippet) =>
        Assert.Empty(Scan(snippet));

    // The cast itself is flagged on its own, so a NotEmpty assertion alone cannot show that a
    // nullable cast also binds its receiver; this pins the receiver read separately.
    [Fact]
    public void DetectorBindsTheReceiverOfANullableCast() =>
        Assert.Contains(
            Scan("var ca = (TenantContext?)HttpContext.Items[TenantContext.HttpItemsKey];\nreturn ca!.TenantId!;"),
            h => h.What.Contains("'ca.TenantId'", StringComparison.Ordinal));

    /// <summary>Every banned read in <paramref name="text"/>, as (character index, description).</summary>
    private static List<(int Index, string What)> Scan(string text)
    {
        var hits = new List<(int, string)>();

        foreach (Match m in HardCast().Matches(text))
        {
            hits.Add((m.Index, "hard (TenantContext) cast"));
        }

        foreach (Match m in InlineAsForgiven().Matches(text))
        {
            hits.Add((m.Index, "null-defeating .TenantId read (! or a literal ?? fallback) on an inline 'as TenantContext'"));
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in new[] { TypedName(), VarAs(), VarCast() })
        {
            foreach (Match m in r.Matches(text))
            {
                names.Add(m.Groups[1].Value);
            }
        }

        foreach (Match method in MethodReturningTenantContext().Matches(text))
        {
            var callResult = new Regex(
                @"\bvar\s+(@?[A-Za-z_]\w*)\s*=\s*(?:await\s+)?(?:this\s*\.\s*)?" +
                Regex.Escape(method.Groups[1].Value) + @"\s*\(");
            foreach (Match m in callResult.Matches(text))
            {
                names.Add(m.Groups[1].Value);
            }
        }

        foreach (string name in names)
        {
            var forgiven = new Regex(
                @"(?<![\w.])" + Regex.Escape(name) + @"\s*[?!]?\s*\.\s*TenantId" + NullDefeat);
            foreach (Match m in forgiven.Matches(text))
            {
                hits.Add((m.Index, $"null-defeating '{name}.TenantId' read (! or a literal ?? fallback) on a TenantContext"));
            }
        }

        return hits;
    }

    private static bool HasMarkerAbove(string text, int index)
    {
        int line = LineOf(text, index);
        string[] lines = text.Split('\n');
        int first = Math.Max(0, line - 1 - MarkerWindow);

        for (int i = first; i < line && i < lines.Length; i++)
        {
            int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int LineOf(string text, int index) => 1 + text.AsSpan(0, index).Count('\n');

    private string Report(List<string> violations, string headline)
    {
        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        return $"{headline} ({violations.Count}):{Environment.NewLine}" +
               string.Join(Environment.NewLine, violations);
    }
}
