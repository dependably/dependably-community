using System.Text;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that every <c>BlockGateRequest</c> factory supplies the full attribution
/// trio — <c>AuditActorId</c>, <c>ActorKind</c>, and <c>AuditActorLabel</c> — so a block-decision
/// audit row can name the actor that caused it.
///
/// <para>
/// The sibling gate <c>BlockGateRequestConstructionComplianceTests</c> enforces that the record is
/// built by a factory rather than field-by-field at a call site. It says nothing about what a
/// factory then puts in the fields, and that blind spot has already shipped: <c>AuditActorLabel</c>
/// was added to the record and wired into the <c>blocked_*</c> audit calls, but three of the five
/// factories never set it, so every block-gate row carried a NULL <c>actor_label</c>.
/// </para>
///
/// <para>
/// Nothing else could have caught it. The omission compiles, because these are optional record
/// parameters — a dropped one defaults to null rather than failing. And every test passed, because
/// the <c>service_tokens</c> join resolves the actor for as long as the token exists; the column is
/// only load-bearing once that row is gone. So the gap is invisible until a token is revoked, which
/// is precisely when an operator is asking who used it.
/// </para>
///
/// <para>
/// Opt-out: <c>// gate-request-ok: &lt;reason&gt;</c> in the 5 lines above the factory declaration.
/// Following the family rule, a marker with no reason after the colon is malformed and is not
/// honoured.
/// </para>
///
/// <para><b>Blind spots — what this gate does NOT prove.</b>
/// <list type="bullet">
/// <item>It proves an argument was <i>supplied</i>, never that its <i>value</i> is right. A factory
/// passing <c>token?.UserId</c> where it should pass <c>token?.AuditActorId</c> satisfies this gate
/// and still writes a NULL actor under a <c>'service'</c> discriminator —
/// <c>AuditActorIdComplianceTests</c> is the gate for <i>which value</i> identifies a token actor,
/// and the two are complementary rather than overlapping.</item>
/// <item>It is textual, not semantic. A factory that names the parameter but passes a literal
/// <c>null</c> is caught only for the positional <c>AuditActorId</c> slot (where a bare <c>null</c>
/// is the exact historical shape of the bug); a named <c>ActorKind: null</c> passes. Runtime-null
/// is legitimate — an anonymous pull has no actor — so the gate cannot demand non-null without
/// failing the honest case.</item>
/// <item>It covers <c>BlockGateRequest</c> only. The other attribution-bearing records
/// (<c>ProxyFetchRequest</c>, <c>ProxyVersionRequest</c>, <c>ProxyContext</c>) are out of scope
/// here: none of them writes <c>actor_label</c>, and their actor-id correctness is already the
/// subject of <c>AuditActorIdComplianceTests</c>. Widening this gate to them would trade a precise
/// failure message for a vague one.</item>
/// <item>It reads only factories declared as <c>public static BlockGateRequest …</c> in the file
/// that declares the record. A factory added elsewhere is invisible to this gate — but not to the
/// construction gate, which fails any <c>new BlockGateRequest(</c> outside that file.</item>
/// </list>
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class BlockGateRequestAttributionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public BlockGateRequestAttributionComplianceTests(ITestOutputHelper output) => _output = output;

    private const string RecordDeclaration = "public sealed record BlockGateRequest(";
    private const string FactorySignature = "public static BlockGateRequest ";
    private const string OptOut = "gate-request-ok:";

    /// <summary>The three fields that together let a block-decision row name its actor.</summary>
    private const string ActorIdField = "AuditActorId";
    private const string ActorKindField = "ActorKind";
    private const string ActorLabelField = "AuditActorLabel";

    [Fact]
    public void EveryBlockGateRequestFactory_SuppliesTheFullAttributionTrio()
    {
        string source = File.ReadAllText(FactoryFilePath());
        var factories = ParseFactories(source);

        // Green-but-blind guard: the parse finding nothing must fail, not pass. A refactor that
        // renames the factories or reshapes their declaration would otherwise leave this gate
        // scanning an empty set and reporting success.
        Assert.True(
            factories.Count >= 5,
            $"only {factories.Count} BlockGateRequest factory/factories parsed — the scanner likely "
            + "regressed against a reshaped declaration. Fix the scanner rather than the assertion.");

        int actorIdSlot = PositionalIndexOf(source, ActorIdField);

        var violations = new List<string>();
        foreach (var factory in factories)
        {
            foreach (string missing in MissingAttribution(factory, actorIdSlot))
            {
                violations.Add(
                    $"BlockGateService.cs:{factory.Line}: factory `{factory.Name}` does not supply "
                    + $"`{missing}`. A block-decision audit row built from it cannot name its actor "
                    + "once the token's own row is gone. Add the argument, or annotate the factory "
                    + "with `// gate-request-ok: <reason>`.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} incomplete BlockGateRequest factory field(s). See test output.");
        }
    }

    /// <summary>
    /// The record must actually declare all three fields. Without this, deleting one would make the
    /// gate above vacuously green — every factory trivially "complete" because there is nothing left
    /// to omit.
    /// </summary>
    [Fact]
    public void TheRecord_DeclaresEveryAttributionFieldThisGateChecks()
    {
        string source = File.ReadAllText(FactoryFilePath());
        string declaration = RecordParameterList(source);

        foreach (string field in new[] { ActorIdField, ActorKindField, ActorLabelField })
        {
            Assert.Contains(field, declaration, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Scanner self-test. Each case is a synthetic factory fed through the same parser and the same
    /// completeness check the real scan uses, so the detector cannot quietly stop firing: an
    /// incomplete factory must be reported, a complete one must not, and the opt-out must require a
    /// reason. The historical regression — <c>AuditActorLabel</c> omitted — is the first case.
    /// </summary>
    [Theory]
    // The exact shape that shipped: id and kind present, label dropped.
    [InlineData(
        "    public static BlockGateRequest ForX(string o) =>\n"
        + "        new(o, eco, purl, vid, ms, vca, userId, tol, ip,\n"
        + "            ActorKind: actorKind);\n",
        ActorLabelField)]
    // Kind dropped: the row renders as anonymous even though it is authenticated.
    [InlineData(
        "    public static BlockGateRequest ForX(string o) =>\n"
        + "        new(o, eco, purl, vid, ms, vca, userId, tol, ip,\n"
        + "            AuditActorLabel: label);\n",
        ActorKindField)]
    // A literal null in the positional actor slot is the omission written out longhand.
    [InlineData(
        "    public static BlockGateRequest ForX(string o) =>\n"
        + "        new(o, eco, purl, vid, ms, vca, null, tol, ip,\n"
        + "            ActorKind: k, AuditActorLabel: l);\n",
        ActorIdField)]
    public void Scanner_FiresOnAnIncompleteFactory(string factorySource, string expectedMissingField)
    {
        var parsed = Assert.Single(ParseFactories(factorySource));
        Assert.Contains(expectedMissingField, MissingAttribution(parsed, actorIdSlot: 6));
    }

    [Theory]
    // All three present — positional id, named kind and label. The shape every real factory uses.
    [InlineData(
        "    public static BlockGateRequest ForX(string o) =>\n"
        + "        new(o, eco, purl, vid, ms, vca, token?.AuditActorId, tol, ip,\n"
        + "            ActorKind: k, AuditActorLabel: l);\n")]
    // The id supplied by name rather than by position is equally complete.
    [InlineData(
        "    public static BlockGateRequest ForX(string o) =>\n"
        + "        new(o, eco, purl, vid, ms, vca, null, tol, ip,\n"
        + "            AuditActorId: id, ActorKind: k, AuditActorLabel: l);\n")]
    // A reasoned opt-out stands the gate down.
    [InlineData(
        "    // gate-request-ok: background sweep with no actor to attribute.\n"
        + "    public static BlockGateRequest ForX(string o) =>\n"
        + "        new(o, eco, purl, vid, ms, vca, null, tol, ip);\n")]
    public void Scanner_StandsDownForACompleteOrAnnotatedFactory(string factorySource)
    {
        var parsed = Assert.Single(ParseFactories(factorySource));
        Assert.Empty(MissingAttribution(parsed, actorIdSlot: 6));
    }

    /// <summary>
    /// A bare marker carries no reason, so it does not excuse anything — the family rule that keeps
    /// an opt-out reviewable rather than a way to silence the gate.
    /// </summary>
    [Fact]
    public void Scanner_RejectsAnOptOutMarkerWithNoReason()
    {
        var parsed = Assert.Single(ParseFactories(
            "    // gate-request-ok:\n"
            + "    public static BlockGateRequest ForX(string o) =>\n"
            + "        new(o, eco, purl, vid, ms, vca, null, tol, ip);\n"));

        Assert.NotEmpty(MissingAttribution(parsed, actorIdSlot: 6));
    }

    // ── Scanner ──────────────────────────────────────────────────────────────────────────────

    private sealed record Factory(string Name, int Line, IReadOnlyList<string> Arguments, bool OptedOut);

    /// <summary>
    /// Every <c>public static BlockGateRequest …</c> declaration in the source, paired with the
    /// top-level arguments of the <c>new(…)</c> expression that is its body.
    /// </summary>
    private static IReadOnlyList<Factory> ParseFactories(string source)
    {
        string[] lines = source.Split('\n');
        var factories = new List<Factory>();

        for (int i = 0; i < lines.Length; i++)
        {
            int signature = lines[i].IndexOf(FactorySignature, StringComparison.Ordinal);
            if (signature < 0)
            {
                continue;
            }

            string afterSignature = lines[i][(signature + FactorySignature.Length)..];
            int nameEnd = afterSignature.IndexOf('(', StringComparison.Ordinal);
            if (nameEnd <= 0)
            {
                continue;
            }

            string name = afterSignature[..nameEnd].Trim();
            string? construction = ConstructionAfter(source, LineStartOffset(lines, i));
            if (construction is null)
            {
                continue;
            }

            factories.Add(new Factory(name, i + 1, SplitTopLevel(construction), HasReasonedOptOut(lines, i)));
        }

        return factories;
    }

    /// <summary>
    /// The argument text of the first <c>new(</c> at or after <paramref name="offset"/>, read to its
    /// matching close paren. Returns null when the declaration has no such expression body.
    /// </summary>
    private static string? ConstructionAfter(string source, int offset)
    {
        int open = source.IndexOf("new(", offset, StringComparison.Ordinal);
        if (open < 0)
        {
            return null;
        }

        int cursor = open + "new(".Length;
        int depth = 1;
        var text = new StringBuilder();
        while (cursor < source.Length && depth > 0)
        {
            char c = source[cursor];
            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0)
                {
                    break;
                }
            }

            text.Append(c);
            cursor++;
        }

        return depth == 0 ? text.ToString() : null;
    }

    /// <summary>
    /// Splits an argument list on its top-level commas, ignoring commas nested in parens, brackets
    /// or string literals. Line comments are stripped first: the real factories carry explanatory
    /// comments between arguments, and a comma inside one would otherwise split an argument in two.
    /// </summary>
    private static IReadOnlyList<string> SplitTopLevel(string arguments)
    {
        var stripped = new StringBuilder();
        foreach (string line in arguments.Split('\n'))
        {
            int comment = IndexOfLineComment(line);
            stripped.Append(comment >= 0 ? line[..comment] : line).Append('\n');
        }

        var args = new List<string>();
        var current = new StringBuilder();
        int depth = 0;
        bool inString = false;

        foreach (char c in stripped.ToString())
        {
            if (c == '"')
            {
                inString = !inString;
            }

            if (!inString)
            {
                if (c is '(' or '[' or '{')
                {
                    depth++;
                }
                else if (c is ')' or ']' or '}')
                {
                    depth--;
                }
                else if (c == ',' && depth == 0)
                {
                    args.Add(current.ToString().Trim());
                    current.Clear();
                    continue;
                }
            }

            current.Append(c);
        }

        if (current.ToString().Trim().Length > 0)
        {
            args.Add(current.ToString().Trim());
        }

        return args;
    }

    /// <summary>Offset of a <c>//</c> that is not inside a string literal, or -1.</summary>
    private static int IndexOfLineComment(string line)
    {
        bool inString = false;
        for (int i = 0; i < line.Length - 1; i++)
        {
            if (line[i] == '"')
            {
                inString = !inString;
            }
            else if (!inString && line[i] == '/' && line[i + 1] == '/')
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Which attribution fields the factory fails to supply. <paramref name="actorIdSlot"/> is the
    /// actor id's index in the record's positional parameter list, derived from the declaration
    /// rather than hard-coded — a reordered record would otherwise silently move this check onto the
    /// wrong argument and keep passing.
    /// </summary>
    private static IReadOnlyList<string> MissingAttribution(Factory factory, int actorIdSlot)
    {
        if (factory.OptedOut)
        {
            return [];
        }

        var missing = new List<string>();

        if (!SuppliesActorId(factory.Arguments, actorIdSlot))
        {
            missing.Add(ActorIdField);
        }

        foreach (string field in new[] { ActorKindField, ActorLabelField })
        {
            if (!factory.Arguments.Any(a => IsNamedArgument(a, field)))
            {
                missing.Add(field);
            }
        }

        return missing;
    }

    /// <summary>
    /// The actor id counts as supplied when it is named explicitly, or when the positional slot
    /// holds something other than a literal <c>null</c>. A bare <c>null</c> there is the omission
    /// written out longhand, so it is treated as one.
    /// </summary>
    private static bool SuppliesActorId(IReadOnlyList<string> arguments, int actorIdSlot)
    {
        if (arguments.Any(a => IsNamedArgument(a, ActorIdField)))
        {
            return true;
        }

        var positional = arguments.TakeWhile(a => !IsAnyNamedArgument(a)).ToList();
        return positional.Count > actorIdSlot
            && !positional[actorIdSlot].Equals("null", StringComparison.Ordinal);
    }

    private static bool IsNamedArgument(string argument, string name) =>
        argument.StartsWith(name, StringComparison.Ordinal)
        && argument.Length > name.Length
        && argument[name.Length..].TrimStart().StartsWith(':');

    /// <summary>
    /// True for any <c>Name: value</c> argument. The scan for the first named argument is what
    /// bounds the positional list, so it must not mistake a ternary or a namespace-qualified value
    /// for a name — hence the identifier-then-single-colon shape rather than a bare IndexOf(':').
    /// </summary>
    private static bool IsAnyNamedArgument(string argument)
    {
        int i = 0;
        while (i < argument.Length && (char.IsLetterOrDigit(argument[i]) || argument[i] == '_'))
        {
            i++;
        }

        if (i == 0 || i >= argument.Length)
        {
            return false;
        }

        string rest = argument[i..].TrimStart();
        return rest.StartsWith(':') && !rest.StartsWith("::", StringComparison.Ordinal);
    }

    /// <summary>
    /// Index of <paramref name="parameter"/> in the record's positional parameter list. Throws
    /// rather than returning a sentinel: a declaration this scanner cannot read is a broken gate,
    /// and a broken gate must fail loudly instead of checking argument slot -1 forever.
    /// </summary>
    private static int PositionalIndexOf(string source, string parameter)
    {
        var parameters = SplitTopLevel(RecordParameterList(source));
        for (int i = 0; i < parameters.Count; i++)
        {
            // A parameter reads "string? AuditActorId" or "string? AuditActorId = null"; the name is
            // the last token before any default.
            string declared = parameters[i].Split('=')[0].Trim();
            if (declared.EndsWith(parameter, StringComparison.Ordinal))
            {
                return i;
            }
        }

        throw new InvalidOperationException(
            $"`{parameter}` is not a positional parameter of BlockGateRequest. If the record was "
            + "reshaped, update this gate — do not delete the assertion.");
    }

    private static string RecordParameterList(string source)
    {
        int start = source.IndexOf(RecordDeclaration, StringComparison.Ordinal);
        if (start < 0)
        {
            throw new InvalidOperationException(
                $"`{RecordDeclaration}` not found — the gate cannot locate the record it checks.");
        }

        // RecordDeclaration ends with the open paren, so its last character is the list's start.
        return ParameterListAt(source, start + RecordDeclaration.Length - 1);
    }

    /// <summary>Reads a parenthesised list starting at the open paren at <paramref name="open"/>.</summary>
    private static string ParameterListAt(string source, int open)
    {
        int cursor = open + 1;
        int depth = 1;
        var text = new StringBuilder();
        while (cursor < source.Length && depth > 0)
        {
            char c = source[cursor];
            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0)
                {
                    break;
                }
            }

            text.Append(c);
            cursor++;
        }

        return text.ToString();
    }

    /// <summary>
    /// A <c>// gate-request-ok:</c> marker in the 5 lines above the declaration, carrying an actual
    /// reason. A bare marker is malformed and does not excuse the factory.
    /// </summary>
    private static bool HasReasonedOptOut(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            int marker = lines[probe].IndexOf(OptOut, StringComparison.OrdinalIgnoreCase);
            if (marker >= 0 && lines[probe][(marker + OptOut.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int LineStartOffset(string[] lines, int lineIndex)
    {
        int offset = 0;
        for (int i = 0; i < lineIndex; i++)
        {
            offset += lines[i].Length + 1;
        }

        return offset;
    }

    private static string FactoryFilePath() =>
        SourceRoots.AllCSharpFiles()
            .FirstOrDefault(f => Path.GetFileName(f).Equals("BlockGateService.cs", StringComparison.Ordinal))
        ?? throw new FileNotFoundException("BlockGateService.cs not found under any source root.");
}
