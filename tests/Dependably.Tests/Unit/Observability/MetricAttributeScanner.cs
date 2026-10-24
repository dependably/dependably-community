using System.Text;
using System.Text.RegularExpressions;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Finds every metric attribute name a C# source file constructs, in each form the
/// <c>System.Diagnostics.Metrics</c> API accepts, for <see cref="CardinalityBudgetTests"/>.
///
/// <para>Forms recognised:</para>
/// <list type="number">
/// <item><c>new KeyValuePair&lt;string, object?&gt;(key, …)</c>, anywhere, including a key on the
/// next line.</item>
/// <item><c>KeyValuePair.Create(key, …)</c> and <c>KeyValuePair.Create&lt;string, object?&gt;(key, …)</c>,
/// anywhere.</item>
/// <item><c>tags.Add(key, …)</c> and <c>tags.Add(new(key, …))</c> on a <c>TagList</c>: a variable
/// declared as <c>TagList</c>, assigned <c>new TagList</c>, assigned the result of a src method
/// that returns <c>TagList</c>, or aliased from one of those.</item>
/// <item><c>TagList</c> collection initializers and collection expressions:
/// <c>new TagList { { key, … }, new(key, …) }</c>, <c>TagList t = new() { … }</c>,
/// <c>TagList t = [ … ]</c>.</item>
/// <item>Target-typed <c>new(key, …)</c> passed directly to an instrument's <c>Add</c>/<c>Record</c>,
/// to <c>new Measurement&lt;T&gt;(…)</c>, to <c>DomainTimer.Start(…)</c>, to an instrument factory
/// (<c>CreateCounter</c>, <c>CreateObservableGauge</c>, …) or to <c>new Meter(…)</c>; also inside
/// a collection expression in those argument lists.</item>
/// <item>Target-typed <c>new(key, …)</c> inside the initializer of a declaration typed
/// <c>KeyValuePair&lt;string, object?&gt;[]</c> or <c>…&lt;KeyValuePair&lt;string, object?&gt;&gt;</c>.</item>
/// </list>
///
/// <para>
/// A key that is not a plain string literal — a constant, field, variable, <c>nameof</c>,
/// interpolation or escaped literal — cannot be checked against the allowlist, so it is
/// reported as <see cref="MetricAttributeKeyKind.NonLiteral"/>. The gate fails it unless a
/// <c>// cardinality-ok: &lt;reason&gt;</c> marker sits on the key's line or in the five lines above.
/// </para>
///
/// <para>
/// Out of scope by design: span attributes (<c>Activity.SetTag</c>/<c>AddTag</c>) and log scopes,
/// where tenant and package attribution belong. Known blind spot: a tag collection built from a
/// type other than <c>KeyValuePair&lt;string, object?&gt;</c> or <c>TagList</c> (a
/// <c>Dictionary</c>, say) and handed to an instrument is not read.
/// </para>
/// </summary>
internal static partial class MetricAttributeScanner
{
    internal const string OptOutMarker = "cardinality-ok:";

    private const string KvpType = @"KeyValuePair\s*<\s*string\s*,\s*object\s*\??\s*>";

    [GeneratedRegex(@"\bnew\s+(?:System\.Collections\.Generic\.)?" + KvpType + @"\s*\(")]
    private static partial Regex ExplicitKvpRegex();

    [GeneratedRegex(@"\bKeyValuePair\s*\.\s*Create\s*(?:<\s*string\s*,\s*object\s*\??\s*>)?\s*\(")]
    private static partial Regex KvpCreateRegex();

    [GeneratedRegex(@"\b(?:Counter|Histogram|UpDownCounter|Gauge)\s*<\s*\w+\s*>\s+@?(?<name>\w+)\b")]
    private static partial Regex InstrumentDeclarationRegex();

    [GeneratedRegex(@"\bTagList\s+(?<name>\w+)\s*\(")]
    private static partial Regex TagListMethodRegex();

    [GeneratedRegex(@"\bTagList\s+@?(?<name>\w+)\s*(?=[=;,)])")]
    private static partial Regex TagListDeclarationRegex();

    [GeneratedRegex(@"\bvar\s+@?(?<name>\w+)\s*=\s*new\s+(?:System\.Diagnostics\.)?TagList\b")]
    private static partial Regex TagListVarNewRegex();

    [GeneratedRegex(@"\bvar\s+@?(?<name>\w+)\s*=\s*(?<rhs>[^;]*?)\.\s*(?<method>\w+)\s*\(")]
    private static partial Regex VarFromMethodRegex();

    [GeneratedRegex(@"\bvar\s+@?(?<name>\w+)\s*=\s*@?(?<source>\w+)\s*;")]
    private static partial Regex VarAliasRegex();

    [GeneratedRegex(@"\bnew\s+(?:System\.Diagnostics\.)?TagList\s*(?:\(\s*\))?\s*\{")]
    private static partial Regex TagListInitializerRegex();

    [GeneratedRegex(@"\bTagList\s+@?\w+\s*=\s*(?:new\s*\(\s*\)\s*\{|\[)")]
    private static partial Regex TagListTargetTypedInitializerRegex();

    [GeneratedRegex(@"(?:\bnew\s+Measurement\s*<\s*\w+\s*>|\bDomainTimer\s*\.\s*Start|\.\s*Create(?:Counter|Histogram|UpDownCounter|Gauge|Observable\w+)\s*(?:<\s*\w+\s*>)?|\bnew\s+(?:System\.Diagnostics\.Metrics\.)?Meter)\s*\(")]
    private static partial Regex MetricApiCallRegex();

    [GeneratedRegex(KvpType + @"\s*(?:\[\s*\]|>)")]
    private static partial Regex KvpCollectionTypeRegex();

    [GeneratedRegex(@"^(?:new\s+(?:System\.Collections\.Generic\.)?KeyValuePair\b|(?:System\.Collections\.Generic\.)?KeyValuePair\s*\.)")]
    private static partial Regex ExplicitPairStartRegex();

    [GeneratedRegex(@"^new\s*\(")]
    private static partial Regex TargetTypedNewRegex();

    [GeneratedRegex(@"^\w+\s*:\s*(?!:)")]
    private static partial Regex NamedArgumentRegex();

    [GeneratedRegex(@"^""(?<v>[^""\\\r\n]*)""$")]
    private static partial Regex RegularLiteralRegex();

    [GeneratedRegex(@"^@""(?<v>(?:[^""]|"""")*)""$")]
    private static partial Regex VerbatimLiteralRegex();

    [GeneratedRegex(@"^(?<q>""{3,})(?<v>[^\r\n]*?)\k<q>$")]
    private static partial Regex RawLiteralRegex();

    /// <summary>Names collected across the whole scanned tree before any file is checked.</summary>
    internal sealed record Context(IReadOnlySet<string> InstrumentNames, IReadOnlySet<string> TagListMethods);

    /// <summary>
    /// Instrument field/parameter names and <c>TagList</c>-returning method names declared in
    /// <paramref name="sources"/>, so a call in one file on an instrument declared in another is read.
    /// </summary>
    internal static Context BuildContext(IEnumerable<string> sources)
    {
        var instruments = new HashSet<string>(StringComparer.Ordinal);
        var methods = new HashSet<string>(StringComparer.Ordinal);
        foreach (string source in sources)
        {
            string masked = Mask(source);
            foreach (Match m in InstrumentDeclarationRegex().Matches(masked))
            {
                instruments.Add(m.Groups["name"].Value);
            }

            foreach (Match m in TagListMethodRegex().Matches(masked))
            {
                methods.Add(m.Groups["name"].Value);
            }
        }

        return new Context(instruments, methods);
    }

    /// <summary>Every metric attribute key constructed in <paramref name="source"/>.</summary>
    internal static IReadOnlyList<MetricAttributeKey> Scan(string source, Context context)
    {
        string masked = Mask(source);
        var found = new SortedDictionary<int, MetricAttributeKey>();

        void AddKey(int start, int end)
        {
            if (found.ContainsKey(start))
            {
                return;
            }

            found[start] = Classify(source, masked, start, end);
        }

        // Explicit pair construction anywhere: the key is the first argument.
        foreach (Match m in ExplicitKvpRegex().Matches(masked))
        {
            AddFirstArgument(m.Index + m.Length, AddKey);
        }

        foreach (Match m in KvpCreateRegex().Matches(masked))
        {
            AddFirstArgument(m.Index + m.Length, AddKey);
        }

        // TagList.Add(key, value) / TagList.Add(new(key, value)).
        foreach (string id in TagListIdentifiers(masked, context))
        {
            var addCall = new Regex(@"(?<![\w.])@?" + Regex.Escape(id) + @"\s*\.\s*Add\s*\(");
            foreach (Match m in addCall.Matches(masked))
            {
                var args = SplitTopLevel(masked, m.Index + m.Length);

                // Add(KeyValuePair<string, object?>) given an explicit pair: its key is read by the
                // explicit form above, and the splitter does not nest on generic angle brackets.
                if (args.Count > 0 && ExplicitPairStartRegex().IsMatch(masked[args[0].Start..args[0].End]))
                {
                    continue;
                }

                if (args.Count >= 2)
                {
                    AddKey(args[0].Start, args[0].End);
                }
                else if (args.Count == 1)
                {
                    ClassifyElement(args[0], AddKey, braceIsPair: false);
                }
            }
        }

        // TagList collection initializers / collection expressions.
        foreach (Match m in TagListInitializerRegex().Matches(masked))
        {
            AddElements(m.Index + m.Length, AddKey, braceIsPair: true);
        }

        foreach (Match m in TagListTargetTypedInitializerRegex().Matches(masked))
        {
            AddElements(m.Index + m.Length, AddKey, braceIsPair: true);
        }

        // Target-typed pairs passed straight into an instrument or metric API call.
        foreach (string instrument in context.InstrumentNames)
        {
            var call = new Regex(@"(?<![\w])@?" + Regex.Escape(instrument) + @"\s*\??\s*\.\s*(?:Add|Record)\s*\(");
            foreach (Match m in call.Matches(masked))
            {
                AddElements(m.Index + m.Length, AddKey, braceIsPair: false);
            }
        }

        foreach (Match m in MetricApiCallRegex().Matches(masked))
        {
            AddElements(m.Index + m.Length, AddKey, braceIsPair: false);
        }

        // Initializers of KeyValuePair<string, object?>[] / List<KeyValuePair<string, object?>>.
        foreach (Match m in KvpCollectionTypeRegex().Matches(masked))
        {
            if (FindInitializer(masked, m.Index + m.Length) is { } open)
            {
                AddElements(open + 1, AddKey, braceIsPair: false);
            }
        }

        return found.Values.ToList();

        void AddFirstArgument(int openEnd, Action<int, int> add)
        {
            var args = SplitTopLevel(masked, openEnd);
            if (args.Count > 0)
            {
                add(args[0].Start, args[0].End);
            }
        }

        void AddElements(int openEnd, Action<int, int> add, bool braceIsPair)
        {
            foreach (var element in SplitTopLevel(masked, openEnd))
            {
                ClassifyElement(element, add, braceIsPair);
            }
        }

        // A target-typed new(...) element contributes its first argument; a { key, value } element
        // of a collection initializer contributes its first item; a nested collection expression
        // is read element by element. Anything else (an explicit KeyValuePair, already matched
        // above, or a variable holding tags built elsewhere) contributes nothing here.
        void ClassifyElement(Span element, Action<int, int> add, bool braceIsPair)
        {
            string text = masked[element.Start..element.End];
            if (TargetTypedNewRegex().Match(text) is { Success: true } newMatch)
            {
                AddFirstArgument(element.Start + newMatch.Length, add);
            }
            else if (braceIsPair && text.StartsWith('{'))
            {
                var items = SplitTopLevel(masked, element.Start + 1);
                if (items.Count >= 2)
                {
                    add(items[0].Start, items[0].End);
                }
            }
            else if (text.StartsWith('['))
            {
                AddElements(element.Start + 1, add, braceIsPair: false);
            }
        }
    }

    private static HashSet<string> TagListIdentifiers(string masked, Context context)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in TagListDeclarationRegex().Matches(masked))
        {
            ids.Add(m.Groups["name"].Value);
        }

        foreach (Match m in TagListVarNewRegex().Matches(masked))
        {
            ids.Add(m.Groups["name"].Value);
        }

        foreach (Match m in VarFromMethodRegex().Matches(masked))
        {
            if (context.TagListMethods.Contains(m.Groups["method"].Value))
            {
                ids.Add(m.Groups["name"].Value);
            }
        }

        bool grew;
        do
        {
            grew = false;
            foreach (Match m in VarAliasRegex().Matches(masked))
            {
                if (ids.Contains(m.Groups["source"].Value) && ids.Add(m.Groups["name"].Value))
                {
                    grew = true;
                }
            }
        }
        while (grew);

        return ids;
    }

    // From just past a collection-typed declaration, walks to its initializer's opening brace or
    // bracket. Stops (no initializer) at the end of the statement, a parameter list, or a
    // non-empty argument list.
    private static int? FindInitializer(string masked, int from)
    {
        for (int i = from; i < masked.Length; i++)
        {
            char c = masked[i];
            switch (c)
            {
                case '{':
                case '[':
                    return i;
                case ';':
                case ')':
                case ',':
                    return null;
                case '(':
                    int j = i + 1;
                    while (j < masked.Length && char.IsWhiteSpace(masked[j]))
                    {
                        j++;
                    }

                    if (j < masked.Length && masked[j] == ')')
                    {
                        i = j;
                        continue;
                    }

                    return null;
            }
        }

        return null;
    }

    private static MetricAttributeKey Classify(string source, string masked, int start, int end)
    {
        string raw = source[start..end].Trim();
        if (NamedArgumentRegex().Match(masked[start..end].TrimStart()) is { Success: true } named)
        {
            raw = source[start..end].TrimStart()[named.Length..].Trim();
        }

        int line = LineOf(source, start);
        if (RegularLiteralRegex().Match(raw) is { Success: true } regular)
        {
            return new MetricAttributeKey(line, MetricAttributeKeyKind.Literal, regular.Groups["v"].Value);
        }

        if (VerbatimLiteralRegex().Match(raw) is { Success: true } verbatim)
        {
            return new MetricAttributeKey(line, MetricAttributeKeyKind.Literal, verbatim.Groups["v"].Value.Replace("\"\"", "\"", StringComparison.Ordinal));
        }

        if (RawLiteralRegex().Match(raw) is { Success: true } rawLiteral)
        {
            return new MetricAttributeKey(line, MetricAttributeKeyKind.Literal, rawLiteral.Groups["v"].Value);
        }

        string shown = raw.ReplaceLineEndings(" ");
        return new MetricAttributeKey(line, MetricAttributeKeyKind.NonLiteral, shown);
    }

    /// <summary>
    /// Whether a reasoned <c>// cardinality-ok:</c> marker sits on <paramref name="line"/> (1-based)
    /// or in the five lines above it.
    /// </summary>
    internal static bool HasOptOut(string[] lines, int line)
    {
        int index = line - 1;
        for (int i = Math.Max(0, index - 5); i <= index && i < lines.Length; i++)
        {
            int at = lines[i].IndexOf("//", StringComparison.Ordinal);
            if (at < 0)
            {
                continue;
            }

            string comment = lines[i][at..];
            int marker = comment.IndexOf(OptOutMarker, StringComparison.Ordinal);
            if (marker >= 0 && comment[(marker + OptOutMarker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private readonly record struct Span(int Start, int End);

    // Splits the comma-separated items from openEnd (just past an opening delimiter) up to the
    // first unmatched closing delimiter, at nesting depth zero. Each span is trimmed.
    private static List<Span> SplitTopLevel(string masked, int openEnd)
    {
        var spans = new List<Span>();
        int depth = 0;
        int itemStart = openEnd;
        for (int i = openEnd; i < masked.Length; i++)
        {
            char c = masked[i];
            if (c is '(' or '[' or '{')
            {
                depth++;
            }
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0)
                {
                    AddTrimmed(itemStart, i);
                    return spans;
                }

                depth--;
            }
            else if (c == ',' && depth == 0)
            {
                AddTrimmed(itemStart, i);
                itemStart = i + 1;
            }
        }

        return spans;

        void AddTrimmed(int s, int e)
        {
            while (s < e && char.IsWhiteSpace(masked[s]))
            {
                s++;
            }

            while (e > s && char.IsWhiteSpace(masked[e - 1]))
            {
                e--;
            }

            if (e > s)
            {
                spans.Add(new Span(s, e));
            }
        }
    }

    private static int LineOf(string source, int index)
    {
        int line = 1;
        for (int i = 0; i < index && i < source.Length; i++)
        {
            if (source[i] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    /// <summary>
    /// Returns <paramref name="source"/> with comment text and the contents of string and char
    /// literals replaced by spaces (newlines kept, delimiters and prefixes kept), so offsets map
    /// one-to-one onto the original and no delimiter inside a literal or comment is structural.
    /// Interpolation holes in a non-raw interpolated string are kept as code.
    /// </summary>
    internal static string Mask(string source)
    {
        var sb = new StringBuilder(source);
        int i = 0;
        MaskCode(source, sb, ref i, stopAtBrace: false);
        return sb.ToString();
    }

    private static void Blank(StringBuilder sb, int from, int to)
    {
        for (int k = from; k < to && k < sb.Length; k++)
        {
            if (sb[k] is not ('\n' or '\r'))
            {
                sb[k] = ' ';
            }
        }
    }

    private static void MaskCode(string s, StringBuilder sb, ref int i, bool stopAtBrace)
    {
        int braceDepth = 0;
        while (i < s.Length)
        {
            char c = s[i];
            char next = i + 1 < s.Length ? s[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                int end = s.IndexOf('\n', i);
                end = end < 0 ? s.Length : end;
                Blank(sb, i, end);
                i = end;
            }
            else if (c == '/' && next == '*')
            {
                int end = s.IndexOf("*/", i + 2, StringComparison.Ordinal);
                end = end < 0 ? s.Length : end + 2;
                Blank(sb, i, end);
                i = end;
            }
            else if (c == '\'')
            {
                int j = i + 1;
                while (j < s.Length && s[j] != '\'' && s[j] != '\n')
                {
                    j += s[j] == '\\' ? 2 : 1;
                }

                Blank(sb, i + 1, j);
                i = Math.Min(j + 1, s.Length);
            }
            else if (c is '"' or '$' or '@' && StringStart(s, i) is { } start)
            {
                MaskString(s, sb, ref i, start.Interpolated, start.Verbatim, start.QuoteIndex);
            }
            else if (stopAtBrace && c == '{')
            {
                braceDepth++;
                i++;
            }
            else if (stopAtBrace && c == '}')
            {
                if (braceDepth == 0)
                {
                    return;
                }

                braceDepth--;
                i++;
            }
            else
            {
                i++;
            }
        }
    }

    private static (bool Interpolated, bool Verbatim, int QuoteIndex)? StringStart(string s, int i)
    {
        bool interpolated = false;
        bool verbatim = false;
        int j = i;
        while (j < s.Length && s[j] is '$' or '@')
        {
            if (s[j] == '$')
            {
                interpolated = true;
            }
            else
            {
                verbatim = true;
            }

            j++;
        }

        if (j >= s.Length || s[j] != '"')
        {
            return null;
        }

        // An identifier character before '@'/'$' means this is not a literal prefix.
        bool identifierBefore = i > 0 && j > i && (char.IsLetterOrDigit(s[i - 1]) || s[i - 1] == '_');
        return identifierBefore ? null : (interpolated, verbatim, j);
    }

    private static void MaskString(string s, StringBuilder sb, ref int i, bool interpolated, bool verbatim, int quoteIndex)
    {
        int quotes = 0;
        while (quoteIndex + quotes < s.Length && s[quoteIndex + quotes] == '"')
        {
            quotes++;
        }

        if (quotes >= 3)
        {
            string fence = new('"', quotes);
            int close = s.IndexOf(fence, quoteIndex + quotes, StringComparison.Ordinal);
            int end = close < 0 ? s.Length : close;
            Blank(sb, quoteIndex + quotes, end);
            i = close < 0 ? s.Length : close + quotes;
            return;
        }

        int j = quoteIndex + 1;
        while (j < s.Length)
        {
            char c = s[j];
            if (verbatim && c == '"')
            {
                if (j + 1 < s.Length && s[j + 1] == '"')
                {
                    sb[j] = ' ';
                    sb[j + 1] = ' ';
                    j += 2;
                    continue;
                }

                break;
            }

            if (!verbatim && c == '\\')
            {
                Blank(sb, j, j + 2);
                j += 2;
                continue;
            }

            if (!verbatim && (c == '"' || c == '\n'))
            {
                break;
            }

            if (interpolated && c == '{')
            {
                if (j + 1 < s.Length && s[j + 1] == '{')
                {
                    sb[j] = ' ';
                    sb[j + 1] = ' ';
                    j += 2;
                    continue;
                }

                j++;
                MaskCode(s, sb, ref j, stopAtBrace: true);
                j++;
                continue;
            }

            if (c is not ('\n' or '\r'))
            {
                sb[j] = ' ';
            }

            j++;
        }

        i = Math.Min(j + 1, s.Length);
    }
}

internal enum MetricAttributeKeyKind
{
    /// <summary>A plain string literal; <see cref="MetricAttributeKey.Text"/> is its value.</summary>
    Literal,

    /// <summary>Anything else; <see cref="MetricAttributeKey.Text"/> is the expression as written.</summary>
    NonLiteral,
}

/// <summary>One metric attribute key found by <see cref="MetricAttributeScanner"/>; <c>Line</c> is 1-based.</summary>
internal sealed record MetricAttributeKey(int Line, MetricAttributeKeyKind Kind, string Text);
