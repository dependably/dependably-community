using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Compares a previous release's schema DDL against the working tree's and reports the changes a
/// blue-green cutover cannot survive. Blue (previous release) and green (this build) run against
/// one database for the whole cutover window, so anything green removes or narrows is something
/// blue is still using.
///
/// <para>Five hazards are reported:</para>
/// <list type="bullet">
///   <item><description>a table declared by the previous release and gone from this one;</description></item>
///   <item><description>a column declared by the previous release and gone from this one;</description></item>
///   <item><description>a <c>CHECK (col IN (...))</c> whose allowed-value set shrinks — green then
///     rejects values blue still writes. Widening, or dropping the constraint outright, is safe and
///     is not reported;</description></item>
///   <item><description>any other <c>CHECK</c> clause on a surviving column that is added or
///     changed. A constraint blue never ran against can reject values blue writes, and the shape of
///     the predicate (a <c>GLOB</c> pattern, a Postgres <c>~</c> regex, an arbitrary boolean
///     expression) says nothing about whether it does. Only two shapes are exempt: a clause set that
///     shrinks or stays identical, and a literal <c>IN (...)</c> list that provably widens;</description></item>
///   <item><description>a column that stops being omittable from an <c>INSERT</c> — it becomes
///     <c>NOT NULL</c> with no <c>DEFAULT</c>, or it was already <c>NOT NULL</c> and loses the
///     <c>DEFAULT</c> that let blue omit it. Both fail blue's inserts identically.</description></item>
/// </list>
///
/// <para>Additive changes (new tables, new columns, widened value sets, relaxed nullability) are
/// invisible to blue and never reported. The deliberate contract step of an expand/migrate/contract
/// sequence — release N+2 dropping what release N+1 stopped reading — is waived per object with a
/// <c>backcompat-ok:</c> marker (see <see cref="BackCompatWaivers"/>), and so is a new constraint
/// whose reviewer has confirmed it cannot reject anything blue writes.</para>
///
/// <para>No attempt is made to decide whether one pattern predicate is a subset of another: regex
/// and <c>GLOB</c> containment is intractable in general, and a gate that got it wrong in the
/// permissive direction would read as comprehensive while passing a real narrowing. Textual change
/// is the signal, and the reviewer supplies the semantics through the waiver's reason.</para>
/// </summary>
internal static partial class SchemaBackwardCompatibility
{
    // `col IN ('a','b')` inside a CHECK expression. Only all-literal lists are read; anything else
    // (a subquery, a function call) yields no value set and is therefore never treated as narrowing.
    [GeneratedRegex(@"\b(?<col>\w+)\s+IN\s*\(\s*(?<vals>'(?:[^']|'')*'(?:\s*,\s*'(?:[^']|'')*')*)\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex InListRegex();

    [GeneratedRegex(@"'(?<val>(?:[^']|'')*)'")]
    private static partial Regex StringLiteralRegex();

    [GeneratedRegex(@"\bNOT\s+NULL\b", RegexOptions.IgnoreCase)]
    private static partial Regex NotNullRegex();

    [GeneratedRegex(@"\bDEFAULT\b", RegexOptions.IgnoreCase)]
    private static partial Regex DefaultRegex();

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();

    // One `\bname\b` matcher per column name met so far. `_` is a word character, so the boundary
    // never falls inside a snake_case identifier: `\bat\b` does not match `created_at`, and
    // `\bid\b` does not match `org_id`. Analyze() runs over every table of both provider files, so
    // the matchers are cached; xUnit runs test classes in parallel, hence the concurrent map.
    private static readonly ConcurrentDictionary<string, Regex> ColumnMentionRegexes = new(StringComparer.Ordinal);

    private static bool Mentions(string checkText, string column) =>
        ColumnMentionRegexes.GetOrAdd(
            column, c => new Regex($@"\b{Regex.Escape(c)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            .IsMatch(checkText);

    /// <summary>
    /// Every backward-incompatible change between <paramref name="previousSql"/> (the previous
    /// release's file) and <paramref name="currentSql"/> (the working tree's), minus the waived
    /// objects. <paramref name="file"/> only labels the diagnostics.
    /// </summary>
    public static List<string> Analyze(
        string file, string previousSql, string currentSql, BackCompatWaivers waivers)
    {
        var previous = SchemaSqlParser.ParseTableDefinitions(previousSql);
        var current = SchemaSqlParser.ParseTableDefinitions(currentSql);
        var violations = new List<string>();

        foreach ((string table, var before) in previous.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if (!current.TryGetValue(table, out var after))
            {
                if (!waivers.Covers(table))
                {
                    violations.Add(
                        $"{file}: table `{table}` is declared by the previous release and removed here — "
                        + "the previous release still reads it during a blue-green cutover");
                }

                continue;
            }

            CompareColumns(violations, file, table, before, after, waivers);
        }

        return violations;
    }

    private static void CompareColumns(
        List<string> violations, string file, string table,
        SchemaTable before, SchemaTable after, BackCompatWaivers waivers)
    {
        var afterColumns = after.Columns.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var beforeChecks = AllowedValueSets(before);
        var afterChecks = AllowedValueSets(after);
        var beforeTexts = CheckTexts(before);
        var afterTexts = CheckTexts(after);

        foreach (var column in before.Columns)
        {
            string qualified = $"{table}.{column.Name}";
            if (!afterColumns.TryGetValue(column.Name, out var afterColumn))
            {
                if (!waivers.Covers(qualified))
                {
                    violations.Add(
                        $"{file}: column `{qualified}` is declared by the previous release and removed here — "
                        + "the previous release still reads it during a blue-green cutover");
                }

                continue;
            }

            if (waivers.Covers(qualified))
            {
                continue;
            }

            // A narrowed IN-list is a changed CHECK too, and its diagnostic is the more specific of
            // the two — naming the lost values. One hazard, one line: report the specific form and
            // suppress the general one. Either way the same `table.column` waiver silences it.
            int reported = violations.Count;
            ReportNarrowedCheck(violations, file, qualified, column.Name, beforeChecks, afterChecks);
            if (violations.Count == reported)
            {
                ReportChangedCheck(
                    violations, file, qualified, column.Name, beforeChecks, afterChecks, beforeTexts, afterTexts);
            }

            ReportTightenedNullability(violations, file, qualified, column, afterColumn);
        }
    }

    private static void ReportNarrowedCheck(
        List<string> violations, string file, string qualified, string column,
        Dictionary<string, HashSet<string>> beforeChecks, Dictionary<string, HashSet<string>> afterChecks)
    {
        // This arm reports one thing only: a value set that survives into this release and is
        // smaller. With a list on one side only there is no shrinkage to measure — a dropped list
        // widens the domain, and a first-ever list is a narrowing of an unbounded one whose lost
        // values cannot be enumerated. Both are ReportChangedCheck's to judge, not this one's.
        if (!beforeChecks.TryGetValue(column, out var allowedBefore)
            || !afterChecks.TryGetValue(column, out var allowedAfter))
        {
            return;
        }

        var lost = allowedBefore.Except(allowedAfter, StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToList();
        if (lost.Count > 0)
        {
            violations.Add(
                $"{file}: CHECK on `{qualified}` no longer allows {string.Join(", ", lost.Select(v => $"'{v}'"))} — "
                + "the previous release still writes those values during a blue-green cutover");
        }
    }

    /// <summary>
    /// Reports a <c>CHECK</c> clause that this release adds to, or changes on, a column the previous
    /// release already declared. This is the arm that covers everything the value-set reader above
    /// cannot express: that reader only understands literal <c>IN (...)</c> lists, so every other
    /// predicate shape — <c>GLOB</c>, Postgres <c>~</c>, a hand-written boolean expression — puts
    /// nothing in either side's dictionary, both when it first appears and on every later change to
    /// it. A brand-new <c>IN (...)</c> list on a column that carried no constraint at all is the
    /// same blind spot from the other direction: an unconstrained column's domain is unbounded, so
    /// a first value list can reject values blue is writing right now.
    ///
    /// <para>The comparison is textual and set-based. Clauses that vanish or stay identical are
    /// safe (dropping a constraint only ever widens). Anything present after and absent before is a
    /// hazard unless it is fully explained by the widened-literal-list case the value-set reader
    /// already proves: the after-set is a superset of the before-set, and every newly-appearing
    /// clause carries an <c>IN (...)</c> list for this column. That keeps the routine "widen a
    /// CHECK enum" workflow waiver-free.</para>
    ///
    /// <para>Two known limits, both conservative and reviewer-closed. A clause that widens its
    /// <c>IN</c> list <i>and</i> gains an unrelated pattern predicate in the same edit reads as
    /// explained. And a multi-column <c>CHECK</c> is attributed to every column it names, so waiving
    /// it takes one marker per column — the waiver vocabulary is <c>table.column</c>, and
    /// over-requiring a marker is the safe direction.</para>
    /// </summary>
    private static void ReportChangedCheck(
        List<string> violations, string file, string qualified, string column,
        Dictionary<string, HashSet<string>> beforeChecks, Dictionary<string, HashSet<string>> afterChecks,
        Dictionary<string, HashSet<string>> beforeTexts, Dictionary<string, HashSet<string>> afterTexts)
    {
        if (!afterTexts.TryGetValue(column, out var textsAfter))
        {
            return;
        }

        var textsBefore = beforeTexts.TryGetValue(column, out var b) ? b : [];
        var appeared = textsAfter.Except(textsBefore, StringComparer.Ordinal).ToList();
        if (appeared.Count == 0 || IsWidenedLiteralList(column, appeared, beforeChecks, afterChecks))
        {
            return;
        }

        violations.Add(
            $"{file}: CHECK on `{qualified}` added or changed since the previous release — "
            + "the previous release's writers were never validated against it. Waive with "
            + "backcompat-ok if the new constraint cannot reject anything the previous release writes.");
    }

    // The one change the gate can prove harmless without a reviewer: a literal IN (...) list whose
    // value set grows. Both sides must have produced a value set (so the before side really was an
    // IN-list constraint, not an absent one), the after set must contain everything the before set
    // did, and each newly-appearing clause must itself be an IN (...) list over this column.
    private static bool IsWidenedLiteralList(
        string column, List<string> appeared,
        Dictionary<string, HashSet<string>> beforeChecks, Dictionary<string, HashSet<string>> afterChecks) =>
        beforeChecks.TryGetValue(column, out var allowedBefore)
        && afterChecks.TryGetValue(column, out var allowedAfter)
        && allowedAfter.IsSupersetOf(allowedBefore)
        && appeared.TrueForAll(text => InListRegex().Matches(text).Any(
            m => string.Equals(m.Groups["col"].Value, column, StringComparison.OrdinalIgnoreCase)));

    // A column the old slot can omit from an INSERT is one that is nullable, or defaulted, or both.
    // Losing the last of those two properties is the hazard — whether it arrives as "became NOT
    // NULL" or as "kept NOT NULL and lost its DEFAULT", the old slot's INSERT now fails.
    private static void ReportTightenedNullability(
        List<string> violations, string file, string qualified,
        SchemaColumn before, SchemaColumn after)
    {
        string beforeText = SchemaSqlParser.WithoutCheckExpressions(before.Declaration);
        string afterText = SchemaSqlParser.WithoutCheckExpressions(after.Declaration);
        bool wasOmittable = !NotNullRegex().IsMatch(beforeText) || DefaultRegex().IsMatch(beforeText);
        bool isOmittable = !NotNullRegex().IsMatch(afterText) || DefaultRegex().IsMatch(afterText);
        if (!wasOmittable || isOmittable)
        {
            return;
        }

        bool becameNotNull = !NotNullRegex().IsMatch(beforeText);
        violations.Add(
            becameNotNull
                ? $"{file}: column `{qualified}` becomes NOT NULL without a DEFAULT — "
                    + "the previous release's inserts omit it during a blue-green cutover"
                : $"{file}: column `{qualified}` is NOT NULL and loses its DEFAULT — "
                    + "the previous release's inserts omit it during a blue-green cutover");
    }

    /// <summary>
    /// Column → the literal values its <c>CHECK (col IN (...))</c> constraints allow, collected from
    /// both the column's own declaration and the table-level constraint items. A column constrained
    /// by more than one such list contributes the union: the gate reports only values that disappear
    /// from every list, so a multi-list column can never produce a false narrowing report.
    /// </summary>
    /// <summary>
    /// Column → the whitespace-normalised text of every <c>CHECK</c> expression that names it,
    /// gathered from both the column's own declaration and the table-level constraint items. A
    /// clause naming several columns lands under each of them, which is what makes a multi-column
    /// constraint visible from whichever column a reviewer looks at.
    ///
    /// <para>Attribution is a word-boundary name match, so it follows the column through whatever
    /// expression shape the clause uses instead of assuming one. Normalising whitespace is what
    /// keeps a pure re-wrap of a long predicate from reading as a change.</para>
    /// </summary>
    private static Dictionary<string, HashSet<string>> CheckTexts(SchemaTable table)
    {
        var texts = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string item in table.Columns.Select(c => c.Declaration).Concat(table.TableConstraints))
        {
            foreach (string check in SchemaSqlParser.CheckExpressions(item))
            {
                string normalized = WhitespaceRegex().Replace(check, " ").Trim();
                foreach (var column in table.Columns.Where(c => Mentions(normalized, c.Name)))
                {
                    if (!texts.TryGetValue(column.Name, out var forColumn))
                    {
                        texts[column.Name] = forColumn = new HashSet<string>(StringComparer.Ordinal);
                    }

                    forColumn.Add(normalized);
                }
            }
        }
        return texts;
    }

    private static Dictionary<string, HashSet<string>> AllowedValueSets(SchemaTable table)
    {
        var sets = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string item in table.Columns.Select(c => c.Declaration).Concat(table.TableConstraints))
        {
            foreach (string check in SchemaSqlParser.CheckExpressions(item))
            {
                foreach (Match inList in InListRegex().Matches(check))
                {
                    string column = inList.Groups["col"].Value;
                    if (!sets.TryGetValue(column, out var values))
                    {
                        sets[column] = values = new HashSet<string>(StringComparer.Ordinal);
                    }

                    foreach (Match literal in StringLiteralRegex().Matches(inList.Groups["vals"].Value))
                    {
                        values.Add(literal.Groups["val"].Value.Replace("''", "'", StringComparison.Ordinal));
                    }
                }
            }
        }
        return sets;
    }
}

/// <summary>
/// The set of objects whose backward-incompatible removal or narrowing is a deliberate, reviewed
/// contract step. Declared with a <c>backcompat-ok: &lt;table&gt;[.&lt;column&gt;] — &lt;reason&gt;</c>
/// marker in a schema-file or <c>SchemaInitializer</c> comment, mirroring the
/// <c>xtenant:</c> / <c>rawsql:</c> / <c>blobkey-ok:</c> opt-out convention. A table-level marker
/// waives only that table's removal; a column needs its own <c>table.column</c> marker.
/// </summary>
internal sealed partial class BackCompatWaivers
{
    // Marker + object + reason. The reason is what makes the waiver reviewable, so a marker that
    // names an object and stops there is reported as malformed rather than honoured.
    [GeneratedRegex(@"backcompat-ok:\s*(?<object>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)(?<reason>[^\r\n]*)")]
    private static partial Regex MarkerRegex();

    private readonly HashSet<string> _objects = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Markers that name an object but give no reason. Reported by the gate, never honoured.</summary>
    public List<string> Malformed { get; } = [];

    /// <summary>Every honoured marker, for diagnostics.</summary>
    public List<string> Declared { get; } = [];

    public bool Covers(string schemaObject) => _objects.Contains(schemaObject);

    /// <summary>
    /// Every marker declared by the working tree. They live where the change they authorise lives:
    /// the two schema files, or the <c>SchemaInitializer</c> partial carrying the migration.
    /// </summary>
    public static BackCompatWaivers FromSourceTree()
    {
        string src = SchemaTestPaths.SourceRoot();
        return FromFiles(
            new[] { SchemaTestPaths.SqliteSchema(src), SchemaTestPaths.PostgresSchema(src) }
                .Concat(SchemaTestPaths.SchemaInitializerFiles()));
    }

    /// <summary>Reads every <c>backcompat-ok:</c> marker out of the given source files.</summary>
    public static BackCompatWaivers FromFiles(IEnumerable<string> files)
    {
        var waivers = new BackCompatWaivers();
        foreach (string file in files)
        {
            string name = Path.GetFileName(file);
            foreach (Match m in MarkerRegex().Matches(File.ReadAllText(file)))
            {
                string schemaObject = m.Groups["object"].Value;
                string reason = m.Groups["reason"].Value.Trim().TrimStart('-', '—', ':', ' ').Trim();
                if (reason.Length == 0)
                {
                    waivers.Malformed.Add($"{name}: `backcompat-ok: {schemaObject}` gives no reason");
                    continue;
                }

                waivers._objects.Add(schemaObject);
                waivers.Declared.Add($"{name}: {schemaObject} — {reason}");
            }
        }
        return waivers;
    }
}
