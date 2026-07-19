using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: a READ (<c>SELECT</c>/<c>WITH</c>) SQL literal in <c>src/</c> that references
/// the uploaded catalogue (<c>package_versions</c>) must EITHER also reference the proxy
/// catalogue (<c>cache_artifact</c> or <c>tenant_artifact_access</c>), OR read from the
/// canonical inventory view (<c>artifact_inventory</c> / <c>artifact_license</c> /
/// <c>org_storage_bytes</c>), OR carry an explicit <c>// plane-ok: &lt;reason&gt;</c> opt-out.
///
/// This is the two-catalogue companion to <see cref="OrgIdFilteringComplianceTests"/> — same
/// crude static-scan style, same opt-out mechanics, same reason it lives in the test suite:
/// so a new read surface that quietly forgets one of the two catalogues an artifact can land in
/// (a hosted push into <c>package_versions</c>, a proxy pull into <c>cache_artifact</c> +
/// <c>tenant_artifact_access</c>) fails locally and on every PR instead of shipping as a scan
/// that reports an image "0 vulnerabilities" or a GC that deletes a still-referenced manifest.
///
/// The rule is applied ONLY to literals whose leading keyword is <c>SELECT</c> or <c>WITH</c>.
/// Write paths (<c>INSERT</c>/<c>UPDATE</c>/<c>DELETE</c>) are single-plane by definition — a
/// write targets the row it is writing, not a cross-catalogue read — so restricting to reads
/// removes the large majority of false positives without a single marker.
///
/// <para><b>This is a COVERAGE gate, not a correctness gate.</b> Its limits, plainly:</para>
/// <list type="bullet">
///   <item>It cannot see plain <c>"…"</c> or <c>+</c>-concatenated SQL — only raw
///     (<c>"""…"""</c>) and verbatim (<c>@"…"</c>) literals are scanned. A short single-line
///     query built as an ordinary quoted string, or one assembled by concatenation, is
///     invisible to it.</item>
///   <item>It cannot tell a CORRECT two-plane union from a broken one. An <c>INNER JOIN</c>
///     that silently drops orphaned cache artifacts still mentions both catalogues and passes —
///     this gate only forces the mention, it does not check the join semantics.</item>
///   <item>It cannot see the C#-side fan-out-then-merge sites at all — a method that issues two
///     separate single-plane queries and merges the results in code (rather than in one SQL
///     literal) never presents a literal that references both tables, so each query is judged
///     alone. <c>PackageRepository.GetLatestGoVersionAsync</c> is exactly this shape and is
///     invisible to the gate for that reason.</item>
///   <item>It cannot enforce OCI symmetry — that is the job of <c>artifact_inventory</c>'s single
///     <c>ecosystem</c> column, not this gate. The gate's job is to force new code onto the
///     read model; the model's job is to make <c>ecosystem != 'oci'</c> mean what its author
///     believes it means.</item>
/// </list>
///
/// <c>src/Dependably.Core/Infrastructure/SchemaInitializer*.cs</c> is excluded by path: its
/// <c>RunOnce</c> migrations legitimately touch one catalogue at a time (backfilling a column,
/// seeding a default) and marking all of them would be noise, not signal.
///
/// Opt-out: prefix the line that opens the SQL string (or one of the 5 lines above it) with
/// <c>// plane-ok: &lt;reason&gt;</c>. Example:
/// <code>
///   // plane-ok: hot-path point lookup on idx_package_versions_filename; the proxy plane is
///   // served by CacheArtifactRepository.GetByCoordinateAsync on its own index.
///   var row = await conn.QuerySingleOrDefaultAsync&lt;PackageVersion&gt;(
///       "SELECT * FROM package_versions WHERE filename = @filename");
/// </code>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class PlaneCoverageComplianceTests
{
    private readonly ITestOutputHelper _output;
    public PlaneCoverageComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>The uploaded / hosted-push catalogue this gate anchors on.</summary>
    private static readonly HashSet<string> UploadedCatalogTables = new(StringComparer.OrdinalIgnoreCase)
    {
        "package_versions",
    };

    /// <summary>The proxy / first-fetch catalogue. Either satisfies the "other plane" half.</summary>
    private static readonly HashSet<string> ProxyCatalogTables = new(StringComparer.OrdinalIgnoreCase)
    {
        "cache_artifact",
        "tenant_artifact_access",
    };

    /// <summary>
    /// The canonical cross-catalogue read model. A literal reading through one of these already
    /// spans both planes by construction, so it always satisfies the rule regardless of what
    /// else it references.
    /// </summary>
    private static readonly HashSet<string> InventoryViews = new(StringComparer.OrdinalIgnoreCase)
    {
        "artifact_inventory",
        "artifact_license",
        "org_storage_bytes",
    };

    [GeneratedRegex(@"""""""\s*(?<sql>.*?)\s*""""""", RegexOptions.Singleline)]
    private static partial Regex RawStringRegex();

    [GeneratedRegex(@"@""(?<sql>(?:[^""]|"""")*)""", RegexOptions.Singleline)]
    private static partial Regex VerbatimStringRegex();

    [GeneratedRegex(@"\b(FROM|JOIN|INTO|UPDATE)\s+(?<table>[a-z_][a-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex TableRefRegex();

    [Fact]
    public void ReadSqlAgainstUploadedCatalogue_AlsoCoversProxyPlane_OrIsExplicitlyOptedOut()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            // SchemaInitializer's RunOnce migrations legitimately touch one catalogue at a
            // time (backfilling a column on package_versions, seeding a default) — see the
            // type doc comment for why this exclusion exists.
            if (Path.GetFileName(file).StartsWith("SchemaInitializer", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            string source = string.Join('\n', lines);

            foreach (var match in EnumerateSqlLiterals(source))
            {
                if (!LooksLikeReadSql(match.Sql))
                {
                    continue;
                }

                var tables = TableRefsIn(match.Sql);
                bool touchesUploaded = tables.Overlaps(UploadedCatalogTables);
                if (!touchesUploaded)
                {
                    continue;
                }

                bool touchesProxy = tables.Overlaps(ProxyCatalogTables);
                bool touchesInventoryView = tables.Overlaps(InventoryViews);
                if (touchesProxy || touchesInventoryView)
                {
                    continue;
                }

                int lineNumber = CountLinesUpTo(source, match.StartIndex);
                if (HasOptOutComment(lines, lineNumber))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{lineNumber + 1}: read SQL touches the uploaded catalogue " +
                    "(package_versions) without also referencing the proxy catalogue " +
                    "(cache_artifact / tenant_artifact_access) or an inventory view " +
                    "(artifact_inventory / artifact_license / org_storage_bytes). " +
                    "Either read through the inventory model, join in the proxy plane, or " +
                    $"annotate the opening line with `// plane-ok: <reason>`. SQL: {Truncate(match.Sql, 120)}");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} read SQL literal(s) touch the uploaded catalogue without " +
                        "covering the proxy plane. See test output for the full list and remediation hint.");
        }
    }

    /// <summary>
    /// Self-test for the scanner. Pins the properties the gate depends on: a raw/verbatim
    /// literal against <c>package_versions</c> alone is flagged; one that also joins in the
    /// proxy catalogue, or reads through an inventory view, is not; a write (<c>UPDATE</c>/
    /// <c>INSERT</c>/<c>DELETE</c>) against <c>package_versions</c> alone is never flagged,
    /// since the gate applies only to <c>SELECT</c>/<c>WITH</c> literals.
    /// </summary>
    [Theory]
    // Read against the uploaded catalogue alone → must be seen.
    [InlineData(
        """await conn.QuerySingleOrDefaultAsync<PackageVersion>(@"SELECT id, version FROM package_versions WHERE package_id = @packageId");""",
        true)]
    // Read that also joins the proxy catalogue → not a violation.
    [InlineData(
        """
        await conn.QueryAsync<string>(@"SELECT pv.version FROM package_versions pv
            UNION ALL
            SELECT ca.version FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id");
        """,
        false)]
    // Read through the canonical inventory view → not a violation, even alone.
    [InlineData(
        """await conn.QueryAsync<string>(@"SELECT * FROM artifact_inventory WHERE org_id = @orgId");""",
        false)]
    // A write against package_versions alone is never in scope for this gate.
    [InlineData(
        """await conn.ExecuteAsync(@"UPDATE package_versions SET last_used = @now WHERE id = @id");""",
        false)]
    public void Scanner_FlagsSingleCatalogueReads_ButNotWritesOrCrossCatalogueReads(string source, bool expectViolation)
    {
        bool flagged = EnumerateSqlLiterals(source)
            .Where(m => LooksLikeReadSql(m.Sql))
            .Where(m => TableRefsIn(m.Sql).Overlaps(UploadedCatalogTables))
            .Any(m => !TableRefsIn(m.Sql).Overlaps(ProxyCatalogTables)
                   && !TableRefsIn(m.Sql).Overlaps(InventoryViews));

        Assert.Equal(expectViolation, flagged);
    }

    private record struct SqlMatch(string Sql, int StartIndex);

    private static IEnumerable<SqlMatch> EnumerateSqlLiterals(string source)
    {
        foreach (Match m in RawStringRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }

        foreach (Match m in VerbatimStringRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }
    }

    // Restricted to SELECT/WITH: write paths (INSERT/UPDATE/DELETE) are single-plane by
    // definition — they target the row being written, not a cross-catalogue read — so
    // excluding them removes the large majority of false positives with zero markers.
    private static bool LooksLikeReadSql(string s)
    {
        var head = s.TrimStart().AsSpan();
        return StartsWithKeyword(head, "SELECT") || StartsWithKeyword(head, "WITH");
    }

    private static bool StartsWithKeyword(ReadOnlySpan<char> s, string keyword)
        => s.Length >= keyword.Length
            && s[..keyword.Length].SequenceEqual(keyword.AsSpan())
            && (s.Length == keyword.Length || char.IsWhiteSpace(s[keyword.Length]));

    private static HashSet<string> TableRefsIn(string sql)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in TableRefRegex().Matches(sql))
        {
            found.Add(m.Groups["table"].Value);
        }
        return found;
    }

    private static int CountLinesUpTo(string source, int index)
    {
        int count = 0;
        for (int i = 0; i < index && i < source.Length; i++)
        {
            if (source[i] == '\n')
            {
                count++;
            }
        }

        return count;
    }

    // Same 6-line window (opening line + 5 above) the other Compliance gates use for their
    // opt-out markers.
    private static bool HasOptOutComment(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("plane-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Truncate(string s, int max)
    {
        s = s.Replace('\n', ' ').Replace('\r', ' ').Trim();
        return s.Length <= max ? s : s[..max] + "...";
    }
}
