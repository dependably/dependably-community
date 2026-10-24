using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Enforces the cardinality budget documented in
/// <c>dependably-community.spec/specs/design/DESIGN-observability-taxonomy.md#cardinality-budget</c>:
/// no metric instrument carries an attribute named <c>tenant_id</c>,
/// <c>org_id</c>, <c>user_id</c>, <c>email</c>, <c>purl</c>, <c>sha256</c>,
/// or <c>ip_address</c>.
///
/// Detection is a source-text scan (<see cref="MetricAttributeScanner"/>) for every form the
/// metrics API accepts an attribute in: an explicit or target-typed
/// <c>KeyValuePair&lt;string, object?&gt;</c>, <c>KeyValuePair.Create</c>, <c>TagList.Add</c> and
/// <c>TagList</c> initializers, and pairs passed straight to an instrument, a
/// <c>Measurement&lt;T&gt;</c> or <c>DomainTimer.Start</c>. Tenant attribution belongs on spans
/// and log records, where high cardinality is cheap, so <c>Activity.SetTag</c> and log scopes are
/// deliberately not read. Putting it on metrics blows up the TSDB working set.
///
/// <para>
/// A key that is not a string literal cannot be checked against the allowlist, so it fails
/// unless a <c>// cardinality-ok: &lt;reason&gt;</c> marker on its line or in the five lines above
/// says why its value set is bounded (or why the pair is not a metric attribute at all). A bare
/// marker with no reason is not honoured. The marker never admits a literal name: an unlisted
/// literal goes on the allowlist or not at all.
/// </para>
///
/// <para>
/// The name check is a <em>closed allowlist</em> (<see cref="AllowedAttributeNames"/>), not a
/// denylist of the obvious identifier names. A denylist only catches an attribute someone
/// named after the identifier it carries; it says nothing about an innocuously named
/// attribute holding a caller-controlled value — which is the same unbounded series count
/// with none of the warning signs. A new attribute name therefore has to be added here
/// deliberately, with its bounded value set stated alongside it.
/// </para>
///
/// <para>
/// The scan covers every <c>src/Dependably*</c> source root via
/// <see cref="SourceRoots.AllCSharpFiles"/>: the instrumented code lives in
/// <c>Dependably.Core</c> and <c>Dependably.Management</c>, so a gate anchored on a single
/// project directory would read as comprehensive while scanning almost nothing.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class CardinalityBudgetTests
{
    /// <summary>
    /// Every metric attribute name the codebase may emit, each with the bounded value set
    /// that justifies it. Adding a name here is an assertion that its values come from a
    /// fixed vocabulary — never from a tenant, a package, a principal, a digest, a version,
    /// or a request-controlled address.
    /// </summary>
    private static readonly HashSet<string> AllowedAttributeNames = new(StringComparer.Ordinal)
    {
        "ecosystem",    // the shared ecosystem vocabulary (ECOSYSTEMS in web/src/lib/ecosystems.js)
        "scope",        // ecosystem|org — the metadata-invalidation counters only: which kind of
                        // cache set the message clears (MetadataInvalidationScopes)
        "outcome",      // the closed vocabulary pinned by OutcomeValueTests
        "reason",       // per-instrument bounded reason vocabularies
        "policy",       // rate-limit policy names declared by [EnableRateLimiting], plus "tenant"
        "partition",    // partition KIND only (token|user|ip|tenant|unknown), never the partition key
        "decision",     // allow|reject
        "cause",        // rate-limit failure-posture cause
        "job_name",     // the fixed background-job name set
        "tier",         // cache|registry
        "event_type",   // the audit event-type vocabulary
        "result",       // block-gate result labels
        "severity",     // advisory severity levels
        "pass",         // provenance verification pass/fail label
    };

    [Fact]
    public void NoAttributeNameOutsideTheAllowlistOnMetricInstruments()
    {
        var files = EnumerateScannedSource().Select(f => (Path: f, Text: File.ReadAllText(f))).ToList();
        var context = MetricAttributeScanner.BuildContext(files.Select(f => f.Text));
        var violations = new List<string>();

        foreach (var (file, text) in files)
        {
            string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
            violations.AddRange(FindViolations(text, context).Select(v => $"{rel}:{v}"));
        }

        Assert.True(
            violations.Count == 0,
            "Metric cardinality-budget violation. Every metric attribute must draw its values " +
            "from a bounded vocabulary; tenant, package, principal, digest, version and address " +
            "attribution belongs on spans / logs, not on metrics. Add a genuinely bounded new " +
            "attribute to AllowedAttributeNames in CardinalityBudgetTests, stating its value set. " +
            "A key the scan cannot read (not a string literal) needs a literal, or a " +
            "`// cardinality-ok: <reason>` marker on its line or in the five lines above. " +
            "See dependably-community.spec/specs/design/DESIGN-observability-taxonomy.md#cardinality-budget.\n  " +
            string.Join("\n  ", violations));
    }

    /// <summary>
    /// Every allowlisted name is emitted somewhere in src. Guards both ways: a scan that has
    /// stopped reading a form goes red here instead of green-but-blind, and a name whose last
    /// emitter was removed leaves the allowlist rather than lingering as pre-approval.
    /// </summary>
    [Fact]
    public void EveryAllowlistedNameIsSeenByTheScan()
    {
        var files = EnumerateScannedSource().Select(File.ReadAllText).ToList();
        var context = MetricAttributeScanner.BuildContext(files);
        var seen = files
            .SelectMany(text => MetricAttributeScanner.Scan(text, context))
            .Where(k => k.Kind == MetricAttributeKeyKind.Literal)
            .Select(k => k.Text)
            .ToHashSet(StringComparer.Ordinal);

        var unseen = AllowedAttributeNames.Where(n => !seen.Contains(n)).Order(StringComparer.Ordinal).ToList();

        Assert.True(
            unseen.Count == 0,
            "Allowlisted metric attribute names the scan found no emitter for: " + string.Join(", ", unseen) +
            ". Either the scan has gone blind to the form that emits them, or the emitter is gone and " +
            "the name should leave AllowedAttributeNames.");
    }

    /// <summary>
    /// The gate's verdict on one source text: each entry is <c>&lt;line&gt;  &lt;why&gt;</c>.
    /// </summary>
    internal static IReadOnlyList<string> FindViolations(string source, MetricAttributeScanner.Context context)
    {
        var violations = new List<string>();
        string[] lines = source.Split('\n');
        foreach (var key in MetricAttributeScanner.Scan(source, context))
        {
            if (key.Kind == MetricAttributeKeyKind.Literal)
            {
                if (!AllowedAttributeNames.Contains(key.Text))
                {
                    violations.Add($"{key.Line}  metric attribute \"{key.Text}\" is not in the allowlist");
                }
            }
            else if (!MetricAttributeScanner.HasOptOut(lines, key.Line))
            {
                violations.Add(
                    $"{key.Line}  metric attribute key `{key.Text}` is not a string literal, so the " +
                    "allowlist cannot check it; use a literal or mark it `// cardinality-ok: <reason>`");
            }
        }

        return violations;
    }

    // ── bounded reason vocabulary on upstream_url_blocks ─────────────────────

    private static readonly string[] AllowedUrlBlockReasons =
    {
        "blocked_range",
        "redirect_to_internal",
        "dns_rebind",
        "dns_failure",
    };

    /// <summary>
    /// Scans every source root for <c>UpstreamUrlBlocks.Add(</c> calls that carry a
    /// <c>"reason"</c> literal, and asserts that each literal belongs to the bounded
    /// vocabulary <c>{blocked_range|redirect_to_internal|dns_rebind|dns_failure}</c>.
    /// Prevents new callers from inventing ad-hoc reason strings that blow up the metric
    /// cardinality or drift from the documented label set.
    /// </summary>
    [Fact]
    public void UpstreamUrlBlocksReasonAttribute_MustBeWithinBoundedVocabulary()
    {
        var violations = new List<string>();

        foreach (string file in EnumerateScannedSource())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                if (!line.Contains("UpstreamUrlBlocks.Add(", StringComparison.Ordinal))
                {
                    continue;
                }

                // Extract the reason literal from `"reason", "<value>"` on the same line.
                int reasonIdx = line.IndexOf("\"reason\", \"", StringComparison.Ordinal);
                if (reasonIdx < 0)
                {
                    continue;
                }

                int valueStart = reasonIdx + "\"reason\", \"".Length;
                int valueEnd = line.IndexOf('"', valueStart);
                if (valueEnd < 0)
                {
                    continue;
                }

                string reason = line[valueStart..valueEnd];
                if (!Array.Exists(AllowedUrlBlockReasons, r => r == reason))
                {
                    string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                    violations.Add(
                        $"{rel}:{i + 1}  reason \"{reason}\" is not in the bounded vocabulary " +
                        $"({string.Join("|", AllowedUrlBlockReasons)})");
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            "UpstreamUrlBlocks reason attribute out of bounded vocabulary. " +
            "Add the new reason to AllowedUrlBlockReasons in CardinalityBudgetTests " +
            "and update the instrument description in DependablyMeter.\n  " +
            string.Join("\n  ", violations));
    }

    // Every hand-written C# file across all source roots. SourceRoots already drops obj/ and
    // bin/; the generated-file suffixes are dropped here because a source generator's output
    // is not a place a human introduces a metric attribute.
    private static IEnumerable<string> EnumerateScannedSource()
        => SourceRoots.AllCSharpFiles().Where(f =>
            !f.EndsWith(".g.cs", StringComparison.Ordinal)
            && !f.EndsWith(".AssemblyInfo.cs", StringComparison.Ordinal));
}
