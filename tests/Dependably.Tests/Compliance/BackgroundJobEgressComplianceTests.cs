using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every <c>WebApplicationFactory&lt;…&gt;</c> subclass under <c>tests/</c> boots a
/// real ASP.NET Core host via <c>Program.ConfigureBuilder</c>, which registers
/// <see cref="Dependably.Infrastructure.VulnerabilityScanService"/> (job names <c>vuln-scan</c>,
/// <c>vuln-rescan</c>), <see cref="Dependably.Infrastructure.ThreatFeedRefreshService"/>
/// (<c>threat-feed</c>), and <c>DeprecationRefreshService</c> (<c>deprecation-refresh</c>) as
/// hosted services with <c>RunOnStartup = true</c> — each fires a real outbound HTTP request
/// (OSV.dev, CISA KEV, FIRST.org EPSS, npm/PyPI/NuGet deprecation feeds) against the public
/// internet the instant the host starts. The same wiring also registers
/// <c>LicenseBackfillService</c> (<c>license-backfill</c>) with <c>RunOnStartup = true</c>; it
/// makes no outbound call, but mutates the shared <c>cache_artifact.license_checked_at</c> column
/// under a leader lock on every boot — its own source of cross-test non-determinism independent
/// of egress. <c>OciBlobSweepService</c> (<c>oci-blob-sweep</c>) is the same category one step
/// further: it DELETES <c>oci_blobs</c> rows no manifest references, which is exactly what a test
/// pushing a bare blob creates, so a tick landing mid-test lowers <c>org_storage_bytes</c> and
/// hands the tenant quota headroom it should not have — a 413 assertion sees 201. Its cron is
/// hourly at :17, so it surfaces only in whichever run straddles that minute.
/// A factory names all six job values in <c>DISABLE_BACKGROUND_JOBS</c>, or sets
/// <c>AIR_GAPPED=true</c> (which subsumes every job), or this gate fails. A factory that boots
/// without either silently reintroduces the outbound egress (or the shared-state boot mutation)
/// this gate exists to catch, and a factory that sets <c>DISABLE_BACKGROUND_JOBS</c> to some other
/// job name (vacuous coverage) is caught too, since the required job names are checked
/// individually rather than just the setting key's presence.
///
/// <para>
/// Limitation: an intermediate base class (<c>class X : SomeBase</c> where
/// <c>SomeBase : WebApplicationFactory&lt;…&gt;</c>) is invisible to this scanner — only a class
/// declared directly against <c>WebApplicationFactory&lt;…&gt;</c> (bare or namespace-qualified,
/// e.g. <c>Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory&lt;…&gt;</c>) is matched. No
/// such intermediate base exists in this repo today. If one is introduced, this gate does not
/// treat a base class's <c>DISABLE_BACKGROUND_JOBS</c> setting as inherited by the derived class —
/// the derived class must set it (or re-set it) itself to satisfy the check.
/// </para>
///
/// Opt-out: a factory that deliberately needs one of these jobs running (for example, a dedicated
/// test of that job's live behavior against an in-process mock) annotates its class body with
/// <c>// bgjobs-ok: &lt;reason&gt;</c>.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class BackgroundJobEgressComplianceTests
{
    private readonly ITestOutputHelper _output;
    public BackgroundJobEgressComplianceTests(ITestOutputHelper output) => _output = output;

    // This file's own name, so the real scan (EveryWebApplicationFactorySubclassDisablesTheRequiredJobs)
    // can exclude it — see the comment at that exclusion for why.
    private const string SelfFileName = nameof(BackgroundJobEgressComplianceTests) + ".cs";

    // The six job names every factory in tests/ must disable. vuln-scan/vuln-rescan
    // (VulnerabilityScanService), threat-feed (ThreatFeedRefreshService), and
    // deprecation-refresh (DeprecationRefreshService) fire a real outbound HTTP request at boot;
    // license-backfill (LicenseBackfillService) makes no outbound call but mutates the shared
    // cache_artifact.license_checked_at column under a leader lock at boot, its own source of
    // cross-test non-determinism. oci-blob-sweep (OciBlobSweepService) deletes oci_blobs rows no
    // manifest references — which is what every test pushing a bare blob creates — so a tick
    // landing mid-test lowers org_storage_bytes and hands the tenant quota headroom it should not
    // have. Kept in sync by hand with the four Infrastructure/*.cs
    // factories' DISABLE_BACKGROUND_JOBS value; a job added to that set without updating this
    // list would under-check new violations, so the two are also cross-checked directly in
    // RequiredJobListMatchesTheFourCanonicalFactories below.
    private static readonly string[] JobsDisabledInTests =
    [
        "vuln-scan",
        "vuln-rescan",
        "threat-feed",
        "deprecation-refresh",
        "license-backfill",
        "oci-blob-sweep",
    ];

    // Matches a class declared directly against WebApplicationFactory<…>, bare or
    // namespace-qualified (e.g. Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<…> or
    // Mvc.Testing.WebApplicationFactory<…>) — a fully-qualified reference is real usage in this
    // repo (see the WebApplicationFactoryClientOptions call sites) even though no factory
    // currently declares itself that way, so the optional-qualifier group is required, not
    // theoretical. See the class-doc limitation note for what this regex does NOT see
    // (intermediate base classes).
    [GeneratedRegex(@"\bclass\s+(?<name>\w+)\s*:\s*(?:[\w.]*\.)?WebApplicationFactory\s*<", RegexOptions.None)]
    private static partial Regex FactoryClassRegex();

    [GeneratedRegex(
        @"UseSetting\(\s*""DISABLE_BACKGROUND_JOBS""\s*,\s*""(?<value>[^""]*)""",
        RegexOptions.None)]
    private static partial Regex DisableJobsSettingRegex();

    [GeneratedRegex(
        @"UseSetting\(\s*""AIR_GAPPED""\s*,\s*""(?:true|1)""",
        RegexOptions.IgnoreCase)]
    private static partial Regex AirGappedSettingRegex();

    [Fact]
    public void EveryWebApplicationFactorySubclassDisablesTheRequiredJobs()
    {
        string repoRoot = SourceRoots.RepoRoot();
        string testsRoot = Path.Combine(repoRoot, "tests");

        var violations = new List<string>();
        foreach (string file in EnumerateSource(testsRoot))
        {
            // This file's own regression-coverage fixtures below contain literal text that
            // matches FactoryClassRegex (namespace-qualified declarations, a brace-desyncing
            // string literal) so the real scanner can be proven against them — but they are data,
            // not real factory declarations. Scanning this file's own raw text would flag them as
            // violations against themselves; exclude it the same way EnumerateSource already
            // excludes obj/ and bin/ build output.
            if (Path.GetFileName(file) == SelfFileName)
            {
                continue;
            }

            violations.AddRange(ScanText(Rel(repoRoot, file), File.ReadAllText(file)));
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail(
                $"{violations.Count} WebApplicationFactory subclass(es) boot without fully "
                + "disabling the required background jobs. See test output for the full list.");
        }
    }

    [Fact]
    public void RequiredJobListMatchesTheFourCanonicalFactories()
    {
        // Pin JobsDisabledInTests above to the value the four Infrastructure/*.cs factories
        // actually use, so a job renamed or added there without updating this list is caught
        // rather than silently under-checking every other factory in the repo.
        string repoRoot = SourceRoots.RepoRoot();
        string infraDir = Path.Combine(repoRoot, "tests", "Dependably.Tests", "Infrastructure");
        string expected = string.Join(",", JobsDisabledInTests);

        foreach (string file in new[] { "DependablyFactory.cs", "DependablyMultiFactory.cs", "DependablyMultiUpstreamFactory.cs", "EdgeFactory.cs" })
        {
            string text = File.ReadAllText(Path.Combine(infraDir, file));
            var m = DisableJobsSettingRegex().Match(text);
            Assert.True(m.Success, $"{file} no longer sets DISABLE_BACKGROUND_JOBS.");
            Assert.Equal(expected, m.Groups["value"].Value);
        }
    }

    // ── Regression coverage: the scanner itself, proven against synthetic fixtures ──────────

    [Theory]
    [InlineData("class FooFactory : WebApplicationFactory<Program>", "FooFactory")]
    [InlineData("class FooFactory : Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>", "FooFactory")]
    [InlineData("class FooFactory : Mvc.Testing.WebApplicationFactory<Program>", "FooFactory")]
    [InlineData("class FooFactory:WebApplicationFactory<Program>", "FooFactory")]
    public void FactoryClassRegex_MatchesBareAndNamespaceQualifiedDeclarations(string declaration, string expectedName)
    {
        var m = FactoryClassRegex().Match(declaration);
        Assert.True(m.Success, $"FactoryClassRegex failed to match: {declaration}");
        Assert.Equal(expectedName, m.Groups["name"].Value);
    }

    [Fact]
    public void Scan_CatchesNamespaceQualifiedFactoryDeclarationsThatDisableNothing()
    {
        // Permanent regression coverage for the hole where a bare-identifier-only regex silently
        // passed a factory declared against a namespace-qualified WebApplicationFactory<…>. Both
        // forms boot a real host and disable nothing, so both must be reported.
        string fixture = Fixture(
            "public sealed class FullyQualifiedLeakFactory",
            "    : Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>",
            "{",
            "}",
            "",
            "public sealed class PartiallyQualifiedLeakFactory : Mvc.Testing.WebApplicationFactory<Program>",
            "{",
            "}");

        var violations = ScanText("fixture.cs", fixture);

        Assert.Equal(2, violations.Count);
        Assert.Contains(violations, v => v.Contains("FullyQualifiedLeakFactory", StringComparison.Ordinal));
        Assert.Contains(violations, v => v.Contains("PartiallyQualifiedLeakFactory", StringComparison.Ordinal));
    }

    [Fact]
    public void Scan_AcceptsNamespaceQualifiedFactoryDeclarationThatDisablesTheRequiredJobs()
    {
        string fixture = Fixture(
            "public sealed class QualifiedButCompliantFactory",
            "    : Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program>",
            "{",
            "    protected override IHost CreateHost(IHostBuilder _)",
            "    {",
            "        builder.WebHost.UseSetting(",
            "            \"DISABLE_BACKGROUND_JOBS\",",
            "            \"vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep\");",
            "    }",
            "}");

        var violations = ScanText("fixture.cs", fixture);

        Assert.Empty(violations);
    }

    [Fact]
    public void Scan_ExtractionOverrunIntoASiblingDeclaration_FailsClosedInsteadOfSilentlyAbsorbingItsSetting()
    {
        // ExtractClassBody's naive brace counter desyncs on an unmatched '{' inside a string
        // literal (documented on ExtractClassBody). Without the over-run guard, the resulting
        // over-long body for LeakyBraceFactory would swallow SecondFactory's real, compliant
        // DISABLE_BACKGROUND_JOBS setting and silently pass LeakyBraceFactory (which sets
        // nothing). The guard must instead report LeakyBraceFactory as an extraction failure and
        // leave SecondFactory's own, independent scan unaffected.
        string fixture = Fixture(
            "namespace Fixture",
            "{",
            "    class LeakyBraceFactory : WebApplicationFactory<Program>",
            "    {",
            "        private const string Weird = \"{\";",
            "    }",
            "",
            "    class SecondFactory : WebApplicationFactory<Program>",
            "    {",
            "        private static void Configure()",
            "        {",
            "            builder.WebHost.UseSetting(",
            "                \"DISABLE_BACKGROUND_JOBS\",",
            "                \"vuln-scan,vuln-rescan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep\");",
            "        }",
            "    }",
            "}");

        var violations = ScanText("fixture.cs", fixture);

        Assert.Single(violations);
        Assert.Contains("LeakyBraceFactory", violations[0], StringComparison.Ordinal);
        Assert.DoesNotContain("SecondFactory", violations[0], StringComparison.Ordinal);
    }

    // ── Scanner internals ────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Scans one file's text for every <see cref="FactoryClassRegex"/> match and returns a
    /// violation string per class that fails to disable <see cref="JobsDisabledInTests"/>.
    /// Factored out of the main compliance <c>[Fact]</c> so the regression tests above can point
    /// it at an in-memory fixture instead of a file on disk.
    /// </summary>
    private static List<string> ScanText(string relPath, string text)
    {
        var violations = new List<string>();

        foreach (Match m in FactoryClassRegex().Matches(text))
        {
            int declStart = m.Index;
            int lineNumber = text[..declStart].Count(c => c == '\n') + 1;
            string className = m.Groups["name"].Value;

            string? body = ExtractClassBody(text, declStart);

            // Fail-closed guard for the brace counter's over-count direction: a body that
            // contains a SECOND factory declaration means extraction ran past this class's real
            // end (typically an unmatched brace inside a string/char literal desyncing the
            // count) and absorbed a sibling class. Treat that the same as an unresolved
            // extraction rather than silently accepting a body that could satisfy this
            // requirement using a DIFFERENT class's DISABLE_BACKGROUND_JOBS setting.
            if (body is not null && FactoryClassRegex().Count(body) > 1)
            {
                body = null;
            }

            if (body is null)
            {
                violations.Add(
                    $"{relPath}:{lineNumber}: class {className} — could not locate a balanced "
                    + "class body (brace-matching failed, or the extraction over-ran into a "
                    + "sibling factory declaration); fix the scan or the source.");
                continue;
            }

            if (body.Contains("bgjobs-ok:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (AirGappedSettingRegex().IsMatch(body))
            {
                continue;
            }

            var disableMatch = DisableJobsSettingRegex().Match(body);
            if (!disableMatch.Success)
            {
                violations.Add(
                    $"{relPath}:{lineNumber}: class {className} boots a real host "
                    + "(Program.ConfigureBuilder) without disabling the required background jobs — "
                    + "add builder.WebHost.UseSetting(\"DISABLE_BACKGROUND_JOBS\", "
                    + $"\"{string.Join(",", JobsDisabledInTests)}\"), set AIR_GAPPED=true, or opt out "
                    + "with `// bgjobs-ok: <reason>`.");
                continue;
            }

            string disabledValue = disableMatch.Groups["value"].Value;
            var missing = JobsDisabledInTests
                .Where(job => !disabledValue.Contains(job, StringComparison.Ordinal))
                .ToList();
            if (missing.Count > 0)
            {
                violations.Add(
                    $"{relPath}:{lineNumber}: class {className} sets DISABLE_BACKGROUND_JOBS="
                    + $"\"{disabledValue}\" but is missing required job(s): "
                    + $"{string.Join(", ", missing)}.");
            }
        }

        return violations;
    }

    /// <summary>
    /// Naive brace-matching class-body extractor: finds the first <c>{</c> at or after
    /// <paramref name="declStart"/> and returns the substring through its matching <c>}</c>.
    /// Braces hidden inside string/char literals desync the count in either direction. An
    /// UNDER-count (an unmatched <c>}</c> inside a literal) makes the counter reach depth 0 too
    /// early or never reach a balanced end before EOF — both already fail closed, returning
    /// <c>null</c> (reported as a violation) rather than a truncated body that might spuriously
    /// pass. An OVER-count (an unmatched <c>{</c> inside a literal) makes the counter run past
    /// this class's real end into subsequent source; <see cref="ScanText"/> guards that direction
    /// separately by rejecting a returned body that contains a second factory declaration.
    /// </summary>
    private static string? ExtractClassBody(string text, int declStart)
    {
        int braceStart = text.IndexOf('{', declStart);
        if (braceStart < 0)
        {
            return null;
        }

        int depth = 0;
        for (int i = braceStart; i < text.Length; i++)
        {
            if (text[i] == '{')
            {
                depth++;
            }
            else if (text[i] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return text[declStart..(i + 1)];
                }
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateSource(string root)
    {
        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            string p = file.Replace('\\', '/');
            if (p.Contains("/obj/") || p.Contains("/bin/"))
            {
                continue;
            }

            yield return file;
        }
    }

    private static string Fixture(params string[] lines) => string.Join('\n', lines);

    private static string Rel(string root, string file) => Path.GetRelativePath(root, file);
}
