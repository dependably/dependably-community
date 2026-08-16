using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every hand-rolled test host pins <c>DEPLOYMENT_MODE</c> before it registers services, so the
/// suite cannot be flipped into another tenancy mode by a variable exported in the developer's
/// shell.
///
/// <para><b>Why this needs a gate.</b> Both composition roots call
/// <c>.AddEnvironmentVariables()</c>, and an integration test boots that same builder, so ambient
/// environment reaches every test host. Storage is safe — the fixtures substitute
/// <c>IMetadataStore</c> and <c>IBlobStore</c> outright — but <c>DEPLOYMENT_MODE</c> selects the
/// tenant-resolver strategy at <em>service-registration</em> time, which no later DI substitution
/// can undo. In <c>multi</c> the host seeds no <c>default</c> org, so a developer running a local
/// multi-mode instance (a supported, deliberate setup) saw a large slice of the integration suite
/// fail with <c>"Default org not found"</c> — an error naming the org rather than the mode.</para>
///
/// <para><b>Ordering is the substance of the check, not a style rule.</b> The failure that
/// prompted this gate was not simply a missing pin: three factories already set
/// <c>UseSetting("DEPLOYMENT_MODE", …)</c> and still failed, because they set it <em>after</em>
/// <c>Program.ConfigureBuilder</c>, by which point the resolver is bound. That form works for
/// keys read at runtime (<c>AIR_GAPPED</c>, <c>OSV_MODE</c>) and sits on adjacent lines, so it is
/// the natural thing to copy — and it is inert here. A gate that only checked for the key's
/// presence would have passed all three and taught the wrong fix.</para>
///
/// <para><b>Deliberately not solved with a shared base class.</b> The obvious refactor — a
/// hermetic base every factory derives from — would silently blind
/// <see cref="BackgroundJobEgressComplianceTests"/>, whose scanner matches only classes declared
/// <em>directly</em> against <c>WebApplicationFactory&lt;…&gt;</c> and which documents that no
/// such intermediate base exists in this repo. Introducing one would drop every migrated factory
/// out of that gate: green-but-blind, which is worse than the problem being fixed. A static helper
/// plus this gate keeps both checks honest.</para>
///
/// <para><b>What this gate cannot see.</b> It matches text, not semantics: a pin reached through a
/// helper of a different name, or a factory that builds its host without calling
/// <c>Program.ConfigureBuilder</c>, is invisible. It also cannot tell whether the mode a factory
/// pins is the mode its assertions actually need — only that the value is fixed rather than
/// inherited. Like every gate in this family it proves a spelling and an ordering, never intent.
/// </para>
///
/// <para>Opt-out: a factory that deliberately wants to inherit the ambient environment annotates
/// its class body with <c>// deploymode-ok: &lt;reason&gt;</c>. A bare marker with no reason after
/// the colon is not honoured, matching the convention in <c>// xtenant:</c> and
/// <c>// audit-attribution-ok:</c>.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class TestHostAmbientEnvComplianceTests
{
    private readonly ITestOutputHelper _output;

    public TestHostAmbientEnvComplianceTests(ITestOutputHelper output) => _output = output;

    private const string OptOut = "deploymode-ok:";

    // This file's own name: it quotes the patterns it scans for, so it must exclude itself or the
    // quoted text reads as a real call site. Same exclusion BackgroundJobEgressComplianceTests makes.
    private const string SelfFileName = nameof(TestHostAmbientEnvComplianceTests) + ".cs";

    // The registration call the pin must precede.
    private const string RegistrationCall = "Program.ConfigureBuilder(";

    // Either spelling counts as a pin. The helper is the recommended form for a hand-rolled
    // factory, but the four canonical Infrastructure fixtures set the key inside a larger
    // settings dictionary they already build, which is equally hermetic — this gate enforces the
    // property (the value is fixed before services are registered), not one way of writing it.
    // Requiring the helper would churn those four for no behavioural gain.
    private static readonly string[] PinForms = ["TestHostEnv.PinAmbient(", "\"DEPLOYMENT_MODE\""];

    // Mirrors BackgroundJobEgressComplianceTests' matcher so the two gates see the same
    // population — a class declared directly against WebApplicationFactory<…>, bare or
    // namespace-qualified. See this class's doc note for what that deliberately excludes.
    [GeneratedRegex(@"\bclass\s+(?<name>\w+)\s*:\s*(?:[\w.]*\.)?WebApplicationFactory\s*<", RegexOptions.None)]
    private static partial Regex FactoryClassRegex();

    [Fact]
    public void EveryHandRolledTestHostPinsDeploymentModeBeforeRegisteringServices()
    {
        var violations = new List<string>();

        foreach (string file in TestSourceFiles())
        {
            string[] lines = File.ReadAllLines(file);
            var classes = FactoryStarts(lines);

            for (int c = 0; c < classes.Count; c++)
            {
                int start = classes[c].Line;
                int end = c + 1 < classes.Count ? classes[c + 1].Line : lines.Length;

                int registration = IndexOf(lines, start, end, RegistrationCall);
                if (registration < 0)
                {
                    // Does not build its own host from the real builder — nothing to pin.
                    continue;
                }

                int pin = IndexOfAny(lines, start, end, PinForms);
                if (pin >= 0 && pin < registration)
                {
                    continue;
                }

                if (HasOptOut(lines, start, end))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);
                violations.Add(pin < 0
                    ? $"{rel}:{registration + 1}: factory `{classes[c].Name}` calls " +
                      $"{RegistrationCall}…) without pinning DEPLOYMENT_MODE. An ambient value " +
                      $"selects the tenant resolver and the host seeds no `default` org. Call " +
                      $"`TestHostEnv.PinAmbient(builder)` immediately before it, or opt out with " +
                      $"`// {OptOut} <reason>`."
                    : $"{rel}:{pin + 1}: factory `{classes[c].Name}` pins DEPLOYMENT_MODE at line " +
                      $"{pin + 1}, AFTER {RegistrationCall}…) at line {registration + 1}. The " +
                      $"tenant resolver is already bound by then, so the pin is inert. Move it " +
                      $"above the {RegistrationCall}…) call.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} test host(s) inherit ambient DEPLOYMENT_MODE. See test output.");
        }
    }

    /// <summary>
    /// The scan is worthless if its matcher never fires, and a gate that silently matches nothing
    /// is the green-but-blind failure this family exists to avoid. Pins that the population is
    /// non-trivial and that both failure shapes are actually detected.
    /// </summary>
    [Fact]
    public void ScanCoversARealPopulation()
    {
        int factories = TestSourceFiles()
            .Select(File.ReadAllLines)
            .Sum(lines => FactoryStarts(lines).Count);

        Assert.True(factories >= 20, $"expected the factory population to be sizeable, found {factories}");
    }

    /// <summary>
    /// The ordering fixtures deliberately contain no class-declaration line.
    /// <see cref="BackgroundJobEgressComplianceTests"/> scans every file under <c>tests/</c> for
    /// factory declarations and excludes only its own, so a literal
    /// <c>class X : WebApplicationFactory&lt;…&gt;</c> written here as test data is read by that
    /// gate as a real factory booting an un-disabled host. The regex is covered separately below
    /// with a string assembled at runtime, so the trigger text never appears contiguously in this
    /// source.
    /// </summary>
    [Fact]
    public void DetectorFlagsAMissingPinAndAnOutOfOrderOne()
    {
        string[] missing =
        [
            "        var builder = WebApplication.CreateBuilder();",
            "        Program.ConfigureBuilder(builder);",
        ];
        Assert.Equal(-1, IndexOfAny(missing, 0, missing.Length, PinForms));
        Assert.True(IndexOf(missing, 0, missing.Length, RegistrationCall) >= 0);

        string[] tooLate =
        [
            "        Program.ConfigureBuilder(builder);",
            "        TestHostEnv.PinAmbient(builder);",
        ];
        Assert.True(IndexOfAny(tooLate, 0, tooLate.Length, PinForms)
                    > IndexOf(tooLate, 0, tooLate.Length, RegistrationCall));

        string[] correct =
        [
            "        TestHostEnv.PinAmbient(builder);",
            "        Program.ConfigureBuilder(builder);",
        ];
        Assert.True(IndexOfAny(correct, 0, correct.Length, PinForms)
                    < IndexOf(correct, 0, correct.Length, RegistrationCall));

        // The dictionary form used by the canonical fixtures also counts as a pin.
        string[] dictForm =
        [
            "            [\"DEPLOYMENT_MODE\"] = DeploymentMode,",
            "        Program.ConfigureBuilder(builder);",
        ];
        Assert.True(IndexOfAny(dictForm, 0, dictForm.Length, PinForms)
                    < IndexOf(dictForm, 0, dictForm.Length, RegistrationCall));
    }

    [Fact]
    public void FactoryClassRegexMatchesADeclaration()
    {
        // Assembled at runtime so the literal never appears contiguously in this file — see the
        // note on DetectorFlagsAMissingPinAndAnOutOfOrderOne for why that matters.
        string decl = "    private sealed class Probe : " + "WebApplicationFactory" + "<Program>";
        var m = FactoryClassRegex().Match(decl);
        Assert.True(m.Success);
        Assert.Equal("Probe", m.Groups["name"].Value);
    }

    [Fact]
    public void OptOutMarkerRequiresAReason()
    {
        Assert.True(LineCarriesReasonedMarker($"// {OptOut} exercises ambient resolution on purpose"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}   "));
    }

    private static IEnumerable<string> TestSourceFiles() =>
        Directory.EnumerateFiles(TestsRoot(), "*.cs", SearchOption.AllDirectories)
            .Where(f => !Path.GetFileName(f).Equals(SelfFileName, StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

    private static string TestsRoot() => Path.Combine(SourceRoots.RepoRoot(), "tests");

    private static List<(int Line, string Name)> FactoryStarts(string[] lines)
    {
        var found = new List<(int, string)>();
        for (int i = 0; i < lines.Length; i++)
        {
            var m = FactoryClassRegex().Match(lines[i]);
            if (m.Success)
            {
                found.Add((i, m.Groups["name"].Value));
            }
        }

        return found;
    }

    private static int IndexOfAny(string[] lines, int start, int end, string[] needles)
    {
        for (int i = start; i < end && i < lines.Length; i++)
        {
            string code = StripLineComment(lines[i]);
            if (needles.Any(n => code.Contains(n, StringComparison.Ordinal)))
            {
                return i;
            }
        }

        return -1;
    }

    private static int IndexOf(string[] lines, int start, int end, string needle)
    {
        for (int i = start; i < end && i < lines.Length; i++)
        {
            string code = StripLineComment(lines[i]);
            if (code.Contains(needle, StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    private static bool HasOptOut(string[] lines, int start, int end)
    {
        for (int i = start; i < end && i < lines.Length; i++)
        {
            if (LineCarriesReasonedMarker(lines[i]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool LineCarriesReasonedMarker(string line)
    {
        int at = line.IndexOf(OptOut, StringComparison.Ordinal);
        return at >= 0 && line[(at + OptOut.Length)..].Trim().Length > 0;
    }

    // Strips a trailing line comment so a call named inside a comment is not read as real code.
    private static string StripLineComment(string line)
    {
        int at = line.IndexOf("//", StringComparison.Ordinal);
        return at >= 0 ? line[..at] : line;
    }
}
