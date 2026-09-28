using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check that no service holds a tier-agnostic <c>IBlobStore</c>. Every service takes
/// <c>TieredBlobStorage</c> and each code path names <c>.Cache</c> or <c>.Registry</c>.
///
/// <para>
/// The two tiers are one instance in a default deployment and two stores once an operator sets a
/// <c>*_CACHE</c> / <c>*_REGISTRY</c> storage override. A service handed a bare <c>IBlobStore</c>
/// reads and writes one fixed tier whatever its bytes are, and nothing fails until the tiers are
/// split: a proxy path that probes the registry tier for bytes the upstream fetch wrote to the
/// cache tier misses every time, re-fetches on every request, and records a size of zero. Making
/// the tier a named choice at each call site is what surfaces the question in review.
/// </para>
///
/// <para>
/// What it flags: an <c>IBlobStore</c> parameter in a constructor parameter list (an explicit
/// constructor of a type declared in the same file, or a <c>class</c>/<c>struct</c>/<c>record</c>
/// primary constructor, except a <c>private</c> record's), and any DI registration or resolution
/// of <c>IBlobStore</c> itself. A method parameter is allowed: the caller chose the tier. Opt out
/// with <c>// blobtier-ok: &lt;reason&gt;</c> in the 5 lines above the parameter; a bare marker
/// with no reason is not honoured.
/// </para>
///
/// <para>
/// Blind spot: it proves a service holds <c>TieredBlobStorage</c>, not that each site picked the
/// right tier. A proxy path that reads <c>.Registry</c> passes this gate. The split-tier tests
/// cover the choice itself: <c>SplitTierProxyServeIntegrationTests</c>,
/// <c>SplitTierPlacementIntegrationTests</c>, <c>SplitTierProxyStoredSizeIntegrationTests</c>,
/// <c>SplitTierNuGetSymbolIntegrationTests</c>, <c>RetentionSplitTierTests</c>,
/// <c>ClaimsPurgeSharedBlobTests</c> and <c>OrgControllerExtendedTests</c>.
/// </para>
///
/// <para>
/// The registration scan matches the generic forms (<c>AddSingleton&lt;IBlobStore&gt;</c>,
/// <c>AddSingleton&lt;IBlobStore, Impl&gt;</c>, <c>GetService&lt;IBlobStore&gt;</c>) and the
/// <c>typeof(IBlobStore)</c> forms passed to <c>Add*</c>/<c>Get*Service</c>. A registration
/// reached through a helper that takes the service type as a variable, or through reflection, is
/// not seen.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class BlobTierSelectionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public BlobTierSelectionComplianceTests(ITestOutputHelper output) => _output = output;

    private const string OptOut = "blobtier-ok:";

    [Fact]
    public void NoServiceInjectsATierAgnosticBlobStore()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            scanned++;
            string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
            foreach (int line in FindConstructorBlobStoreParameters(File.ReadAllText(file)))
            {
                violations.Add(
                    $"{rel}:{line}: IBlobStore constructor parameter. Take TieredBlobStorage and name "
                    + "the tier (.Cache for proxied bytes, .Registry for published bytes) at each "
                    + "use site. A deliberate exception needs `// blobtier-ok: <reason>` above it.");
            }
        }

        Assert.True(scanned >= 50, $"only {scanned} C# files scanned — the source-root walk likely regressed.");
        Report(violations, "tier-agnostic IBlobStore constructor parameter(s)");
    }

    [Fact]
    public void NoTierAgnosticBlobStoreIsRegisteredOrResolved()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
            foreach (int line in FindBlobStoreRegistrations(File.ReadAllText(file)))
            {
                violations.Add(
                    $"{rel}:{line}: IBlobStore registered or resolved from DI. Register and resolve "
                    + "TieredBlobStorage; a bare IBlobStore silently binds every consumer to one tier.");
            }
        }

        Report(violations, "IBlobStore DI registration(s) or resolution(s)");
    }

    // ── Self-tests: the scanner flags what it claims to and nothing else ─────────────────────

    [Theory]
    [InlineData("public sealed class Handler(ILogger log, IBlobStore blobs)\n{\n}")]
    [InlineData("public sealed record Services(\n    OrgRepository Orgs,\n    IBlobStore Blobs,\n    TimeProvider Time);")]
    [InlineData("internal sealed record Services(Dependably.Storage.IBlobStore Blobs);")]
    [InlineData("public sealed class Svc\n{\n    public Svc(\n        IMetadataStore db,\n        IBlobStore blobs)\n    {\n    }\n}")]
    [InlineData("public sealed class Svc\n{\n    internal Svc(IBlobStore? blobs) { }\n}")]
    public void Scanner_FlagsAConstructorParameter(string source)
    {
        Assert.Single(FindConstructorBlobStoreParameters(source));
    }

    [Theory]
    [InlineData("public sealed class Svc\n{\n    private Task ServeAsync(IBlobStore store, string key) => Task.CompletedTask;\n}")]
    [InlineData("public sealed class Svc\n{\n    private sealed record ResolvedLocalBlob(IBlobStore Tier, string BlobKey);\n}")]
    [InlineData("public sealed class Svc(TieredBlobStorage blobs)\n{\n    public Task<Stream?> GetAsync(IBlobStore tier) => tier.GetAsync(\"k\");\n}")]
    [InlineData("public sealed class Svc\n{\n    public Svc(\n        // blobtier-ok: a value object carrying the tier its caller chose\n        IBlobStore store)\n    {\n    }\n}")]
    [InlineData("public sealed class Svc(\n    // the IBlobStore is chosen by TieredBlobStorage\n    TieredBlobStorage blobs)\n{\n}")]
    public void Scanner_DoesNotFlagAMethodParameterPrivateRecordOrMarkedSite(string source)
    {
        Assert.Empty(FindConstructorBlobStoreParameters(source));
    }

    [Fact]
    public void Scanner_DoesNotHonourABareMarker()
    {
        const string source = "public sealed class Svc\n{\n    public Svc(\n        // blobtier-ok:\n        IBlobStore store)\n    {\n    }\n}";
        Assert.Single(FindConstructorBlobStoreParameters(source));
    }

    [Theory]
    [InlineData("builder.Services.AddSingleton<IBlobStore>(sp => sp.GetRequiredService<TieredBlobStorage>().Registry);")]
    [InlineData("services.AddScoped<Dependably.Storage.IBlobStore>(_ => store);")]
    [InlineData("var blobs = sp.GetRequiredService<IBlobStore>();")]
    [InlineData("var blobs = sp.GetService< IBlobStore >();")]
    [InlineData("services.AddSingleton<IBlobStore, LocalBlobStore>();")]
    [InlineData("services.TryAddScoped<Dependably.Storage.IBlobStore , S3BlobStore>();")]
    [InlineData("services.AddSingleton(typeof(IBlobStore), typeof(LocalBlobStore));")]
    [InlineData("services.AddTransient( typeof( Dependably.Storage.IBlobStore ), sp => store);")]
    [InlineData("var blobs = (IBlobStore)sp.GetService(typeof(IBlobStore))!;")]
    [InlineData("var blobs = sp.GetRequiredService(typeof(IBlobStore));")]
    public void Scanner_FlagsARegistrationOrResolution(string source)
    {
        Assert.Single(FindBlobStoreRegistrations(source));
    }

    [Fact]
    public void Scanner_DoesNotFlagATieredRegistration()
    {
        Assert.Empty(FindBlobStoreRegistrations(
            "builder.Services.AddSingleton<TieredBlobStorage>(sp => new TieredBlobStorage(a, b));\n"
            + "var t = sp.GetRequiredService<TieredBlobStorage>();\n"
            + "services.AddSingleton<IBlobStoreFactory, BlobStoreFactory>();\n"
            + "services.AddSingleton(typeof(TieredBlobStorage), typeof(TieredBlobStorage));\n"
            + "services.AddSingleton<TieredBlobStorage, TieredBlobStorage>();\n"
            + "var s = sp.GetService(typeof(IBlobStoreFactory));"));
    }

    // ── Scanner ──────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Line numbers (1-based) of each <c>IBlobStore</c> parameter inside a constructor parameter
    /// list in <paramref name="source"/>, excluding opted-out sites.
    /// </summary>
    internal static IReadOnlyList<int> FindConstructorBlobStoreParameters(string source)
    {
        string code = StripLineComments(source);
        string[] lines = source.Split('\n');
        var typeNames = TypeDeclaration().Matches(code)
            .Select(m => m.Groups["name"].Value)
            .ToHashSet(StringComparer.Ordinal);

        var listStarts = new SortedSet<int>();
        foreach (Match m in PrimaryConstructor().Matches(code))
        {
            bool privateRecord = m.Groups["kind"].Value == "record"
                && PrivateModifier().IsMatch(m.Groups["mods"].Value);
            if (!privateRecord)
            {
                listStarts.Add(m.Index + m.Length - 1);
            }
        }

        foreach (Match m in ExplicitConstructor().Matches(code))
        {
            if (typeNames.Contains(m.Groups["name"].Value))
            {
                listStarts.Add(m.Index + m.Length - 1);
            }
        }

        var hits = new SortedSet<int>();
        foreach (int open in listStarts)
        {
            int close = MatchingParen(code, open);
            if (close < 0)
            {
                continue;
            }

            string list = code[(open + 1)..close];
            foreach (Match p in BlobStoreParameter().Matches(list))
            {
                int line = LineOf(code, open + 1 + p.Index);
                if (!HasOptOut(lines, line - 1))
                {
                    hits.Add(line);
                }
            }
        }

        return hits.ToList();
    }

    /// <summary>Line numbers (1-based) of each DI registration or resolution of <c>IBlobStore</c>.</summary>
    internal static IReadOnlyList<int> FindBlobStoreRegistrations(string source)
    {
        string code = StripLineComments(source);
        return BlobStoreRegistration().Matches(code)
            .Select(m => LineOf(code, m.Index))
            .Distinct()
            .ToList();
    }

    private static int MatchingParen(string code, int open)
    {
        int depth = 0;
        for (int i = open; i < code.Length; i++)
        {
            if (code[i] == '(')
            {
                depth++;
            }
            else if (code[i] == ')' && --depth == 0)
            {
                return i;
            }
        }

        return -1;
    }

    private static int LineOf(string code, int index)
    {
        int line = 1;
        for (int i = 0; i < index; i++)
        {
            if (code[i] == '\n')
            {
                line++;
            }
        }

        return line;
    }

    /// <summary>
    /// Blanks every <c>//</c> comment to spaces, preserving offsets so line numbers still line up
    /// with the original text. A <c>//</c> inside a string literal is blanked too, which can only
    /// hide code on that one line, never invent a match.
    /// </summary>
    private static string StripLineComments(string source) =>
        LineComment().Replace(source, m => new string(' ', m.Length));

    private static bool HasOptOut(string[] lines, int zeroBasedLine)
    {
        for (int i = Math.Max(0, zeroBasedLine - 5); i <= zeroBasedLine && i < lines.Length; i++)
        {
            int at = lines[i].IndexOf(OptOut, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + OptOut.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private void Report(List<string> violations, string what)
    {
        if (violations.Count == 0)
        {
            return;
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.Fail($"{violations.Count} {what}:\n{string.Join('\n', violations)}");
    }

    [GeneratedRegex(@"//[^\n]*")]
    private static partial Regex LineComment();

    [GeneratedRegex(@"\b(?:class|record|struct)\s+(?<name>\w+)")]
    private static partial Regex TypeDeclaration();

    // class Name(  /  record Name<T>(  /  record struct Name(  — the list opens at the final '('.
    [GeneratedRegex(@"(?<mods>(?:\b(?:public|internal|protected|private|sealed|abstract|static|partial|readonly|file)\s+)*)\b(?<kind>class|record|struct)\s+(?:struct\s+|class\s+)?\w+\s*(?:<[^>()]*>)?\s*\(")]
    private static partial Regex PrimaryConstructor();

    [GeneratedRegex(@"\bprivate\b")]
    private static partial Regex PrivateModifier();

    // An access-modified member named like a type and followed directly by '(' is a constructor:
    // a method has a return type between the modifier and its name.
    [GeneratedRegex(@"(?m)^\s*(?:(?:public|internal|protected|private)\s+)+(?<name>\w+)\s*\(")]
    private static partial Regex ExplicitConstructor();

    [GeneratedRegex(@"\bIBlobStore\??\s+\w+")]
    private static partial Regex BlobStoreParameter();

    [GeneratedRegex(@"\b(?:TryAdd|Add)(?:Singleton|Scoped|Transient)\s*<\s*(?:[\w.]+\.)?IBlobStore\s*[,>]|\bGet(?:Required)?Service\s*<\s*(?:[\w.]+\.)?IBlobStore\s*>|\b(?:(?:TryAdd|Add)(?:Singleton|Scoped|Transient)|Get(?:Required)?Service)\s*\(\s*typeof\s*\(\s*(?:[\w.]+\.)?IBlobStore\s*\)")]
    private static partial Regex BlobStoreRegistration();
}
