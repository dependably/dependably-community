using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins where a presigned redirect can come from.
///
/// <para>
/// A redirect hands the client a bearer URL for an object's bytes and meters the transfer by the
/// size the caller passed in, so two properties have to hold structurally rather than by
/// convention. First, <c>RecordRedirectedEgress</c> is called from exactly one place — the seam,
/// <c>BlobPresignService.TryRedirectAsync</c> — so no serve path can record a redirect the seam
/// did not decide, or redirect without the seam's refusals (feature off, ecosystem not listed,
/// HEAD, <c>Range</c>, metadata-classified, unknown size, unsignable, missing object). Second, the
/// seam is never reachable from a route action declared <c>[MeteredEgress(EgressKind.Metadata, …)]</c>:
/// metadata is mutable or rendered, and a redirect to a stored object would serve a stale or
/// wrong answer under a URL that outlives the request.
/// </para>
///
/// <para>
/// The second property is also enforced at runtime (the seam refuses a request whose metering kind
/// is <c>Metadata</c> or still <c>PerResponse</c>); this gate catches the wiring before it ships.
/// It reads source, so it resolves reachability by method NAME: from every method that calls the
/// seam it walks callers transitively across all source roots until it reaches route actions (see
/// <see cref="ReachedActions"/> for the two call shapes it follows). Within those shapes, matching
/// by name over-approximates — two methods sharing a name are treated as one — which can only add
/// reached actions, never hide one, so a collision fails this gate rather than passing it blind.
/// It does not follow calls made through delegates or reflection; none of the serve paths
/// dispatch that way.
/// </para>
///
/// <para>
/// The set of files that call the seam is also pinned, so a new call site is a reviewed change to
/// the list below and not an unnoticed one.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class PresignedRedirectPostureComplianceTests
{
    private readonly ITestOutputHelper _output;
    public PresignedRedirectPostureComplianceTests(ITestOutputHelper output) => _output = output;

    private const string SeamCall = ".TryRedirectAsync(";

    /// <summary>
    /// Every source file that calls the seam, one artefact serve site per ecosystem (npm, PyPI and
    /// NuGet serve from handler classes; the rest from their controllers). A file added or removed
    /// here is a decision about which downloads may redirect.
    /// </summary>
    private static readonly string[] SeamCallers =
    [
        "ApkController.cs",
        "CargoController.Serve.cs",
        "GoController.cs",
        "HexController.Serve.cs",
        "MavenController.cs",
        "NpmTarballHandler.cs",
        "NuGetFlatContainerHandler.cs",
        "OciController.Blobs.cs",
        "PyPiDownloadHandler.cs",
        "RpmController.Proxy.cs",
        "TerraformController.cs",
    ];

    [Fact]
    public void RecordRedirectedEgress_HasExactlyOneCaller_TheSeam()
    {
        var callers = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string code = StripComment(lines[i]);
                if (code.Contains("RecordRedirectedEgress(", StringComparison.Ordinal)
                    && !code.Contains("static void RecordRedirectedEgress(", StringComparison.Ordinal))
                {
                    callers.Add($"{Path.GetFileName(file)}:{i + 1}");
                }
            }
        }

        callers.ForEach(_output.WriteLine);
        string only = Assert.Single(callers);
        Assert.StartsWith("BlobPresignService.cs:", only, StringComparison.Ordinal);
    }

    [Fact]
    public void SeamCallSites_AreThePinnedArtefactServeFiles()
    {
        var actual = SourceRoots.AllCSharpFiles()
            .Where(f => !f.EndsWith("BlobPresignService.cs", StringComparison.Ordinal))
            .Where(f => File.ReadAllLines(f).Any(l => StripComment(l).Contains(SeamCall, StringComparison.Ordinal)))
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Equal(SeamCallers, actual);
    }

    [Fact]
    public void Seam_IsNeverReachableFromAMetadataDeclaredAction()
    {
        var methods = SourceRoots.AllCSharpFiles()
            .Where(f => !f.EndsWith("BlobPresignService.cs", StringComparison.Ordinal))
            .SelectMany(f => ParseMethods(Path.GetFileName(f), File.ReadAllLines(f)))
            .ToList();

        var reached = ReachedActions(methods);
        foreach (var action in reached.OrderBy(a => a.Id, StringComparer.Ordinal))
        {
            _output.WriteLine($"{action.Id}: {action.Attributes.Replace('\n', ' ')}");
        }

        // Non-vacuous: every pinned caller file reaches at least one route action.
        Assert.True(reached.Count >= SeamCallers.Length, $"only {reached.Count} route actions reach the seam — the walk is broken");

        var violations = reached.Where(IsMetadataDeclared).Select(a => a.Id).Order(StringComparer.Ordinal).ToList();
        Assert.True(violations.Count == 0,
            "The presigned-redirect seam is reachable from Metadata-declared action(s): " + string.Join(", ", violations));
    }

    // ── Adversarial twins for the walk itself ──────────────────────────────────

    [Fact]
    public void Walk_FlagsAMetadataActionThatReachesTheSeamThroughAHelper()
    {
        var methods = ParseMethods("Fixture.cs", MetadataFixture.Split('\n')).ToList();
        var reached = ReachedActions(methods);

        Assert.Contains(reached, a => a.Name == "GetIndex" && IsMetadataDeclared(a));
        Assert.Contains(reached, a => a.Name == "GetTarball" && !IsMetadataDeclared(a));
    }

    [Fact]
    public void Walk_PassesAnArtifactActionAndIgnoresCommentedCalls()
    {
        var methods = ParseMethods("Fixture.cs", ArtifactFixture.Split('\n')).ToList();
        var reached = ReachedActions(methods);

        var only = Assert.Single(reached);
        Assert.Equal("GetTarball", only.Name);
        Assert.False(IsMetadataDeclared(only));
    }

    [Fact]
    public void Walk_FollowsAControllerIntoAHandlerClass()
    {
        var methods = ParseMethods("Fixture.cs", HandlerFixture.Split('\n')).ToList();
        var reached = ReachedActions(methods);

        var only = Assert.Single(reached);
        Assert.Equal("GetPackage", only.Name);
        Assert.True(IsMetadataDeclared(only));
    }

    private const string HandlerFixture = """
        public sealed class FixtureController
        {
            [HttpGet("/fixture/{name}")]
            [MeteredEgress(EgressKind.Metadata, "npm")]
            public Task<IActionResult> GetPackage(string name, CancellationToken ct)
                => _handler.RenderAsync(HttpContext, name, ct);
        }

        public sealed class FixtureHandler
        {
            public async Task<IActionResult> RenderAsync(HttpContext http, string name, CancellationToken ct)
                => await _presign.TryRedirectAsync(http, _blobs, name, 1, BlobOrigin.Proxied, "npm", ct) ?? new OkResult();
        }
        """;

    private const string MetadataFixture = """
        public sealed class FixtureController
        {
            [HttpGet("/fixture/index")]
            [MeteredEgress(EgressKind.Metadata, "npm")]
            public Task<IActionResult> GetIndex(CancellationToken ct)
                => ServeAsync(ct);

            [HttpGet("/fixture/tarball")]
            [MeteredEgress(EgressKind.Artifact, "npm")]
            public Task<IActionResult> GetTarball(CancellationToken ct)
                => ServeAsync(ct);

            private async Task<IActionResult> ServeAsync(CancellationToken ct)
            {
                return await _presign.TryRedirectAsync(HttpContext, _blobs, "k", 1, BlobOrigin.Proxied, "npm", ct) ?? Ok();
            }
        }
        """;

    private const string ArtifactFixture = """
        public sealed class FixtureController
        {
            [HttpGet("/fixture/index")]
            [MeteredEgress(EgressKind.Metadata, "npm")]
            public Task<IActionResult> GetIndex(CancellationToken ct)
            {
                // A note that ServeAsync( is deliberately not called here.
                return Task.FromResult<IActionResult>(Ok());
            }

            [HttpGet("/fixture/tarball")]
            [MeteredEgress(EgressKind.Artifact, "npm")]
            public Task<IActionResult> GetTarball(CancellationToken ct)
                => ServeAsync(ct);

            private async Task<IActionResult> ServeAsync(CancellationToken ct)
                => await _presign.TryRedirectAsync(HttpContext, _blobs, "k", 1, BlobOrigin.Proxied, "npm", ct) ?? Ok();
        }
        """;

    // ── Source model ──────────────────────────────────────────────────────────

    /// <summary>
    /// A method: the top-level type it sits in, its name, the attribute lines above it, and its
    /// body text (comments stripped).
    /// </summary>
    internal sealed record SourceMethod(string File, string Type, string Name, int Line, string Attributes, string Body)
    {
        public string Id => $"{File}:{Line} {Type}.{Name}";
        public bool IsRouteAction => Attributes.Contains("[Http", StringComparison.Ordinal);
    }

    private static bool IsMetadataDeclared(SourceMethod action)
        => action.Attributes.Contains("MeteredEgress(EgressKind.Metadata", StringComparison.Ordinal);

    /// <summary>
    /// The route actions from which the seam is reachable: seeded with every method whose body
    /// calls it, then closed over "is called by" until no new method is added. Two call shapes
    /// link a caller to a callee. An unqualified call (<c>Name(…)</c> or <c>this.Name(…)</c>)
    /// links methods of the same top-level type, across all of its partial files — this is how a
    /// controller action reaches its private serve helpers, and how one action delegates to
    /// another. A qualified call (<c>_handler.Name(…)</c>) links across types — how a controller
    /// reaches a handler class — and never into a route action, since nothing invokes a
    /// controller action through a reference.
    /// </summary>
    internal static List<SourceMethod> ReachedActions(IReadOnlyList<SourceMethod> methods)
    {
        var visited = new HashSet<SourceMethod>(methods.Where(m => m.Body.Contains(SeamCall, StringComparison.Ordinal)));
        var frontier = new Queue<SourceMethod>(visited);
        while (frontier.Count > 0)
        {
            var callee = frontier.Dequeue();
            string name = Regex.Escape(callee.Name);
            var unqualified = new Regex($@"(?<![\w.])(this\.)?{name}\s*(<[^()]*>)?\s*\(");
            var qualified = new Regex($@"(?<!\bthis)\.{name}\s*(<[^()]*>)?\s*\(");
            foreach (var caller in methods)
            {
                if (visited.Contains(caller))
                {
                    continue;
                }

                bool sameType = string.Equals(caller.Type, callee.Type, StringComparison.Ordinal);
                bool calls = sameType
                    ? unqualified.IsMatch(caller.Body)
                    : !callee.IsRouteAction && qualified.IsMatch(caller.Body);
                if (calls)
                {
                    visited.Add(caller);
                    frontier.Enqueue(caller);
                }
            }
        }

        return visited.Where(m => m.IsRouteAction).ToList();
    }

    private static readonly HashSet<string> NotAName = new(StringComparer.Ordinal)
    {
        "public", "private", "internal", "protected", "static", "async", "override", "sealed", "virtual",
        "new", "partial", "extern", "unsafe", "readonly", "abstract", "void", "Task", "ValueTask",
        "if", "for", "foreach", "while", "switch", "using", "return", "await", "catch", "lock", "nameof", "typeof",
    };

    [GeneratedRegex(@"^(public|internal|file)?\s*(static\s+|sealed\s+|abstract\s+|partial\s+)*(class|record|struct)\s+(?<name>\w+)")]
    private static partial Regex TopLevelType();

    [GeneratedRegex(@"^\s*(public|private|internal|protected)\b(?!.*\b(class|record|struct|interface|enum|delegate|event)\b)[^=;]*\(")]
    private static partial Regex Declaration();

    /// <summary>
    /// Splits a file into methods. A declaration is a line opening with an access modifier and
    /// containing a parameter list; its body runs to the next declaration. The attributes are the
    /// contiguous attribute and comment lines directly above it.
    /// </summary>
    internal static IEnumerable<SourceMethod> ParseMethods(string file, string[] lines)
    {
        var starts = new List<(int Line, string Type, string Name)>();
        string type = "";
        for (int i = 0; i < lines.Length; i++)
        {
            if (TopLevelType().Match(lines[i]) is { Success: true } declared)
            {
                type = declared.Groups["name"].Value;
            }
            else if (Declaration().IsMatch(lines[i]) && MethodName(lines[i]) is { } name)
            {
                starts.Add((i, type, name));
            }
        }

        for (int s = 0; s < starts.Count; s++)
        {
            var (line, owner, name) = starts[s];
            int end = s + 1 < starts.Count ? starts[s + 1].Line : lines.Length;

            var attributes = new List<string>();
            for (int a = line - 1; a >= 0; a--)
            {
                string t = lines[a].Trim();
                if (t.StartsWith('[') || t.StartsWith("//", StringComparison.Ordinal) || t.StartsWith("#pragma", StringComparison.Ordinal))
                {
                    attributes.Insert(0, t);
                    continue;
                }

                break;
            }

            string declaration = lines[line];
            int arrow = declaration.IndexOf("=>", StringComparison.Ordinal);
            var body = new List<string>();
            if (arrow >= 0)
            {
                body.Add(declaration[arrow..]);
            }

            for (int b = line + 1; b < end; b++)
            {
                string code = StripComment(lines[b]);
                if (!code.TrimStart().StartsWith('['))
                {
                    body.Add(code);
                }
            }

            yield return new SourceMethod(file, owner, name, line + 1, string.Join('\n', attributes), string.Join('\n', body));
        }
    }

    /// <summary>
    /// The identifier before the first parameter list that sits outside any generic or tuple
    /// return type. Returns null for a line that turns out not to declare a method.
    /// </summary>
    private static string? MethodName(string line)
    {
        int angle = 0;
        int paren = 0;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            switch (c)
            {
                case '<': angle++; break;
                case '>': angle--; break;
                case ')': paren--; break;
                case '(':
                    if (angle == 0 && paren == 0)
                    {
                        int end = i;
                        while (end > 0 && char.IsWhiteSpace(line[end - 1]))
                        {
                            end--;
                        }

                        int start = end;
                        while (start > 0 && (char.IsLetterOrDigit(line[start - 1]) || line[start - 1] == '_'))
                        {
                            start--;
                        }

                        string candidate = line[start..end];
                        if (candidate.Length > 0 && !NotAName.Contains(candidate) && !char.IsDigit(candidate[0]))
                        {
                            return candidate;
                        }
                    }

                    paren++;
                    break;
            }
        }

        return null;
    }

    /// <summary>Drops a trailing or whole-line <c>//</c> comment. String literals containing <c>//</c> (URLs) are left alone.</summary>
    private static string StripComment(string line)
    {
        string trimmed = line.TrimStart();
        if (trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            return "";
        }

        int idx = line.IndexOf(" //", StringComparison.Ordinal);
        return idx >= 0 && line.LastIndexOf('"', idx) < 0 ? line[..idx] : line;
    }
}
