using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins the OCI pull gate's symmetry. OCI does not route through <c>ProxyFetchService</c>, so it
/// does not inherit the proxy-serve posture gate; this is its equivalent. Every OCI action that
/// can return manifest bytes must call the one helper (<c>EvaluateOciPullGateAsync</c>), which
/// builds its request through one factory (<c>BlockGateRequest.ForOciImage</c>) and reads its facts
/// through one resolver — so a cache hit, an upstream miss, a stale serve, a HEAD and a blob-route
/// read of one (org, digest) cannot disagree. The licence-only helper the gate grew out of
/// (<c>EvaluateLicenseBlockAsync</c>) may be called from nowhere but inside that helper: a direct
/// call is a serve path that silently skips every scan arm.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class OciPullGatePostureComplianceTests
{
    private const string Helper = "EvaluateOciPullGateAsync(";
    private const string LicenseOnly = "EvaluateLicenseBlockAsync(";

    // The sites discovery must find at minimum, with how many helper calls each body must carry
    // (the upstream manifest path answers HEAD and GET separately). Discovery finds every
    // served-bytes method on its own; this floor only proves discovery has not gone blind.
    private static readonly (string File, string Method, int Calls)[] KnownSites =
    [
        ("OciController.Manifests.cs", "TryServeLocalManifestAsync", 1),
        ("OciController.Manifests.cs", "ServeUpstreamManifestAsync", 2),
        ("OciController.Manifests.cs", "TryServeStaleTagManifestAsync", 1),
        ("OciController.Blobs.cs", "TryServeLocalBlobAsync", 1),
        ("OciController.Blobs.cs", "ServeUpstreamBlobAsync", 1),
    ];

    // A writer that is not itself a serve site because its caller has already run the gate: the
    // method, and the caller that must still call both it and the helper. A new byte-writing method
    // is not on this list, so it fails until it either calls the helper or is named here.
    private static readonly (string File, string Method, string GatedBy)[] GatedByCaller =
    [
        ("OciController.Blobs.cs", "TryServeRangedBlobAsync", "TryServeLocalBlobAsync"),
        ("OciController.Blobs.cs", "CreateUpstreamBlobSink", "ServeUpstreamBlobAsync"),
    ];

    // Members are found line by line: a declaration at the class's own indentation that opens with
    // an access modifier runs to the next one. A method of any signature (sync, async, any return
    // type) is therefore seen; a field or property (an '=', '{' or ';' before its first '(') is not.
    private static Dictionary<string, string> Methods(string source)
    {
        var methods = new Dictionary<string, string>(StringComparer.Ordinal);
        // Comment lines are dropped: a doc comment above a member would otherwise be read as part
        // of the previous one.
        string[] lines = source.Split('\n').Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal)).ToArray();
        int start = -1;
        for (int i = 0; i <= lines.Length; i++)
        {
            bool declaration = i < lines.Length && MemberStart().IsMatch(lines[i]);
            if (!declaration && i < lines.Length)
            {
                continue;
            }

            if (start >= 0)
            {
                string text = string.Join('\n', lines[start..i]) + "\n";
                int paren = text.IndexOf('(');
                string head = paren < 0 ? text : text[..paren];
                if (paren >= 0 && head.IndexOfAny(['=', '{', ';']) < 0)
                {
                    string name = head.TrimEnd().Split(' ', '>', '?')[^1];
                    methods[name] = text;
                }
            }

            start = i;
        }

        return methods;
    }

    [GeneratedRegex(@"^    (public|private|internal|protected)\b")]
    private static partial Regex MemberStart();

    // A method that hands object bytes to the client returns them as MVC's File(...) result or
    // writes them to the response body (a ranged read, a streamed mirror).
    [GeneratedRegex(@"(?<![\w.])File\(|\bResponse\.Body\b|\bFileStreamResult\b|\bFileContentResult\b")]
    private static partial Regex ByteWriter();

    private static bool ServesBytes(string body) => ByteWriter().IsMatch(body);

    private static IEnumerable<(string File, string Method, string Body)> DiscoverServeSites() =>
        SourceRoots.AllCSharpFiles()
            .Where(f => Path.GetFileName(f).StartsWith("OciController", StringComparison.Ordinal))
            .SelectMany(f => Methods(File.ReadAllText(f))
                .Where(m => ServesBytes(m.Value))
                .Select(m => (Path.GetFileName(f), m.Key, m.Value)));

    private static List<string> GateFailures(
        IReadOnlyCollection<(string File, string Method, string Body)> sites,
        IReadOnlyDictionary<string, Dictionary<string, string>> methodsByFile)
    {
        var failures = new List<string>();
        foreach (var (file, method, body) in sites)
        {
            var gated = GatedByCaller.FirstOrDefault(g => g.File == file && g.Method == method);
            if (gated.Method is not null)
            {
                bool callerOk = methodsByFile[file].TryGetValue(gated.GatedBy, out string? caller)
                    && caller.Contains(method + "(", StringComparison.Ordinal)
                    && caller.Contains(Helper, StringComparison.Ordinal);
                if (!callerOk)
                {
                    failures.Add($"{file}: {method} writes bytes and is allowlisted as gated by {gated.GatedBy}, "
                        + $"which no longer calls both it and {Helper}.");
                }

                continue;
            }

            int expected = Math.Max(1, KnownSites.FirstOrDefault(k => k.File == file && k.Method == method).Calls);
            int found = Regex.Count(body, Regex.Escape(Helper));
            if (found < expected)
            {
                failures.Add($"{file}: {method} writes bytes but calls {Helper} {found} time(s), expected at least {expected}. "
                    + "Call the helper, or name it in GatedByCaller with the caller that already did.");
            }
        }

        return failures;
    }

    /// <summary>
    /// The upstream resolver's tag-observation path reads org settings through the injected,
    /// cached repository and decides quarantine through the injected one: a raw
    /// <c>org_settings</c> SELECT runs uncached on every tag revalidation even at posture off, and
    /// an inline repository drifts from the DI-built one.
    /// </summary>
    [Fact]
    public void TagObservation_UsesInjectedRepositories_NotRawSettingsReads()
    {
        string source = File.ReadAllText(Path.Combine(
            SourceRoots.RepoRoot(), "src", "Dependably.Core", "Protocol", "OciUpstreamResolver.TagObservation.cs"));

        Assert.DoesNotContain("FROM org_settings", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new OrgRepository(", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new QuarantineRepository(", source, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryDiscoveredServeSite_CallsTheOnePullGateHelper()
    {
        var methodsByFile = SourceRoots.AllCSharpFiles()
            .Where(f => Path.GetFileName(f).StartsWith("OciController", StringComparison.Ordinal))
            .ToDictionary(f => Path.GetFileName(f), f => Methods(File.ReadAllText(f)), StringComparer.Ordinal);

        var failures = GateFailures(DiscoverServeSites().ToList(), methodsByFile);

        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    [Fact]
    public void EveryGatedByCallerEntry_StillNamesAByteWriter()
    {
        var discovered = DiscoverServeSites().Select(d => (d.File, d.Method)).ToHashSet();
        var stale = GatedByCaller.Where(g => !discovered.Contains((g.File, g.Method))).ToList();
        Assert.True(stale.Count == 0,
            "GatedByCaller names methods that no longer write bytes: " + string.Join(", ", stale.Select(s => $"{s.File}:{s.Method}")));
    }

    [Fact]
    public void Discovery_FindsAtLeastTheKnownServeSites()
    {
        var discovered = DiscoverServeSites().Select(d => (d.File, d.Method)).ToHashSet();
        var missing = KnownSites.Where(k => !discovered.Contains((k.File, k.Method))).ToList();
        Assert.True(missing.Count == 0,
            "Serve-site discovery no longer finds: " + string.Join(", ", missing.Select(m => $"{m.File}:{m.Method}")));
    }

    [Theory]
    [InlineData("    private async Task<IActionResult> Rogue(int a)\n    {\n        return File(stream, mt);\n    }\n")]
    [InlineData("    public Task<ActionResult> Rogue(int a)\n    {\n        return Task.FromResult<ActionResult>(File(stream, mt));\n    }\n")]
    [InlineData("    internal async Task Rogue(Stream s)\n    {\n        await s.CopyToAsync(Response.Body, ct);\n    }\n")]
    [InlineData("    private FileStreamResult Rogue()\n    {\n        return new FileStreamResult(s, mt);\n    }\n")]
    public void Discovery_FlagsAByteWriterOfAnySignatureThatSkipsTheHelper(string source)
    {
        var methods = Methods(source);
        var sites = methods.Where(m => ServesBytes(m.Value)).Select(m => ("Rogue.cs", m.Key, m.Value)).ToList();
        Assert.Single(sites);

        var failures = GateFailures(sites, new Dictionary<string, Dictionary<string, string>> { ["Rogue.cs"] = methods });

        Assert.Single(failures);
    }

    [Fact]
    public void Discovery_FlagsAnAllowlistedWriterWhoseCallerStoppedGatingIt()
    {
        string source = "    private async Task Ranged(int a)\n    {\n        await s.CopyToAsync(Response.Body, ct);\n    }\n"
            + "    private async Task Caller()\n    {\n        await Ranged(1);\n    }\n";
        var methods = Methods(source);
        var sites = new[] { ("OciController.Blobs.cs", "TryServeRangedBlobAsync", methods["Ranged"]) };

        var failures = GateFailures(sites, new Dictionary<string, Dictionary<string, string>>
        {
            ["OciController.Blobs.cs"] = new() { ["TryServeLocalBlobAsync"] = methods["Caller"] },
        });

        Assert.Single(failures);
    }

    [Fact]
    public void TheLicenceOnlyHelper_IsCalledOnlyFromInsideThePullGateHelper()
    {
        var offenders = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string source = File.ReadAllText(file);
            if (!source.Contains(LicenseOnly, StringComparison.Ordinal))
            {
                continue;
            }

            var methods = Methods(source);
            foreach (var (name, body) in methods)
            {
                if (name is "EvaluateOciPullGateAsync" or "EvaluateLicenseBlockAsync")
                {
                    continue;
                }

                if (body.Contains(LicenseOnly, StringComparison.Ordinal))
                {
                    offenders.Add($"{Path.GetFileName(file)}: {name}");
                }
            }

            // A call outside any recognised method body (an expression-bodied member, a lambda in a
            // field initialiser) is counted too: every occurrence must sit inside one of the two.
            int total = Regex.Count(source, Regex.Escape(LicenseOnly));
            int accounted = methods
                .Where(m => m.Key is "EvaluateOciPullGateAsync" or "EvaluateLicenseBlockAsync")
                .Sum(m => Regex.Count(m.Value, Regex.Escape(LicenseOnly)));
            int inOtherMethods = methods
                .Where(m => m.Key is not ("EvaluateOciPullGateAsync" or "EvaluateLicenseBlockAsync"))
                .Sum(m => Regex.Count(m.Value, Regex.Escape(LicenseOnly)));
            if (total != accounted + inOtherMethods)
            {
                offenders.Add($"{Path.GetFileName(file)}: a call outside any method body the gate recognises");
            }
        }

        Assert.True(offenders.Count == 0,
            "EvaluateLicenseBlockAsync is called outside EvaluateOciPullGateAsync, so that path skips the "
            + "OCI scan arms: " + string.Join(", ", offenders));
    }

    [Fact]
    public void ThePullGateHelper_BuildsItsRequestThroughForOciImage()
    {
        var methods = Methods(File.ReadAllText(SourceRoots.AllCSharpFiles()
            .Single(f => Path.GetFileName(f) == "OciController.cs")));
        Assert.True(methods.TryGetValue("EvaluateOciPullGateAsync", out string? body), "EvaluateOciPullGateAsync not found.");
        Assert.Contains("BlockGateRequest.ForOciImage(", body, StringComparison.Ordinal);
        Assert.Contains("PullGate.ResolveAsync(", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("    private async Task<IActionResult?> Foo(int a)\n    {\n        await EvaluateLicenseBlockAsync(x);\n    }\n", 1)]
    [InlineData("    private async Task<IActionResult?> EvaluateOciPullGateAsync(int a)\n    {\n        await EvaluateLicenseBlockAsync(x);\n    }\n", 0)]
    public void Scanner_FindsADirectCallOutsideTheHelper(string source, int expectedOffenders)
    {
        int offenders = Methods(source)
            .Count(m => m.Key is not ("EvaluateOciPullGateAsync" or "EvaluateLicenseBlockAsync")
                && m.Value.Contains(LicenseOnly, StringComparison.Ordinal));
        Assert.Equal(expectedOffenders, offenders);
    }
}
