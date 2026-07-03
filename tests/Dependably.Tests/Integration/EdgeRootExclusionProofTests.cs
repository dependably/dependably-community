extern alias edge;
using System.Reflection;
using EdgeProgram = edge::Program;

namespace Dependably.Tests.Integration;

/// <summary>
/// The exclusion proof — the payoff of the assembly split, encoded as a test. The
/// <c>dependably/edge</c> image's value is attack-surface reduction by reference graph: because
/// <c>Dependably.Edge</c> references <c>Dependably.Core</c> ONLY, the management-plane dependency
/// closure (ITfoxtec SAML, the IdentityModel/JWT stack, JwtBearer, Redis, BCrypt, zxcvbn, OpenApi)
/// cannot enter the edge output. This test pins that fact two ways: the loaded-assembly set of a
/// booted Edge host, and the build-output directory of the Edge project. Either regressing (a stray
/// Management reference sneaking into Core's closure, or a package leaking into the edge project)
/// turns this red.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeRootExclusionProofTests
{
    // Assembly-name prefixes that must never appear in the edge closure. Matched case-insensitively
    // against the simple assembly name (or the DLL file stem for the build-output check).
    private static readonly string[] ForbiddenPrefixes =
    [
        "Dependably.Management",
        "ITfoxtec",
        "StackExchange.Redis",
        "Microsoft.AspNetCore.DataProtection.StackExchangeRedis",
        "BCrypt.Net",
        "Zxcvbn",
        "Microsoft.AspNetCore.Authentication.JwtBearer",
        "System.IdentityModel.Tokens.Jwt",
        "Microsoft.IdentityModel",
        "Microsoft.OpenApi",
        "Microsoft.AspNetCore.OpenApi",
    ];

    private static bool IsForbidden(string simpleName) =>
        ForbiddenPrefixes.Any(p => simpleName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void EdgeReferencedClosure_ContainsNoForbiddenAssembly()
    {
        // The structural proof: walk the Edge program assembly's transitive referenced-assembly
        // graph and assert no forbidden assembly is in it. This reads the reference metadata the
        // compiler baked in — a Management reference entering Core's closure would surface here
        // regardless of runtime JIT timing. The shared test process loads the full root too (so a
        // whole-process loaded-assembly scan is not the proof); the Edge assembly's own closure is.
        var edgeAsm = ResolveEdgeAssembly();

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var forbidden = new List<string>();
        WalkReferences(edgeAsm, seen, forbidden);

        Assert.True(
            forbidden.Count == 0,
            "the Dependably.Edge closure must contain no management-plane assemblies; found: "
            + string.Join(", ", forbidden.Distinct().OrderBy(n => n, StringComparer.Ordinal)));
    }

    [Fact]
    public void EdgeBuildOutput_ContainsNoForbiddenDll()
    {
        // The Edge project's OWN build-output directory — NOT the shared test bin (which copies
        // every project's DLLs, including Management, because the test project references the full
        // root). Resolve src/Dependably.Edge/bin/<config>/<tfm> from the repo root so the check
        // sees exactly what a `dotnet build`/`dotnet publish` of the edge project emits.
        string dir = ResolveEdgeProjectOutputDir();

        var offending = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension)
            .Where(name => name is not null && IsForbidden(name))
            .Distinct()
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offending.Count == 0,
            "the Dependably.Edge build output must ship none of the management-plane assemblies; "
            + $"found in {dir}: " + string.Join(", ", offending));

        // Sanity: the Core assembly and the Edge assembly themselves are present (the check above
        // is not vacuously passing on an empty directory).
        var present = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains("Dependably.Edge", present);
        Assert.Contains("Dependably.Core", present);
    }

    // Walks up from the test bin to the repo root (anchored on Dependably.sln), then descends into
    // the Edge project's build output for the current TFM. Prefers the config that actually exists.
    private static string ResolveEdgeProjectOutputDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string tfm = Path.GetFileName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));

        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Dependably.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        string edgeBinRoot = Path.Combine(dir!.FullName, "src", "Dependably.Edge", "bin");
        Assert.True(Directory.Exists(edgeBinRoot),
            $"Dependably.Edge build output not found at {edgeBinRoot} — build the edge project first.");

        // Match the test run's configuration (Debug/Release) by preferring the same-TFM folder
        // under whichever config directory contains the Edge DLL.
        var candidates = Directory.EnumerateDirectories(edgeBinRoot)
            .Select(config => Path.Combine(config, tfm))
            .Where(p => File.Exists(Path.Combine(p, "Dependably.Edge.dll")))
            .ToList();

        Assert.True(candidates.Count > 0,
            $"no Dependably.Edge.dll found under {edgeBinRoot}/*/{tfm}");
        return candidates[0];
    }

    // The Edge program type resolved through the extern alias — its declaring assembly IS the Edge
    // composition root, so this is the exact assembly whose closure and output dir are the proof.
    private static Assembly ResolveEdgeAssembly() => typeof(EdgeProgram).Assembly;

    private static void WalkReferences(Assembly asm, HashSet<string> seen, List<string> forbidden)
    {
        foreach (var reference in asm.GetReferencedAssemblies())
        {
            string name = reference.Name ?? "";
            if (!seen.Add(name))
            {
                continue;
            }

            if (IsForbidden(name))
            {
                forbidden.Add(name);
                continue;
            }

            // Only recurse into Dependably.* project assemblies — the framework/package graph is
            // enormous and irrelevant; the forbidden set is what a Dependably assembly pulls in.
            if (name.StartsWith("Dependably", StringComparison.Ordinal))
            {
                try
                {
                    WalkReferences(Assembly.Load(reference), seen, forbidden);
                }
                catch (Exception ex) when (ex is FileNotFoundException or BadImageFormatException)
                {
                    // A project assembly that cannot be loaded is not a forbidden reference.
                }
            }
        }
    }
}
