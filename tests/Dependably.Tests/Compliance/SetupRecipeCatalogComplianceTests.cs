using System.Text.RegularExpressions;
using Dependably.Api.Setup;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Coverage and shape gate for the Setup page's client-configuration recipes.
///
/// The failure this exists to prevent is silent: the Setup page selects a recipe by
/// (ecosystem, operation, scope, variant), so an ecosystem the catalog never learned about —
/// or a variant advertised in the picker with no recipe behind it — renders an empty step 3
/// rather than throwing. Nothing else in the suite would notice. Adding an ecosystem to
/// <c>web/src/lib/ecosystems.js</c> therefore fails here until its recipes land, the same
/// fail-closed posture <c>installCommand.test.js</c> applies to the invocation half.
///
/// The ecosystem list is read from <c>ecosystems.js</c> as text rather than duplicated here,
/// because a hand-copied list in the gate is exactly the drift the gate is meant to catch.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class SetupRecipeCatalogComplianceTests
{
    // export const ECOSYSTEMS = ['pypi', 'npm', …]
    [GeneratedRegex(@"export\s+const\s+ECOSYSTEMS\s*=\s*\[(?<body>[^\]]*)\]", RegexOptions.Singleline)]
    private static partial Regex EcosystemVocabularyRegex();

    [GeneratedRegex(@"'(?<eco>[a-z0-9]+)'", RegexOptions.Singleline)]
    private static partial Regex QuotedKeyRegex();

    private const string HttpsBase = "https://repo.example.com";
    private const string HttpBase = "http://192.168.1.50:8080";

    private static IReadOnlyList<string> Ecosystems()
    {
        string path = Path.Combine(SourceRoots.RepoRoot(), "web", "src", "lib", "ecosystems.js");
        Assert.True(File.Exists(path), $"Ecosystem vocabulary not found at {path}.");

        var match = EcosystemVocabularyRegex().Match(File.ReadAllText(path));
        Assert.True(match.Success, $"Could not parse the ECOSYSTEMS array out of {path}.");

        string[] keys = QuotedKeyRegex().Matches(match.Groups["body"].Value)
            .Select(m => m.Groups["eco"].Value)
            .ToArray();

        Assert.NotEmpty(keys);
        return keys;
    }

    [Fact]
    public void EveryEcosystem_HasRecipes()
    {
        var missing = Ecosystems()
            .Where(eco => SetupRecipeCatalog.Build(eco, HttpsBase) is null)
            .ToList();

        Assert.True(missing.Count == 0,
            "Every ecosystem in web/src/lib/ecosystems.js needs recipes in SetupRecipeCatalog, "
            + "or the Setup page renders an empty configuration step for it. Missing: "
            + string.Join(", ", missing));
    }

    /// <summary>
    /// Install is the path every ecosystem supports — Dependably proxies all ten. Publish is
    /// deliberately absent for the proxy-only ones (Go, apk, Terraform have no hosted push
    /// path), so this asserts only the install direction.
    /// </summary>
    [Fact]
    public void EveryEcosystem_HasAtLeastOneInstallRecipe()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            var built = SetupRecipeCatalog.Build(eco, HttpsBase);
            if (built is null || !built.Recipes.Any(r => r.Operation == SetupVocabulary.OperationInstall))
            {
                offenders.Add(eco);
            }
        }

        Assert.True(offenders.Count == 0,
            "Every ecosystem must offer at least one install recipe: " + string.Join(", ", offenders));
    }

    /// <summary>
    /// Each advertised variant must have a recipe, and each recipe must name an advertised
    /// variant. A mismatch in either direction renders a control the page cannot satisfy.
    /// </summary>
    [Fact]
    public void VariantsAndRecipes_AgreeInBothDirections()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            var built = SetupRecipeCatalog.Build(eco, HttpsBase)!;
            var advertised = built.Variants.Select(v => v.Id).ToHashSet(StringComparer.Ordinal);
            var used = built.Recipes.Select(r => r.Variant).ToHashSet(StringComparer.Ordinal);

            foreach (string orphan in advertised.Except(used))
            {
                offenders.Add($"{eco}: variant '{orphan}' is offered but has no recipe");
            }

            foreach (string unlisted in used.Except(advertised))
            {
                offenders.Add($"{eco}: recipe names variant '{unlisted}', which is not in Variants");
            }

            Assert.Equal(advertised.Count, built.Variants.Count);
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    [Fact]
    public void EveryRecipe_DrawsFromTheClosedVocabularies()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            foreach (var r in SetupRecipeCatalog.Build(eco, HttpsBase)!.Recipes)
            {
                string id = $"{eco}/{r.Variant}/{r.Operation}/{r.Scope}";
                if (!SetupVocabulary.Operations.Contains(r.Operation))
                {
                    offenders.Add($"{id}: unknown operation '{r.Operation}'");
                }

                if (!SetupVocabulary.Scopes.Contains(r.Scope))
                {
                    offenders.Add($"{id}: unknown scope '{r.Scope}'");
                }

                if (!SetupVocabulary.Presets.Contains(r.CapabilityPreset))
                {
                    offenders.Add($"{id}: unknown capability preset '{r.CapabilityPreset}'");
                }

                if (!SetupVocabulary.DeliveryKinds.Contains(r.TokenDelivery.Kind))
                {
                    offenders.Add($"{id}: unknown token-delivery kind '{r.TokenDelivery.Kind}'");
                }
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    /// <summary>
    /// The preset a recipe asks for has to match what it does. A publish recipe minting a
    /// read-only token hands the reader a credential that 403s at the one moment they are
    /// trying to confirm the setup worked.
    /// </summary>
    [Fact]
    public void PublishRecipes_RequestAPushToken_AndInstallRecipesDoNot()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            foreach (var r in SetupRecipeCatalog.Build(eco, HttpsBase)!.Recipes)
            {
                string expected = r.Operation == SetupVocabulary.OperationPublish
                    ? SetupVocabulary.PresetPush
                    : SetupVocabulary.PresetPull;

                if (r.CapabilityPreset != expected)
                {
                    offenders.Add(
                        $"{eco}/{r.Variant}/{r.Operation}/{r.Scope}: expected preset '{expected}', got '{r.CapabilityPreset}'");
                }
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    /// <summary>
    /// The rule that makes the page's env-var posture real rather than aspirational: a
    /// project-scoped file is committed, so it must never hold the literal token. Any recipe
    /// that genuinely needs a credential on disk carries it in a home-directory file instead,
    /// which is marked secret-bearing and rendered with a "do not commit" note.
    /// </summary>
    [Fact]
    public void ProjectScopedFiles_InTheRepoRoot_NeverHoldTheLiteralToken()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            foreach (var r in SetupRecipeCatalog.Build(eco, HttpsBase)!.Recipes)
            {
                if (r.Scope != SetupVocabulary.ScopeProject)
                {
                    continue;
                }

                foreach (var f in r.Files.Where(f => f.SecretBearing && f.LocationHint is "repoRoot" or "workspaceRoot"))
                {
                    offenders.Add(
                        $"{eco}/{r.Variant}/{r.Operation}: '{f.Path}' is committed but marked secret-bearing");
                }
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    /// <summary>
    /// A file whose body still contains the token placeholder has to declare itself
    /// secret-bearing, and one that declares itself secret-bearing has to actually carry the
    /// placeholder. The page keys its "do not commit" warning off that flag, so a flag that
    /// disagrees with the body either hides a real secret or cries wolf.
    /// </summary>
    [Fact]
    public void SecretBearingFlag_MatchesThePlaceholderInTheBody()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            foreach (var r in SetupRecipeCatalog.Build(eco, HttpsBase)!.Recipes)
            {
                foreach (var f in r.Files)
                {
                    bool carriesPlaceholder = f.Body.Contains("<token>", StringComparison.Ordinal);
                    string id = $"{eco}/{r.Variant}/{r.Operation}/{r.Scope}: '{f.Path}'";

                    if (carriesPlaceholder && !f.SecretBearing)
                    {
                        offenders.Add($"{id} carries <token> but is not marked secret-bearing");
                    }

                    if (!carriesPlaceholder && f.SecretBearing)
                    {
                        offenders.Add($"{id} is marked secret-bearing but carries no <token>");
                    }
                }
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    /// <summary>
    /// An <c>envVar</c> recipe promises the file interpolates a variable. If no file mentions
    /// that variable, the reader exports something nothing reads and the config resolves with
    /// an empty credential — a 401 with no visible cause.
    /// </summary>
    [Fact]
    public void EnvVarRecipes_ReferenceThatVariableInAFile()
    {
        var offenders = new List<string>();
        foreach (string eco in Ecosystems())
        {
            foreach (var r in SetupRecipeCatalog.Build(eco, HttpsBase)!.Recipes)
            {
                if (r.TokenDelivery.Kind != SetupVocabulary.DeliveryEnvVar)
                {
                    continue;
                }

                string name = r.TokenDelivery.EnvVar!;
                bool referenced = r.Files.Any(f => f.Body.Contains(name, StringComparison.Ordinal))
                    || (r.Verify?.Contains(name, StringComparison.Ordinal) ?? false);

                if (!referenced)
                {
                    offenders.Add($"{eco}/{r.Variant}/{r.Operation}/{r.Scope}: nothing references ${name}");
                }
            }
        }

        Assert.True(offenders.Count == 0, string.Join("\n", offenders));
    }

    /// <summary>
    /// Every ecosystem must survive a plain-HTTP deployment without throwing: self-hosted
    /// installs on a LAN are the common case, and several builders branch on the scheme to
    /// attach a tool-specific override.
    /// </summary>
    [Fact]
    public void EveryEcosystem_BuildsOverPlainHttp()
    {
        foreach (string eco in Ecosystems())
        {
            var built = SetupRecipeCatalog.Build(eco, HttpBase);
            Assert.NotNull(built);
            Assert.NotEmpty(built.Recipes);
        }
    }

    [Fact]
    public void UnknownEcosystem_ReturnsNull()
    {
        Assert.Null(SetupRecipeCatalog.Build("not-an-ecosystem", HttpsBase));
    }
}
