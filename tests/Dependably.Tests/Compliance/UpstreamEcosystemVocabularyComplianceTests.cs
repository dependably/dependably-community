using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: the four places that independently spell out which ecosystems have configurable
/// upstreams agree with one another. Adding an ecosystem touches a protocol controller, the seeder,
/// an API allowlist, and a frontend filter, and nothing links them — so a partial addition compiles,
/// passes every other gate, and ships an ecosystem that proxies for new orgs but cannot be seen or
/// edited in Settings → Proxy. Terraform shipped exactly that way.
///
/// The three assertions, each anchored to a way the drift actually bites:
/// <list type="bullet">
/// <item>every seeded default is API-configurable — otherwise the row exists but
/// <c>UpstreamRegistryController</c> 400s on every create/update naming it;</item>
/// <item>the Svelte filter matches the API allowlist exactly — otherwise the ecosystem's card is
/// dropped before render and the upstream list is unreachable from the UI;</item>
/// <item>every API-configurable ecosystem is in the shared frontend vocabulary — otherwise it has
/// no label or badge palette and renders as <c>undefined</c>.</item>
/// </list>
/// The backfill side is covered by <c>TerraformUpstreamBackfillMigrationTests</c>: a new default
/// source also needs its own one-shot pass, since existing orgs are past the earlier backfills.
///
/// A second, independent vocabulary list has the same drift shape: <see
/// cref="ReservedNamespaceService.SupportedEcosystems"/> gates the only <c>reserved_namespace</c>
/// write path (<c>OrgListsController</c>), and the Settings → Reserved Namespaces "Add" modal
/// hard-codes its own dropdown. An ecosystem missing from either side leaves a serve-path guard
/// unreachable (no row can ever exist for it) even though the guard's own code and docs say it
/// applies — terraform shipped exactly that way. <see cref="TheReservedNamespaceModalMatchesTheServiceVocabularyExactly"/>
/// closes that gap the same way the three assertions above close the upstream one.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class UpstreamEcosystemVocabularyComplianceTests
{
    // export const ECOSYSTEMS = ['pypi', 'npm', …]
    [GeneratedRegex(@"export\s+const\s+ECOSYSTEMS\s*=\s*\[(?<body>[^\]]*)\]", RegexOptions.Singleline)]
    private static partial Regex FrontendVocabularyRegex();

    // const DB_UPSTREAM_ECOSYSTEMS = new Set([ 'pypi', 'npm', … ])
    [GeneratedRegex(@"DB_UPSTREAM_ECOSYSTEMS\s*=\s*new\s+Set\(\s*\[(?<body>[^\]]*)\]", RegexOptions.Singleline)]
    private static partial Regex UiFilterRegex();

    [GeneratedRegex(@"'(?<eco>[a-z0-9]+)'", RegexOptions.Singleline)]
    private static partial Regex QuotedKeyRegex();

    // <select id="rsvd-ecosystem" bind:value={newRsvdEcosystem}> … </select>
    [GeneratedRegex(
        """id="rsvd-ecosystem"[^>]*>(?<body>.*?)</select>""",
        RegexOptions.Singleline)]
    private static partial Regex ReservedNamespaceModalRegex();

    [GeneratedRegex("value=\"(?<eco>[a-z0-9]+)\"", RegexOptions.Singleline)]
    private static partial Regex QuotedValueRegex();

    [Fact]
    public void EverySeededUpstreamDefaultIsApiConfigurable()
    {
        // Null config: the hard-coded public defaults, which is the set a fresh org is seeded with.
        var seeded = UpstreamRegistrySeeder.ResolveDefaults(config: null)
            .Select(d => d.Ecosystem)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(seeded.Count >= 8,
            $"Expected the seeder's default sources to parse; got [{string.Join(", ", seeded)}].");

        var missing = seeded
            .Where(e => !UpstreamRegistryRepository.SupportedEcosystems.Contains(e))
            .OrderBy(e => e, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0,
            $"{missing.Count} ecosystem(s) are seeded into upstream_registry but missing from " +
            $"UpstreamRegistryRepository.SupportedEcosystems: [{string.Join(", ", missing)}]. " +
            "UpstreamRegistryController validates create/update against that list, so the seeded " +
            "row would be readable but not editable. Add the key there.");
    }

    [Fact]
    public void UiFilterMatchesTheApiAllowlistExactly()
    {
        var uiKeys = ParseKeys(
            UiFilterRegex(),
            ReadWebFile(Path.Combine("lib", "settings", "SettingsUpstreamRegistries.svelte")),
            "DB_UPSTREAM_ECOSYSTEMS");

        var apiKeys = UpstreamRegistryRepository.SupportedEcosystems.ToHashSet(StringComparer.Ordinal);

        var missingFromUi = apiKeys.Except(uiKeys).OrderBy(e => e, StringComparer.Ordinal).ToList();
        var missingFromApi = uiKeys.Except(apiKeys).OrderBy(e => e, StringComparer.Ordinal).ToList();

        Assert.True(missingFromUi.Count == 0,
            $"Configurable via the API but filtered out of Settings → Proxy → Upstream registries: " +
            $"[{string.Join(", ", missingFromUi)}]. SettingsUpstreamRegistries.svelte renders one card " +
            "per ecosystem in DB_UPSTREAM_ECOSYSTEMS; an omitted key makes the list unreachable.");

        Assert.True(missingFromApi.Count == 0,
            $"Rendered by the UI but rejected by the API: [{string.Join(", ", missingFromApi)}]. " +
            "The card would offer an Add button whose request 400s.");
    }

    [Fact]
    public void EveryConfigurableEcosystemIsInTheSharedFrontendVocabulary()
    {
        var vocabulary = ParseKeys(
            FrontendVocabularyRegex(),
            ReadWebFile(Path.Combine("lib", "ecosystems.js")),
            "ECOSYSTEMS");

        var missing = UpstreamRegistryRepository.SupportedEcosystems
            .Where(e => !vocabulary.Contains(e))
            .OrderBy(e => e, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0,
            $"{missing.Count} configurable ecosystem(s) missing from web/src/lib/ecosystems.js: " +
            $"[{string.Join(", ", missing)}]. Without an ECO_LABEL entry the card renders an " +
            "undefined heading, and without the app.css --eco-/--badge- variables it has no palette.");
    }

    [Fact]
    public void TheReservedNamespaceModalMatchesTheServiceVocabularyExactly()
    {
        string source = ReadWebFile(Path.Combine("pages", "OrgSettings.svelte"));
        var match = ReservedNamespaceModalRegex().Match(source);
        Assert.True(match.Success,
            "Could not locate the reserved-namespace Add modal's ecosystem <select> — did its " +
            "id or markup shape change? This gate parses it textually; update the regex alongside it.");

        var uiKeys = QuotedValueRegex().Matches(match.Groups["body"].Value)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(uiKeys.Count >= 6, $"Parsed only [{string.Join(", ", uiKeys)}] from the modal dropdown.");

        var serviceKeys = ReservedNamespaceService.SupportedEcosystems.ToHashSet(StringComparer.Ordinal);

        var missingFromUi = serviceKeys.Except(uiKeys).OrderBy(e => e, StringComparer.Ordinal).ToList();
        var missingFromService = uiKeys.Except(serviceKeys).OrderBy(e => e, StringComparer.Ordinal).ToList();

        Assert.True(missingFromUi.Count == 0,
            $"Writable via the reserved-namespace API but missing from the Settings → Reserved " +
            $"Namespaces \"Add\" modal dropdown: [{string.Join(", ", missingFromUi)}]. " +
            "OrgSettings.svelte's rsvd-ecosystem <select> must offer every ecosystem " +
            "OrgListsController.AddReservedNamespace accepts, or an operator has no UI path to " +
            "reserve a namespace for it.");

        Assert.True(missingFromService.Count == 0,
            $"Offered by the reserved-namespace modal but rejected by the API: " +
            $"[{string.Join(", ", missingFromService)}]. The dropdown's Add button would 400 for " +
            "these ecosystems — add them to ReservedNamespaceService.SupportedEcosystems.");
    }

    private static HashSet<string> ParseKeys(Regex listRegex, string source, string listName)
    {
        var match = listRegex.Match(source);
        Assert.True(match.Success,
            $"Could not locate the {listName} list — did its declaration shape change? " +
            "This gate parses it textually; update the regex alongside the declaration.");

        var keys = QuotedKeyRegex().Matches(match.Groups["body"].Value)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(keys.Count >= 8, $"Parsed only [{string.Join(", ", keys)}] from {listName}.");
        return keys;
    }

    private static string ReadWebFile(string relativePath)
    {
        string path = Path.Combine(SourceRoots.RepoRoot(), "web", "src", relativePath);
        Assert.True(File.Exists(path), $"Expected frontend source at {path}.");
        return File.ReadAllText(path);
    }
}
