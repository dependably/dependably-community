using System.Reflection;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The compliance gate <see cref="CycloneDxParser.ExplicitUnknownPropertyNames"/>'s own doc
/// comment promises: every <c>DependablyExportProperties.*Status</c> constant is accounted for,
/// either as a key in that dictionary or in this test's documented exclusion set, so a SEVENTH
/// status property added to the exporter without a matching read-back decision fails this test
/// instead of silently exporting a duty-field marker nothing ever reads back.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CycloneDxStatusPropertyCoverageTests
{
    // Reflects rather than hand-lists the export side: a new "*Status" const landing in
    // DependablyExportProperties is picked up here automatically, so the gate below actually
    // fires on addition instead of only ever checking the same fixed set forever.
    private static IReadOnlySet<string> AllExportedStatusPropertyValues()
    {
        var values = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in typeof(DependablyExportProperties)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(string) && f.Name.EndsWith("Status", StringComparison.Ordinal)))
        {
            values.Add((string)field.GetValue(null)!);
        }

        return values;
    }

    [Fact]
    public void EveryExportedStatusPropertyIsEitherReadBackOrADocumentedExclusion()
    {
        var exported = AllExportedStatusPropertyValues();

        // ToolVersionStatus is document-level (CycloneDxParser.ReadTool reads it directly off the
        // metadata.tools entry into CycloneDxDocument.ToolVersionExplicitlyUnknown), never through
        // this component-scoped dictionary. HashStatus is deliberately excluded — see
        // SbomExplicitUnknownFields's own class doc comment for why a null component_hashes
        // already avoids the false-Absent claim this vocabulary exists to prevent, with no
        // precision gap left to close.
        var documentedExclusions = new HashSet<string>(StringComparer.Ordinal)
        {
            DependablyExportProperties.ToolVersionStatus,
            DependablyExportProperties.HashStatus,
        };

        var accounted = new HashSet<string>(
            CycloneDxParser.ExplicitUnknownPropertyNames.Keys, StringComparer.Ordinal);
        accounted.UnionWith(documentedExclusions);

        Assert.True(
            exported.SetEquals(accounted),
            "DependablyExportProperties gained or lost a *Status constant that "
            + "CycloneDxParser.ExplicitUnknownPropertyNames and this test's documented exclusion "
            + $"set do not both account for. Exported: [{string.Join(", ", exported.OrderBy(v => v, StringComparer.Ordinal))}]. "
            + $"Accounted for: [{string.Join(", ", accounted.OrderBy(v => v, StringComparer.Ordinal))}].");
    }

    [Fact]
    public void ExactlySixStatusPropertiesAreExported()
    {
        // Pins the count CISA X4/P4a names (D8b/D10e/D12a/D13a/D14d/D16e) so a property silently
        // dropped from DependablyExportProperties — which would make the test above pass
        // vacuously — is caught here instead.
        Assert.Equal(6, AllExportedStatusPropertyValues().Count);
    }
}
