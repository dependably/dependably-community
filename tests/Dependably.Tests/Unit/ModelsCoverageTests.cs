using System.Text.Json;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Coverage for small projection/getter members on <c>Models.cs</c> POCOs that the
/// repository/integration paths don't read back: the <see cref="TokenRecord"/> getters and
/// the OSV detail record graph (constructed on the deserialize path).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ModelsCoverageTests
{
    [Fact]
    public void TokenRecord_CapabilitiesGetter_RoundTripsStoredJson()
    {
        var token = new TokenRecord { Capabilities = """["read:packages","write:packages"]""" };
        Assert.Equal("""["read:packages","write:packages"]""", token.Capabilities);
        Assert.Contains("read:packages", token.CapabilitySet);
    }

    [Theory]
    [InlineData(TokenSource.User, "user")]
    [InlineData(TokenSource.Service, "service")]
    public void TokenRecord_ActorKind_MapsKnownSources(TokenSource source, string expected)
    {
        Assert.Equal(expected, new TokenRecord { Source = source }.ActorKind);
    }

    [Fact]
    public void TokenRecord_ActorKind_UnknownSourceFallsBackToUser()
    {
        // Defensive default arm: a value outside the defined enum maps to "user".
        Assert.Equal("user", new TokenRecord { Source = (TokenSource)99 }.ActorKind);
    }

    [Fact]
    public void OsvDetail_RecordGraph_ConstructsFromDeserializedParts()
    {
        var dbSpecific = JsonDocument.Parse("""{"severity":"HIGH"}""").RootElement;
        var ecoSpecific = JsonDocument.Parse("""{"imported":true}""").RootElement;

        var detail = new OsvDetail(
            Id: "GHSA-xxxx",
            SchemaVersion: "1.6.0",
            Published: "2026-01-01T00:00:00Z",
            Modified: "2026-02-01T00:00:00Z",
            Withdrawn: null,
            Summary: "Example advisory",
            Details: "Longer details",
            Aliases: new[] { "CVE-2026-0001" },
            Related: new[] { "GHSA-yyyy" },
            References: new[] { new OsvReference("WEB", "https://example.test") },
            Severity: new[] { new OsvSeverityEntry("CVSS_V3", "9.8") },
            Affected: new[]
            {
                new OsvAffectedDetail(
                    Package: new OsvAffectedPackageRef("npm", "left-pad", "pkg:npm/left-pad"),
                    Ranges: new[] { new OsvRange("SEMVER", null, null) },
                    Versions: new[] { "1.0.0" },
                    EcosystemSpecific: ecoSpecific,
                    DatabaseSpecific: dbSpecific),
            },
            Credits: new[] { new OsvCredit("reporter", new[] { "mailto:r@example.test" }, "REPORTER") },
            DatabaseSpecific: dbSpecific);

        Assert.Equal("GHSA-xxxx", detail.Id);
        Assert.Equal("CVE-2026-0001", Assert.Single(detail.Aliases!));
        var affected = Assert.Single(detail.Affected!);
        Assert.Equal("left-pad", affected.Package!.Name);
        Assert.Equal("REPORTER", Assert.Single(detail.Credits!).Type);
    }
}
