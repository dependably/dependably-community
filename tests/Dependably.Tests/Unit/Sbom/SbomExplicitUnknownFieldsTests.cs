using Dependably.Infrastructure.Sbom;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// <see cref="SbomExplicitUnknownFields"/>'s own serialize/parse round trip, independent of
/// either parser that feeds it — <see cref="SpdxParserTests"/> and
/// <see cref="CycloneDxComponentMetadataTests"/> cover those call sites.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomExplicitUnknownFieldsTests
{
    [Fact]
    public void Serialize_ReturnsNull_ForAnEmptyList()
    {
        Assert.Null(SbomExplicitUnknownFields.Serialize([]));
    }

    [Fact]
    public void Parse_RoundTripsWhatSerializeWrote()
    {
        string? json = SbomExplicitUnknownFields.Serialize(
            [SbomExplicitUnknownFields.Producer, SbomExplicitUnknownFields.License]);

        var parsed = SbomExplicitUnknownFields.Parse(json);

        Assert.Contains(SbomExplicitUnknownFields.Producer, parsed);
        Assert.Contains(SbomExplicitUnknownFields.License, parsed);
        Assert.Equal(2, parsed.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not valid json")]
    [InlineData("""{"not":"an array"}""")]
    public void Parse_TreatsAMalformedOrAbsentColumnAsEmpty_RatherThanThrowing(string? stored)
    {
        Assert.Empty(SbomExplicitUnknownFields.Parse(stored));
    }

    [Fact]
    public void Parse_DropsAnUnrecognisedEntry_RatherThanFailingTheWholeSet()
    {
        // A hand-edited or otherwise corrupted row should not make every other entry unreadable.
        var parsed = SbomExplicitUnknownFields.Parse("""["producer","not-a-real-field"]""");

        Assert.Equal(SbomExplicitUnknownFields.Producer, Assert.Single(parsed));
    }
}
