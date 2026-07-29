using System.Text.Json;
using Dependably.Infrastructure.Caching;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The replica-to-replica wire format. Two properties matter: a message survives the round trip
/// with every coordinate intact (a dropped <c>version</c> silently downgrades a Maven SNAPSHOT
/// invalidation to artifact-level only), and anything the receiver cannot confidently interpret
/// is rejected rather than guessed at — a rolling deploy runs two builds against one channel.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetadataInvalidationCodecTests
{
    public static TheoryData<MetadataInvalidation> AllEcosystems() =>
    [
        MetadataInvalidation.ForNpm("org-a", "@scope/pkg"),
        MetadataInvalidation.ForPyPi("org-a", "My_Package"),
        MetadataInvalidation.ForNuGet("org-a", "Contoso.Utils"),
        MetadataInvalidation.ForMaven("org-a", "com.example", "widget"),
        MetadataInvalidation.ForMaven("org-a", "com.example", "widget", "1.0-SNAPSHOT"),
        MetadataInvalidation.ForRpm("org-a"),
    ];

    [Theory]
    [MemberData(nameof(AllEcosystems))]
    public void RoundTripsEveryCoordinate(MetadataInvalidation original)
    {
        string payload = MetadataInvalidationCodec.Encode(original, origin: "replica-1");

        Assert.True(MetadataInvalidationCodec.TryDecode(payload, out var decoded, out string origin));

        Assert.Equal("replica-1", origin);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void EmitsSnakeCaseFieldsAndASchemaVersion()
    {
        string payload = MetadataInvalidationCodec.Encode(
            MetadataInvalidation.ForMaven("org-a", "com.example", "widget", "1.0-SNAPSHOT"),
            origin: "replica-1");

        using var doc = JsonDocument.Parse(payload);
        var root = doc.RootElement;

        Assert.Equal(MetadataInvalidationCodec.SchemaVersion, root.GetProperty("v").GetInt32());
        Assert.Equal("replica-1", root.GetProperty("origin").GetString());
        Assert.Equal("org-a", root.GetProperty("org_id").GetString());
        Assert.Equal("maven", root.GetProperty("ecosystem").GetString());
        Assert.Equal("com.example", root.GetProperty("group_id").GetString());
        Assert.Equal("widget", root.GetProperty("artifact_id").GetString());
        Assert.Equal("1.0-SNAPSHOT", root.GetProperty("version").GetString());
    }

    [Fact]
    public void OmitsCoordinatesAnEcosystemDoesNotUse()
    {
        string payload = MetadataInvalidationCodec.Encode(
            MetadataInvalidation.ForRpm("org-a"), origin: "replica-1");

        using var doc = JsonDocument.Parse(payload);
        Assert.False(doc.RootElement.TryGetProperty("name", out _));
        Assert.False(doc.RootElement.TryGetProperty("group_id", out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("[1,2,3]")]
    // A future schema version: ignore rather than mis-parse.
    [InlineData("{\"v\":2,\"ecosystem\":\"npm\",\"org_id\":\"org-a\",\"name\":\"pkg\"}")]
    // An ecosystem this build has no cache for.
    [InlineData("{\"v\":1,\"ecosystem\":\"conan\",\"org_id\":\"org-a\",\"name\":\"pkg\"}")]
    // No tenant: every rendered key is org-scoped, so this cannot address anything.
    [InlineData("{\"v\":1,\"ecosystem\":\"npm\",\"org_id\":\"\",\"name\":\"pkg\"}")]
    public void RejectsAnythingItCannotInterpret(string? payload)
    {
        Assert.False(MetadataInvalidationCodec.TryDecode(payload, out _, out _));
    }
}
