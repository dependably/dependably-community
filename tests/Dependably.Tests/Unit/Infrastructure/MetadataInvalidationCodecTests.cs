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
    // Keyed by a plain string rather than TheoryData<MetadataInvalidation> directly: xUnit's
    // VSTest adapter needs a serializable type argument to enumerate theory rows individually in
    // Test Explorer, and MetadataInvalidation is a production wire-format record with no reason
    // to carry that test-runner concern.
    public static TheoryData<string> AllEcosystems() => new()
    {
        MetadataInvalidationEcosystems.Npm,
        MetadataInvalidationEcosystems.PyPi,
        MetadataInvalidationEcosystems.NuGet,
        MetadataInvalidationEcosystems.Maven,
        "maven-snapshot",
        MetadataInvalidationEcosystems.Rpm,
        MetadataInvalidationEcosystems.Org,
    };

    private static MetadataInvalidation BuildInvalidation(string ecosystemKey) => ecosystemKey switch
    {
        MetadataInvalidationEcosystems.Npm => MetadataInvalidation.ForNpm("org-a", "@scope/pkg"),
        MetadataInvalidationEcosystems.PyPi => MetadataInvalidation.ForPyPi("org-a", "My_Package"),
        MetadataInvalidationEcosystems.NuGet => MetadataInvalidation.ForNuGet("org-a", "Contoso.Utils"),
        MetadataInvalidationEcosystems.Maven => MetadataInvalidation.ForMaven("org-a", "com.example", "widget"),
        "maven-snapshot" => MetadataInvalidation.ForMaven("org-a", "com.example", "widget", "1.0-SNAPSHOT"),
        MetadataInvalidationEcosystems.Rpm => MetadataInvalidation.ForRpm("org-a"),
        MetadataInvalidationEcosystems.Org => MetadataInvalidation.ForOrg("org-a"),
        _ => throw new ArgumentOutOfRangeException(nameof(ecosystemKey), ecosystemKey, "Unknown test ecosystem key."),
    };

    [Theory]
    [MemberData(nameof(AllEcosystems))]
    public void RoundTripsEveryCoordinate(string ecosystemKey)
    {
        var original = BuildInvalidation(ecosystemKey);
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

    [Fact]
    public void OrgWideMessageCarriesOnlyTheOrgAndTheCurrentSchemaVersion()
    {
        string payload = MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg("org-a"), origin: "replica-1");

        using var doc = JsonDocument.Parse(payload);
        var names = doc.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal);
        Assert.Equal(["ecosystem", "org_id", "origin", "v"], names);
        Assert.Equal("org", doc.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal(1, MetadataInvalidationCodec.SchemaVersion);
    }

    /// <summary>
    /// The rolling-deploy case. A replica on the previous build shares the channel with one that
    /// publishes org-wide messages. That build's decoder accepts schema version 1 with one of
    /// five ecosystems; the org-wide message is version 1 with a sixth value, so it must be
    /// rejected there and evict nothing, rather than being read as a per-package message.
    /// Each per-package message must still decode on the previous build, or this change would
    /// break the existing fan-out mid-deploy.
    /// </summary>
    [Fact]
    public void PreviousBuildDropsTheOrgWideMessage_AndStillReadsEveryOtherKind()
    {
        string orgWide = MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg("org-a"), origin: "new-build");
        Assert.False(PreviousBuildCodec.TryDecode(orgWide));

        string[] perPackageKinds =
        [
            MetadataInvalidationEcosystems.Npm,
            MetadataInvalidationEcosystems.PyPi,
            MetadataInvalidationEcosystems.NuGet,
            MetadataInvalidationEcosystems.Maven,
            "maven-snapshot",
            MetadataInvalidationEcosystems.Rpm,
        ];
        foreach (string kind in perPackageKinds)
        {
            string payload = MetadataInvalidationCodec.Encode(BuildInvalidation(kind), origin: "new-build");
            Assert.True(PreviousBuildCodec.TryDecode(payload), kind);
        }
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
    // A blank org is no org either, whatever the kind.
    [InlineData("{\"v\":1,\"ecosystem\":\"npm\",\"org_id\":\"   \",\"name\":\"pkg\"}")]
    [InlineData("{\"v\":1,\"ecosystem\":\"org\",\"org_id\":\" \\t \"}")]
    [InlineData("{\"v\":1,\"ecosystem\":\"org\",\"org_id\":\"\"}")]
    [InlineData("{\"v\":1,\"ecosystem\":\"org\"}")]
    public void RejectsAnythingItCannotInterpret(string? payload)
    {
        Assert.False(MetadataInvalidationCodec.TryDecode(payload, out _, out _));
    }

    /// <summary>
    /// The acceptance rule of the build before org-wide messages, restated: snake_case JSON,
    /// schema version 1, a non-empty org, and an ecosystem from the five that build knew. Kept
    /// as a frozen copy on purpose: it must not follow the live vocabulary.
    /// </summary>
    private static class PreviousBuildCodec
    {
        private static readonly string[] KnownEcosystems = ["npm", "pypi", "nuget", "maven", "rpm"];

        private static readonly JsonSerializerOptions WireOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        };

        public static bool TryDecode(string payload)
        {
            Envelope? envelope;
            try
            {
                envelope = JsonSerializer.Deserialize<Envelope>(payload, WireOptions);
            }
            catch (JsonException)
            {
                return false;
            }

            return envelope is not null
                && envelope.V == 1
                && !string.IsNullOrEmpty(envelope.OrgId)
                && envelope.Ecosystem is not null
                && KnownEcosystems.Contains(envelope.Ecosystem, StringComparer.Ordinal);
        }

        private sealed class Envelope
        {
            public int V { get; set; }
            public string? Ecosystem { get; set; }
            public string? OrgId { get; set; }
        }
    }
}
