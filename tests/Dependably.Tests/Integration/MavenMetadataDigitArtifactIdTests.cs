using System.Net;
using System.Xml.Linq;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// The end-to-end half of the artifactId-with-a-digit misparse: over HTTP, a published
/// <c>commons-lang3</c> answered 404 for its own <c>maven-metadata.xml</c> while both versions sat
/// in the catalogue. The parser unit tests pin the classification; this pins the symptom, because
/// the classification only matters through this route.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MavenMetadataDigitArtifactIdTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public MavenMetadataDigitArtifactIdTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Metadata_ForArtifactIdContainingADigit_ListsItsVersions()
    {
        await _factory.PushMavenArtifact("org.apache.commons", "commons-lang3", "3.12.0");
        await _factory.PushMavenArtifact("org.apache.commons", "commons-lang3", "3.14.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync("/maven/org/apache/commons/commons-lang3/maven-metadata.xml");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = XDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("org.apache.commons", doc.Root!.Element("groupId")!.Value);
        Assert.Equal("commons-lang3", doc.Root!.Element("artifactId")!.Value);
        // Containment, not equality: an upstream merge may add versions this org has not
        // published, and asserting the exact set would be asserting that proxying is off.
        var versions = doc.Descendants("version").Select(v => v.Value).ToList();
        Assert.Contains("3.12.0", versions);
        Assert.Contains("3.14.0", versions);
    }

    /// <summary>
    /// The sidecar the client verifies the document with was broken by the same misparse, and it
    /// must describe the bytes actually served.
    /// </summary>
    [Fact]
    public async Task MetadataChecksum_ForArtifactIdContainingADigit_MatchesTheServedDocument()
    {
        await _factory.PushMavenArtifact("org.slf4j", "slf4j-api", "2.0.16");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        const string path = "/maven/org/slf4j/slf4j-api/maven-metadata.xml";
        var docResp = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, docResp.StatusCode);
        byte[] body = await docResp.Content.ReadAsByteArrayAsync();

        var shaResp = await client.GetAsync(path + ".sha1");
        Assert.Equal(HttpStatusCode.OK, shaResp.StatusCode);
        string sha1 = (await shaResp.Content.ReadAsStringAsync()).Trim();

        Assert.Equal(
            Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(body)).ToLowerInvariant(),
            sha1);
    }

    /// <summary>
    /// The control that keeps the fix honest in the other direction: a genuine version-level
    /// SNAPSHOT request must still resolve, or the narrowed check has simply broken SNAPSHOT
    /// metadata instead.
    /// </summary>
    [Fact]
    public async Task VersionLevelSnapshotMetadata_StillResolves()
    {
        await _factory.PushMavenArtifact("com.example", "snaplib2", "1.0-SNAPSHOT");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync(
            "/maven/com/example/snaplib2/1.0-SNAPSHOT/maven-metadata.xml");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = XDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("1.0-SNAPSHOT", doc.Root!.Element("version")!.Value);
    }
}
