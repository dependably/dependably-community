using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Over HTTP, the group-level <c>maven-metadata.xml</c> Maven reads to resolve a short plugin
/// prefix (<c>mvn help:help</c> → <c>org/apache/maven/plugins/maven-metadata.xml</c>) is relayed
/// from the org's Maven upstream byte-for-byte, and its checksum sidecars describe those bytes.
/// The controller-level tests pin the branching; this pins what reaches the wire through the
/// real pipeline (routing, auth, response encoding).
/// </summary>
[Trait("Category", "Integration")]
public sealed class MavenGroupMetadataPassthroughTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string GroupPath = "org/apache/maven/plugins";

    // A second group so the BOM body gets its own upstream stub and its own metadata cache entry.
    private const string BomGroupPath = "org/codehaus/mojo";

    // CRLF line endings and a trailing comment: neither survives a re-render, so a byte-for-byte
    // match proves the upstream body was relayed rather than rebuilt.
    private static readonly byte[] PluginGroupXml = Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
        "<metadata>\r\n" +
        "  <plugins>\r\n" +
        "    <plugin><name>Apache Maven Help Plugin</name><prefix>help</prefix><artifactId>maven-help-plugin</artifactId></plugin>\r\n" +
        "  </plugins>\r\n" +
        "</metadata>\r\n" +
        "<!-- served by upstream -->\r\n");

    // The same document behind a UTF-8 BOM. The served body is decoded to a string and
    // re-encoded on the way out, so this pins that the BOM survives that round trip on the wire.
    private static readonly byte[] PluginGroupXmlWithBom =
    [
        0xEF, 0xBB, 0xBF,
        .. Encoding.UTF8.GetBytes(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
            "<metadata><plugins><plugin><name>Exec Maven Plugin</name><prefix>exec</prefix>" +
            "<artifactId>exec-maven-plugin</artifactId></plugin></plugins></metadata>\r\n"),
    ];

    private readonly DependablyFactory _factory;

    public MavenGroupMetadataPassthroughTests(DependablyFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        await ((IAsyncLifetime)_factory).InitializeAsync();

        // The default org's Maven upstream is seeded at Maven Central; point it at the mock so
        // this test never leaves the host.
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
        await conn.ExecuteAsync(
            "UPDATE upstream_registry SET url = @url WHERE org_id = @orgId AND ecosystem = 'maven'",
            new { url = _factory.MockUpstream.Urls[0], orgId });

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{GroupPath}/maven-metadata.xml").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(PluginGroupXml));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{BomGroupPath}/maven-metadata.xml").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBody(PluginGroupXmlWithBom));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task GroupMetadata_PluginPrefixDocument_IsServedWithTheUpstreamBytes()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/maven/{GroupPath}/maven-metadata.xml");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/xml", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal(PluginGroupXml, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task GroupMetadata_ChecksumSidecars_MatchTheServedBytes()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string path = $"/maven/{GroupPath}/maven-metadata.xml";
        byte[] body = await (await client.GetAsync(path)).Content.ReadAsByteArrayAsync();

        var sha1Resp = await client.GetAsync(path + ".sha1");
        Assert.Equal(HttpStatusCode.OK, sha1Resp.StatusCode);
        Assert.Equal(
            Convert.ToHexString(SHA1.HashData(body)).ToLowerInvariant(),
            (await sha1Resp.Content.ReadAsStringAsync()).Trim());

        var md5Resp = await client.GetAsync(path + ".md5");
        Assert.Equal(HttpStatusCode.OK, md5Resp.StatusCode);
        Assert.Equal(
            Convert.ToHexString(MD5.HashData(body)).ToLowerInvariant(),
            (await md5Resp.Content.ReadAsStringAsync()).Trim());

        Assert.Equal(PluginGroupXml, body);
    }

    [Fact]
    public async Task GroupMetadata_PluginPrefixDocumentWithBom_IsServedWithTheBomAndMatchingSidecars()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string path = $"/maven/{BomGroupPath}/maven-metadata.xml";
        var resp = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        byte[] body = await resp.Content.ReadAsByteArrayAsync();

        Assert.Equal(PluginGroupXmlWithBom, body);

        var sha1Resp = await client.GetAsync(path + ".sha1");
        Assert.Equal(HttpStatusCode.OK, sha1Resp.StatusCode);
        Assert.Equal(
            Convert.ToHexString(SHA1.HashData(PluginGroupXmlWithBom)).ToLowerInvariant(),
            (await sha1Resp.Content.ReadAsStringAsync()).Trim());

        var md5Resp = await client.GetAsync(path + ".md5");
        Assert.Equal(HttpStatusCode.OK, md5Resp.StatusCode);
        Assert.Equal(
            Convert.ToHexString(MD5.HashData(PluginGroupXmlWithBom)).ToLowerInvariant(),
            (await md5Resp.Content.ReadAsStringAsync()).Trim());
    }
}
