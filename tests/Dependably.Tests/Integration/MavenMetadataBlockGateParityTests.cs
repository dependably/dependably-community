using System.Net;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>maven-metadata.xml</c> is Maven's version-discovery document, and it carried no block-gate
/// filter at all — a manually blocked artifact was listed and then refused at the jar. Maven
/// resolves a range or a `LATEST`/`RELEASE` marker through this document, so a listed-but-refused
/// version is a build that fails after resolution rather than one that routes around it.
///
/// The document has a second property worth protecting: it must stay byte-stable for a given
/// version set, because the ETag and the generated <c>.sha1</c>/<c>.md5</c> sidecars are derived
/// from these exact bytes. Filtering must therefore change the document when the version set
/// changes and at no other time.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MavenMetadataBlockGateParityTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string GroupId = "com.example";

    private readonly DependablyFactory _factory;

    public MavenMetadataBlockGateParityTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// The blocked version leaves the document and the clean one stays — the mixed case, so a
    /// filter that emptied the list would not pass. Also asserts the parity direction that
    /// matters: the version the document stopped naming is the one the jar route refuses.
    /// </summary>
    [Fact]
    public async Task Metadata_BlockedVersion_IsAbsent_AndItsJarIs403()
    {
        string artifactId = $"gatelib3-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushMavenArtifact(GroupId, artifactId, "1.0.0");
        await _factory.PushMavenArtifact(GroupId, artifactId, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        Assert.Equal(["1.0.0", "2.0.0"], await VersionsAsync(client, artifactId));

        await BlockVersionAsync(artifactId, "1.0.0");
        await EvictMetadataCacheAsync(artifactId);

        Assert.Equal(["2.0.0"], await VersionsAsync(client, artifactId));

        var jar = await client.GetAsync(
            $"/maven/com/example/{artifactId}/1.0.0/{artifactId}-1.0.0.jar");
        Assert.Equal(HttpStatusCode.Forbidden, jar.StatusCode);
    }

    /// <summary>
    /// The other direction: a version the document still names must actually download. A filter
    /// that hid too much would satisfy every "blocked version is absent" assertion while breaking
    /// every build that resolves through this document.
    /// </summary>
    [Fact]
    public async Task Metadata_SurvivingVersion_IsStillDownloadable()
    {
        string artifactId = $"survlib3-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushMavenArtifact(GroupId, artifactId, "1.0.0");
        await _factory.PushMavenArtifact(GroupId, artifactId, "2.0.0");
        await BlockVersionAsync(artifactId, "1.0.0");
        await EvictMetadataCacheAsync(artifactId);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        Assert.Contains("2.0.0", await VersionsAsync(client, artifactId));

        var jar = await client.GetAsync(
            $"/maven/com/example/{artifactId}/2.0.0/{artifactId}-2.0.0.jar");
        Assert.Equal(HttpStatusCode.OK, jar.StatusCode);
    }

    /// <summary>
    /// The control: with nothing blocked, every version is listed. Without it a filter that
    /// dropped everything, or one that failed closed on a settings read, would pass the tests
    /// above while making the registry useless.
    /// </summary>
    [Fact]
    public async Task Metadata_WithNothingBlocked_ListsEveryVersion()
    {
        string artifactId = $"ctllib3-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushMavenArtifact(GroupId, artifactId, "1.0.0");
        await _factory.PushMavenArtifact(GroupId, artifactId, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        Assert.Equal(["1.0.0", "2.0.0"], await VersionsAsync(client, artifactId));
    }

    /// <summary>
    /// The property the sidecars depend on. <c>ServeMetadataAsync</c> hashes the same cached bytes
    /// it serves, so a document that varied between two reads of an unchanged version set would
    /// hand clients a <c>.sha1</c> that does not describe the XML they fetched. Filtering must not
    /// introduce that: it is a function of stored facts and policy, not of when it ran.
    /// </summary>
    [Fact]
    public async Task Metadata_WithAVersionFiltered_IsStillByteStableAcrossReads()
    {
        string artifactId = $"stablib3-{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushMavenArtifact(GroupId, artifactId, "1.0.0");
        await _factory.PushMavenArtifact(GroupId, artifactId, "2.0.0");
        await BlockVersionAsync(artifactId, "1.0.0");
        await EvictMetadataCacheAsync(artifactId);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string path = $"/maven/com/example/{artifactId}/maven-metadata.xml";
        string first = await (await client.GetAsync(path)).Content.ReadAsStringAsync();

        // Assert the filter actually ran, so this cannot pass as a byte-stability test over an
        // unfiltered document — which is what it would otherwise do with the filter removed.
        Assert.DoesNotContain("<version>1.0.0</version>", first, StringComparison.Ordinal);
        Assert.Contains("<version>2.0.0</version>", first, StringComparison.Ordinal);

        // Evict so the second read is a genuine rebuild rather than the same cached array.
        await EvictMetadataCacheAsync(artifactId);
        string second = await (await client.GetAsync(path)).Content.ReadAsStringAsync();

        Assert.Equal(first, second);

        // And the sidecar describes exactly those bytes.
        string sha1 = (await (await client.GetAsync(path + ".sha1")).Content.ReadAsStringAsync()).Trim();
        string expected = Convert.ToHexString(
            System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(second)))
            .ToLowerInvariant();
        Assert.Equal(expected, sha1);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static async Task<List<string>> VersionsAsync(HttpClient client, string artifactId)
    {
        var resp = await client.GetAsync($"/maven/com/example/{artifactId}/maven-metadata.xml");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = XDocument.Parse(await resp.Content.ReadAsStringAsync());
        return [.. doc.Descendants("version").Select(v => v.Value)];
    }

    private async Task BlockVersionAsync(string artifactId, string version)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        int rows = await conn.ExecuteAsync(
            """
            UPDATE package_versions SET manual_block_state = 'blocked'
            WHERE version = @version
              AND package_id IN (
                  SELECT id FROM packages
                  WHERE org_id = @orgId AND ecosystem = 'maven' AND purl_name = @purlName)
            """,
            new { orgId, purlName = $"{GroupId}:{artifactId}", version });

        // A silent no-op would leave the version unblocked and make every following assertion
        // pass for the wrong reason.
        Assert.Equal(1, rows);
    }

    private async Task EvictMetadataCacheAsync(string artifactId)
    {
        string orgId = await DefaultOrgIdAsync();
        _factory.Services.GetRequiredService<RenderedResponseCache<MavenMetadataKey>>()
            .Evict(new MavenMetadataKey(orgId, GroupId, artifactId));
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }
}
