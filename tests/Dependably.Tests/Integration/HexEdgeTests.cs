using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Hex on an edge node. A Hex client checks a resource's signature against the key it registered
/// and the payload's embedded repository name against the name it configured, and every node here
/// signs under the one well-known name — so an edge that re-signed with a key of its own would be
/// indistinguishable from a tampered master to a client that registered against the master. These
/// tests pin the two halves that make that impossible: the signed resources are the master's own
/// bytes, and the node mints no key to sign with in the first place.
///
/// The master is the factory's WireMock upstream: an edge seeds one <c>upstream_registry</c> row
/// per ecosystem pointing at it, so the Hex row's base URL is <c>{master}/hex</c> and every stub
/// here is the master's own read plane.
/// </summary>
[Trait("Category", "Integration")]
public sealed class HexEdgeTests
{
    private const string EdgeToken = DependablyFactory.DefaultEdgeToken;

    // One key for the whole class: RSA-4096 generation is the slowest thing in these tests, and
    // every case wants the same "the master's key, not the edge's" comparison anyway.
    private static readonly RSA MasterKey = HexRegistrySigner.GenerateSigningKey();

    /// <summary>
    /// A stock edge: no <c>DEPENDABLY_MASTER_KEY</c>, which is the default an operator gets and the
    /// configuration under which this node could not sign anything even if it wanted to.
    /// </summary>
    private static DependablyFactory NewEdgeFactory() => new() { DeploymentMode = "edge" };

    private static string Metadata(string name, string version) =>
        $"{{<<\"name\">>,<<\"{name}\">>}}.\n{{<<\"version\">>,<<\"{version}\">>}}.\n{{<<\"app\">>,<<\"{name}\">>}}.\n"
        + "{<<\"licenses\">>,[<<\"MIT\">>]}.\n{<<\"requirements\">>,[]}.\n{<<\"build_tools\">>,[<<\"mix\">>]}.\n";

    private static byte[] Contents()
    {
        using var ms = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress, leaveOpen: true))
        using (var tw = new System.Formats.Tar.TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "lib/demo.ex")
            {
                DataStream = new MemoryStream("defmodule Demo do end\n"u8.ToArray()),
            });
        }

        return ms.ToArray();
    }

    private static string NewName() => $"hexedge{Guid.NewGuid():N}"[..14];

    /// <summary>Stubs one of the master's resources, matching only when the edge token is presented.</summary>
    private static void StubMaster(DependablyFactory f, string path, byte[] body, string contentType = "application/octet-stream")
        => f.MockUpstream
            .Given(Request.Create().WithPath(path).WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", contentType).WithBody(body));

    private static void StubMasterPublicKey(DependablyFactory f) =>
        StubMaster(f, "/hex/public_key",
            System.Text.Encoding.UTF8.GetBytes(HexRegistrySigner.ExportPublicKeyPem(MasterKey)), "text/plain");

    private static byte[] SignedPackage(string name, HexRelease release) =>
        HexRegistrySigner.BuildResource(
            HexRegistryCodec.EncodePackage(new HexPackage(
                name, HexIndexBuilder.RepositoryName, new[] { release }, Array.Empty<HexSecurityAdvisory>())),
            MasterKey);

    private static int MasterCalls(DependablyFactory f, string path) =>
        f.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));

    private static async Task<HttpClient> PullClientAsync(DependablyFactory f) =>
        f.CreateClientWithBearer(await f.CreateToken("pull"));

    private static async Task<int> SigningKeyRowsAsync(DependablyFactory f)
    {
        var store = f.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM hex_signing_key");
    }

    [Fact]
    public async Task SignedResources_AreTheMastersBytes_AndVerifyUnderTheMastersKey()
    {
        await using var f = NewEdgeFactory();
        string name = NewName();
        byte[] names = HexRegistrySigner.BuildResource(
            HexRegistryCodec.EncodeNames(new HexNames(HexIndexBuilder.RepositoryName, new[] { new HexNameEntry(name) })), MasterKey);
        byte[] package = SignedPackage(name, new HexRelease("1.0.0", new byte[32], Array.Empty<HexDependency>(), null, new byte[32]));

        StubMasterPublicKey(f);
        StubMaster(f, "/hex/names", names);
        StubMaster(f, $"/hex/packages/{name}", package);

        using var client = await PullClientAsync(f);

        // The key a client would register with is the master's own PEM, served through the edge.
        var keyResponse = await client.GetAsync("/hex/public_key");
        Assert.Equal(HttpStatusCode.OK, keyResponse.StatusCode);
        Assert.Equal(HexRegistrySigner.ExportPublicKeyPem(MasterKey), await keyResponse.Content.ReadAsStringAsync());

        var namesResponse = await client.GetAsync("/hex/names");
        Assert.Equal(HttpStatusCode.OK, namesResponse.StatusCode);
        Assert.Equal(names, await namesResponse.Content.ReadAsByteArrayAsync());

        var packageResponse = await client.GetAsync($"/hex/packages/{name}");
        Assert.Equal(HttpStatusCode.OK, packageResponse.StatusCode);
        byte[] served = await packageResponse.Content.ReadAsByteArrayAsync();
        Assert.Equal(package, served);

        // What the client actually does with it: open the resource under the master's key. A
        // locally re-signed body would be byte-different above and unopenable here.
        var decoded = HexRegistryCodec.DecodePackage(HexRegistrySigner.OpenResource(served, MasterKey));
        Assert.Equal(name, decoded.Name);
        Assert.Equal(HexIndexBuilder.RepositoryName, decoded.Repository);

        // And the node never minted a key of its own on the way through.
        Assert.Equal(0, await SigningKeyRowsAsync(f));
    }

    [Fact]
    public async Task SignedResource_IfNoneMatch_Answers304()
    {
        await using var f = NewEdgeFactory();
        byte[] versions = HexRegistrySigner.BuildResource(
            HexRegistryCodec.EncodeVersions(new HexVersions(HexIndexBuilder.RepositoryName, Array.Empty<HexVersionsEntry>())), MasterKey);
        StubMaster(f, "/hex/versions", versions);

        using var client = await PullClientAsync(f);
        var first = await client.GetAsync("/hex/versions");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        string etag = first.Headers.ETag!.ToString();

        using var conditional = new HttpRequestMessage(HttpMethod.Get, "/hex/versions");
        conditional.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var second = await client.SendAsync(conditional);
        Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
    }

    [Fact]
    public async Task MasterUnavailable_Is503_AndNothingIsSignedLocally()
    {
        await using var f = NewEdgeFactory();
        f.MockUpstream
            .Given(Request.Create().WithPath("/hex/names").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        using var client = await PullClientAsync(f);
        var response = await client.GetAsync("/hex/names");

        // A master that is temporarily unable to answer is retryable, not a verdict — collapsing
        // this into 502 would make a master restart look permanent to every client on the network.
        // The failure that matters most is the one this replaces: falling through to the local
        // signing path, which would answer 200 with bytes no client could verify.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, await SigningKeyRowsAsync(f));
    }

    [Fact]
    public async Task MasterRefusesTheEdgeCredential_Is502()
    {
        await using var f = NewEdgeFactory();
        f.MockUpstream
            .Given(Request.Create().WithPath("/hex/names").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.Unauthorized));

        using var client = await PullClientAsync(f);

        // A refusal of the edge's own token is deterministic: no retry fixes it, so it is a 502
        // and distinct from the unavailability above (the #345 upstream-refusal contract).
        Assert.Equal(HttpStatusCode.BadGateway, (await client.GetAsync("/hex/names")).StatusCode);
    }

    [Fact]
    public async Task MissingPackage_OnTheMaster_Is404()
    {
        await using var f = NewEdgeFactory();
        f.MockUpstream
            .Given(Request.Create().WithPath("/hex/packages/absent").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        using var client = await PullClientAsync(f);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/packages/absent")).StatusCode);

        // The master is what decided this, not a local index that happens to be empty too — the
        // 404 has to come from the passthrough or the assertion above proves nothing on an edge.
        Assert.Equal(1, MasterCalls(f, "/hex/packages/absent"));
    }

    [Fact]
    public async Task TarballMiss_LearnsTheMastersKeyFromItsPublicKeyResource_ThenFetchesAndVerifies()
    {
        await using var f = NewEdgeFactory();
        string name = NewName();
        const string version = "1.0.0";
        byte[] tarball = HexTarball.Build(Metadata(name, version), Contents());
        var parsed = HexTarball.Parse(tarball, 64 * 1024 * 1024);

        StubMasterPublicKey(f);
        StubMaster(f, $"/hex/packages/{name}", SignedPackage(name, new HexRelease(
            version, parsed.InnerChecksum, Array.Empty<HexDependency>(), null, parsed.OuterChecksum)));
        StubMaster(f, $"/hex/tarballs/{name}-{version}.tar", tarball);

        using var client = await PullClientAsync(f);
        var response = await client.GetAsync($"/hex/tarballs/{name}-{version}.tar");

        // The tarball path reaches upstream only through the shared fetcher, which skips an
        // upstream with no public key — and the seeded edge row has none. Serving these bytes is
        // proof the key was read from the master's own resource and the outer checksum verified.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(tarball, await response.Content.ReadAsByteArrayAsync());
        Assert.True(MasterCalls(f, "/hex/public_key") >= 1);
        Assert.Equal(0, await SigningKeyRowsAsync(f));
    }

    [Fact]
    public async Task MasterWithoutAPublicKeyResource_LeavesTheUpstreamUnkeyed_AndServesNoTarball()
    {
        await using var f = NewEdgeFactory();
        string name = NewName();
        const string version = "1.0.0";
        byte[] tarball = HexTarball.Build(Metadata(name, version), Contents());
        var parsed = HexTarball.Parse(tarball, 64 * 1024 * 1024);

        // No /hex/public_key stub: the master answers 404 for its key. The index and the tarball
        // are both available, so anything but a refusal here would be an unverified fetch.
        StubMaster(f, $"/hex/packages/{name}", SignedPackage(name, new HexRelease(
            version, parsed.InnerChecksum, Array.Empty<HexDependency>(), null, parsed.OuterChecksum)));
        StubMaster(f, $"/hex/tarballs/{name}-{version}.tar", tarball);

        using var client = await PullClientAsync(f);
        var response = await client.GetAsync($"/hex/tarballs/{name}-{version}.tar");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, MasterCalls(f, $"/hex/tarballs/{name}-{version}.tar"));
    }
}
