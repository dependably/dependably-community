using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The first-fetch helpers behind the NuGet flatcontainer proxy path: canonical-id recovery
/// from cached bytes, registration-leaf metadata, and the fetch request that carries the
/// upstream facts into the block gate. Untrusted upstream content degrades a single fact (or
/// falls back to the URL-derived id) and never throws out of the helper.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetNupkgProxyHelperTests
{
    private const string Base = "https://api.nuget.example/v3";
    private const string NuspecNs = "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd";

    private static string Nuspec(string id, bool withNamespace = true)
        => withNamespace
            ? $"<package xmlns=\"{NuspecNs}\"><metadata><id>{id}</id><version>13.0.3</version></metadata></package>"
            : $"<package><metadata><id>{id}</id></metadata></package>";

    private static byte[] Nupkg(params (string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = zip.CreateEntry(name);
                using var w = new StreamWriter(e.Open(), new UTF8Encoding(false));
                w.Write(content);
            }
        }

        return ms.ToArray();
    }

    private static async Task<InMemoryBlobStore> StoreAsync(string key, byte[] bytes)
    {
        var store = new InMemoryBlobStore();
        await store.PutAsync(key, new MemoryStream(bytes));
        return store;
    }

    // ── canonical id ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ANupkgWithARootNuspec_YieldsTheCanonicalCasedId()
    {
        var store = await StoreAsync("k", Nupkg(("Newtonsoft.Json.nuspec", Nuspec("Newtonsoft.Json")), ("lib/net8.0/a.dll", "x")));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "newtonsoft.json.13.0.3.nupkg", "k", "newtonsoft.json", default);

        Assert.Equal("Newtonsoft.Json", id);
    }

    [Fact]
    public async Task ANuspecWithoutANamespace_StillYieldsItsId()
    {
        var store = await StoreAsync("k", Nupkg(("Serilog.nuspec", Nuspec("Serilog", withNamespace: false))));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "serilog.4.0.0.nupkg", "k", "serilog", default);

        Assert.Equal("Serilog", id);
    }

    [Fact]
    public async Task ABareNuspecFile_YieldsTheCanonicalCasedId()
    {
        var store = await StoreAsync("k", Encoding.UTF8.GetBytes(Nuspec("Dapper")));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "dapper.nuspec", "k", "dapper", default);

        Assert.Equal("Dapper", id);
    }

    [Fact]
    public async Task ANuspecWithABlankId_FallsBackToTheNormalizedId()
    {
        var store = await StoreAsync("k", Encoding.UTF8.GetBytes(Nuspec("   ")));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "dapper.nuspec", "k", "dapper", default);

        Assert.Equal("dapper", id);
    }

    [Fact]
    public async Task ANupkgWithABlankNuspecId_FallsBackToTheNormalizedId()
    {
        var store = await StoreAsync("k", Nupkg(("Dapper.nuspec", Nuspec(""))));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "dapper.2.1.0.nupkg", "k", "dapper", default);

        Assert.Equal("dapper", id);
    }

    [Fact]
    public async Task ANupkgWhoseOnlyNuspecIsNested_FallsBackToTheNormalizedId()
    {
        var store = await StoreAsync("k", Nupkg(("content/Evil.nuspec", Nuspec("Evil.Package"))));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "dapper.2.1.0.nupkg", "k", "dapper", default);

        Assert.Equal("dapper", id);
    }

    [Fact]
    public async Task ANupkgWithNoNuspec_FallsBackToTheNormalizedId()
    {
        var store = await StoreAsync("k", Nupkg(("lib/net8.0/a.dll", "x")));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            store, "dapper.2.1.0.nupkg", "k", "dapper", default);

        Assert.Equal("dapper", id);
    }

    [Theory]
    [InlineData("dapper.2.1.0.snupkg")]
    [InlineData("dapper.2.1.0.zip")]
    public async Task AnUnrecognisedExtension_FallsBackWithoutParsing(string file)
    {
        var store = await StoreAsync("k", Nupkg(("Dapper.nuspec", Nuspec("Dapper"))));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(store, file, "k", "dapper", default);

        Assert.Equal("dapper", id);
    }

    [Theory]
    [InlineData("dapper.2.1.0.nupkg")]
    [InlineData("dapper.nuspec")]
    public async Task CorruptBytes_FallBackToTheNormalizedId(string file)
    {
        var store = await StoreAsync("k", Encoding.UTF8.GetBytes("this is not a zip or xml"));

        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(store, file, "k", "dapper", default);

        Assert.Equal("dapper", id);
    }

    [Fact]
    public async Task AMissingBlob_FallsBackToTheNormalizedId()
    {
        string id = await NuGetNupkgProxyHelper.ResolveCanonicalNuGetIdFromBlobAsync(
            new InMemoryBlobStore(), "dapper.2.1.0.nupkg", "absent", "dapper", default);

        Assert.Equal("dapper", id);
    }

    // ── registration leaf ───────────────────────────────────────────────────────

    [Fact]
    public async Task ALeafWithRootLevelFields_YieldsPublishedChecksumAndIntegrity()
    {
        string leaf = """
            {"published":"2023-05-08T14:00:00+00:00","packageHash":"QUJDRA==","packageHashAlgorithm":"SHA512","listed":true}
            """;
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(leaf));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "newtonsoft.json", "13.0.3", default);

        Assert.Equal(DateTimeOffset.Parse("2023-05-08T14:00:00Z"), meta.PublishedAt);
        Assert.Equal(new ChecksumSpec(ChecksumAlgorithm.Sha512, "QUJDRA=="), meta.Checksum);
        Assert.Equal("QUJDRA==", meta.IntegrityBase64);
        Assert.Null(meta.Deprecated);
        Assert.Equal($"{Base}/registration5-semver1/newtonsoft.json/13.0.3.json", Assert.Single(up.Requests.Urls));
    }

    [Fact]
    public async Task ALeafWithFieldsNestedUnderCatalogEntry_IsReadFromThere_AndUnlistedMapsToADeprecation()
    {
        string leaf = """
            {"catalogEntry":{"published":"2022-01-02T03:04:05Z","packageHash":"QUJDRA==","packageHashAlgorithm":"sha512","listed":false}}
            """;
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(leaf));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "serilog", "4.0.0", default);

        Assert.Equal(DateTimeOffset.Parse("2022-01-02T03:04:05Z"), meta.PublishedAt);
        Assert.Equal("QUJDRA==", meta.IntegrityBase64);
        Assert.Equal("Unlisted upstream", meta.Deprecated);
    }

    [Fact]
    public async Task ANonSha512Hash_YieldsNeitherAChecksumNorAnIntegrityLabel()
    {
        string leaf = """{"packageHash":"QUJDRA==","packageHashAlgorithm":"SHA256"}""";
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(leaf));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "serilog", "4.0.0", default);

        Assert.Null(meta.Checksum);
        Assert.Null(meta.IntegrityBase64);
    }

    [Fact]
    public async Task AHashWithNoAlgorithm_YieldsNoIntegrityLabel()
    {
        string leaf = """{"packageHash":"QUJDRA=="}""";
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(leaf));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "serilog", "4.0.0", default);

        Assert.Null(meta.Checksum);
        Assert.Null(meta.IntegrityBase64);
    }

    [Fact]
    public async Task ANonSuccessLeaf_YieldsTheEmptyRecord()
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Status(HttpStatusCode.NotFound));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "serilog", "4.0.0", default);

        Assert.Equal(NuGetFirstFetchMetadata.Empty, meta);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"packageHash":12,"packageHashAlgorithm":"SHA512"}""")]
    public async Task AMalformedLeaf_YieldsTheEmptyRecord(string body)
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(body));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "serilog", "4.0.0", default);

        Assert.Equal(NuGetFirstFetchMetadata.Empty, meta);
    }

    [Fact]
    public async Task ATransportFailure_YieldsTheEmptyRecord()
    {
        await using var up = await StubUpstream.CreateAsync(_ => throw new HttpRequestException("connection refused"));

        var meta = await NuGetNupkgProxyHelper.TryFetchNuGetFirstFetchMetadataAsync(
            up.Client, new UpstreamSource(Base, null), "serilog", "4.0.0", default);

        Assert.Equal(NuGetFirstFetchMetadata.Empty, meta);
    }

    [Theory]
    [InlineData("""{"published":"1900-01-01T00:00:00+00:00"}""", false)]
    [InlineData("""{"published":"2021-07-01T00:00:00Z"}""", true)]
    [InlineData("""{"published":"garbage"}""", false)]
    [InlineData("""{"published":12345}""", false)]
    [InlineData("""{"catalogEntry":{"published":"2021-07-01T00:00:00Z"}}""", true)]
    [InlineData("""{}""", false)]
    public void ParsePublishedAt_CoercesSentinelsAndWrongTypesToNull(string json, bool expectValue)
    {
        var parsed = NuGetNupkgProxyHelper.ParsePublishedAt(JsonNode.Parse(json));

        Assert.Equal(expectValue, parsed.HasValue);
    }

    [Fact]
    public void ParsePublishedAt_OfNull_IsNull() => Assert.Null(NuGetNupkgProxyHelper.ParsePublishedAt(null));

    [Theory]
    [InlineData("""{"listed":false}""", "Unlisted upstream")]
    [InlineData("""{"catalogEntry":{"listed":false}}""", "Unlisted upstream")]
    [InlineData("""{"listed":true}""", null)]
    [InlineData("""{"listed":"false"}""", null)]
    [InlineData("""{}""", null)]
    public void ParseUnlistedDeprecation_OnlyAnExplicitFalseBooleanDeprecates(string json, string? expected)
        => Assert.Equal(expected, NuGetNupkgProxyHelper.ParseUnlistedDeprecation(JsonNode.Parse(json)));

    // ── fetch request ───────────────────────────────────────────────────────────

    private static ProxyFetchRequest Build(string file, TokenRecord? token, NuGetFirstFetchMetadata meta)
        => NuGetNupkgProxyHelper.BuildNuGetProxyFetchRequest(
            "org-a", "newtonsoft.json", "13.0.3", "pkg:nuget/newtonsoft.json@13.0.3", file,
            new BlobHandle("k", "abc", 10, _ => Task.FromResult<Stream>(new MemoryStream())),
            Base, token,
            new OrgSettings { OrgId = "org-a", VerifyNuGetSignatures = "warn", LicenseEnforcementMode = "block" },
            meta, "203.0.113.9", ProvenanceResult.Verified("CN=NuGet Gallery"));

    [Fact]
    public void TheRequest_CarriesUpstreamFactsTokenIdentityAndProvenance()
    {
        var token = new TokenRecord { Id = "tok-1", Source = TokenSource.Service, Name = "ci-restore" };
        var checksum = new ChecksumSpec(ChecksumAlgorithm.Sha512, "QUJDRA==");
        var published = new DateTimeOffset(2023, 5, 8, 14, 0, 0, TimeSpan.Zero);

        var req = Build("newtonsoft.json.13.0.3.nupkg", token,
            new NuGetFirstFetchMetadata(published, checksum, "QUJDRA==", "Unlisted upstream"));

        Assert.Equal("nuget", req.Ecosystem);
        Assert.Equal("tok-1", req.AuditActorId);
        Assert.Equal("ci-restore", req.AuditActorLabel);
        Assert.Equal(ActorKinds.Service, req.ActorKind);
        Assert.Equal(published, req.PublishedAt);
        Assert.Equal(checksum, req.UpstreamChecksum);
        Assert.Equal("QUJDRA==", req.UpstreamIntegrityValue);
        Assert.Equal("sha512-b64", req.UpstreamIntegrityAlgorithm);
        Assert.Equal("Unlisted upstream", req.Deprecated);
        Assert.Equal("warn", req.VerifyProvenanceMode);
        Assert.Equal("block", req.LicenseEnforcementMode);
        Assert.Equal(ProvenanceStatuses.ToColumn(ProvenanceStatus.Verified), req.ProvenanceStatus);
        Assert.Equal("CN=NuGet Gallery", req.ProvenanceSigner);
        Assert.Equal(
            $"{Base}/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
            req.CacheAccess!.UpstreamUrl);
    }

    [Fact]
    public void AnAnonymousRequestWithNoIntegrity_CarriesNoActorAndNoIntegrityAlgorithm()
    {
        var req = Build("newtonsoft.json.13.0.3.nupkg", null, NuGetFirstFetchMetadata.Empty);

        Assert.Null(req.AuditActorId);
        Assert.Null(req.AuditActorLabel);
        Assert.Null(req.ActorKind);
        Assert.Null(req.UpstreamIntegrityValue);
        Assert.Null(req.UpstreamIntegrityAlgorithm);
        Assert.Null(req.UpstreamChecksum);
    }

    [Fact]
    public void LicenceExtraction_RunsForANupkgOnly()
    {
        byte[] nupkg = Nupkg(("Newtonsoft.Json.nuspec",
            $"<package xmlns=\"{NuspecNs}\"><metadata><id>Newtonsoft.Json</id><license type=\"expression\">MIT</license></metadata></package>"));

        var forNupkg = Build("newtonsoft.json.13.0.3.nupkg", null, NuGetFirstFetchMetadata.Empty)
            .ExtractLicenses!(new MemoryStream(nupkg));
        var forSymbols = Build("newtonsoft.json.13.0.3.snupkg", null, NuGetFirstFetchMetadata.Empty)
            .ExtractLicenses!(new MemoryStream(nupkg));

        Assert.Equal(["MIT"], forNupkg.Spdx);
        Assert.Empty(forSymbols.Spdx);
    }
}
