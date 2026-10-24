using System.Net;
using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The packument reader the npm tarball path runs once per proxy first-fetch. Every failure
/// mode (upstream error, non-JSON body, wrong-typed members, a transport exception) must
/// degrade to "no facts" so the caller proceeds without verification rather than failing the
/// install; the provenance step must never report a verdict for an org that opted out.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmFirstFetchMetadataReaderTests
{
    private const string Base = "https://registry.npmjs.example";

    private static NpmFirstFetchMetadataReader Reader(
        StubUpstream upstream, StubPerOrgTrustAnchorStore? anchors = null)
        => new(upstream.Client, new NpmProvenanceVerifier(
            new NpmSignatureKeyStore(anchors ?? new StubPerOrgTrustAnchorStore())));

    private static string Packument(string versionBody, string time = "\"1.0.0\":\"2024-03-05T10:20:30.000Z\"")
        => "{\"name\":\"express\",\"time\":{" + time + "},\"versions\":{\"1.0.0\":" + versionBody + "}}";

    [Fact]
    public async Task FullPackument_YieldsEveryFactTheTarballPathRecords()
    {
        string json = Packument("""
            {"dist":{"integrity":"sha512-QUJD","shasum":"da39a3ee5e6b4b0d3255bfef95601890afd80709",
              "signatures":[{"keyid":"SHA256:abc","sig":"c2ln"},{"keyid":"","sig":"x"},{"keyid":"k2"},null]},
             "deprecated":"use 2.x"}
            """);
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(json));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "1.0.0", default);

        Assert.Equal(DateTimeOffset.Parse("2024-03-05T10:20:30Z"), meta.PublishedAt);
        Assert.Equal(new ChecksumSpec(ChecksumAlgorithm.Sha512, "QUJD"), meta.Checksum);
        Assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", meta.Sha1Hex);
        Assert.Equal("sha512-QUJD", meta.IntegritySri);
        Assert.Equal("sha512-QUJD", meta.RawIntegrity);
        Assert.Equal("use 2.x", meta.Deprecated);
        var sig = Assert.Single(meta.Signatures);
        Assert.Equal(new ProvenanceSignature("SHA256:abc", "c2ln"), sig);
        Assert.Equal($"{Base}/express", Assert.Single(up.Requests.Urls));
    }

    [Fact]
    public async Task LegacyShasumOnly_FallsBackToSha1_AndSurfacesNoSri()
    {
        string json = Packument("""{"dist":{"integrity":"sha1-notsri","shasum":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}}""");
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(json));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "1.0.0", default);

        Assert.Equal(ChecksumAlgorithm.Sha1, meta.Checksum!.Algorithm);
        Assert.Null(meta.IntegritySri);
        Assert.Equal("sha1-notsri", meta.RawIntegrity);
        Assert.Empty(meta.Signatures);
    }

    [Fact]
    public async Task UnparseableOrMissingPublishTime_LeavesPublishedAtNull()
    {
        string json = Packument("""{"dist":{"shasum":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}}""", "\"1.0.0\":\"not-a-date\"");
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(json));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "1.0.0", default);

        Assert.Null(meta.PublishedAt);
        Assert.NotNull(meta.Checksum);
    }

    [Fact]
    public async Task VersionAbsentFromThePackument_YieldsNoChecksum()
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(Packument("{}")));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "9.9.9", default);

        Assert.Null(meta.Checksum);
        Assert.Null(meta.PublishedAt);
        Assert.Null(meta.RawIntegrity);
        Assert.Empty(meta.Signatures);
    }

    [Fact]
    public async Task NonSuccessUpstream_YieldsTheEmptyRecord()
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Status(HttpStatusCode.NotFound));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "1.0.0", default);

        Assert.Equal(NpmFirstFetchMetadata.Empty, meta);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("""{"time":{"1.0.0":42},"versions":{}}""")]
    public async Task MalformedBody_YieldsTheEmptyRecord_InsteadOfThrowing(string body)
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Text(body));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "1.0.0", default);

        Assert.Equal(NpmFirstFetchMetadata.Empty, meta);
    }

    [Fact]
    public async Task ATransportFailure_YieldsTheEmptyRecord_InsteadOfThrowing()
    {
        await using var up = await StubUpstream.CreateAsync(_ => throw new HttpRequestException("connection reset"));

        var meta = await Reader(up).TryFetchAsync(new UpstreamSource(Base, null), "express", "1.0.0", default);

        Assert.Equal(NpmFirstFetchMetadata.Empty, meta);
    }

    [Fact]
    public async Task ProvenanceOff_ReportsNotApplicable_EvenWithSignaturesPresent()
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Status(HttpStatusCode.OK));
        var meta = new NpmFirstFetchMetadata(null, null, null, null, null, "sha512-QUJD",
            [new ProvenanceSignature("SHA256:abc", "c2ln")]);

        var result = await Reader(up).ResolveProvenanceAsync(
            new OrgSettings { VerifyNpmSignatures = "off" }, "org-a", "express", "1.0.0", meta, default);

        Assert.Equal(ProvenanceResult.NotApplicable, result);
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task ProvenanceEnabledWithNoPinnedAnchor_ReportsNotApplicable_NotVerified(string mode)
    {
        await using var up = await StubUpstream.CreateAsync(_ => StubUpstream.Status(HttpStatusCode.OK));
        var meta = new NpmFirstFetchMetadata(null, null, null, null, null, "sha512-QUJD",
            [new ProvenanceSignature("SHA256:abc", "c2ln")]);

        var result = await Reader(up).ResolveProvenanceAsync(
            new OrgSettings { VerifyNpmSignatures = mode }, "org-a", "express", "1.0.0", meta, default);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
        Assert.Null(result.Signer);
    }
}
