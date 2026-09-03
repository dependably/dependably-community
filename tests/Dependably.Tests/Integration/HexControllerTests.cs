using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// The Hex repository read plane against a stubbed upstream that signs its own resources: what
/// a Mix or Rebar3 client sees is a resource signed by THIS org's key under the repository name
/// it registered, carrying the upstream's releases, with the tarball verified against the outer
/// checksum the upstream's signed index vouched for.
/// </summary>
[Trait("Category", "Integration")]
public sealed class HexControllerTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    private readonly RSA _upstreamKey = RSA.Create(2048);

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'hex'", new { orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, public_key_pem)
            VALUES (@id, @orgId, 'hex', @url, 0, @pem)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, url = _factory.MockUpstream.Urls[0], pem = HexRegistrySigner.ExportPublicKeyPem(_upstreamKey) });
    }

    public async Task DisposeAsync()
    {
        _upstreamKey.Dispose();
        await _factory.DisposeAsync();
    }

    // ── fixtures ──────────────────────────────────────────────────────────────

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

    private sealed record UpstreamFixture(string Name, string Version, byte[] Tarball, HexTarballParsed Parsed);

    private UpstreamFixture StubUpstream(string name, string version, DateTimeOffset? publishedAt = null,
        HexRetirementStatus? retired = null, bool corruptTarball = false, string repository = "upstream-repo")
    {
        byte[] tarball = HexTarball.Build(Metadata(name, version), Contents());
        var parsed = HexTarball.Parse(tarball, 64 * 1024 * 1024);
        var package = new HexPackage(name, repository, new[]
        {
            new HexRelease(version, parsed.InnerChecksum, Array.Empty<HexDependency>(), retired, parsed.OuterChecksum, null,
                publishedAt is { } p ? HexTimestamp.FromDateTimeOffset(p) : null),
        }, Array.Empty<HexSecurityAdvisory>());

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/packages/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), _upstreamKey)));
        byte[] served = corruptTarball ? tarball.Concat("x"u8.ToArray()).ToArray() : tarball;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/tarballs/{name}-{version}.tar").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(served));
        return new UpstreamFixture(name, version, tarball, parsed);
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task<HttpClient> PullClientAsync() => _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));

    private static string NewName() => $"hexpkg{Guid.NewGuid():N}"[..14];

    private static async Task<RSA> OrgPublicKeyAsync(HttpClient client)
    {
        var resp = await client.GetAsync("/hex/public_key");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return HexRegistrySigner.ParsePublicKeyPem(await resp.Content.ReadAsStringAsync());
    }

    private static async Task<HexPackage> OpenPackageAsync(HttpResponseMessage resp, RSA orgKey) =>
        HexRegistryCodec.DecodePackage(HexRegistrySigner.OpenResource(await resp.Content.ReadAsByteArrayAsync(), orgKey));

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PackageResource_IsResignedUnderTheOrgKeyAndRepositoryName_WithTheUpstreamRelease()
    {
        var fx = StubUpstream(NewName(), "1.2.3", publishedAt: new DateTimeOffset(2025, 1, 2, 3, 4, 5, TimeSpan.Zero));
        using var client = await PullClientAsync();
        using var orgKey = await OrgPublicKeyAsync(client);
        var resp = await client.GetAsync($"/hex/packages/{fx.Name}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var package = await OpenPackageAsync(resp, orgKey);
        Assert.Equal(HexIndexBuilder.RepositoryName, package.Repository);
        Assert.Equal(fx.Name, package.Name);
        var release = Assert.Single(package.Releases);
        Assert.Equal("1.2.3", release.Version);
        Assert.Equal(fx.Parsed.InnerChecksum, release.InnerChecksum);
        Assert.Equal(fx.Parsed.OuterChecksum, release.OuterChecksum);
        Assert.Equal(2025, release.PublishedAt!.ToDateTimeOffset().Year);
        // The upstream's own key must NOT verify the re-signed resource: it is this org's now.
        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.OpenResource(resp.Content.ReadAsByteArrayAsync().Result, _upstreamKey));
    }

    [Fact]
    public async Task PackageResource_CarriesAStableStrongETag_AndAnswers304()
    {
        var fx = StubUpstream(NewName(), "1.0.0");
        using var client = await PullClientAsync();

        var first = await client.GetAsync($"/hex/packages/{fx.Name}");
        string etag = first.Headers.ETag!.Tag;
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/hex/packages/{fx.Name}");
        req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var second = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
    }

    [Fact]
    public async Task Tarball_IsFetchedVerifiedRecordedAndServed_ThenHits()
    {
        var fx = StubUpstream(NewName(), "1.0.0");
        using var client = await PullClientAsync();

        var miss = await client.GetAsync($"/hex/tarballs/{fx.Name}-1.0.0.tar");
        Assert.Equal(HttpStatusCode.OK, miss.StatusCode);
        Assert.Equal(fx.Tarball, await miss.Content.ReadAsByteArrayAsync());
        Assert.Equal("MISS", miss.Headers.GetValues("X-Cache").Single());

        var hit = await client.GetAsync($"/hex/tarballs/{fx.Name}-1.0.0.tar");
        Assert.Equal(HttpStatusCode.OK, hit.StatusCode);
        Assert.Equal("HIT", hit.Headers.GetValues("X-Cache").Single());

        // rebar3 refuses a tarball response without an etag, and both clients send if-none-match.
        string etag = "\"" + Convert.ToHexString(SHA256.HashData(fx.Tarball)).ToLowerInvariant() + "\"";
        Assert.Equal(etag, miss.Headers.ETag!.Tag);
        Assert.Equal(etag, hit.Headers.ETag!.Tag);
        using var conditional = new HttpRequestMessage(HttpMethod.Get, $"/hex/tarballs/{fx.Name}-1.0.0.tar");
        conditional.Headers.TryAddWithoutValidation("If-None-Match", etag);
        Assert.Equal(HttpStatusCode.NotModified, (await client.SendAsync(conditional)).StatusCode);

        // Recorded on the cache plane with the release facts the index needs offline.
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? inner = await conn.ExecuteScalarAsync<string>(
            """
            SELECT hr.inner_checksum FROM hex_release hr
            JOIN cache_artifact ca ON ca.id = hr.cache_artifact_id
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = 'hex' AND ca.name = @name AND ca.version = '1.0.0'
            """, new { orgId, name = fx.Name });
        Assert.Equal(Convert.ToHexString(fx.Parsed.InnerChecksum), inner);

        // And the fetched release now shows in the org's own names/versions listing.
        using var orgKey = await OrgPublicKeyAsync(client);
        var names = HexRegistryCodec.DecodeNames(HexRegistrySigner.OpenResource(
            await (await client.GetAsync("/hex/names")).Content.ReadAsByteArrayAsync(), orgKey));
        Assert.Contains(names.Packages, p => p.Name == fx.Name);
        var versions = HexRegistryCodec.DecodeVersions(HexRegistrySigner.OpenResource(
            await (await client.GetAsync("/hex/versions")).Content.ReadAsByteArrayAsync(), orgKey));
        Assert.Equal(new[] { "1.0.0" }, versions.Packages.Single(p => p.Name == fx.Name).Versions);
    }

    [Fact]
    public async Task Tarball_WhoseBytesDoNotMatchTheSignedChecksum_IsRefusedAndNotStored()
    {
        var fx = StubUpstream(NewName(), "1.0.0", corruptTarball: true);
        using var client = await PullClientAsync();

        var resp = await client.GetAsync($"/hex/tarballs/{fx.Name}-1.0.0.tar");

        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'hex' AND name = @name", new { name = fx.Name }));
        _ = orgId;
    }

    [Fact]
    public async Task UpstreamResourceSignedByAnotherKey_IsNotTrusted()
    {
        string name = NewName();
        using var rogue = RSA.Create(2048);
        var package = new HexPackage(name, "upstream-repo", new[]
        {
            new HexRelease("1.0.0", new byte[32], Array.Empty<HexDependency>(), null, new byte[32]),
        }, Array.Empty<HexSecurityAdvisory>());
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/packages/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithBody(HexRegistrySigner.BuildResource(HexRegistryCodec.EncodePackage(package), rogue)));
        using var client = await PullClientAsync();

        var resp = await client.GetAsync($"/hex/packages/{name}");

        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
    }

    [Fact]
    public async Task ReleaseYoungerThanTheCooldown_IsWithheldFromTheIndex_AndRefusedOnFetch()
    {
        var clock = _factory.Services.GetRequiredService<TimeProvider>();
        var fx = StubUpstream(NewName(), "1.0.0", publishedAt: clock.GetUtcNow().AddHours(-1));
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE org_settings SET min_release_age_hours = 72 WHERE org_id = @orgId", new { orgId });
        }

        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        using var client = await PullClientAsync();

        var index = await client.GetAsync($"/hex/packages/{fx.Name}");
        var fetch = await client.GetAsync($"/hex/tarballs/{fx.Name}-1.0.0.tar");

        Assert.Equal(HttpStatusCode.NotFound, index.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, fetch.StatusCode);
    }

    [Fact]
    public async Task RepositoryAlias_AcceptsTheSignedName_AndRefusesOthers()
    {
        var fx = StubUpstream(NewName(), "1.0.0");
        using var client = await PullClientAsync();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/hex/repos/{HexIndexBuilder.RepositoryName}/packages/{fx.Name}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/repos/someone-else/packages/{fx.Name}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/repos/hexpm/names")).StatusCode);
    }

    [Fact]
    public async Task WithoutAnonymousPull_ReadsNeedAToken_AndTheTokenNeedsTheReadCapability()
    {
        var fx = StubUpstream(NewName(), "1.0.0");
        using var anonymous = _factory.CreateClient();
        using var pull = await PullClientAsync();

        var noToken = await anonymous.GetAsync($"/hex/packages/{fx.Name}");
        var withToken = await pull.GetAsync($"/hex/packages/{fx.Name}");
        var publicKey = await anonymous.GetAsync("/hex/public_key");

        Assert.Equal(HttpStatusCode.Unauthorized, noToken.StatusCode);
        Assert.Equal("Bearer realm=\"hex\"", noToken.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.OK, withToken.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, publicKey.StatusCode);
    }

    [Fact]
    public async Task BareTokenHeader_TheFormHexClientsSend_IsAccepted()
    {
        var fx = StubUpstream(NewName(), "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", token);

        var resp = await client.GetAsync($"/hex/packages/{fx.Name}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task UnknownPackage_Is404_AndMalformedNamesNeverReachTheUpstream()
    {
        using var client = await PullClientAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/packages/{NewName()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/packages/Bad-Name")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/tarballs/demo-notaversion.tar")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/packages/../etc")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/api/packages/x")).StatusCode);
    }
}
