using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The Hex API plane as Mix and Rebar3 drive it: publish a tarball, see the release in the
/// signed index and download it from the read plane, retire and unretire it, upload and remove
/// docs, revert it — with every reply decodable by hex_core (an Erlang term) when asked for one.
/// </summary>
[Trait("Category", "Integration")]
public sealed class HexApiControllerTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    public Task InitializeAsync() => _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── fixtures ──────────────────────────────────────────────────────────────

    private static string Metadata(string name, string version, string requirements = "[]") =>
        $"{{<<\"name\">>,<<\"{name}\">>}}.\n{{<<\"version\">>,<<\"{version}\">>}}.\n{{<<\"app\">>,<<\"{name}\">>}}.\n"
        + "{<<\"description\">>,<<\"A test package\">>}.\n{<<\"licenses\">>,[<<\"MIT\">>]}.\n"
        + $"{{<<\"requirements\">>,{requirements}}}.\n{{<<\"build_tools\">>,[<<\"mix\">>]}}.\n{{<<\"elixir\">>,<<\"~> 1.15\">>}}.\n";

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

    private static byte[] Tarball(string name, string version, string requirements = "[]") =>
        HexTarball.Build(Metadata(name, version, requirements), Contents());

    private static string NewName() => $"hexapi{Guid.NewGuid():N}"[..14];

    private async Task<HttpClient> ClientAsync(string kind, bool erlang = true)
    {
        string token = await _factory.CreateToken(kind);
        var client = _factory.CreateClient();
        // The exact header shape hex_core sends: a bare token and the Erlang media type.
        client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", token);
        if (erlang)
        {
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.hex+erlang"));
        }

        return client;
    }

    private static ByteArrayContent Octets(byte[] bytes)
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return content;
    }

    private static async Task<IReadOnlyDictionary<object, object?>> TermAsync(HttpResponseMessage resp)
    {
        Assert.Equal("application/vnd.hex+erlang", resp.Content.Headers.ContentType?.MediaType);
        return Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(ErlangTermFormat.Decode(await resp.Content.ReadAsByteArrayAsync()));
    }

    private static async Task<HexPackage> ReadIndexAsync(HttpClient client, string name)
    {
        var keyResp = await client.GetAsync("/hex/public_key");
        using var key = HexRegistrySigner.ParsePublicKeyPem(await keyResp.Content.ReadAsStringAsync());
        var resp = await client.GetAsync($"/hex/packages/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return HexRegistryCodec.DecodePackage(HexRegistrySigner.OpenResource(await resp.Content.ReadAsByteArrayAsync(), key));
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Publish_StoresTheRelease_IndexesIt_AndServesTheExactTarball()
    {
        string name = NewName();
        byte[] tar = Tarball(name, "1.0.0", "[{<<\"jason\">>,[{<<\"app\">>,<<\"jason\">>},{<<\"optional\">>,false},{<<\"requirement\">>,<<\"~> 1.4\">>}]}]");
        using var client = await ClientAsync("push");

        var resp = await client.PostAsync($"/hex/api/packages/{name}/releases?replace=false", Octets(tar));

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var body = await TermAsync(resp);
        Assert.Equal("1.0.0", body["version"]);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(tar)).ToLowerInvariant(), body["checksum"]);
        Assert.Contains($"/hex/api/packages/{name}/releases/1.0.0", (string)body["url"]!);
        Assert.NotNull(body["html_url"]);
        var requirements = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(body["requirements"]);
        var jason = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(requirements["jason"]);
        Assert.Equal("~> 1.4", jason["requirement"]);

        // The signed index now advertises the hosted release with the tarball's own checksums.
        var package = await ReadIndexAsync(client, name);
        var release = Assert.Single(package.Releases);
        Assert.Equal("1.0.0", release.Version);
        var parsed = HexTarball.Parse(tar, 64 * 1024 * 1024);
        Assert.Equal(parsed.InnerChecksum, release.InnerChecksum);
        Assert.Equal(parsed.OuterChecksum, release.OuterChecksum);
        Assert.Equal(new HexDependency("jason", "~> 1.4"), Assert.Single(release.Dependencies));
        Assert.NotNull(release.PublishedAt);

        // And the read plane serves the bytes as published.
        var download = await client.GetAsync($"/hex/tarballs/{name}-1.0.0.tar");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal(tar, await download.Content.ReadAsByteArrayAsync());

        // Licence captured from metadata.config.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? spdx = await conn.ExecuteScalarAsync<string>(
            """
            SELECT pvl.license_spdx FROM package_version_licenses pvl
            JOIN package_versions pv ON pv.id = pvl.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = 'hex' AND p.name = @name AND pv.version = '1.0.0'
            """, new { name });
        Assert.Equal("MIT", spdx);
    }

    [Fact]
    public async Task Publish_JsonClient_GetsJson()
    {
        string name = NewName();
        using var client = await ClientAsync("push", erlang: false);

        var resp = await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "0.1.0")));

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
        Assert.Contains("\"version\":\"0.1.0\"", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Publish_TarballNamingAnotherPackage_Is422_AndNothingIsStored()
    {
        string name = NewName();
        using var client = await ClientAsync("push");

        var resp = await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(NewName(), "1.0.0")));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var body = await TermAsync(resp);
        Assert.Equal("validation failed", body["message"]);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/packages/{name}")).StatusCode);
    }

    [Fact]
    public async Task Publish_NotATarball_Is422()
    {
        using var client = await ClientAsync("push");
        var resp = await client.PostAsync($"/hex/api/packages/{NewName()}/releases", Octets("nope"u8.ToArray()));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var body = await TermAsync(resp);
        var errors = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(body["errors"]);
        Assert.Contains("tarball", errors.Keys.Cast<string>());
    }

    [Fact]
    public async Task Publish_SameVersionTwice_Is422_UnlessReplaceAndOverwriteAllowed()
    {
        string name = NewName();
        using var client = await ClientAsync("push");
        byte[] tar = Tarball(name, "1.0.0");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(tar))).StatusCode);

        var again = await client.PostAsync($"/hex/api/packages/{name}/releases?replace=true", Octets(tar));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, again.StatusCode);

        string orgId = await OrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE org_settings SET allow_version_overwrite = 1, version_overwrite_policy = 'allow' WHERE org_id = @orgId", new { orgId });
        }

        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        var replaced = await client.PostAsync($"/hex/api/packages/{name}/releases?replace=true", Octets(tar));
        Assert.Equal(HttpStatusCode.Created, replaced.StatusCode);
    }

    [Fact]
    public async Task Publish_NeedsThePublishCapability_AndAToken()
    {
        string name = NewName();
        using var pull = await ClientAsync("pull");
        using var anonymous = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.Forbidden, (await pull.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "1.0.0")))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "1.0.0")))).StatusCode);
    }

    [Fact]
    public async Task Retire_MarksTheIndexEntry_AndUnretireClearsIt()
    {
        string name = NewName();
        using var client = await ClientAsync("push");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "1.0.0")))).StatusCode);

        var retireBody = new ByteArrayContent(ErlangTermFormat.Encode(ErlangTermModel.Map(("reason", "security"), ("message", "CVE-2026-1"))));
        retireBody.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.hex+erlang");
        var retire = await client.PostAsync($"/hex/api/packages/{name}/releases/1.0.0/retire", retireBody);
        Assert.Equal(HttpStatusCode.NoContent, retire.StatusCode);

        var retired = Assert.Single((await ReadIndexAsync(client, name)).Releases);
        Assert.Equal(new HexRetirementStatus(HexRetirementReason.Security, "CVE-2026-1"), retired.Retired);
        var view = await TermAsync(await client.GetAsync($"/hex/api/packages/{name}/releases/1.0.0"));
        var retirement = Assert.IsAssignableFrom<IReadOnlyDictionary<object, object?>>(view["retirement"]);
        Assert.Equal("security", retirement["reason"]);

        var unretire = await client.DeleteAsync($"/hex/api/packages/{name}/releases/1.0.0/retire");
        Assert.Equal(HttpStatusCode.NoContent, unretire.StatusCode);
        Assert.Null(Assert.Single((await ReadIndexAsync(client, name)).Releases).Retired);
    }

    [Fact]
    public async Task Retire_WithAnUnknownReason_Is422_AndNeedsYankCapability()
    {
        string name = NewName();
        using var client = await ClientAsync("push");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "1.0.0")))).StatusCode);

        var bad = new StringContent("{\"reason\":\"because\"}", Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await client.PostAsync($"/hex/api/packages/{name}/releases/1.0.0/retire", bad)).StatusCode);

        using var pull = await ClientAsync("pull");
        var ok = new StringContent("{\"reason\":\"other\"}", Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.Forbidden, (await pull.PostAsync($"/hex/api/packages/{name}/releases/1.0.0/retire", ok)).StatusCode);
    }

    [Fact]
    public async Task Docs_UploadServeAndDelete()
    {
        string name = NewName();
        using var client = await ClientAsync("push");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "1.0.0")))).StatusCode);
        byte[] docs = Contents();

        var upload = await client.PostAsync($"/hex/api/packages/{name}/releases/1.0.0/docs", Octets(docs));
        Assert.Equal(HttpStatusCode.Created, upload.StatusCode);
        Assert.Contains($"/hex/api/packages/{name}/releases/1.0.0/docs", upload.Headers.Location!.ToString());

        var served = await client.GetAsync($"/hex/docs/{name}-1.0.0.tar.gz");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal(docs, await served.Content.ReadAsByteArrayAsync());
        var view = await TermAsync(await client.GetAsync($"/hex/api/packages/{name}/releases/1.0.0"));
        Assert.True(view["has_docs"] is ErlangAtom { IsTrue: true });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await client.PostAsync($"/hex/api/packages/{name}/releases/1.0.0/docs", Octets("not gzip"u8.ToArray()))).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/hex/api/packages/{name}/releases/1.0.0/docs")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/docs/{name}-1.0.0.tar.gz")).StatusCode);
    }

    [Fact]
    public async Task Revert_RemovesTheReleaseAndItsBytes()
    {
        string name = NewName();
        using var client = await ClientAsync("push");
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsync($"/hex/api/packages/{name}/releases", Octets(Tarball(name, "1.0.0")))).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/hex/api/packages/{name}/releases/1.0.0")).StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/packages/{name}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/tarballs/{name}-1.0.0.tar")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/hex/api/packages/{name}")).StatusCode);
    }

    [Fact]
    public async Task UsersMe_AnswersTheCaller_WithNoOrganizations()
    {
        using var client = await ClientAsync("push");

        var resp = await client.GetAsync("/hex/api/users/me");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await TermAsync(resp);
        Assert.False(string.IsNullOrEmpty(body["username"] as string));
        Assert.Empty(Assert.IsAssignableFrom<IReadOnlyList<object?>>(body["organizations"]));
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/hex/api/users/me")).StatusCode);
    }

    [Fact]
    public async Task UnknownApiPaths_AnswerADecodableNotFound()
    {
        using var client = await ClientAsync("push");
        var resp = await client.GetAsync("/hex/api/repos/hexpm/packages/plug");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal("not found", (await TermAsync(resp))["message"]);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/api/keys")).StatusCode);
    }

    private async Task<string> OrgIdAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }
}
