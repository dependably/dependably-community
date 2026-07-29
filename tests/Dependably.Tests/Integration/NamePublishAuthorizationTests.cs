using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end proof that name-level publish authorization is wired into every hosted-push path.
/// With <c>PUBLISH_NAME_BINDING=on</c>, the first principal to publish a name owns it, and a
/// second principal (a different token) publishing the same name is refused — the exact seizure
/// the supply-chain review found unguarded. Without the enforcement code, the second publish
/// would succeed (the assertions here would read 2xx), so each test fails without the fix.
///
/// Authorization keys on the authenticated token principal, never a request field: the two
/// publishers here differ only in their token (each <see cref="DependablyFactory.CreateToken"/>
/// mints a distinct service principal), and the body/coordinate they send is identical.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NamePublishAuthorizationTests
{
    private static DependablyFactory Factory() => new()
    {
        PublishNameBinding = "on",
        // RPM refuses hosted publish in passthrough mode; merged mode allows it.
        RpmUpstreamMode = "merged",
    };

    private static HttpClient Bearer(DependablyFactory f, string token)
    {
        var c = f.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    private static HttpClient Basic(DependablyFactory f, string token)
    {
        var c = f.CreateClient();
        string creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", creds);
        return c;
    }

    // ── npm (shared PackagePublishService path) — full flow incl. grant ──────

    [Fact]
    public async Task Npm_FirstOwns_SecondDenied_OwnerRepublishes_GrantAllows()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string name = $"internal-lib-{Guid.NewGuid():N}";
        string tokenA = await f.CreateToken("push");
        string tokenB = await f.CreateToken("push");

        // A publishes first → binds the name to A.
        using (var a = Bearer(f, tokenA))
        using (var body = new StringContent(NpmFixtures.BuildPublishBody(name, "1.0.0"), Encoding.UTF8, "application/json"))
        {
            var r = await a.PutAsync($"/npm/{name}", body);
            Assert.True(r.IsSuccessStatusCode, $"first publish should bind, got {(int)r.StatusCode}");
        }

        // B publishes the SAME name with an identical body → refused (403). Without the fix this is 2xx.
        using (var b = Bearer(f, tokenB))
        using (var body = new StringContent(NpmFixtures.BuildPublishBody(name, "2.0.0"), Encoding.UTF8, "application/json"))
        {
            var r = await b.PutAsync($"/npm/{name}", body);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }

        // A (the owner) still publishes new versions freely.
        using (var a = Bearer(f, tokenA))
        using (var body = new StringContent(NpmFixtures.BuildPublishBody(name, "1.1.0"), Encoding.UTF8, "application/json"))
        {
            var r = await a.PutAsync($"/npm/{name}", body);
            Assert.True(r.IsSuccessStatusCode, $"owner republish should succeed, got {(int)r.StatusCode}");
        }

        // Grant B co-publish on this name → B is now authorized.
        await GrantAsync(f, "npm", name, tokenB);
        using (var b = Bearer(f, tokenB))
        using (var body = new StringContent(NpmFixtures.BuildPublishBody(name, "2.0.0"), Encoding.UTF8, "application/json"))
        {
            var r = await b.PutAsync($"/npm/{name}", body);
            Assert.True(r.IsSuccessStatusCode, $"granted publish should succeed, got {(int)r.StatusCode}");
        }
    }

    [Fact]
    public async Task Npm_SameName_DifferentEcosystem_IsIndependent()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string name = $"shared-{Guid.NewGuid():N}";
        string tokenA = await f.CreateToken("push");
        string tokenB = await f.CreateToken("push");

        using (var a = Bearer(f, tokenA))
        using (var body = new StringContent(NpmFixtures.BuildPublishBody(name, "1.0.0"), Encoding.UTF8, "application/json"))
        {
            (await a.PutAsync($"/npm/{name}", body)).EnsureSuccessStatusCode();
        }

        // B cannot take the npm name, but the pypi name of the same string is a distinct binding.
        using (var b = Bearer(f, tokenB))
        using (var body = new StringContent(NpmFixtures.BuildPublishBody(name, "2.0.0"), Encoding.UTF8, "application/json"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await b.PutAsync($"/npm/{name}", body)).StatusCode);
        }

        using (var b = Basic(f, tokenB))
        {
            var r = await PublishPyPiAsync(b, name.Replace('-', '_'), "1.0.0");
            Assert.True(r.IsSuccessStatusCode, $"pypi of same string should be independent, got {(int)r.StatusCode}");
        }
    }

    // ── pypi / nuget (shared PackagePublishService path) ─────────────────────

    [Fact]
    public async Task PyPi_FirstOwns_SecondDenied()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string name = $"pkg{Guid.NewGuid():N}"[..16];
        string tokenA = await f.CreateToken("push");
        string tokenB = await f.CreateToken("push");

        using (var a = Basic(f, tokenA))
        {
            (await PublishPyPiAsync(a, name, "1.0.0")).EnsureSuccessStatusCode();
        }
        using var b = Basic(f, tokenB);
        Assert.Equal(HttpStatusCode.Forbidden, (await PublishPyPiAsync(b, name, "2.0.0")).StatusCode);
    }

    [Fact]
    public async Task NuGet_FirstOwns_SecondDenied()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string id = $"Pkg.{Guid.NewGuid():N}";
        string tokenA = await f.CreateToken("push");
        string tokenB = await f.CreateToken("push");

        using (var a = f.CreateClient())
        {
            (await PublishNuGetAsync(a, tokenA, id, "1.0.0")).EnsureSuccessStatusCode();
        }
        using var b = f.CreateClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await PublishNuGetAsync(b, tokenB, id, "2.0.0")).StatusCode);
    }

    // ── maven (bespoke controller path) ──────────────────────────────────────

    [Fact]
    public async Task Maven_FirstOwns_SecondDenied()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string artifact = $"lib{Guid.NewGuid():N}"[..12];
        string path = $"/maven/com/acme/{artifact}/1.0.0/{artifact}-1.0.0.jar";
        string tokenA = await f.CreateToken("push");
        string tokenB = await f.CreateToken("push");
        byte[] jar = [0x50, 0x4B];

        using (var a = Basic(f, tokenA))
        using (var body = new ByteArrayContent(jar))
        {
            var r = await a.PutAsync(path, body);
            Assert.True(r.IsSuccessStatusCode, $"first maven publish should bind, got {(int)r.StatusCode}");
        }
        using (var b = Basic(f, tokenB))
        using (var body = new ByteArrayContent(jar))
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await b.PutAsync(path, body)).StatusCode);
        }
    }

    // ── rpm (bespoke controller path) ────────────────────────────────────────

    [Fact]
    public async Task Rpm_FirstOwns_SecondDenied()
    {
        await using var f = Factory();
        await f.InitializeAsync();

        // Each UploadRpm mints a fresh service principal and targets the same NEVRA (testpkg),
        // so the first upload binds the name and the second — a different principal — is refused.
        using var first = await f.UploadRpm();
        Assert.True(first.IsSuccessStatusCode, $"first rpm publish should bind, got {(int)first.StatusCode}");
        using var second = await f.UploadRpm();
        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
    }

    // ── oci (bespoke controller path; enforced at manifest PUT) ──────────────

    [Fact]
    public async Task Oci_BoundRepository_SecondPrincipalDenied()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string repo = $"team/app{Guid.NewGuid():N}"[..20];
        string token = await f.CreateToken("push");

        // Seed the repository as owned by a different principal, then a fresh token's manifest PUT
        // is refused before the manifest body is even read.
        var orgs = f.Services.GetRequiredService<OrgRepository>();
        string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
        await f.Services.GetRequiredService<NameBindingRepository>()
            .BindIfAbsentAsync(orgId, "oci", repo, new NamePrincipal(ActorKinds.User, "someone-else"));

        using var c = Basic(f, token);
        using var body = new ByteArrayContent([]);
        body.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");
        var r = await c.PutAsync($"/v2/{repo}/manifests/1.0.0", body);
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    // ── cargo (shared PackagePublishService path) ────────────────────────────

    [Fact]
    public async Task Cargo_FirstOwns_SecondDenied()
    {
        await using var f = Factory();
        await f.InitializeAsync();
        string name = $"crate{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string tokenA = await f.CreateToken("push");
        string tokenB = await f.CreateToken("push");

        using (var a = Bearer(f, tokenA))
        {
            var r = await a.PutAsync("/cargo/api/v1/crates/new", CargoFrame(name, "1.0.0"));
            Assert.True(r.IsSuccessStatusCode, $"first cargo publish should bind, got {(int)r.StatusCode}");
        }
        using (var b = Bearer(f, tokenB))
        {
            var r = await b.PutAsync("/cargo/api/v1/crates/new", CargoFrame(name, "2.0.0"));
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static async Task<HttpResponseMessage> PublishPyPiAsync(HttpClient client, string name, string version)
    {
        var (bytes, sha256) = PyPiFixtures.BuildWheel(name, version);
        using var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent(version), "version" },
            { new StringContent(sha256), "sha256_digest" },
        };
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(file, "content", $"{name.Replace('-', '_')}-{version}-py3-none-any.whl");
        return await client.PostAsync("/pypi/legacy/", content);
    }

    private static async Task<HttpResponseMessage> PublishNuGetAsync(
        HttpClient client, string token, string id, string version)
    {
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);
        using var content = new MultipartFormDataContent();
        var file = new ByteArrayContent(bytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(file, "package", $"{id}.{version}.nupkg");
        return await client.PutAsync("/nuget/publish", content);
    }

    private static ByteArrayContent CargoFrame(string name, string version)
    {
        string metadata = $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"features":{},"description":"test"}""";
        byte[] meta = Encoding.UTF8.GetBytes(metadata);
        byte[] crate = Encoding.UTF8.GetBytes($"crate-bytes-{name}-{version}");
        byte[] buf = new byte[4 + meta.Length + 4 + crate.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)meta.Length);
        meta.CopyTo(buf, 4);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4 + meta.Length), (uint)crate.Length);
        crate.CopyTo(buf, 4 + meta.Length + 4);
        var content = new ByteArrayContent(buf);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return content;
    }

    // Grants a co-publish permission to the service principal behind <paramref name="token"/>.
    private static async Task GrantAsync(DependablyFactory f, string ecosystem, string purlName, string token)
    {
        var orgs = f.Services.GetRequiredService<OrgRepository>();
        string orgId = (await orgs.GetBySlugAsync("default"))!.Id;
        var tokens = f.Services.GetRequiredService<TokenRepository>();
        var resolved = await tokens.ResolveAsync(token)
            ?? throw new InvalidOperationException("token did not resolve");
        var grantee = NamePrincipal.FromToken(resolved)
            ?? throw new InvalidOperationException("token yielded no principal");
        await f.Services.GetRequiredService<NameBindingRepository>()
            .AddGrantAsync(orgId, ecosystem, purlName, grantee, createdBy: null);
    }
}
