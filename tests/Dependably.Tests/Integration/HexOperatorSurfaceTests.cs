using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The operator surfaces around the Hex ecosystem: the signing-key management endpoint and its
/// rotation, the upstream repository public key on the upstream-registry API, and the signed
/// policy resource that projects the org's block-gate posture for opted-in clients.
/// </summary>
[Trait("Category", "Integration")]
public sealed class HexOperatorSurfaceTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    public Task InitializeAsync() => _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private sealed record KeyView(bool CanSign, bool Exists, string? PublicKeyPem, string? Fingerprint, string? CreatedAt);

    [Fact]
    public async Task SigningKey_IsCreatedOnFirstRead_MatchesTheReadPlane_AndRotates()
    {
        using var admin = await AdminClientAsync();

        var first = await admin.GetFromJsonAsync<KeyView>("/api/v1/hex/signing-key", Web);
        Assert.NotNull(first);
        Assert.True(first!.CanSign);
        Assert.True(first.Exists);
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", first.PublicKeyPem);
        Assert.Equal(64, first.Fingerprint!.Length);

        // The read plane serves the same public key.
        using var pull = _factory.CreateClientWithBearer(await _factory.CreateToken("pull"));
        string served = await (await pull.GetAsync("/hex/public_key")).Content.ReadAsStringAsync();
        Assert.Equal(first.PublicKeyPem, served);

        var rotated = await (await admin.PostAsync("/api/v1/hex/signing-key/rotate", null)).Content.ReadFromJsonAsync<KeyView>(Web);
        Assert.NotEqual(first.PublicKeyPem, rotated!.PublicKeyPem);
        Assert.Equal(rotated.PublicKeyPem, await (await pull.GetAsync("/hex/public_key")).Content.ReadAsStringAsync());

        // Rotation is audited.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE action = 'hex_signing_key_rotated'"));
    }

    [Fact]
    public async Task SigningKey_NeedsTenantConfigureToRotate()
    {
        // A signed-in member without tenant:configure cannot rotate the key (nor read it: the
        // key is tenant configuration, read:tenant like the trust anchors).
        string userId = await _factory.CreateUser($"hex-member-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(userId, "member");
        using var member = _factory.CreateClient();
        member.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/api/v1/hex/signing-key")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.PostAsync("/api/v1/hex/signing-key/rotate", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsync("/api/v1/hex/signing-key/rotate", null)).StatusCode);
    }

    [Fact]
    public async Task UpstreamRegistry_AcceptsAValidHexPublicKey_AndRefusesItElsewhere()
    {
        using var admin = await AdminClientAsync();
        using var key = RSA.Create(2048);
        string pem = HexRegistrySigner.ExportPublicKeyPem(key);

        var ok = await admin.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "hex",
            url = "https://hex.internal.example",
            name = "internal",
            publicKeyPem = pem,
        });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        using var created = JsonDocument.Parse(await ok.Content.ReadAsStringAsync());
        Assert.Equal(pem, created.RootElement.GetProperty("publicKeyPem").GetString());

        var garbage = await admin.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "hex",
            url = "https://hex2.internal.example",
            publicKeyPem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, garbage.StatusCode);

        var wrongEcosystem = await admin.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "npm",
            url = "https://npm.internal.example",
            publicKeyPem = pem,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, wrongEcosystem.StatusCode);
    }

    [Fact]
    public async Task PolicyResource_ProjectsTheOrgPosture_AndIsSigned()
    {
        string orgId = await OrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET min_release_age_hours = 30, block_deprecated = 'block_all', max_osv_score_tolerance = 7.0, anonymous_pull = 1 WHERE org_id = @orgId",
                new { orgId });
            await conn.ExecuteAsync(
                "INSERT INTO blocklist (id, org_id, pattern) VALUES (@id, @orgId, @pattern)",
                new { id = Guid.NewGuid().ToString("N"), orgId, pattern = "^pkg:hex/evilpkg@" });
        }

        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
        using var client = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        // A held package the blocklist names, so the policy carries a DENY override for it.
        var octets = new ByteArrayContent(HexTarball.Build(
            "{<<\"name\">>,<<\"evilpkg\">>}.\n{<<\"version\">>,<<\"1.0.0\">>}.\n{<<\"requirements\">>,[]}.\n", new byte[] { 0x1F, 0x8B, 0x08, 0x00 }));
        octets.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        string keyPem = await (await client.GetAsync("/hex/public_key")).Content.ReadAsStringAsync();
        using var orgKey = HexRegistrySigner.ParsePublicKeyPem(keyPem);
        var resp = await client.GetAsync($"/hex/repos/{HexIndexBuilder.RepositoryName}/policies/{HexController.PolicyName}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var policy = HexRegistryCodec.DecodePolicy(HexRegistrySigner.OpenResource(await resp.Content.ReadAsByteArrayAsync(), orgKey));
        Assert.Equal(HexIndexBuilder.RepositoryName, policy.Repository);
        Assert.Equal(HexVisibility.Public, policy.Visibility);
        var own = policy.Repositories.Single(r => r.Repository == HexIndexBuilder.RepositoryName);
        Assert.Equal(HexAdvisorySeverity.High, own.Restriction!.AdvisoryMinSeverity);
        Assert.Equal("2d", own.Restriction.Cooldown);
        Assert.Equal(5, own.Restriction.RetirementReasons.Count);
        Assert.Contains(policy.Repositories, r => r.Repository == "hexpm");
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/hex/policies/other")).StatusCode);
    }

    [Theory]
    [InlineData(10.0, null)]
    [InlineData(9.5, HexAdvisorySeverity.Critical)]
    [InlineData(7.0, HexAdvisorySeverity.High)]
    [InlineData(5.0, HexAdvisorySeverity.Medium)]
    [InlineData(0.5, HexAdvisorySeverity.Low)]
    [InlineData(0.0, HexAdvisorySeverity.None)]
    public void AdvisoryMinSeverity_MapsTheScoreCeilingOntoABand(double tolerance, HexAdvisorySeverity? expected) =>
        Assert.Equal(expected, HexController.AdvisoryMinSeverityFor(tolerance));

    private async Task<HttpClient> AdminClientAsync()
    {
        var client = _factory.CreateClient();
        string jwt = await _factory.CreateAdminJwt();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private async Task<string> OrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }
}
