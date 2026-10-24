using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The SBOM author-signature and Hex registry signing-key management endpoints on an instance
/// with no master key (nothing can be stored, so signing is unavailable and rotation is refused)
/// and on one with a master key (keys are minted on first read and rotation retires the old one),
/// plus the capability denials and the apex refusal of the public key listing.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SigningKeyEndpointsTests
{
    private static string NewMasterKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static async Task<HttpClient> AdminAsync(DependablyFactory factory)
    {
        await factory.InitializeAsync();
        return factory.CreateClientWithBearer(await factory.CreateAdminJwt());
    }

    private static async Task<HttpClient> ClientWithCapsAsync(DependablyFactory factory, params string[] caps)
    {
        string id = await factory.CreateUser($"keys-{Guid.NewGuid():N}@example.com", "Password12345");
        return factory.CreateClientWithBearer(await factory.CreateUserJwtWithCaps(id, caps));
    }

    // ── SBOM signing key ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Sbom_WithoutMasterKey_ReportsUnsignedAndRefusesRotation()
    {
        await using var factory = new DependablyFactory();
        using var admin = await AdminAsync(factory);

        var view = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/sbom-signing-key"));
        Assert.False(view.GetProperty("canSign").GetBoolean());
        Assert.False(view.GetProperty("exists").GetBoolean());
        Assert.Equal(SbomAuthorSigner.UnsignedNoMasterKeyState, view.GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, view.GetProperty("keyId").ValueKind);

        var rotate = await admin.PostAsync("/api/v1/sbom-signing-key/rotate", null);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, rotate.StatusCode);

        // Nothing was minted by the refused rotation, and the public listing is empty.
        using var anon = factory.CreateClient();
        var keys = await anon.GetFromJsonAsync<JsonElement>("/api/v1/sbom-signing-keys");
        Assert.Equal(0, keys.GetArrayLength());
    }

    [Fact]
    public async Task Sbom_WithMasterKey_MintsOnFirstReadAndRotationRetiresThePreviousKey()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var admin = await AdminAsync(factory);

        var first = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/sbom-signing-key"));
        Assert.True(first.GetProperty("canSign").GetBoolean());
        Assert.Equal(SbomAuthorSigner.SignedState, first.GetProperty("state").GetString());
        string firstId = first.GetProperty("keyId").GetString()!;
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", first.GetProperty("publicKeyPem").GetString());
        Assert.NotNull(first.GetProperty("createdAt").GetString());

        var rotateResp = await admin.PostAsync("/api/v1/sbom-signing-key/rotate", null);
        Assert.Equal(HttpStatusCode.OK, rotateResp.StatusCode);
        var rotated = await ProblemBody.ReadAsync(rotateResp);
        string rotatedId = rotated.GetProperty("keyId").GetString()!;
        Assert.NotEqual(firstId, rotatedId);
        Assert.Equal(SbomAuthorSigner.SignedState, rotated.GetProperty("state").GetString());

        // The public listing is anonymous, carries both keys, and the first is marked retired.
        using var anon = factory.CreateClient();
        var listResp = await anon.GetAsync("/api/v1/sbom-signing-keys");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        var list = await ProblemBody.ReadAsync(listResp);
        var byId = list.EnumerateArray().ToDictionary(e => e.GetProperty("keyId").GetString()!);
        Assert.Equal(JsonValueKind.String, byId[firstId].GetProperty("retiredAt").ValueKind);
        Assert.Equal(JsonValueKind.Null, byId[rotatedId].GetProperty("retiredAt").ValueKind);
        Assert.All(byId.Values, e => Assert.False(e.TryGetProperty("privateKey", out _)));

        // The settings view now reports the rotated key as the active one.
        var current = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/sbom-signing-key"));
        Assert.Equal(rotatedId, current.GetProperty("keyId").GetString());
    }

    [Fact]
    public async Task Sbom_CapabilityDenials_AreForbiddenAndTheKeyIsUnchanged()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var admin = await AdminAsync(factory);
        string activeId = (await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/sbom-signing-key")))
            .GetProperty("keyId").GetString()!;

        using var noRead = await ClientWithCapsAsync(factory, "read:packages");
        using var readOnly = await ClientWithCapsAsync(factory, "read:tenant");

        await ProblemBody.AssertForbiddenAsync(await noRead.GetAsync("/api/v1/sbom-signing-key"));
        await ProblemBody.AssertForbiddenAsync(await readOnly.PostAsync("/api/v1/sbom-signing-key/rotate", null));
        Assert.Equal(HttpStatusCode.OK, (await readOnly.GetAsync("/api/v1/sbom-signing-key")).StatusCode);

        var after = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/sbom-signing-key"));
        Assert.Equal(activeId, after.GetProperty("keyId").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await factory.CreateClient().PostAsync("/api/v1/sbom-signing-key/rotate", null)).StatusCode);
    }

    [Fact]
    public async Task Sbom_PublicKeyListing_OnTheApexHost_Returns404()
    {
        await using var factory = new DependablyMultiFactory();
        await factory.InitializeAsync();
        using var apex = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);

        var resp = await apex.GetAsync("/api/v1/sbom-signing-keys");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Hex signing key ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Hex_WithoutMasterKey_ReportsNoKeyAndRefusesRotation()
    {
        await using var factory = new DependablyFactory();
        using var admin = await AdminAsync(factory);

        var view = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key"));
        Assert.False(view.GetProperty("canSign").GetBoolean());
        Assert.False(view.GetProperty("exists").GetBoolean());
        Assert.Equal(JsonValueKind.Null, view.GetProperty("publicKeyPem").ValueKind);
        Assert.Equal(JsonValueKind.Null, view.GetProperty("fingerprint").ValueKind);

        var rotate = await admin.PostAsync("/api/v1/hex/signing-key/rotate", null);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, rotate.StatusCode);

        var still = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key"));
        Assert.False(still.GetProperty("exists").GetBoolean());
    }

    [Fact]
    public async Task Hex_WithoutMasterKey_StillPublishesAKeyMintedWhileOneWasConfigured()
    {
        await using var factory = new DependablyFactory();
        using var admin = await AdminAsync(factory);
        await using (var conn = await factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>().OpenAsync())
        {
            string orgId = await Dapper.SqlMapper.ExecuteScalarAsync<string>(
                conn, "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1") ?? throw new InvalidOperationException("no default org");
            await Dapper.SqlMapper.ExecuteAsync(
                conn,
                """
                INSERT INTO hex_signing_key (org_id, private_key, public_key_pem, fingerprint, created_at)
                VALUES (@orgId, 'enc:v1:unreadable', '-----BEGIN PUBLIC KEY-----legacy-----END PUBLIC KEY-----', @fingerprint, '2026-01-02T03:04:05Z')
                """,
                new { orgId, fingerprint = new string('a', 64) });
        }

        var view = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key"));

        Assert.False(view.GetProperty("canSign").GetBoolean());
        Assert.True(view.GetProperty("exists").GetBoolean());
        Assert.Equal(new string('a', 64), view.GetProperty("fingerprint").GetString());
        Assert.Equal("2026-01-02T03:04:05Z", view.GetProperty("createdAt").GetString());
        Assert.Equal(HttpStatusCode.ServiceUnavailable,
            (await admin.PostAsync("/api/v1/hex/signing-key/rotate", null)).StatusCode);
    }

    [Fact]
    public async Task Hex_WithMasterKey_ReadIsStableAndRotationChangesTheFingerprint()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var admin = await AdminAsync(factory);

        var first = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key"));
        var again = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key"));
        Assert.Equal(first.GetProperty("fingerprint").GetString(), again.GetProperty("fingerprint").GetString());

        var rotated = await ProblemBody.ReadAsync(await admin.PostAsync("/api/v1/hex/signing-key/rotate", null));
        Assert.NotEqual(first.GetProperty("fingerprint").GetString(), rotated.GetProperty("fingerprint").GetString());
        Assert.True(rotated.GetProperty("canSign").GetBoolean());
        Assert.NotNull(rotated.GetProperty("createdAt").GetString());
    }

    [Fact]
    public async Task Hex_CapabilityDenials_AreForbiddenAndTheKeyIsUnchanged()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var admin = await AdminAsync(factory);
        string fingerprint = (await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key")))
            .GetProperty("fingerprint").GetString()!;
        using var readOnly = await ClientWithCapsAsync(factory, "read:tenant");

        await ProblemBody.AssertForbiddenAsync(await readOnly.PostAsync("/api/v1/hex/signing-key/rotate", null));
        Assert.Equal(HttpStatusCode.OK, (await readOnly.GetAsync("/api/v1/hex/signing-key")).StatusCode);

        var after = await ProblemBody.ReadAsync(await admin.GetAsync("/api/v1/hex/signing-key"));
        Assert.Equal(fingerprint, after.GetProperty("fingerprint").GetString());
    }
}
