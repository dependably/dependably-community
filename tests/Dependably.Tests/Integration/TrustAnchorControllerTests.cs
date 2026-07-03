using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dependably.Tests.Integration;

/// <summary>
/// Full-surface coverage of <see cref="Dependably.Api.TrustAnchorController"/>: list (with
/// material excluded), add (happy path + the validation-order branches + audit), delete
/// (+ audit), and the tenant:configure / read:tenant capability gates. The RPM PGP-key
/// generation helper mirrors <c>PgpKeyRingBuilderTests.GenerateArmoredPublicKey</c> — a real
/// ASCII-armored OpenPGP key is generated in-process rather than committing a fixture, since
/// no pre-baked PGP fixture file exists in the repository.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TrustAnchorControllerTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public TrustAnchorControllerTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"ta-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    /// <summary>
    /// A JWT session scoped to read:tenant only — enough to List, never enough to Add/Delete.
    /// TrustAnchorController's class-level [Authorize] validates only the "Bearer" (JWT) scheme
    /// (no method-level scheme union to "ApiToken"), so the capability-narrowing must ride a JWT
    /// with explicit cap claims rather than an API token (PAT).
    /// </summary>
    private async Task<HttpClient> ReadTenantOnlyClient()
    {
        string id = await _factory.CreateUser($"ta-readonly-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwtWithCaps(id, ["read:tenant"]);
        return _factory.CreateClientWithBearer(jwt);
    }

    // ── List ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_FreshOrg_ReturnsEmptyArray()
    {
        // Uses its own factory/host (not the shared _factory) because DEPLOYMENT_MODE=single
        // resolves every request to the one earliest-created org — the shared fixture's org
        // accumulates anchors across the other tests in this class, so "fresh org" needs an
        // isolated single-tenant instance to actually be empty.
        await using var freshFactory = new DependablyFactory();
        using var c = freshFactory.CreateClient();
        string jwt = await freshFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await c.GetAsync("/api/v1/trust-anchors");
        resp.EnsureSuccessStatusCode();

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        Assert.Empty(doc.RootElement.EnumerateArray());
    }

    [Fact]
    public async Task List_AfterAdd_ContainsEntry_WithoutMaterialField()
    {
        using var c = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();

        var add = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = armored,
            label = "CI signing key",
        });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        string id = (await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        var list = await c.GetAsync("/api/v1/trust-anchors");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        var entry = items.EnumerateArray().FirstOrDefault(e => e.GetProperty("id").GetString() == id);
        Assert.NotEqual(default, entry);

        Assert.Equal("rpm", entry.GetProperty("ecosystem").GetString());
        Assert.Equal("pgp", entry.GetProperty("anchorKind").GetString());
        Assert.Equal("CI signing key", entry.GetProperty("label").GetString());
        // The list payload never carries material, on any row.
        Assert.False(entry.TryGetProperty("material", out _),
            "List response must not include the material field.");

        // Cleanup
        await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    // ── Add — RPM happy path ─────────────────────────────────────────────────

    [Fact]
    public async Task Add_ValidRpmPgpKey_Returns201WithDerivedFingerprintKeyId()
    {
        using var c = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = armored,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;

        Assert.Equal("rpm", root.GetProperty("ecosystem").GetString());
        Assert.Equal("pgp", root.GetProperty("anchorKind").GetString());
        string? keyId = root.GetProperty("keyId").GetString();
        Assert.NotNull(keyId);
        Assert.NotEmpty(keyId);
        Assert.Matches("^[0-9a-f]+$", keyId!);

        // Cleanup
        string id = root.GetProperty("id").GetString()!;
        await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    // ── Add — validation errors (each a distinct 400/422 branch) ───────────────

    [Fact]
    public async Task Add_UnsupportedEcosystem_ReturnsValidationError()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "conan",
            anchorKind = "pgp",
            material = "irrelevant",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Contains("Must be one of", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Add_DisallowedAnchorKind_ReturnsValidationError()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "not-a-real-kind",
            material = "irrelevant",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Contains("Must be one of", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Add_EmptyMaterial_ReturnsMaterialEmptyError()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = "   ",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Contains("must not be empty", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Add_InvalidPgpMaterial_ReturnsParseError()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = "this is not an OpenPGP key at all",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Contains("could not be parsed as an OpenPGP public key",
            doc.RootElement.GetProperty("detail").GetString());
    }

    /// <summary>
    /// Mixed partial-failure: a good RPM key add succeeds; a garbage-material add for the same
    /// ecosystem in the same test fails — confirms per-request validation runs independently
    /// and a bad request never corrupts a prior successful insert.
    /// </summary>
    [Fact]
    public async Task Add_MixedOutcome_ValidKeySucceeds_GarbageMaterialFails()
    {
        using var c = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();

        var good = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = armored,
        });
        var bad = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = "garbage",
        });

        Assert.Equal(HttpStatusCode.Created, good.StatusCode);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, bad.StatusCode);

        string id = (await JsonDocument.ParseAsync(await good.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        var list = await c.GetAsync("/api/v1/trust-anchors");
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.Single(items.EnumerateArray(), e => e.GetProperty("id").GetString() == id);

        // Cleanup
        await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    // ── Add — audit ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Add_WritesTrustAnchorAddedAuditEvent()
    {
        using var c = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = armored,
        });
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        string id = (await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'trust_anchor_added' AND ecosystem = 'rpm'");
        Assert.True(count >= 1);

        // Cleanup
        await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Delete_RemovesAnchor_Returns204_AndAuditsRemoval()
    {
        using var c = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();

        var add = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = armored,
        });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);
        string id = (await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        var del = await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        var list = await c.GetAsync("/api/v1/trust-anchors");
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.DoesNotContain(items.EnumerateArray(), e => e.GetProperty("id").GetString() == id);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'trust_anchor_removed'");
        Assert.True(count >= 1);
    }

    // ── AuthZ ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task List_Unauthenticated_Returns401()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/trust-anchors");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task List_MemberRole_LacksReadTenant_Returns403()
    {
        // "member" maps to reader caps only (read:metadata/artifact/packages) — no
        // read:tenant — so even the list (read-only) endpoint rejects it.
        using var c = await MemberClient();
        var resp = await c.GetAsync("/api/v1/trust-anchors");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Add_ReadTenantOnlyCap_Returns403()
    {
        using var c = await ReadTenantOnlyClient();
        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = "irrelevant",
        });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Delete_ReadTenantOnlyCap_Returns403()
    {
        // Seed an anchor with the admin client so there is something a lesser-privileged
        // caller could (but must not be able to) delete.
        using var admin = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();
        var add = await admin.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "rpm",
            anchorKind = "pgp",
            material = armored,
        });
        string id = (await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        using var readOnly = await ReadTenantOnlyClient();
        var del = await readOnly.DeleteAsync($"/api/v1/trust-anchors/{id}");
        Assert.Equal(HttpStatusCode.Forbidden, del.StatusCode);

        // Still present — the forbidden caller did not delete it.
        var list = await admin.GetAsync("/api/v1/trust-anchors");
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        Assert.Contains(items.EnumerateArray(), e => e.GetProperty("id").GetString() == id);

        // Cleanup
        await admin.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    [Fact]
    public async Task ReadTenantOnlyCap_CanStillList()
    {
        // read:tenant is exactly what List requires — confirms the 403s above are a
        // capability-gate distinction (read:tenant vs tenant:configure), not a broken token.
        using var c = await ReadTenantOnlyClient();
        var resp = await c.GetAsync("/api/v1/trust-anchors");
        resp.EnsureSuccessStatusCode();
    }

    // ── PGP key generation ───────────────────────────────────────────────────
    // Mirrors PgpKeyRingBuilderTests.GenerateArmoredPublicKey: builds a real ASCII-armored
    // OpenPGP public key in-process (no PGP fixture file exists in the repository to reuse).

    private static string GenerateArmoredPublicKeyString()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new SecureRandom(), 1024, 12));
        var kp = gen.GenerateKeyPair();

        var pgpPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp,
            new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification, pgpPair,
            "trust-anchor-test@example.com", SymmetricKeyAlgorithmTag.Null,
            passPhrase: null, useSha1: true, null, null, new SecureRandom());

        using var ms = new MemoryStream();
        using (var ao = new ArmoredOutputStream(ms))
        {
            secretKey.PublicKey.Encode(ao);
        }
        return Encoding.ASCII.GetString(ms.ToArray());
    }
}
