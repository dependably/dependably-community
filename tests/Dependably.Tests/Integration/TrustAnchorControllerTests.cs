using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        // A pair with a registered validator is flagged as such.
        Assert.True(entry.GetProperty("isRegisteredPair").GetBoolean());

        // Cleanup
        await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    /// <summary>
    /// The per-row flag on <c>GET /api/v1/trust-anchors</c> for both shapes at once: a normal
    /// anchor added through the API and a suspect one seeded straight into the table (the only
    /// way to produce a row the add path now refuses). The material-absence regression guard
    /// rides along, checked against the raw response body so a serializer change that started
    /// emitting the column would fail here rather than in production.
    /// </summary>
    [Fact]
    public async Task List_FlagsSuspectRowsAndNeverEmitsMaterial()
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
        string goodId = (await JsonDocument.ParseAsync(await add.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        // The suspect row: the pair gate refuses it over HTTP, so seed it at the repository
        // level, exactly as a pre-validation insert left it in the table.
        const string Sentinel = "SENTINEL-MATERIAL-MUST-NOT-LEAK";
        var repo = _factory.Services.GetRequiredService<TrustAnchorRepository>();
        string orgId = await ResolveDefaultOrgIdAsync();
        var suspect = await repo.AddAsync(orgId, new NewTrustAnchor(
            "npm", "pgp", Sentinel, "kid-suspect", "pre-validation paste", null));

        try
        {
            var list = await c.GetAsync("/api/v1/trust-anchors");
            list.EnsureSuccessStatusCode();
            string body = await list.Content.ReadAsStringAsync();

            Assert.DoesNotContain(Sentinel, body, StringComparison.Ordinal);
            Assert.DoesNotContain("\"material\"", body, StringComparison.Ordinal);

            var items = JsonDocument.Parse(body).RootElement.EnumerateArray().ToList();
            var good = items.First(e => e.GetProperty("id").GetString() == goodId);
            var bad = items.First(e => e.GetProperty("id").GetString() == suspect.Id);

            Assert.True(good.GetProperty("isRegisteredPair").GetBoolean());
            Assert.False(bad.GetProperty("isRegisteredPair").GetBoolean());
        }
        finally
        {
            await c.DeleteAsync($"/api/v1/trust-anchors/{goodId}");
            await repo.DeleteAsync(orgId, suspect.Id);
        }
    }

    // The default single-tenant org the admin JWT is scoped to.
    private async Task<string> ResolveDefaultOrgIdAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default'"))!;
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

    // ── Add — apk happy path ─────────────────────────────────────────────────

    [Fact]
    public async Task Add_ValidApkRsaKey_Returns201WithDerivedSha256KeyId()
    {
        using var c = await AdminClient();
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        string pem = rsa.ExportSubjectPublicKeyInfoPem();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "apk",
            anchorKind = "rsa",
            material = pem,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;

        Assert.Equal("apk", root.GetProperty("ecosystem").GetString());
        Assert.Equal("rsa", root.GetProperty("anchorKind").GetString());
        string? keyId = root.GetProperty("keyId").GetString();
        Assert.NotNull(keyId);
        Assert.StartsWith("SHA256:", keyId);

        // Cleanup
        string id = root.GetProperty("id").GetString()!;
        await c.DeleteAsync($"/api/v1/trust-anchors/{id}");
    }

    /// <summary>
    /// The minimum-strength floor, end to end: a well-formed 1024-bit RSA anchor parses cleanly
    /// and is still refused at import, so the operator learns immediately rather than discovering
    /// it as a signature mismatch later. Paired with the 2048-bit test above and the 4096-bit
    /// twin below, which prove the floor is a floor and not a blanket rejection.
    /// </summary>
    [Fact]
    public async Task Add_ApkRsaKeyBelowTheKeySizeFloor_IsRefusedAtImport()
    {
        using var c = await AdminClient();
        using var rsa = System.Security.Cryptography.RSA.Create(1024);

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "apk",
            anchorKind = "rsa",
            material = rsa.ExportSubjectPublicKeyInfoPem(),
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Contains("1024-bit RSA", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Add_ApkRsa4096Key_IsStillAccepted()
    {
        using var c = await AdminClient();
        using var rsa = System.Security.Cryptography.RSA.Create(4096);

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "apk",
            anchorKind = "rsa",
            material = rsa.ExportSubjectPublicKeyInfoPem(),
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        await c.DeleteAsync($"/api/v1/trust-anchors/{doc.RootElement.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Add_MalformedApkRsaMaterial_ReturnsParseError()
    {
        using var c = await AdminClient();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "apk",
            anchorKind = "rsa",
            material = "this is not a PEM public key at all",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Contains("could not be parsed as an RSA public key",
            doc.RootElement.GetProperty("detail").GetString());
    }

    // ── Add — maven/npm/nuget/pypi happy paths (registered pairs) ──────────────
    // rpm/pgp and apk/rsa are covered above; these four cover the remaining registered
    // (ecosystem, anchorKind) pairs so the pair-validation gate cannot regress the happy path
    // for any of the 8 pairs EcosystemValidators registers.

    [Fact]
    public async Task Add_ValidMavenPgpKey_Returns201WithDerivedFingerprintKeyId()
    {
        using var c = await AdminClient();
        string armored = GenerateArmoredPublicKeyString();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "maven",
            anchorKind = "pgp",
            material = armored,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("maven", root.GetProperty("ecosystem").GetString());
        Assert.Equal("pgp", root.GetProperty("anchorKind").GetString());
        Assert.Matches("^[0-9a-f]+$", root.GetProperty("keyId").GetString()!);

        await c.DeleteAsync($"/api/v1/trust-anchors/{root.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Add_ValidNpmSpkiKey_Returns201WithCallerSuppliedKeyId()
    {
        using var c = await AdminClient();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "npm",
            anchorKind = "spki",
            material = spki,
            keyId = "SHA256:test-npm-key-id",
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("npm", root.GetProperty("ecosystem").GetString());
        Assert.Equal("spki", root.GetProperty("anchorKind").GetString());
        Assert.Equal("SHA256:test-npm-key-id", root.GetProperty("keyId").GetString());

        await c.DeleteAsync($"/api/v1/trust-anchors/{root.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Add_ValidNuGetX509Cert_Returns201WithDerivedThumbprintKeyId()
    {
        using var c = await AdminClient();
        string pem = SelfSignedRsaCertificatePem(2048);

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "nuget",
            anchorKind = "x509",
            material = pem,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("nuget", root.GetProperty("ecosystem").GetString());
        Assert.Equal("x509", root.GetProperty("anchorKind").GetString());
        Assert.Matches("^[0-9a-f]+$", root.GetProperty("keyId").GetString()!);

        await c.DeleteAsync($"/api/v1/trust-anchors/{root.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Add_ValidPyPiSigstoreRootCert_Returns201WithDerivedThumbprintKeyId()
    {
        using var c = await AdminClient();
        string pem = SelfSignedRsaCertificatePem(2048);

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "pypi",
            anchorKind = "sigstore_root",
            material = pem,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("pypi", root.GetProperty("ecosystem").GetString());
        Assert.Equal("sigstore_root", root.GetProperty("anchorKind").GetString());
        Assert.Matches("^[0-9a-f]+$", root.GetProperty("keyId").GetString()!);

        await c.DeleteAsync($"/api/v1/trust-anchors/{root.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Add_ValidPyPiRekorKey_Returns201WithDerivedLogIdKeyId()
    {
        using var c = await AdminClient();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "pypi",
            anchorKind = "rekor_key",
            material = spki,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("pypi", root.GetProperty("ecosystem").GetString());
        Assert.Equal("rekor_key", root.GetProperty("anchorKind").GetString());
        Assert.NotNull(root.GetProperty("keyId").GetString());

        await c.DeleteAsync($"/api/v1/trust-anchors/{root.GetProperty("id").GetString()}");
    }

    [Fact]
    public async Task Add_ValidPyPiTrustedPublisher_Returns201()
    {
        using var c = await AdminClient();
        string material = """{"issuer":"https://token.actions.githubusercontent.com","subject":"repo:example/example"}""";

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "pypi",
            anchorKind = "trusted_publisher",
            material,
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("pypi", root.GetProperty("ecosystem").GetString());
        Assert.Equal("trusted_publisher", root.GetProperty("anchorKind").GetString());

        await c.DeleteAsync($"/api/v1/trust-anchors/{root.GetProperty("id").GetString()}");
    }

    // ── Add — (ecosystem, anchorKind) pair validation ──────────────────────────
    // TrustAnchorPairs.Registered holds exactly 8 (ecosystem, anchorKind) pairs, each with a
    // material validator behind it in TrustAnchorController.EcosystemValidators. Every other
    // combination of a supported ecosystem and an allowed anchorKind must be rejected with 422
    // before any material is parsed or stored — an unregistered pair falling through with no
    // material validation silently stores arbitrary bytes as a signature trust root.
    // The pair set is read from the shared constant so this theory cannot drift from the gate;
    // its exact contents are pinned by TrustAnchorPairsTests.

    private static readonly HashSet<(string Ecosystem, string AnchorKind)> RegisteredPairs =
        [.. TrustAnchorPairs.Registered];

    public static TheoryData<string, string> UnregisteredEcosystemAnchorKindPairs()
    {
        var data = new TheoryData<string, string>();
        foreach (string ecosystem in TrustAnchorRepository.SupportedEcosystems)
        {
            foreach (string anchorKind in TrustAnchorRepository.AllowedAnchorKinds)
            {
                if (!RegisteredPairs.Contains((ecosystem, anchorKind)))
                {
                    data.Add(ecosystem, anchorKind);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(UnregisteredEcosystemAnchorKindPairs))]
    public async Task Add_UnregisteredEcosystemAnchorKindPair_Returns422_AndPersistsNothing(
        string ecosystem, string anchorKind)
    {
        using var c = await AdminClient();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem,
            anchorKind,
            material = "Zm9vYmFy",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("anchorKind", doc.RootElement.GetProperty("field").GetString());

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM signature_trust_anchor WHERE ecosystem = @eco AND anchor_kind = @kind",
            new { eco = ecosystem, kind = anchorKind });
        Assert.Equal(0, count);
    }

    /// <summary>
    /// The exact previously-reported repro: npm/pgp (unregistered — npm's registered anchorKind
    /// is spki) with base64 material "Zm9vYmFy" ("foobar") used to fall through to no material
    /// validation at all and store the garbage bytes as a signature trust root with 201. It now
    /// returns 422 before the material is ever inspected, and stores nothing.
    /// </summary>
    [Fact]
    public async Task Add_NpmPgp_WithGarbageMaterial_IsRejectedRatherThan201()
    {
        using var c = await AdminClient();

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "npm",
            anchorKind = "pgp",
            material = "Zm9vYmFy",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM signature_trust_anchor WHERE ecosystem = 'npm' AND anchor_kind = 'pgp'");
        Assert.Equal(0, count);
    }

    /// <summary>
    /// The material shape that previously produced an unhandled
    /// <see cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException"/> and a 500 (a well-formed OpenPGP
    /// literal-data packet, not a public key ring) posted against an unregistered pair now
    /// returns 422, not 500 — the pair-validation gate rejects it before
    /// <c>TrustAnchorKeyStrength.Validate</c> ever runs.
    /// </summary>
    [Fact]
    public async Task Add_UnregisteredPair_WithWellFormedNonKeyRingPgpMaterial_Returns422NotServerError()
    {
        using var c = await AdminClient();
        string material = Convert.ToBase64String(BuildPgpLiteralDataPacket());

        var resp = await c.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "npm",
            anchorKind = "pgp",
            material,
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
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
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // ── Certificate / non-key-ring PGP object generation ────────────────────
    // Self-signed RSA certificate PEM, for the nuget/x509 and pypi/sigstore_root happy paths.
    private static string SelfSignedRsaCertificatePem(int bits)
    {
        using var rsa = RSA.Create(bits);
        var req = new CertificateRequest(
            "CN=dependably-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return cert.ExportCertificatePem();
    }

    // A well-formed OpenPGP literal-data packet (not a public key ring) — the same shape as the
    // reported "PgpCompressedData found where PgpPublicKeyRing expected" crash, thrown by the
    // same PgpPublicKeyRingBundle object-type check for any non-key-ring OpenPGP object.
    private static byte[] BuildPgpLiteralDataPacket()
    {
        using var ms = new MemoryStream();
        var litGen = new PgpLiteralDataGenerator();
        using (var os = litGen.Open(
            ms, PgpLiteralData.Binary, "x", new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), new byte[1024]))
        {
            os.Write(Encoding.ASCII.GetBytes("not a public key ring"));
        }

        return ms.ToArray();
    }

    // ── PGP key generation ───────────────────────────────────────────────────
    // Mirrors PgpKeyRingBuilderTests.GenerateArmoredPublicKey: builds a real ASCII-armored
    // OpenPGP public key in-process (no PGP fixture file exists in the repository to reuse).
    // 2048-bit rather than the 1024 the pure-parser tests use for speed: material posted to
    // POST /api/v1/trust-anchors clears the trust-anchor minimum-strength floor.

    private static string GenerateArmoredPublicKeyString()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new SecureRandom(), 2048, 12));
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
