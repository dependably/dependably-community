using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Canonicalization;
using Dependably.Infrastructure.Sbom;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The ingest half of ADR-sbom-author-signature end to end over real HTTP: a supplier's
/// signature verifying against an operator-pinned anchor, a document altered after signing
/// failing that same check, an unsigned document and a policy with no anchor left to check
/// against both denying under <c>block</c> rather than passing silently, and <c>warn</c>
/// recording the verdict without refusing the upload.
///
/// <para>The "supplier" key here is a plain ECDSA keypair generated in the test — never the
/// org's own <see cref="SbomSigningKeyRepository"/> key, which signs EXPORTS. Ingest
/// verification checks an UPLOADED document's signature against an anchor the operator pinned
/// for a third party, which is exactly what registering the test keypair's public half via
/// <c>POST /api/v1/trust-anchors</c> simulates.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomAuthorSignatureIngestTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new()
    {
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
    };

    public Task InitializeAsync() => _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private const string BaseDocument = """
        {"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:8d4f6a3e-2b1c-4c8e-9f2a-7e5d0c1b9a44","version":1,
         "metadata":{"timestamp":"2026-08-01T09:30:00Z","component":{"type":"application","bom-ref":"ingest-check@1.0.0","name":"ingest-check","version":"1.0.0"}},
         "components":[{"type":"library","bom-ref":"pkg:npm/lodash@4.17.21","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}
        """;

    private static (string SignedJson, string SpkiBase64, string KeyId) SignAsSupplier()
    {
        using var supplierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string keyId = SbomSigningKeyRepository.ComputeFingerprint(supplierKey);
        var key = new SbomSigningKey(keyId, "supplier", supplierKey);

        var doc = (JsonObject)JsonNode.Parse(BaseDocument)!;
        SbomAuthorSigner.Attach(doc, key);

        return (doc.ToJsonString(), Convert.ToBase64String(supplierKey.ExportSubjectPublicKeyInfo()), keyId);
    }

    private async Task<HttpClient> AdminClientAsync()
    {
        var client = _factory.CreateClient();
        string jwt = await _factory.CreateAdminJwt();
        client.DefaultRequestHeaders.Authorization = new("Bearer", jwt);
        return client;
    }

    /// <summary>
    /// A service token scoped to exactly <c>sbom:upload</c> — the shape a CI pipeline's build
    /// token actually has, and the shape <see cref="SbomController"/>'s own doc comment says
    /// this endpoint is gated for ("both credentials are accepted: a JWT session ... and an API
    /// token from a pipeline"). Named so an audit row this token trips is attributable back to
    /// it by name after the token is later revoked, the same denormalized-label reason
    /// <c>TokenRecord.AuditActorLabel</c> exists for.
    /// </summary>
    private async Task<(HttpClient Client, string TokenName)> ServiceTokenClientAsync()
    {
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var org = await orgs.GetBySlugAsync("default")
            ?? throw new InvalidOperationException("default org not seeded");
        string name = Unique("ci-build-token");
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            org.Id, name, """["sbom:upload"]""", expiresAt: null);
        return (_factory.CreateClientWithBearer(raw), name);
    }

    private static async Task<HttpResponseMessage> AddSbomAnchorAsync(HttpClient admin, string spkiBase64) =>
        await admin.PostAsJsonAsync("/api/v1/trust-anchors", new
        {
            ecosystem = "sbom",
            anchorKind = "spki",
            material = spkiBase64,
        });

    private static Task<HttpResponseMessage> SetSbomModeAsync(HttpClient admin, string mode) =>
        admin.PutAsJsonAsync("/api/v1/proxy-settings", new { verifySbomSignatures = mode });

    private static async Task<HttpResponseMessage> UploadAsync(HttpClient client, string projectName, string json)
    {
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await client.PutAsync(
            $"/api/v1/sbom?projectName={projectName}&projectVersion=1.0.0&autoCreate=true", content);
    }

    private async Task<string?> SignatureStatusAsync(string projectName)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pd.signature_status FROM project_documents pd
            JOIN project_versions pv ON pv.id = pd.project_version_id
            JOIN projects p ON p.id = pv.project_id
            WHERE p.name = @projectName
            """,
            new { projectName });
    }

    [Fact]
    public async Task VerifiedSignature_UnderBlock_AllowsTheUploadAndPersistsVerified()
    {
        using var admin = await AdminClientAsync();
        var (signedJson, spki, keyId) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        string project = Unique("verified");
        var resp = await UploadAsync(admin, project, signedJson);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("verified", await SignatureStatusAsync(project));

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? persistedKeyId = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pd.signature_key_id FROM project_documents pd
            JOIN project_versions pv ON pv.id = pd.project_version_id
            JOIN projects p ON p.id = pv.project_id
            WHERE p.name = @project
            """,
            new { project });
        Assert.Equal(keyId, persistedKeyId);
    }

    // The mutant: skip the tamper line below (upload the SIGNED, unmodified JSON) and this
    // degrades into a duplicate of the "allows" case above — the assertion that must go red is
    // specifically "a byte the signature covers changed after signing", the exact CVE-class D2
    // exists to catch.
    [Fact]
    public async Task TamperedAfterSigning_UnderBlock_DeniesTheUpload()
    {
        using var admin = await AdminClientAsync();
        var (signedJson, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        var tampered = (JsonObject)JsonNode.Parse(signedJson)!;
        tampered["components"]![0]!["version"] = "4.17.22";

        string project = Unique("tampered");
        var resp = await UploadAsync(admin, project, tampered.ToJsonString());

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var problem = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("failed", problem.RootElement.GetProperty("reason").GetString());

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'sbom_signature_blocked'"));
        // Refused before the merge: no project was ever created for this upload.
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM projects WHERE name = @project", new { project }));
    }

    [Fact]
    public async Task UnsignedDocument_UnderBlock_DeniesTheUpload()
    {
        using var admin = await AdminClientAsync();
        var (_, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        var resp = await UploadAsync(admin, Unique("unsigned"), BaseDocument);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var problem = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("unsigned", problem.RootElement.GetProperty("reason").GetString());
    }

    /// <summary>
    /// The empty-trust-anchor-set case, isolated from a merely-bad signature: the signature
    /// itself is genuinely valid — it is the ANCHOR that is gone, deleted after
    /// <c>verify_sbom_signatures</c> was already set to <c>block</c> (which required an anchor
    /// to exist at the time). This pins that enforcement is checked again, independently, at
    /// upload time — an anchor deleted after enablement must deny, not silently pass the next
    /// upload through as though "block" had quietly become "off". The audit reason
    /// distinguishes it from a plain verification failure: "unverifiable", never "failed" —
    /// the same synthesis, and the same never-persisted status,
    /// <c>BlockGateService.IsProvenanceEnforcementUnbackedAsync</c> uses for artefacts.
    ///
    /// <para>If you mutate this test's target line to confirm it goes red: rebuild the whole
    /// solution (<c>dotnet build Dependably.sln</c>), not just <c>Dependably.Management.csproj</c>.
    /// Rebuilding only the assembly you edited, then reverting the source with a plain file
    /// move/rename (rather than editing it back in place), can roll the file's mtime backward far
    /// enough that MSBuild's incremental check reads "source unchanged, DLL newer" and silently
    /// skips recompilation — the test then runs against a STALE dll and reports a false negative
    /// either way (mutant looks green, or a real revert looks like it is still mutated). `touch`
    /// the file (or run a full solution build) before trusting either result.</para>
    /// </summary>
    [Fact]
    public async Task EmptyTrustAnchorSetAfterEnablement_UnderBlock_DeniesAsUnverifiable_NotAsANoOp()
    {
        using var admin = await AdminClientAsync();
        var (signedJson, spki, _) = SignAsSupplier();
        var added = await AddSbomAnchorAsync(admin, spki);
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);
        string anchorId = (await added.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        // The anchor is removed AFTER enablement — the runtime-editable drift the config-time
        // check cannot see.
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/trust-anchors/{anchorId}")).StatusCode);

        var resp = await UploadAsync(admin, Unique("unbacked"), signedJson);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var problem = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("unverifiable", problem.RootElement.GetProperty("reason").GetString());

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? reason = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM audit_log WHERE action = 'sbom_signature_blocked' ORDER BY created_at DESC LIMIT 1");
        Assert.Contains("unverifiable", reason);
    }

    [Fact]
    public async Task WarnMode_RecordsTheVerdict_ButAllowsTheUpload()
    {
        using var admin = await AdminClientAsync();
        var (_, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "warn")).StatusCode);

        string project = Unique("warn");
        var resp = await UploadAsync(admin, project, BaseDocument);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("unsigned", await SignatureStatusAsync(project));

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'sbom_signature_warn'"));
    }

    /// <summary>The default posture: 'off' never invokes the verifier at all, so a signed
    /// document's status stays NULL rather than being scored as though it had been checked.</summary>
    [Fact]
    public async Task OffMode_NeverChecksTheSignature_StatusStaysNull()
    {
        using var admin = await AdminClientAsync();
        var (signedJson, _, _) = SignAsSupplier();

        string project = Unique("off");
        var resp = await UploadAsync(admin, project, signedJson);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Null(await SignatureStatusAsync(project));
    }

    /// <summary>
    /// F4: this endpoint is gated on <see cref="Capabilities.SbomUpload"/>, which a service
    /// token satisfies as readily as a user session — a CI build token is the common caller,
    /// not the exception. A refusal a service token trips must carry the real
    /// <c>ActorKinds.Service</c> kind and the token's denormalized name, the same
    /// <see cref="SbomIngestRepository.ResolveActorAsync"/> lookup
    /// <c>RecordUploadAsync</c>'s own (non-security) <c>sbom_uploaded</c> event already uses —
    /// never a fabricated <c>ActorKinds.User</c> with no label, which is exactly the hole
    /// <c>AuditActorIdComplianceTests</c> exists to close.
    ///
    /// <para>Mutant: revert the two <c>ApplySbomSignaturePolicyAsync</c> audit calls to hardcode
    /// <c>actorKind: actorId is null ? null : ActorKinds.User</c> (the pre-fix shape) and this
    /// test goes red — the row's <c>actor_kind</c> reads <c>'user'</c> and <c>actor_label</c> is
    /// NULL for a token that is not a user at all.</para>
    /// </summary>
    [Fact]
    public async Task ServiceTokenTrippingBlock_AuditsUnderTheRealActorKindAndLabel_NotAFabricatedUser()
    {
        using var admin = await AdminClientAsync();
        var (_, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        var (serviceClient, tokenName) = await ServiceTokenClientAsync();
        using (serviceClient)
        {
            var resp = await UploadAsync(serviceClient, Unique("svc-token"), BaseDocument);
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var (actorKind, actorLabel) = await conn.QuerySingleAsync<(string? ActorKind, string? ActorLabel)>(
            """
            SELECT actor_kind AS ActorKind, actor_label AS ActorLabel FROM audit_log
            WHERE action = 'sbom_signature_blocked'
            ORDER BY created_at DESC LIMIT 1
            """);
        Assert.Equal(ActorKinds.Service, actorKind);
        Assert.Equal(tokenName, actorLabel);
    }

    /// <summary>
    /// F5: <c>Schema.sql</c>, <c>Models.cs</c> and <c>SbomDocumentStore.cs</c> all document
    /// <c>project_documents.signature_key_id</c> as set ONLY when
    /// <c>signature_status = 'verified'</c>. The value comes straight off the uploaded
    /// document's own <c>signature.keyId</c> field before any anchor has matched it, so under
    /// 'warn' — which persists a verdict without refusing — an unverified document's attacker-
    /// controlled keyId must never reach that column, whatever it contains.
    ///
    /// <para>Mutant: in <c>ApplySbomSignaturePolicyAsync</c>, return <c>verdict.KeyId</c>
    /// unconditionally instead of the verified-only, length-capped <c>persistedKeyId</c> (the
    /// pre-fix shape) and this test goes red — <c>signature_status</c> is <c>'failed'</c> while
    /// <c>signature_key_id</c> carries the raw payload below.</para>
    /// </summary>
    [Fact]
    public async Task UnverifiedUpload_UnderWarn_NeverPersistsTheClaimedKeyId_EvenAttackerControlled()
    {
        using var admin = await AdminClientAsync();
        // An anchor is required to even SET 'warn' (the config-time fail-closed check), but it
        // is for a real supplier key that has nothing to do with the attacker-controlled keyId
        // below — the point is that keyId never matches it, which is the common case, not an
        // anchor-less org.
        var (_, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "warn")).StatusCode);

        var doc = (JsonObject)JsonNode.Parse(BaseDocument)!;
        doc["signature"] = new JsonObject
        {
            ["algorithm"] = "ES256",
            ["keyId"] = "<script>alert(1)</script>" + new string('a', 4000),
            ["value"] = "AA",
        };

        string project = Unique("badkeyid");
        var resp = await UploadAsync(admin, project, doc.ToJsonString());

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("failed", await SignatureStatusAsync(project));

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? persistedKeyId = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pd.signature_key_id FROM project_documents pd
            JOIN project_versions pv ON pv.id = pd.project_version_id
            JOIN projects p ON p.id = pv.project_id
            WHERE p.name = @project
            """,
            new { project });
        Assert.Null(persistedKeyId);
    }

    /// <summary>
    /// F1: an unsigned document lands under the default 'off' — no verdict is recorded, per
    /// <see cref="OffMode_NeverChecksTheSignature_StatusStaysNull"/> above. An operator then
    /// pins an anchor and enables 'block'. Re-uploading the IDENTICAL bytes must be denied, not
    /// waved through as a dedup hit: <c>TryDedupAsync</c> answers a hash match before the
    /// signature policy ever runs, so without an explicit "stale verdict" check, the supplier's
    /// original unsigned bytes hold a permanent free pass regardless of what the org later sets
    /// <c>verify_sbom_signatures</c> to.
    ///
    /// <para>Mutant: revert <c>SbomController.IngestSbomAsync</c>'s <c>forceMiss</c> argument to
    /// <c>TryDedupAsync</c> (i.e. call it with no <c>forceMiss</c>, the pre-fix shape) and this
    /// test goes red — the re-upload comes back 200 with zero <c>sbom_signature_blocked</c> rows,
    /// exactly the bypass this pins closed.</para>
    /// </summary>
    [Fact]
    public async Task UnsignedUpload_UnderOff_ThenBlockEnabled_ReUploadOfTheSameBytes_IsDenied_NotADedupHit()
    {
        using var admin = await AdminClientAsync();
        string project = Unique("stale-dedup");

        // First upload: policy is 'off' (the default) — succeeds, records no verdict.
        var first = await UploadAsync(admin, project, BaseDocument);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Null(await SignatureStatusAsync(project));

        // An operator turns on enforcement AFTER the fact.
        var (_, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        // Re-uploading the EXACT SAME bytes must be re-checked against the now-live policy, not
        // short-circuited on the hash match from before the policy existed.
        var second = await UploadAsync(admin, project, BaseDocument);

        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
        using var problem = JsonDocument.Parse(await second.Content.ReadAsStringAsync());
        Assert.Equal("unsigned", problem.RootElement.GetProperty("reason").GetString());

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'sbom_signature_blocked'"));
    }

    /// <summary>
    /// F3: SPDX 2.3 defines no JSF signature carrier, but it is NOT exempt from
    /// <c>verify_sbom_signatures</c> — only <c>'off'</c> exempts a document from this check.
    /// Under <c>block</c>, an SPDX upload is scored exactly as an unsigned CycloneDX document
    /// would be and denied, so switching format is never a way to evade the policy.
    ///
    /// <para>Mutant: revert <see cref="Dependably.Api.SbomController"/>'s
    /// <c>ApplySbomSignaturePolicyAsync</c> to its pre-fix shape — an early
    /// <c>if (format != "cyclonedx-json") return (null, null, null);</c> — and this test goes
    /// red: the SPDX upload comes back 200 with <c>signature_status</c> NULL instead of a 403.
    /// </para>
    /// </summary>
    [Fact]
    public async Task SpdxDocument_UnderBlock_IsScoredAsUnsigned_NotExempt()
    {
        using var admin = await AdminClientAsync();
        var (_, spki, _) = SignAsSupplier();
        Assert.Equal(HttpStatusCode.Created, (await AddSbomAnchorAsync(admin, spki)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await SetSbomModeAsync(admin, "block")).StatusCode);

        string spdxJson = await File.ReadAllTextAsync(
            Path.Combine(FixtureManifest.SbomFixturesRoot, "spdx-2.3-npm-syft.json"));

        var resp = await UploadAsync(admin, Unique("spdx"), spdxJson);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        using var problem = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("unsigned", problem.RootElement.GetProperty("reason").GetString());
    }

    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];
}
