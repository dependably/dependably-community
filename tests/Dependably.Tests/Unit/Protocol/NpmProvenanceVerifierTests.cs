using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="NpmProvenanceVerifier"/> end to end with a self-generated ECDSA P-256
/// keypair (never a real npm key). The registry signs an ECDSA P-256 / SHA-256 DER signature over
/// the exact UTF-8 string <c>"{name}@{version}:{integrity}"</c>; the verifier must accept a valid
/// signature from a pinned key and reject everything else without throwing — tampered signatures,
/// wrong keys, unknown keyids, missing signatures, and malformed input.
/// Per-org key isolation: org-A's key must not be usable to verify org-B's packages.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmProvenanceVerifierTests
{
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";
    private const string KeyId = "SHA256:test-anchor";
    private const string PackageName = "left-pad";
    private const string Version = "1.3.0";
    private const string Integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // ── happy path ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidSignature_FromPinnedKey_Verifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(KeyId, result.Signer);
    }

    [Fact]
    public async Task ValidSignature_AmongMultiple_Verifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string goodSig = Sign(key, PackageName, Version, Integrity);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        // A leading entry for an unknown keyid must not stop the verifier reaching the good one.
        var result = await verifier.VerifyForOrgAsync(
            OrgA, Input([("SHA256:other", "Zm9v"), (KeyId, goodSig)]));

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(KeyId, result.Signer);
    }

    // ── per-org key isolation ───────────────────────────────────────────────

    [Fact]
    public async Task OrgA_Key_DoesNotVerify_OrgB_Package()
    {
        // Org-A has an anchor; org-B has none. Verifying for org-B must return NotApplicable,
        // never Verified (the key is isolated to org-A's anchor set).
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgB, Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    [Fact]
    public async Task OrgB_WithAnchor_VerifiesIndependently()
    {
        // Both orgs have anchors but with different keys; each verifies its own signature.
        using var keyA = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var keyB = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sigForA = Sign(keyA, PackageName, Version, Integrity);
        string sigForB = Sign(keyB, PackageName, Version, Integrity);

        var store = new StubPerOrgTrustAnchorStore();
        AddNpmAnchor(store, OrgA, KeyId, Spki(keyA));
        AddNpmAnchor(store, OrgB, "SHA256:key-b", Spki(keyB));
        var verifier = BuildVerifier(store);

        var resultA = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, sigForA)]));
        var resultB = await verifier.VerifyForOrgAsync(OrgB, Input([("SHA256:key-b", sigForB)]));

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.Equal(ProvenanceStatus.Verified, resultB.Status);
    }

    [Fact]
    public async Task OrgA_Key_CannotVerify_OrgB_SignedPackage()
    {
        // Org-A signed a package; org-B should fail — wrong key for that org.
        using var keyA = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var keyB = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sigByA = Sign(keyA, PackageName, Version, Integrity);

        var store = new StubPerOrgTrustAnchorStore();
        AddNpmAnchor(store, OrgA, KeyId, Spki(keyA));
        AddNpmAnchor(store, OrgB, KeyId, Spki(keyB)); // org-B has a different key under same id

        var verifier = BuildVerifier(store);
        var result = await verifier.VerifyForOrgAsync(OrgB, Input([(KeyId, sigByA)]));

        // Sig was made by org-A's key; org-B's pinned key differs → Failed.
        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── failure paths (signature present but does not establish trust) ───────

    [Fact]
    public async Task TamperedSignature_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] sigBytes = key.SignData(
            Encoding.UTF8.GetBytes($"{PackageName}@{Version}:{Integrity}"),
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        // Flip a byte in the middle of the DER signature.
        sigBytes[sigBytes.Length / 2] ^= 0xFF;
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, Convert.ToBase64String(sigBytes))]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task SignatureOverDifferentPayload_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Sign a different version string — a valid signature, but not over this artefact's payload.
        string sig = Sign(key, PackageName, "9.9.9", Integrity);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task WrongKey_Fails()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pinnedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(signingKey, PackageName, Version, Integrity);
        // Pin a different key under the same keyid the signature quotes.
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(pinnedKey)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task UnknownKeyId_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);
        // The pinned anchor has a different keyid than the signature quotes — no anchor to verify.
        var verifier = VerifierForOrg(OrgA, ("SHA256:different", Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── unsigned / not-applicable ────────────────────────────────────────────

    [Fact]
    public async Task NoSignatures_Unsigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([]));

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task NoPinnedKeys_OrgHasNoAnchors_NotApplicable()
    {
        // Org with no anchors → NotApplicable (verifier skips, nothing blocks).
        var verifier = VerifierForOrg(OrgA); // no keys added

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, "Zm9v")]));

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    [Fact]
    public async Task NoPinnedKeys_IsConfiguredForAsync_ReturnsFalse()
    {
        var verifier = VerifierForOrg(OrgA); // no keys

        Assert.False(await verifier.IsConfiguredForAsync(OrgA));
    }

    [Fact]
    public async Task WithPinnedKey_IsConfiguredForAsync_ReturnsTrue()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        Assert.True(await verifier.IsConfiguredForAsync(OrgA));
    }

    // ── malformed input → Failed, never throws ───────────────────────────────

    [Fact]
    public async Task MissingIntegrity_WithSignature_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(
            OrgA,
            new ProvenanceInput("npm", PackageName, Version, Integrity: null,
                [new ProvenanceSignature(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task MalformedBase64Signature_Fails_DoesNotThrow()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, "not valid base64 !!!")]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task GarbageSignatureBytes_Fail_DoesNotThrow()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierForOrg(OrgA, (KeyId, Spki(key)));

        // Valid base64 but not a DER ECDSA signature.
        var result = await verifier.VerifyForOrgAsync(
            OrgA, Input([(KeyId, Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }))]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void MalformedPinnedKey_IsSkipped_OrgHasNoUsableAnchors()
    {
        // A typo in the pinned key must not throw at load time and must leave no usable anchor.
        var map = NpmSignatureKeyStore.BuildSpkiMap(
            [new TrustAnchorMaterial { KeyId = "SHA256:bad", Material = "this is not base64 SPKI", AnchorKind = "spki" }],
            NullLogger.Instance);

        Assert.Empty(map);
    }

    // ── TrustAnchorController validator: TryParseSpki ──────────────────────

    [Fact]
    public void TryParseSpki_ValidKey_ReturnsTrue()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string b64 = Spki(key);

        bool ok = NpmSignatureKeyStore.TryParseSpki("SHA256:test", b64, out byte[]? spki, NullLogger.Instance);

        Assert.True(ok);
        Assert.NotNull(spki);
        Assert.NotEmpty(spki!);
    }

    [Fact]
    public void TryParseSpki_GarbageBase64_ReturnsFalse()
    {
        bool ok = NpmSignatureKeyStore.TryParseSpki(
            "SHA256:bad", "not-valid-base64!!!", out _, NullLogger.Instance);

        Assert.False(ok);
    }

    [Fact]
    public void TryParseSpki_ValidBase64ButNotSpki_ReturnsFalse()
    {
        bool ok = NpmSignatureKeyStore.TryParseSpki(
            "SHA256:bad", Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }), out _, NullLogger.Instance);

        Assert.False(ok);
    }

    // ── mixed partial-failure batch ─────────────────────────────────────────

    [Fact]
    public async Task MixedAnchors_OneGoodOneGarbage_GoodOneVerifies()
    {
        // A batch with one parseable and one garbage anchor: the parseable one must succeed.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { KeyId = "SHA256:garbage", Material = "not-valid-base64!!!", AnchorKind = "spki" },
            new() { KeyId = KeyId, Material = Spki(key), AnchorKind = "spki" },
        };
        var map = NpmSignatureKeyStore.BuildSpkiMap(anchors, NullLogger.Instance);

        // The garbage entry must be skipped; the good entry must be present.
        Assert.Single(map);
        Assert.True(map.ContainsKey(KeyId));

        // And the verifier using that map must verify the signature.
        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(OrgA, "npm", new TrustAnchorMaterial
        { KeyId = "SHA256:garbage", Material = "not-valid-base64!!!", AnchorKind = "spki" });
        store.AddAnchor(OrgA, "npm", new TrustAnchorMaterial
        { KeyId = KeyId, Material = Spki(key), AnchorKind = "spki" });
        var verifier = BuildVerifier(store);

        var result = await verifier.VerifyForOrgAsync(OrgA, Input([(KeyId, sig)]));
        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static ProvenanceInput Input(IReadOnlyList<(string KeyId, string Sig)> sigs) =>
        new("npm", PackageName, Version, Integrity,
            sigs.Select(s => new ProvenanceSignature(s.KeyId, s.Sig)).ToArray());

    private static string Sign(ECDsa key, string name, string version, string integrity)
    {
        byte[] payload = Encoding.UTF8.GetBytes($"{name}@{version}:{integrity}");
        byte[] der = key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Convert.ToBase64String(der);
    }

    private static string Spki(ECDsa key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    private static NpmProvenanceVerifier VerifierForOrg(
        string orgId, params (string KeyId, string SpkiBase64)[] keys)
    {
        var store = new StubPerOrgTrustAnchorStore();
        foreach (var (keyId, spki) in keys)
        {
            AddNpmAnchor(store, orgId, keyId, spki);
        }
        return BuildVerifier(store);
    }

    private static void AddNpmAnchor(StubPerOrgTrustAnchorStore store, string orgId, string keyId, string spkiBase64)
        => store.AddAnchor(orgId, "npm", new TrustAnchorMaterial { KeyId = keyId, Material = spkiBase64, AnchorKind = "spki" });

    private static NpmProvenanceVerifier BuildVerifier(StubPerOrgTrustAnchorStore store)
    {
        var keyStore = new NpmSignatureKeyStore(store);
        return new NpmProvenanceVerifier(keyStore);
    }
}
