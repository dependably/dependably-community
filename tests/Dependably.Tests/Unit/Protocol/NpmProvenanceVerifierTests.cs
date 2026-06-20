using System.Security.Cryptography;
using System.Text;
using Dependably.Protocol.Provenance;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="NpmProvenanceVerifier"/> end to end with a self-generated ECDSA P-256
/// keypair (never a real npm key). The registry signs an ECDSA P-256 / SHA-256 DER signature over
/// the exact UTF-8 string <c>"{name}@{version}:{integrity}"</c>; the verifier must accept a valid
/// signature from a pinned key and reject everything else without throwing — tampered signatures,
/// wrong keys, unknown keyids, missing signatures, and malformed input.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmProvenanceVerifierTests
{
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
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        var result = await verifier.VerifyAsync(Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(KeyId, result.Signer);
    }

    [Fact]
    public async Task ValidSignature_AmongMultiple_Verifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string goodSig = Sign(key, PackageName, Version, Integrity);
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        // A leading entry for an unknown keyid must not stop the verifier reaching the good one.
        var result = await verifier.VerifyAsync(
            Input([("SHA256:other", "Zm9v"), (KeyId, goodSig)]));

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(KeyId, result.Signer);
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
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        var result = await verifier.VerifyAsync(Input([(KeyId, Convert.ToBase64String(sigBytes))]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task SignatureOverDifferentPayload_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Sign a different version string — a valid signature, but not over this artefact's payload.
        string sig = Sign(key, PackageName, "9.9.9", Integrity);
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        var result = await verifier.VerifyAsync(Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task WrongKey_Fails()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pinnedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(signingKey, PackageName, Version, Integrity);
        // Pin a different key under the same keyid the signature quotes.
        var verifier = VerifierWithKeys((KeyId, Spki(pinnedKey)));

        var result = await verifier.VerifyAsync(Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task UnknownKeyId_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);
        // The pinned anchor has a different keyid than the signature quotes — no anchor to verify.
        var verifier = VerifierWithKeys(("SHA256:different", Spki(key)));

        var result = await verifier.VerifyAsync(Input([(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── unsigned / not-applicable ────────────────────────────────────────────

    [Fact]
    public async Task NoSignatures_Unsigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        var result = await verifier.VerifyAsync(Input([]));

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void NoPinnedKeys_VerifierNotConfigured()
    {
        var verifier = VerifierWithKeys();
        Assert.False(verifier.IsConfigured);
    }

    // ── malformed input → Failed, never throws ───────────────────────────────

    [Fact]
    public async Task MissingIntegrity_WithSignature_Fails()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string sig = Sign(key, PackageName, Version, Integrity);
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        var result = await verifier.VerifyAsync(
            new ProvenanceInput("npm", PackageName, Version, Integrity: null,
                [new ProvenanceSignature(KeyId, sig)]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task MalformedBase64Signature_Fails_DoesNotThrow()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        var result = await verifier.VerifyAsync(Input([(KeyId, "not valid base64 !!!")]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task GarbageSignatureBytes_Fail_DoesNotThrow()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = VerifierWithKeys((KeyId, Spki(key)));

        // Valid base64 but not a DER ECDSA signature.
        var result = await verifier.VerifyAsync(
            Input([(KeyId, Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }))]));

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void MalformedPinnedKey_IsSkipped_NotConfigured()
    {
        // A typo in the pinned key must not throw at load time and must leave it unusable.
        var store = StoreWithKeys(("SHA256:bad", "this is not base64 SPKI"));

        Assert.False(store.IsConfigured);
        Assert.Null(store.GetSpki("SHA256:bad"));
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

    private static NpmProvenanceVerifier VerifierWithKeys(params (string KeyId, string SpkiBase64)[] keys)
        => new(StoreWithKeys(keys));

    // Builds the key store from a JSON config stream shaped like appsettings.json: Npm:SignatureKeys
    // is an ARRAY of { keyid, key } objects, because npm keyids contain a colon (e.g.
    // SHA256:jl3bw…) which the configuration system treats as a hierarchy separator — a keyid-keyed
    // object would be mangled. Mirrors how Oci:Upstreams binds an array.
    private static NpmSignatureKeyStore StoreWithKeys(params (string KeyId, string SpkiBase64)[] keys)
    {
        var entries = keys.Select(k => new Dictionary<string, string> { ["keyid"] = k.KeyId, ["key"] = k.SpkiBase64 }).ToArray();
        string json = System.Text.Json.JsonSerializer.Serialize(
            new Dictionary<string, object> { ["Npm"] = new Dictionary<string, object> { ["SignatureKeys"] = entries } });
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();
        return new NpmSignatureKeyStore(config, NullLogger<NpmSignatureKeyStore>.Instance);
    }
}
