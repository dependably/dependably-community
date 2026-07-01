using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// End-to-end tests for the Rekor inclusion-proof + SET + valid-at-signing path in
/// <see cref="PyPiProvenanceVerifier"/>. All fixtures are self-consistent: the test generates its
/// own ECDSA P-256 Rekor log key, computes the leaf and root hashes, signs the SET canonical JSON
/// with that key, and pins it in the trust store via config. No external network or Sigstore
/// material is needed.
///
/// Headline scenario: a Fulcio leaf that has EXPIRED relative to wall-clock time but whose
/// <c>integratedTime</c> (the Rekor-proven signing instant) falls within the leaf's original
/// validity window must be accepted. This is the core "valid-at-signing" guarantee: the leaf was
/// genuinely current when it was used, and the Rekor log proves it. The chain build already
/// ignores time validity (IgnoreNotTimeValid) — this test validates that check 5c correctly
/// accepts the leaf when the integratedTime is within bounds.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiRekorVerifierTests
{
    // ── constants shared by all fixtures ─────────────────────────────────────

    private const string FileName = "mylib-2.0.0-py3-none-any.whl";
    private const string FileSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Issuer = "https://token.actions.githubusercontent.com";
    private const string Identity = "https://github.com/example/mylib/.github/workflows/publish.yml@refs/heads/main";

    // The Fulcio leaf validity window used for the "short-lived, now expired" scenario. The
    // window is 2020-01-01 → 2021-01-01: comfortably past wall-clock time, so the leaf is
    // expired at the moment the test runs. The integratedTime is placed inside this window.
    private static readonly DateTimeOffset ShortLivedNotBefore = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ShortLivedNotAfter = new(2021, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // A second validity window used for long-lived certs in the standard happy-path tests.
    private static readonly DateTimeOffset LongNotBefore = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset LongNotAfter = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── happy path ────────────────────────────────────────────────────────────

    [Fact]
    public void ValidRekorEntry_AllChecksPass_Verifies()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);

        // Choose an integratedTime inside the leaf validity window.
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: false);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    // ── headline case: leaf expired at real time, but integratedTime is within the window ────

    [Fact]
    public void ExpiredLeafAtRealTime_IntegratedTimeWithinWindow_Verifies()
    {
        // The leaf was issued 2020-01-01 and expired 2021-01-01 — it is expired right now.
        // The Rekor log proves the signing happened at 2020-07-01, inside the window.
        // The chain build ignores time validity (IgnoreNotTimeValid), and check 5c must accept
        // the leaf because integratedTime falls within [NotBefore, NotAfter].
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(ShortLivedNotBefore, ShortLivedNotAfter);

        // integratedTime = 2020-07-01 00:00:00 UTC — within [2020-01-01, 2021-01-01].
        long integratedTime = new DateTimeOffset(2020, 7, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: false);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        // The leaf is expired at wall-clock time but the Rekor-proven integratedTime is within
        // the validity window — the result must be Verified.
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    // ── failure: tampered inclusion proof ────────────────────────────────────

    [Fact]
    public void TamperedInclusionProof_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: true, tamperSet: false);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── failure: corrupted SET signature ─────────────────────────────────────

    [Fact]
    public void CorruptedSetSignature_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: true);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── failure: integratedTime is BEFORE the leaf's NotBefore ───────────────

    [Fact]
    public void IntegratedTimeBeforeLeafNotBefore_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(ShortLivedNotBefore, ShortLivedNotAfter);

        // integratedTime = 2019-06-01 — before the leaf's NotBefore (2020-01-01).
        long integratedTime = new DateTimeOffset(2019, 6, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: false);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── failure: integratedTime is AFTER the leaf's NotAfter ─────────────────

    [Fact]
    public void IntegratedTimeAfterLeafNotAfter_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(ShortLivedNotBefore, ShortLivedNotAfter);

        // integratedTime = 2022-01-01 — after the leaf's NotAfter (2021-01-01).
        long integratedTime = new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: false);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── no Rekor keys configured: existing bundles keep verifying ────────────

    [Fact]
    public void NoRekorKeys_BundleWithoutTlogEntry_Verifies()
    {
        // When HasRekorKeys is false, the Rekor check is skipped entirely.
        // A bundle with no tlog_entries (the same shape the original four-check tests use) must
        // still verify through checks 1–4. This is the non-regression case.
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);

        // Build a bundle WITHOUT any tlog_entries (the original ProvenanceDocument shape).
        string json = ProvenanceDocumentNoRekor(leaf, FileName, FileSha256);

        // Trust material with no Rekor keys configured.
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    [Fact]
    public void NoRekorKeys_BundleWithTlogEntry_Verifies()
    {
        // HasRekorKeys=false: the tlog_entries block in the bundle is present but ignored.
        // Checks 1–4 still run and still pass.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        string json = ProvenanceDocumentWithRekor(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: false);

        // Trust material with NO Rekor keys — Rekor check is disabled.
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── HasRekorKeys enabled but tlog_entries absent → Failed ────────────────

    [Fact]
    public void RekorKeysConfigured_BundleWithoutTlogEntry_Fails()
    {
        // When HasRekorKeys=true, a bundle that does not carry a tlog entry must be rejected.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);

        // Bundle has no tlog_entries.
        string json = ProvenanceDocumentNoRekor(leaf, FileName, FileSha256);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── HasRekorKeys configured + HasRekorKeys check passes → rekorKey in material ─

    [Fact]
    public void TrustMaterial_HasRekorKeys_TrueWhenKeyConfigured()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var material = BuildTrustMaterialWithRekor([], rekorKey, []);
        Assert.True(material.HasRekorKeys);
    }

    [Fact]
    public void TrustMaterial_HasRekorKeys_FalseWhenNoKeyConfigured()
    {
        var material = BuildTrustMaterialNoRekor([], []);
        Assert.False(material.HasRekorKeys);
    }

    // ── GetRekorKey lookup ────────────────────────────────────────────────────

    [Fact]
    public void GetRekorKey_MatchingLogId_ReturnsKey()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);

        var material = BuildTrustMaterialWithRekor([], rekorKey, []);

        var found = material.GetRekorKey(logId);
        Assert.NotNull(found);
    }

    [Fact]
    public void GetRekorKey_WrongLogId_ReturnsNull()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var material = BuildTrustMaterialWithRekor([], rekorKey, []);

        byte[] wrongId = new byte[32]; // all zeros
        var found = material.GetRekorKey(wrongId);
        Assert.Null(found);
    }

    // ── mixed partial-failure scenario ────────────────────────────────────────
    // Two attestations in the same bundle: the first has a tampered SET (fails), the second has a
    // valid Rekor entry (passes). The verifier must try the second attestation and return Verified.

    [Fact]
    public void MixedBundle_FirstFails_SecondVerifies_ReturnsVerified()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(LongNotBefore, LongNotAfter);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        // First attestation: tampered SET — must fail.
        string badBundle = BuildSingleAttestationJson(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: true);

        // Second attestation: valid — must pass.
        string goodBundle = BuildSingleAttestationJson(
            leaf, FileName, FileSha256, rekorKey, integratedTime, tamperProof: false, tamperSet: false);

        // Wrap both in a PEP 740 provenance document with one attestation_bundle carrying two
        // attestations. Parse each into JsonElement and combine.
        string json = BuildMultiAttestationDocument(badBundle, goodBundle);

        var (verifier, trust) = VerifierTrustingWithRekor(new[] { root }, rekorKey,
            (Issuer, "https://github.com/example/mylib/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── fixture helpers ────────────────────────────────────────────────────────

    private const string FulcioIssuerV2Oid = "1.3.6.1.4.1.57264.1.8";
    private const string SanOid = "2.5.29.17";
    private const string InTotoPayloadType = "application/vnd.in-toto+json";

    // Builds the CA root and a Fulcio-style leaf with a SAN URI + Fulcio OIDC-issuer extension.
    private static (X509Certificate2 Root, X509Certificate2 Leaf) BuildChain(
        DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Dependably Rekor Test Root", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        var root = rootReq.CreateSelfSigned(notBefore, notAfter);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=sigstore-intermediate", leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(BuildSanUriExtension(Identity));
        leafReq.CertificateExtensions.Add(BuildFulcioIssuerExtension(Issuer));

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        var leafPublic = leafReq.Create(root, notBefore, notAfter, serial);
        var leaf = leafPublic.CopyWithPrivateKey(leafKey);
        return (root, leaf);
    }

    private static X509Extension BuildSanUriExtension(string uri)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(
                UniversalTagNumber.IA5String, uri, new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        return new X509Extension(new Oid(SanOid), writer.Encode(), critical: false);
    }

    private static X509Extension BuildFulcioIssuerExtension(string issuer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, issuer);
        return new X509Extension(new Oid(FulcioIssuerV2Oid), writer.Encode(), critical: false);
    }

    // Builds a PEP 740 provenance document containing a single attestation WITH a valid Rekor
    // tlog_entries block. tamperProof flips a byte in the inclusion-proof root hash; tamperSet
    // flips a byte in the SET signature.
    private static string ProvenanceDocumentWithRekor(
        X509Certificate2 leaf,
        string fileName,
        string sha256,
        ECDsa rekorKey,
        long integratedTime,
        bool tamperProof,
        bool tamperSet)
    {
        string attestationJson = BuildSingleAttestationJson(
            leaf, fileName, sha256, rekorKey, integratedTime, tamperProof, tamperSet);

        // Wrap in a PEP 740 envelope.
        using var attDoc = JsonDocument.Parse(attestationJson);
        var attestation = attDoc.RootElement.Clone();

        var bundle = new
        {
            version = 1,
            attestation_bundles = new[]
            {
                new { attestations = new[] { attestation } },
            },
        };
        return JsonSerializer.Serialize(bundle);
    }

    // Builds a provenance document WITHOUT tlog_entries (the original fixture shape).
    private static string ProvenanceDocumentNoRekor(X509Certificate2 leaf, string fileName, string sha256)
    {
        byte[] payload = BuildStatementPayload(fileName, sha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var key = leaf.GetECDsaPrivateKey()!;
        byte[] signature = key.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        string certB64 = Convert.ToBase64String(leaf.Export(X509ContentType.Cert));

        var bundle = new
        {
            version = 1,
            attestation_bundles = new[]
            {
                new
                {
                    attestations = new[]
                    {
                        new
                        {
                            version = 1,
                            verification_material = new { certificate = new { raw_bytes = certB64 } },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(signature),
                            },
                        },
                    },
                },
            },
        };
        return JsonSerializer.Serialize(bundle);
    }

    // Builds a single attestation JSON object (not the outer PEP 740 wrapper).
    private static string BuildSingleAttestationJson(
        X509Certificate2 leaf,
        string fileName,
        string sha256,
        ECDsa rekorKey,
        long integratedTime,
        bool tamperProof,
        bool tamperSet)
    {
        byte[] payload = BuildStatementPayload(fileName, sha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafPrivKey = leaf.GetECDsaPrivateKey()!;
        byte[] signature = leafPrivKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        string certB64 = Convert.ToBase64String(leaf.Export(X509ContentType.Cert));

        // Build a minimal Rekor entry body (the canonicalized_body field). In a real bundle this
        // is the base64-encoded JSON body of the Rekor entry, but the verifier treats it as an
        // opaque blob — only its hash matters for the inclusion proof.
        byte[] canonicalizedBody = Encoding.UTF8.GetBytes(
            $"{{\"kind\":\"hashedrekord\",\"apiVersion\":\"0.0.1\",\"spec\":{{\"data\":{{\"hash\":{{\"algorithm\":\"sha256\",\"value\":\"{sha256}\"}}}}}}}}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);

        // Compute the log key SPKI and log id.
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();

        // Build inclusion proof for a single-entry tree (tree_size=1, empty hashes, root=leafHash).
        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);
        string rootHashB64 = Convert.ToBase64String(leafHash);

        if (tamperProof)
        {
            // Flip a byte in the root hash to break the inclusion proof.
            byte[] tampered = (byte[])leafHash.Clone();
            tampered[0] ^= 0xFF;
            rootHashB64 = Convert.ToBase64String(tampered);
        }

        // Build and sign the SET canonical JSON.
        long logIndex = 42;
        string setJson =
            $"{{\"body\":\"{bodyB64}\","
            + $"\"integratedTime\":{integratedTime},"
            + $"\"logID\":\"{logIdHex}\","
            + $"\"logIndex\":{logIndex}}}";
        byte[] setJsonBytes = Encoding.UTF8.GetBytes(setJson);
        byte[] setSignature = rekorKey.SignData(setJsonBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        if (tamperSet)
        {
            // Flip a byte in the SET signature.
            setSignature[setSignature.Length / 2] ^= 0xFF;
        }

        string setB64 = Convert.ToBase64String(setSignature);

        // Assemble the attestation object.
        var attestation = new
        {
            version = 1,
            verification_material = new
            {
                certificate = new { raw_bytes = certB64 },
                tlog_entries = new[]
                {
                    new
                    {
                        canonicalized_body = bodyB64,
                        integrated_time = integratedTime,
                        log_index = logIndex,
                        log_id = new { key_id = logIdB64 },
                        inclusion_proof = new
                        {
                            log_index = 0L,
                            root_hash = rootHashB64,
                            tree_size = 1L,
                            hashes = Array.Empty<string>(),
                            checkpoint = "test-checkpoint",
                        },
                        inclusion_promise = new { signed_entry_timestamp = setB64 },
                    },
                },
            },
            envelope = new
            {
                statement = Convert.ToBase64String(payload),
                signature = Convert.ToBase64String(signature),
            },
        };
        return JsonSerializer.Serialize(attestation);
    }

    // Builds a PEP 740 document containing two attestations in the same bundle.
    private static string BuildMultiAttestationDocument(string attestation1Json, string attestation2Json)
    {
        using var doc1 = JsonDocument.Parse(attestation1Json);
        using var doc2 = JsonDocument.Parse(attestation2Json);
        var a1 = doc1.RootElement.Clone();
        var a2 = doc2.RootElement.Clone();

        var bundle = new
        {
            version = 1,
            attestation_bundles = new[]
            {
                new { attestations = new[] { a1, a2 } },
            },
        };
        return JsonSerializer.Serialize(bundle);
    }

    private static byte[] BuildStatementPayload(string fileName, string sha256)
    {
        string statement = JsonSerializer.Serialize(new
        {
            _type = "https://in-toto.io/Statement/v1",
            subject = new[] { new { name = fileName, digest = new { sha256 } } },
            predicateType = "https://docs.pypi.org/attestations/publish/v1",
            predicate = new { },
        });
        return Encoding.UTF8.GetBytes(statement);
    }

    private static byte[] BuildDssePae(string payloadType, byte[] payload)
    {
        byte[] typeBytes = Encoding.ASCII.GetBytes(payloadType);
        string prefix = $"DSSEv1 {typeBytes.Length} {payloadType} {payload.Length} ";
        byte[] prefixBytes = Encoding.ASCII.GetBytes(prefix);
        byte[] pae = new byte[prefixBytes.Length + payload.Length];
        Buffer.BlockCopy(prefixBytes, 0, pae, 0, prefixBytes.Length);
        Buffer.BlockCopy(payload, 0, pae, prefixBytes.Length, payload.Length);
        return pae;
    }

    // ── trust-material factory helpers ────────────────────────────────────────

    // Returns a verifier backed by an empty stub store, plus trust material built from anchors.
    private static (PyPiProvenanceVerifier Verifier, PyPiTrustMaterial Trust) VerifierTrusting(
        X509Certificate2[] roots, params (string Issuer, string Subject)[] publishers)
    {
        var trust = BuildTrustMaterialNoRekor(roots, publishers);
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);
        return (verifier, trust);
    }

    private static (PyPiProvenanceVerifier Verifier, PyPiTrustMaterial Trust) VerifierTrustingWithRekor(
        X509Certificate2[] roots,
        ECDsa rekorKey,
        params (string Issuer, string Subject)[] publishers)
    {
        var trust = BuildTrustMaterialWithRekor(roots, rekorKey, publishers);
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);
        return (verifier, trust);
    }

    // Builds trust material from cert roots and publishers, with no Rekor keys.
    private static PyPiTrustMaterial BuildTrustMaterialNoRekor(
        X509Certificate2[] roots,
        (string Issuer, string Subject)[] publishers)
    {
        var anchors = new List<TrustAnchorMaterial>();

        foreach (var cert in roots)
        {
            anchors.Add(new TrustAnchorMaterial
            {
                Id = Guid.NewGuid().ToString(),
                AnchorKind = "sigstore_root",
                Material = Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
            });
        }

        foreach (var (issuer, subject) in publishers)
        {
            anchors.Add(new TrustAnchorMaterial
            {
                Id = Guid.NewGuid().ToString(),
                AnchorKind = "trusted_publisher",
                Material = JsonSerializer.Serialize(new { issuer, subject, match = "prefix" }),
            });
        }

        return PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);
    }

    // Builds trust material with one Rekor log key and optional roots/publishers.
    internal static PyPiTrustMaterial BuildTrustMaterialWithRekor(
        X509Certificate2[] roots,
        ECDsa rekorKey,
        (string Issuer, string Subject)[] publishers)
    {
        var anchors = new List<TrustAnchorMaterial>();

        foreach (var cert in roots)
        {
            anchors.Add(new TrustAnchorMaterial
            {
                Id = Guid.NewGuid().ToString(),
                AnchorKind = "sigstore_root",
                Material = Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
            });
        }

        foreach (var (issuer, subject) in publishers)
        {
            anchors.Add(new TrustAnchorMaterial
            {
                Id = Guid.NewGuid().ToString(),
                AnchorKind = "trusted_publisher",
                Material = JsonSerializer.Serialize(new { issuer, subject, match = "prefix" }),
            });
        }

        // Compute the log id as SHA-256(SPKI DER) and encode as base64.
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        string logIdB64 = Convert.ToBase64String(SHA256.HashData(spki));
        string keyB64 = Convert.ToBase64String(spki);

        anchors.Add(new TrustAnchorMaterial
        {
            Id = Guid.NewGuid().ToString(),
            AnchorKind = "rekor_key",
            KeyId = logIdB64,
            Material = keyB64,
        });

        return PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);
    }
}
