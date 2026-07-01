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
/// Covers edge paths and error branches in <see cref="PyPiProvenanceVerifier"/> and
/// <see cref="PyPiSigstoreTrustStore"/> that are not exercised by the happy-path and
/// primary-failure scenarios in <see cref="PyPiProvenanceVerifierTests"/> and
/// <see cref="PyPiRekorVerifierTests"/>. Tests include:
/// <list type="bullet">
///   <item>Alternate attestation input shapes (bare array, single object with envelope).</item>
///   <item>Older x509_certificate_chain bundle structure.</item>
///   <item>Leaf with DNS SAN and v1 Fulcio issuer extension.</item>
///   <item>Malformed certificate bytes triggering the FormatException/CryptographicException catch.</item>
///   <item>Missing tlog entry fields causing TryParseTlogEntryFields failures.</item>
///   <item>Unknown Rekor log id (GetRekorKey returns null) path.</item>
///   <item>Missing Rekor inclusion_proof causing ParseInclusionProof null path.</item>
///   <item>Missing SET (inclusion_promise absent) failing VerifySignedEntryTimestamp.</item>
///   <item>ParseHashBytes — hex string input and base64 input.</item>
///   <item>TrustStore LoadRoots — whitespace entry skip and invalid-cert warning path.</item>
///   <item>TrustStore LoadPublishers — incomplete entry skip.</item>
///   <item>TrustStore LoadRekorKeys — missing fields skip, invalid key, mismatched keyId warning.</item>
///   <item>TrustStore ExtractBase64 — PEM armour strip path.</item>
///   <item>Mixed partial-failure: first attestation has no verification_material, second verifies.</item>
/// </list>
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiProvenanceEdgePathTests
{
    // ── shared certificate validity dates ────────────────────────────────────
    private static readonly DateTimeOffset NotBefore = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private const string FileName = "mypkg-1.0.0-py3-none-any.whl";
    private const string FileSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string Issuer = "https://token.actions.githubusercontent.com";
    private const string Subject = "https://github.com/org/repo/";
    private const string Identity = Subject + ".github/workflows/release.yml@refs/heads/main";

    // OID constants used by the fixture helpers.
    private const string FulcioIssuerV2Oid = "1.3.6.1.4.1.57264.1.8";
    private const string FulcioIssuerV1Oid = "1.3.6.1.4.1.57264.1.1";
    private const string SanOid = "2.5.29.17";
    private const string InTotoPayloadType = "application/vnd.in-toto+json";

    // ── ExtractAttestations: bare JSON array form ─────────────────────────────

    [Fact]
    public void BareAttestationArray_Verifies()
    {
        // PEP 691 files[].attestations is a raw JSON array of attestation objects.
        var (root, leaf) = BuildChain(identity: Identity);
        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // Wrap as a bare JSON array: [<attestation>]
        string json = JsonSerializer.Serialize(new[]
        {
            new
            {
                verification_material = new { certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) } },
                envelope = new
                {
                    statement = Convert.ToBase64String(payload),
                    signature = Convert.ToBase64String(sig),
                },
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    // ── ExtractAttestations: single inline attestation object ─────────────────

    [Fact]
    public void SingleInlineAttestationObject_Verifies()
    {
        // A lone attestation object (carries an "envelope" property) — the single-object path.
        var (root, leaf) = BuildChain(identity: Identity);
        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // Bare object (not wrapped in attestation_bundles, not a bare array).
        string json = JsonSerializer.Serialize(new
        {
            verification_material = new { certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) } },
            envelope = new
            {
                statement = Convert.ToBase64String(payload),
                signature = Convert.ToBase64String(sig),
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // A bare JSON object that has no "envelope" property is treated as unsigned (empty list).
    [Fact]
    public void SingleObjectWithoutEnvelopeProperty_Unsigned()
    {
        var (root, _) = BuildChain();
        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));

        var result = verifier.VerifyAttestation(FileName, FileSha256, """{"version":1,"publisher":"pypi"}""", trust);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    // ── x509_certificate_chain (older bundle structure) ────────────────────────

    [Fact]
    public void X509CertificateChainBundle_Verifies()
    {
        // Older Sigstore bundle: verification_material.x509_certificate_chain.certificates[].raw_bytes
        var (root, leaf) = BuildChain(identity: Identity);
        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                x509_certificate_chain = new
                                {
                                    certificates = new[]
                                    {
                                        new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── missing verification_material → null leaf → Failed ─────────────────────

    [Fact]
    public void MissingVerificationMaterial_Fails()
    {
        // The attestation is structurally an object with an envelope but no verification_material.
        // ExtractLeafCertificate returns null and VerifyOne returns Failed.
        var (root, leaf) = BuildChain();
        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        string json = JsonSerializer.Serialize(new
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
                            // no verification_material at all
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── malformed base64 certificate → CryptographicException path ─────────────

    [Fact]
    public void MalformedCertificateBase64_Fails_DoesNotThrow()
    {
        // The certificate raw_bytes is valid base64 but not a valid DER X.509 certificate.
        // This triggers the FormatException/CryptographicException catch in VerifyOne.
        var (root, _) = BuildChain();

        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(new byte[] { 0x01, 0x02, 0x03 }) },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(new byte[] { 1, 2 }),
                                signature = Convert.ToBase64String(new byte[] { 3, 4 }),
                            },
                        },
                    },
                },
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── leaf with DNS SAN only (no URI) + v1 Fulcio issuer ────────────────────

    [Fact]
    public void DnsSanLeaf_FulcioV1Issuer_Verifies()
    {
        // Build a leaf with a DNS SAN (not a URI) and the v1 Fulcio issuer extension (raw UTF-8,
        // not DER-wrapped). Both the DNS fallback and v1-issuer code paths must execute.
        string dnsName = "publisher.example.com";
        var (root, leaf) = BuildChainWithDnsSanAndV1Issuer(dnsName, Issuer);

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        string json = JsonSerializer.Serialize(new
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
                            verification_material = new { certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) } },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        // Trust the issuer + DNS name as the identity.
        var (verifier, trust) = MakeVerifier(root, (Issuer, dnsName));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(dnsName, result.Signer);
    }

    // ── Rekor: unknown log id (GetRekorKey returns null) ──────────────────────

    [Fact]
    public void RekorKeysConfigured_UnknownLogId_Fails()
    {
        // The tlog entry references a log id that is not in the trust store.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherRekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        // Build a bundle signed with otherRekorKey (but pin rekorKey in the store).
        string json = BuildRekorBundle(leaf, FileName, FileSha256, otherRekorKey, integratedTime,
            tamperProof: false, tamperSet: false);

        // Trust material contains rekorKey, but the bundle was signed with otherRekorKey.
        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── Rekor: missing inclusion_proof → ParseInclusionProof returns null ─────

    [Fact]
    public void RekorKeysConfigured_MissingInclusionProof_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes("{}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();

        string setJson = $"{{\"body\":\"{bodyB64}\",\"integratedTime\":{integratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":1}}";
        byte[] setBytes = Encoding.UTF8.GetBytes(setJson);
        byte[] setSig = rekorKey.SignData(setBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // tlog entry has no inclusion_proof — ParseInclusionProof must return null.
        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                tlog_entries = new[]
                                {
                                    new
                                    {
                                        canonicalized_body = bodyB64,
                                        integrated_time = integratedTime,
                                        log_index = 1L,
                                        log_id = new { key_id = logIdB64 },
                                        // no inclusion_proof property
                                        inclusion_promise = new { signed_entry_timestamp = Convert.ToBase64String(setSig) },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── Rekor: missing SET (inclusion_promise absent) → VerifySignedEntryTimestamp fails ──

    [Fact]
    public void RekorKeysConfigured_MissingInclusionPromise_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes("{}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);
        string rootHashB64 = Convert.ToBase64String(leafHash);

        // inclusion_proof is present but inclusion_promise is absent.
        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                tlog_entries = new[]
                                {
                                    new
                                    {
                                        canonicalized_body = bodyB64,
                                        integrated_time = integratedTime,
                                        log_index = 0L,
                                        log_id = new { key_id = logIdB64 },
                                        inclusion_proof = new
                                        {
                                            log_index = 0L,
                                            root_hash = rootHashB64,
                                            tree_size = 1L,
                                            hashes = Array.Empty<string>(),
                                        },
                                        // no inclusion_promise
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── Rekor: missing canonicalized_body → TryParseTlogEntryFields returns false ──

    [Fact]
    public void RekorKeysConfigured_MissingCanonicalizedBody_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);

        // tlog entry has no canonicalized_body — TryParseTlogEntryFields must return false.
        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                tlog_entries = new[]
                                {
                                    new
                                    {
                                        // no canonicalized_body
                                        integrated_time = integratedTime,
                                        log_index = 0L,
                                        log_id = new { key_id = logIdB64 },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── Rekor: missing integratedTime → TryParseTlogEntryFields returns false ──

    [Fact]
    public void RekorKeysConfigured_MissingIntegratedTime_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes("{}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);

        // tlog entry omits integrated_time entirely.
        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                tlog_entries = new[]
                                {
                                    new
                                    {
                                        canonicalized_body = bodyB64,
                                        // no integrated_time
                                        log_index = 0L,
                                        log_id = new { key_id = logIdB64 },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── Rekor: camelCase tlog entry property names (tlogEntries) ─────────────

    [Fact]
    public void RekorKeysConfigured_CamelCaseTlogEntries_Verifies()
    {
        // Some Sigstore clients emit camelCase property names instead of snake_case.
        // TryLocateTlogEntry must fall back to the camelCase "tlogEntries" property name.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sigBytes = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes(
            $"{{\"kind\":\"hashedrekord\",\"spec\":{{\"hash\":{{\"value\":\"{FileSha256}\"}}}}}}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();
        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);
        string rootHashB64 = Convert.ToBase64String(leafHash);
        long logIndex = 99L;

        string setJson = $"{{\"body\":\"{bodyB64}\",\"integratedTime\":{integratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{logIndex}}}";
        byte[] setJsonBytes = Encoding.UTF8.GetBytes(setJson);
        byte[] setSig = rekorKey.SignData(setJsonBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // Use camelCase property names throughout the tlog section.
        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                // camelCase: "tlogEntries" not "tlog_entries"
                                tlogEntries = new[]
                                {
                                    new
                                    {
                                        // camelCase: "canonicalizedBody"
                                        canonicalizedBody = bodyB64,
                                        integratedTime,
                                        logIndex,
                                        logId = new { keyId = logIdB64 },
                                        inclusionProof = new
                                        {
                                            logIndex = 0L,
                                            rootHash = rootHashB64,
                                            treeSize = 1L,
                                            hashes = Array.Empty<string>(),
                                        },
                                        inclusionPromise = new { signedEntryTimestamp = Convert.ToBase64String(setSig) },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sigBytes),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── Rekor: empty tlog_entries array → TryLocateTlogEntry returns false ────

    [Fact]
    public void RekorKeysConfigured_EmptyTlogEntriesArray_Fails()
    {
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // tlog_entries is present but empty.
        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
                                tlog_entries = Array.Empty<object>(),
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── ParseHashBytes — hex and base64 input paths ────────────────────────────

    [Fact]
    public void RekorInclusionProof_HexRootHash_Verifies()
    {
        // ParseHashBytes: a 64-char lowercase hex string is treated as a hex-encoded SHA-256.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes("{}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();
        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);

        // Provide root_hash as a lowercase hex string (not base64).
        string rootHashHex = Convert.ToHexString(leafHash).ToLowerInvariant();
        long logIndex = 5L;

        string setJson = $"{{\"body\":\"{bodyB64}\",\"integratedTime\":{integratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{logIndex}}}";
        byte[] setBytes = Encoding.UTF8.GetBytes(setJson);
        byte[] setSig = rekorKey.SignData(setBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
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
                                            root_hash = rootHashHex,   // hex string, not base64
                                            tree_size = 1L,
                                            hashes = Array.Empty<string>(),
                                        },
                                        inclusion_promise = new { signed_entry_timestamp = Convert.ToBase64String(setSig) },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── ParseHashBytes: non-64-char string falls through to base64 path ──────

    [Fact]
    public void RekorInclusionProof_ShortNonHexHashString_FallsToBase64()
    {
        // A string shorter than 64 chars that contains hex digits is not treated as hex;
        // it goes through Convert.FromBase64String. Use a valid base64-encoded root hash.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = BuildChain(identity: Identity);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();

        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes("{}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();
        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);

        // Provide root_hash as base64 (44 chars, < 64).
        string rootHashB64 = Convert.ToBase64String(leafHash);
        long logIndex = 3L;

        string setJson = $"{{\"body\":\"{bodyB64}\",\"integratedTime\":{integratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{logIndex}}}";
        byte[] setBytes = Encoding.UTF8.GetBytes(setJson);
        byte[] setSig = rekorKey.SignData(setBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        string json = JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
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
                                            root_hash = rootHashB64,   // base64 (< 64 chars)
                                            tree_size = 1L,
                                            hashes = Array.Empty<string>(),
                                        },
                                        inclusion_promise = new { signed_entry_timestamp = Convert.ToBase64String(setSig) },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var trust = PyPiRekorVerifierTests.BuildTrustMaterialWithRekor(
            new[] { root }, rekorKey, new[] { (Issuer, Subject) });
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

        // The base64 path is taken; since this is a valid proof, it should verify.
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);
        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── mixed partial-failure: first attestation missing verification_material, second verifies ─

    [Fact]
    public void MixedBundle_FirstMissingVerificationMaterial_SecondVerifies()
    {
        var (root, leaf) = BuildChain(identity: Identity);
        byte[] payload = BuildStatementPayload(FileName, FileSha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        string certB64 = Convert.ToBase64String(leaf.Export(X509ContentType.Cert));

        // First attestation: no verification_material → fails leaf extraction.
        // Second attestation: fully valid.
        string json = JsonSerializer.Serialize(new
        {
            version = 1,
            attestation_bundles = new[]
            {
                new
                {
                    attestations = new object[]
                    {
                        new
                        {
                            // missing verification_material
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                        new
                        {
                            verification_material = new { certificate = new { raw_bytes = certB64 } },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    // ── mixed partial-failure: all attestations fail → Failed (not Unsigned) ──

    [Fact]
    public void MixedBundle_AllAttestationsFail_ReturnsFailed()
    {
        var (root, leaf) = BuildChain(identity: Identity);

        // Both attestations have malformed statements (valid base64 but not valid JSON in-toto).
        string badStatement = Convert.ToBase64String(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        string certB64 = Convert.ToBase64String(leaf.Export(X509ContentType.Cert));

        string json = JsonSerializer.Serialize(new
        {
            version = 1,
            attestation_bundles = new[]
            {
                new
                {
                    attestations = new object[]
                    {
                        new
                        {
                            verification_material = new { certificate = new { raw_bytes = certB64 } },
                            envelope = new
                            {
                                statement = badStatement,
                                signature = Convert.ToBase64String(new byte[] { 1, 2, 3 }),
                            },
                        },
                        new
                        {
                            verification_material = new { certificate = new { raw_bytes = certB64 } },
                            envelope = new
                            {
                                statement = badStatement,
                                signature = Convert.ToBase64String(new byte[] { 4, 5, 6 }),
                            },
                        },
                    },
                },
            },
        });

        var (verifier, trust) = MakeVerifier(root, (Issuer, Subject));
        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        // At least one attestation present but none verified — must return Failed, not Unsigned.
        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── BuildFromAnchors: invalid cert entry is skipped with a warning ──────────

    [Fact]
    public void TrustStore_LoadRoots_InvalidCertEntry_IsSkippedAndNotConfigured()
    {
        // A base64 string that is not a valid DER certificate should be silently skipped;
        // BuildFromAnchors ends up with zero roots and IsConfigured is false.
        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = Convert.ToBase64String(new byte[] { 0x01, 0x02, 0x03 }) },
            new() { Id = "p1", AnchorKind = "trusted_publisher", Material = JsonSerializer.Serialize(new { issuer = Issuer, subject = Subject, match = "prefix" }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        Assert.False(material.IsConfigured);
        Assert.Empty(material.GetRoots());
    }

    // ── BuildFromAnchors: whitespace-only entry is skipped ───────────────────

    [Fact]
    public void TrustStore_LoadRoots_WhitespaceEntry_ValidEntryStillLoads()
    {
        // A whitespace-only sigstore_root entry should be silently skipped; the next valid
        // entry is still loaded and IsConfigured should be true.
        var (root, _) = BuildChain();
        string validRootB64 = Convert.ToBase64String(root.Export(X509ContentType.Cert));

        var anchors = new List<TrustAnchorMaterial>
        {
            // Whitespace-only entry (skipped) then valid entry.
            new() { Id = "r0", AnchorKind = "sigstore_root", Material = "   " },
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = validRootB64 },
            new() { Id = "p1", AnchorKind = "trusted_publisher", Material = JsonSerializer.Serialize(new { issuer = Issuer, subject = Subject, match = "prefix" }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        // One valid root loaded; whitespace entry skipped; IsConfigured should be true.
        Assert.True(material.IsConfigured);
        Assert.Single(material.GetRoots());
    }

    // ── BuildFromAnchors: publisher entry missing issuer/subject is skipped ───

    [Fact]
    public void TrustStore_LoadPublishers_MissingIssuer_IsSkipped()
    {
        // An entry with a missing issuer must be logged and skipped; Publishers.Count = 0 → not configured.
        var (root, _) = BuildChain();
        string validRootB64 = Convert.ToBase64String(root.Export(X509ContentType.Cert));

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = validRootB64 },
            // Entry has subject but no issuer — should be skipped.
            new() { Id = "p1", AnchorKind = "trusted_publisher", Material = JsonSerializer.Serialize(new { subject = Subject }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        // Publishers count is 0 because the incomplete entry was skipped.
        Assert.Empty(material.Publishers);
        Assert.False(material.IsConfigured);
    }

    [Fact]
    public void TrustStore_LoadPublishers_MissingSubject_IsSkipped()
    {
        // Same as above, but subject is missing instead of issuer.
        var (root, _) = BuildChain();
        string validRootB64 = Convert.ToBase64String(root.Export(X509ContentType.Cert));

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = validRootB64 },
            // Entry has issuer but no subject — should be skipped.
            new() { Id = "p1", AnchorKind = "trusted_publisher", Material = JsonSerializer.Serialize(new { issuer = Issuer }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        Assert.Empty(material.Publishers);
        Assert.False(material.IsConfigured);
    }

    // ── BuildFromAnchors: rekor_key entry missing key material is skipped ─────

    [Fact]
    public void TrustStore_LoadRekorKeys_MissingKeyId_HasNoRekorKeys()
    {
        // A rekor_key anchor with no key material (empty string) should be skipped.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string keyB64 = Convert.ToBase64String(rekorKey.ExportSubjectPublicKeyInfo());

        var anchors = new List<TrustAnchorMaterial>
        {
            // Provide only the material (key bytes) but empty KeyId — the row has empty material
            // to simulate the "missing key" failure path.
            new() { Id = "k1", AnchorKind = "rekor_key", Material = "" },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        Assert.False(material.HasRekorKeys);
    }

    [Fact]
    public void TrustStore_LoadRekorKeys_MissingKey_HasNoRekorKeys()
    {
        // A rekor_key anchor with empty material should be skipped since it can't be parsed.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        string logIdB64 = Convert.ToBase64String(SHA256.HashData(spki));

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "k1", AnchorKind = "rekor_key", KeyId = logIdB64, Material = "" },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        Assert.False(material.HasRekorKeys);
    }

    // ── BuildFromAnchors: invalid key material is skipped ────────────────────

    [Fact]
    public void TrustStore_LoadRekorKeys_InvalidKeyMaterial_HasNoRekorKeys()
    {
        // KeyId is valid base64 but the key bytes are not a valid ECDSA SPKI.
        string keyIdB64 = Convert.ToBase64String(new byte[32]);
        string badKeyB64 = Convert.ToBase64String(new byte[] { 0x01, 0x02, 0x03 });

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "k1", AnchorKind = "rekor_key", KeyId = keyIdB64, Material = badKeyB64 },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        Assert.False(material.HasRekorKeys);
    }

    // ── BuildFromAnchors: mismatched keyId logs warning, uses computed id ─────

    [Fact]
    public void TrustStore_LoadRekorKeys_MismatchedKeyId_UsesComputedId()
    {
        // The operator supplies a KeyId that does not match SHA-256(SPKI) of the key.
        // BuildFromAnchors must log a warning and use the computed id; GetRekorKey must match on
        // the computed id, not the configured (wrong) one.
        using var rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] computedLogId = SHA256.HashData(spki);
        string keyB64 = Convert.ToBase64String(spki);

        // Deliberately wrong KeyId: all zeros.
        string wrongKeyIdB64 = Convert.ToBase64String(new byte[32]);

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "k1", AnchorKind = "rekor_key", KeyId = wrongKeyIdB64, Material = keyB64 },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        // HasRekorKeys should still be true (the key parsed even though the KeyId was wrong).
        Assert.True(material.HasRekorKeys);

        // GetRekorKey with the COMPUTED id should find the key.
        var found = material.GetRekorKey(computedLogId);
        Assert.NotNull(found);

        // GetRekorKey with the WRONG (configured) id should NOT find the key.
        var notFound = material.GetRekorKey(new byte[32]);
        Assert.Null(notFound);
    }

    // ── ExtractBase64 — PEM armour strip path ────────────────────────────────

    [Fact]
    public void TrustStore_LoadRoots_PemInput_ParsedCorrectly()
    {
        // When a sigstore_root anchor is in PEM format, ExtractBase64 must strip the armour
        // and produce a valid DER certificate.
        var (root, _) = BuildChain();
        byte[] der = root.Export(X509ContentType.Cert);

        // Format as PEM manually.
        string pem = "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END CERTIFICATE-----";

        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = pem },
            new() { Id = "p1", AnchorKind = "trusted_publisher", Material = JsonSerializer.Serialize(new { issuer = Issuer, subject = Subject, match = "prefix" }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);

        Assert.True(material.IsConfigured);
        Assert.Single(material.GetRoots());
    }

    // ── TrustedPublisher.Matches — exact and prefix matching ─────────────────

    [Fact]
    public void TrustedPublisher_ExactMatch_Matches()
    {
        var publisher = new TrustedPublisher(Issuer, Identity);
        Assert.True(publisher.Matches(Issuer, Identity));
    }

    [Fact]
    public void TrustedPublisher_PrefixMatch_Matches()
    {
        // A publisher configured with a subject prefix must match any identity that starts with it.
        var publisher = new TrustedPublisher(Issuer, Subject);
        Assert.True(publisher.Matches(Issuer, Identity)); // Identity starts with Subject
    }

    [Fact]
    public void TrustedPublisher_WrongIssuer_NoMatch()
    {
        var publisher = new TrustedPublisher("https://other-issuer.example.com", Subject);
        Assert.False(publisher.Matches(Issuer, Identity));
    }

    [Fact]
    public void TrustedPublisher_WrongSubject_NoMatch()
    {
        var publisher = new TrustedPublisher(Issuer, "https://github.com/other-org/other-repo/");
        Assert.False(publisher.Matches(Issuer, Identity));
    }

    // ── Exact vs Prefix match mode ────────────────────────────────────────────

    [Fact]
    public void TrustedPublisher_ExactMode_RejectsLongerIdentity()
    {
        // An Exact-mode publisher pins a full workflow+ref identity.
        // The leaf's SAN is the full identity — exact match passes.
        var exact = new TrustedPublisher(Issuer, Identity, TrustedPublisherMatchMode.Exact);
        Assert.True(exact.Matches(Issuer, Identity));

        // A Prefix-mode publisher with only the org prefix accepts the same leaf.
        var prefix = new TrustedPublisher(Issuer, Subject, TrustedPublisherMatchMode.Prefix);
        Assert.True(prefix.Matches(Issuer, Identity));

        // Exact-mode publisher with only the org prefix rejects the longer leaf identity.
        var exactPrefix = new TrustedPublisher(Issuer, Subject, TrustedPublisherMatchMode.Exact);
        Assert.False(exactPrefix.Matches(Issuer, Identity));
    }

    [Fact]
    public void TrustedPublisher_ExactMode_DifferentRef_Fails()
    {
        // Exact match on a specific ref: a leaf with a different ref must be rejected.
        const string mainRef = "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main";
        const string prRef = "https://github.com/org/repo/.github/workflows/release.yml@refs/pull/99/merge";

        var publisher = new TrustedPublisher(Issuer, mainRef, TrustedPublisherMatchMode.Exact);

        Assert.True(publisher.Matches(Issuer, mainRef));
        Assert.False(publisher.Matches(Issuer, prRef));
    }

    // ── InferMatchMode smart default ──────────────────────────────────────────

    [Fact]
    public void InferMatchMode_WorkflowYmlWithRef_ReturnsExact()
    {
        // A subject that contains a .yml workflow path + @ref marker should infer Exact.
        const string workflowSubject =
            "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main";
        Assert.Equal(TrustedPublisherMatchMode.Exact, TrustedPublisher.InferMatchMode(workflowSubject));
    }

    [Fact]
    public void InferMatchMode_WorkflowYamlWithRef_ReturnsExact()
    {
        // Same as above but with a .yaml extension.
        const string workflowSubject =
            "https://github.com/org/repo/.github/workflows/publish.yaml@refs/tags/v1.0.0";
        Assert.Equal(TrustedPublisherMatchMode.Exact, TrustedPublisher.InferMatchMode(workflowSubject));
    }

    [Fact]
    public void InferMatchMode_OrgPrefix_ReturnsPrefix()
    {
        // An org/repo URL prefix with no workflow path infers Prefix.
        Assert.Equal(TrustedPublisherMatchMode.Prefix, TrustedPublisher.InferMatchMode("https://github.com/org/repo/"));
    }

    [Fact]
    public void InferMatchMode_RepoRootOnly_ReturnsPrefix()
    {
        // A short repository root identity with no workflow path infers Prefix.
        Assert.Equal(TrustedPublisherMatchMode.Prefix, TrustedPublisher.InferMatchMode("https://github.com/org/"));
    }

    // ── IsConfigured on trust material ───────────────────────────────────────

    [Fact]
    public void TrustMaterial_IsConfigured_TrueWhenRootsAndPublishersPresent()
    {
        // IsConfigured requires at least one root AND at least one publisher.
        var (root, _) = BuildChain();
        var configured = MakeTrustMaterial(new[] { root }, new[] { (Issuer, Subject) });
        Assert.True(configured.IsConfigured);

        var empty = MakeTrustMaterial(Array.Empty<X509Certificate2>(), Array.Empty<(string, string)>());
        Assert.False(empty.IsConfigured);
    }

    [Fact]
    public void Verifier_Ecosystem_IsPypi()
    {
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);
        Assert.Equal("pypi", verifier.Ecosystem);
    }

    // ── fixture helpers ────────────────────────────────────────────────────────

    // Builds a self-signed CA + ECDSA P-256 leaf with a SAN URI (the given identity) and the
    // Fulcio v2 OIDC-issuer extension.
    private static (X509Certificate2 Root, X509Certificate2 Leaf) BuildChain(
        string identity = Identity, string issuer = Issuer)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        var root = rootReq.CreateSelfSigned(NotBefore, NotAfter);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=sigstore-leaf", leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(BuildSanUriExtension(identity));
        leafReq.CertificateExtensions.Add(BuildFulcioV2IssuerExtension(issuer));

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        var leafPublic = leafReq.Create(root, NotBefore, NotAfter, serial);
        return (root, leafPublic.CopyWithPrivateKey(leafKey));
    }

    // Builds a leaf with a DNS SAN (not URI) and the v1 Fulcio issuer extension (raw UTF-8).
    private static (X509Certificate2 Root, X509Certificate2 Leaf) BuildChainWithDnsSanAndV1Issuer(
        string dnsName, string issuer)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Test Root DNS", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        var root = rootReq.CreateSelfSigned(NotBefore, NotAfter);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=sigstore-leaf-dns", leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(BuildSanDnsExtension(dnsName));
        leafReq.CertificateExtensions.Add(BuildFulcioV1IssuerExtension(issuer));

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        var leafPublic = leafReq.Create(root, NotBefore, NotAfter, serial);
        return (root, leafPublic.CopyWithPrivateKey(leafKey));
    }

    private static X509Extension BuildSanUriExtension(string uri)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, uri, new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        return new X509Extension(new Oid(SanOid), writer.Encode(), critical: false);
    }

    private static X509Extension BuildSanDnsExtension(string dnsName)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, dnsName, new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        return new X509Extension(new Oid(SanOid), writer.Encode(), critical: false);
    }

    // v2 issuer: DER UTF8String-wrapped issuer URL.
    private static X509Extension BuildFulcioV2IssuerExtension(string issuer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, issuer);
        return new X509Extension(new Oid(FulcioIssuerV2Oid), writer.Encode(), critical: false);
    }

    // v1 issuer: raw UTF-8 bytes (no DER wrapper).
    private static X509Extension BuildFulcioV1IssuerExtension(string issuer)
    {
        byte[] raw = Encoding.UTF8.GetBytes(issuer);
        return new X509Extension(new Oid(FulcioIssuerV1Oid), raw, critical: false);
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

    // Builds a fully-structured PEP 740 provenance document with a tlog entry.
    private static string BuildRekorBundle(
        X509Certificate2 leaf, string fileName, string sha256,
        ECDsa rekorKey, long integratedTime,
        bool tamperProof, bool tamperSet)
    {
        byte[] payload = BuildStatementPayload(fileName, sha256);
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);
        using var leafKey = leaf.GetECDsaPrivateKey()!;
        byte[] sig = leafKey.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] canonicalizedBody = Encoding.UTF8.GetBytes(
            $"{{\"kind\":\"hashedrekord\",\"spec\":{{\"hash\":{{\"value\":\"{sha256}\"}}}}}}");
        string bodyB64 = Convert.ToBase64String(canonicalizedBody);

        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logId = SHA256.HashData(spki);
        string logIdB64 = Convert.ToBase64String(logId);
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();

        byte[] leafHash = RekorMerkle.LeafHash(canonicalizedBody);
        string rootHashB64 = Convert.ToBase64String(tamperProof ? new byte[32] : leafHash);

        long logIndex = 7L;
        string setJson = $"{{\"body\":\"{bodyB64}\",\"integratedTime\":{integratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{logIndex}}}";
        byte[] setBytes = Encoding.UTF8.GetBytes(setJson);
        byte[] setSig = rekorKey.SignData(setBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        if (tamperSet) { setSig[setSig.Length / 2] ^= 0xFF; }

        return JsonSerializer.Serialize(new
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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = Convert.ToBase64String(leaf.Export(X509ContentType.Cert)) },
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
                                        },
                                        inclusion_promise = new { signed_entry_timestamp = Convert.ToBase64String(setSig) },
                                    },
                                },
                            },
                            envelope = new
                            {
                                statement = Convert.ToBase64String(payload),
                                signature = Convert.ToBase64String(sig),
                            },
                        },
                    },
                },
            },
        });
    }

    private static (PyPiProvenanceVerifier Verifier, PyPiTrustMaterial Trust) MakeVerifier(
        X509Certificate2 root, params (string Issuer, string Subject)[] publishers)
    {
        var trust = MakeTrustMaterial(new[] { root }, publishers);
        var verifier = new PyPiProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);
        return (verifier, trust);
    }

    // Builds PyPiTrustMaterial from cert roots and publishers using BuildFromAnchors.
    private static PyPiTrustMaterial MakeTrustMaterial(
        X509Certificate2[] roots, (string Issuer, string Subject)[] publishers)
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
}
