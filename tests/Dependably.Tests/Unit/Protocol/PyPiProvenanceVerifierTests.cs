using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="PyPiProvenanceVerifier"/> end to end with a self-generated CA → leaf
/// (ECDSA P-256) certificate chain (never a real Sigstore/Fulcio key) and a hand-built PEP 740
/// attestation: an in-toto statement bound to a file's name + sha256, wrapped in a DSSE envelope
/// signed by the leaf, wrapped in a Sigstore bundle carrying the Fulcio-style leaf certificate.
///
/// The verifier must accept an attestation that passes all four offline checks (digest binding,
/// DSSE signature, chain to a pinned root, identity match) and reject everything else — digest
/// mismatch, tampered DSSE signature, untrusted root, identity not in the allowlist, no attestation,
/// malformed JSON — without ever throwing.
///
/// Fixed certificate validity dates keep the test deterministic (no wall-clock read); the verifier
/// builds its chain with IgnoreNotTimeValid, so the pin — not the clock — is the trust decision.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiProvenanceVerifierTests
{
    private static readonly DateTimeOffset NotBefore = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private const string FileName = "example-1.0.0-py3-none-any.whl";
    private const string FileSha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    private const string Issuer = "https://token.actions.githubusercontent.com";
    private const string Identity = "https://github.com/example/example/.github/workflows/publish.yml@refs/heads/main";

    // ── happy path ─────────────────────────────────────────────────────────

    [Fact]
    public void ValidAttestation_AllChecksPass_Verifies()
    {
        var (root, leaf) = BuildChain();
        string json = ProvenanceDocument(leaf, FileName, FileSha256);
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    // ── failure paths ────────────────────────────────────────────────────────

    [Fact]
    public void DigestMismatch_Fails()
    {
        var (root, leaf) = BuildChain();
        // The attestation binds a DIFFERENT digest than the file dependably verified.
        string otherSha = new('a', 64);
        string json = ProvenanceDocument(leaf, FileName, otherSha);
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void TamperedDsseSignature_Fails()
    {
        var (root, leaf) = BuildChain();
        string json = ProvenanceDocument(leaf, FileName, FileSha256, tamperSignature: true);
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void UntrustedRoot_Fails()
    {
        var (_, leaf) = BuildChain();
        string json = ProvenanceDocument(leaf, FileName, FileSha256);
        // Pin a DIFFERENT root: the signature is valid but the leaf chains to an anchor we did not pin.
        var (otherRoot, _) = BuildChain();
        var (verifier, trust) = VerifierTrusting(new[] { otherRoot }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void IdentityNotInAllowlist_Fails()
    {
        var (root, leaf) = BuildChain();
        string json = ProvenanceDocument(leaf, FileName, FileSha256);
        // Right root, but the Trusted Publisher allowlist names a different repo.
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/someone-else/repo/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void WrongIssuer_Fails()
    {
        var (root, leaf) = BuildChain();
        string json = ProvenanceDocument(leaf, FileName, FileSha256);
        // Right subject prefix, but a different OIDC issuer than the cert carries.
        var (verifier, trust) = VerifierTrusting(new[] { root }, ("https://gitlab.com", "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void SubjectNameMismatch_Fails()
    {
        var (root, leaf) = BuildChain();
        // The in-toto subject names a different file than the one being served.
        string json = ProvenanceDocument(leaf, "some-other-file-2.0.0.tar.gz", FileSha256);
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, json, trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── unsigned ───────────────────────────────────────────────────────────

    [Fact]
    public void NoAttestation_NullDocument_Unsigned()
    {
        var (root, _) = BuildChain();
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, provenanceJson: null, trust);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void EmptyBundleList_Unsigned()
    {
        var (root, _) = BuildChain();
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(
            FileName, FileSha256, """{ "version": 1, "attestation_bundles": [] }""", trust);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    // ── malformed → Failed, never throws ──────────────────────────────────────

    [Fact]
    public void MalformedJson_Fails_DoesNotThrow()
    {
        var (root, _) = BuildChain();
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(FileName, FileSha256, "{ this is not valid json", trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public void BundleMissingEnvelope_Fails()
    {
        var (root, _) = BuildChain();
        var (verifier, trust) = VerifierTrusting(new[] { root }, (Issuer, "https://github.com/example/example/"));

        var result = verifier.VerifyAttestation(
            FileName, FileSha256, """{ "attestation_bundles": [ { "attestations": [ { } ] } ] }""", trust);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── configuration (PyPiTrustMaterial.IsConfigured) ────────────────────────

    [Fact]
    public void RootButNoPublishers_NotConfigured()
    {
        var (root, _) = BuildChain();
        var material = TrustStoreWith(new[] { root }, Array.Empty<(string, string)>());
        Assert.False(material.IsConfigured);
    }

    [Fact]
    public void PublishersButNoRoot_NotConfigured()
    {
        var material = TrustStoreWith(Array.Empty<X509Certificate2>(), new[] { (Issuer, "x") });
        Assert.False(material.IsConfigured);
    }

    [Fact]
    public void BothRootAndPublisher_Configured()
    {
        var (root, _) = BuildChain();
        var material = TrustStoreWith(new[] { root }, new[] { (Issuer, "x") });
        Assert.True(material.IsConfigured);
    }

    [Fact]
    public async Task MetadataDrivenVerify_IsNotApplicableForPyPi()
    {
        var (root, _) = BuildChain();
        var (verifier, _) = VerifierTrusting(new[] { root }, (Issuer, "x"));

        // PyPI attestations are fetched as a separate provenance document, not from the registry
        // metadata signature list; the ProvenanceInput entry point must report NotApplicable.
        var result = await verifier.VerifyAsync(new ProvenanceInput("pypi", "example", "1.0.0", null, []));

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    // ── fixture helpers ────────────────────────────────────────────────────────

    // Fulcio OIDC-issuer (v2) extension OID and SAN OID.
    private const string FulcioIssuerV2Oid = "1.3.6.1.4.1.57264.1.8";
    private const string SanOid = "2.5.29.17";
    private const string InTotoPayloadType = "application/vnd.in-toto+json";

    // Builds a self-signed CA root and an ECDSA P-256 leaf signed by it. The leaf carries a SAN URI
    // (the publisher identity) and the Fulcio v2 OIDC-issuer extension, plus its signing key.
    private static (X509Certificate2 Root, X509Certificate2 Leaf) BuildChain()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Dependably Test Sigstore Root", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        var root = rootReq.CreateSelfSigned(NotBefore, NotAfter);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=sigstore-intermediate", leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(BuildSanUriExtension(Identity));
        leafReq.CertificateExtensions.Add(BuildFulcioIssuerExtension(Issuer));

        byte[] serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        var leafPublic = leafReq.Create(root, NotBefore, NotAfter, serial);
        var leaf = leafPublic.CopyWithPrivateKey(leafKey);
        return (root, leaf);
    }

    // Encodes a SAN extension containing a single uniformResourceIdentifier ([6] IA5String).
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

    // Encodes the Fulcio v2 OIDC-issuer extension: a DER UTF8String of the issuer URL.
    private static X509Extension BuildFulcioIssuerExtension(string issuer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, issuer);
        return new X509Extension(new Oid(FulcioIssuerV2Oid), writer.Encode(), critical: false);
    }

    // Builds a full PEP 740 provenance document: the in-toto statement bound to (fileName, sha256),
    // DSSE-signed by the leaf key over the PAE, wrapped in a Sigstore bundle carrying the leaf cert.
    private static string ProvenanceDocument(
        X509Certificate2 leaf, string fileName, string sha256, bool tamperSignature = false)
    {
        // In-toto statement (the DSSE payload).
        string statement = JsonSerializer.Serialize(new
        {
            _type = "https://in-toto.io/Statement/v1",
            subject = new[] { new { name = fileName, digest = new { sha256 } } },
            predicateType = "https://docs.pypi.org/attestations/publish/v1",
            predicate = new { },
        });
        byte[] payload = Encoding.UTF8.GetBytes(statement);

        // DSSE PAE = "DSSEv1 " len(type) " " type " " len(payload) " " payload.
        byte[] pae = BuildDssePae(InTotoPayloadType, payload);

        using var key = leaf.GetECDsaPrivateKey()!;
        byte[] signature = key.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        if (tamperSignature)
        {
            signature[signature.Length / 2] ^= 0xFF;
        }

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
                            verification_material = new
                            {
                                certificate = new { raw_bytes = certB64 },
                            },
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

    // ── per-org enforcement ───────────────────────────────────────────────────

    [Fact]
    public async Task PerOrg_OrgAWithAnchors_OrgBWithout_IndependentResults()
    {
        // Org A has a root + publisher anchor in the stub; org B has none.
        // IsConfiguredForAsync(orgA) must be true; IsConfiguredForAsync(orgB) must be false.
        // GetPyPiTrustAsync(orgA) must return IsConfigured=true; orgB returns Empty.
        var (root, _) = BuildChain();
        string rootB64 = Convert.ToBase64String(root.Export(X509ContentType.Cert));
        const string OrgA = "org-a";
        const string OrgB = "org-b";

        var stub = new StubPerOrgTrustAnchorStore();
        stub.AddAnchor(OrgA, "pypi", new Dependably.Infrastructure.TrustAnchorMaterial
        {
            Id = "r1",
            AnchorKind = "sigstore_root",
            Material = rootB64,
        });
        stub.AddAnchor(OrgA, "pypi", new Dependably.Infrastructure.TrustAnchorMaterial
        {
            Id = "p1",
            AnchorKind = "trusted_publisher",
            Material = JsonSerializer.Serialize(new { issuer = Issuer, subject = "https://github.com/example/example/", match = "prefix" }),
        });

        var verifier = new PyPiProvenanceVerifier(stub, NullLogger<PyPiProvenanceVerifier>.Instance);

        Assert.True(await verifier.IsConfiguredForAsync(OrgA));
        Assert.False(await verifier.IsConfiguredForAsync(OrgB));

        var trustA = await verifier.GetTrustMaterialAsync(OrgA);
        var trustB = await verifier.GetTrustMaterialAsync(OrgB);

        Assert.True(trustA.IsConfigured);
        Assert.False(trustB.IsConfigured);
        Assert.Same(PyPiTrustMaterial.Empty, trustB);
    }

    // ── row → PyPiTrustMaterial loader ──────────────────────────────────────

    [Fact]
    public void BuildFromAnchors_BothHalves_IsConfiguredTrue()
    {
        // IsConfigured requires at least one root AND at least one publisher.
        var (root, _) = BuildChain();
        string rootB64 = Convert.ToBase64String(root.Export(X509ContentType.Cert));

        var anchors = new List<Dependably.Infrastructure.TrustAnchorMaterial>
        {
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = rootB64 },
            new() { Id = "p1", AnchorKind = "trusted_publisher",
                Material = JsonSerializer.Serialize(new { issuer = Issuer, subject = "https://github.com/example/", match = "prefix" }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);
        Assert.True(material.IsConfigured);
    }

    [Fact]
    public void BuildFromAnchors_RootOnly_IsConfiguredFalse()
    {
        // A root without any publisher cannot have IsConfigured = true.
        var (root, _) = BuildChain();
        string rootB64 = Convert.ToBase64String(root.Export(X509ContentType.Cert));

        var anchors = new List<Dependably.Infrastructure.TrustAnchorMaterial>
        {
            new() { Id = "r1", AnchorKind = "sigstore_root", Material = rootB64 },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);
        Assert.False(material.IsConfigured);
    }

    [Fact]
    public void BuildFromAnchors_PublisherOnly_IsConfiguredFalse()
    {
        // A publisher without a root cannot have IsConfigured = true.
        var anchors = new List<Dependably.Infrastructure.TrustAnchorMaterial>
        {
            new() { Id = "p1", AnchorKind = "trusted_publisher",
                Material = JsonSerializer.Serialize(new { issuer = Issuer, subject = "https://github.com/example/", match = "prefix" }) },
        };

        var material = PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);
        Assert.False(material.IsConfigured);
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

    // Returns a verifier backed by a per-org stub store and the corresponding PyPiTrustMaterial.
    // The material must be passed to VerifyAttestation at call sites.
    private static (PyPiProvenanceVerifier Verifier, PyPiTrustMaterial Trust) VerifierTrusting(
        X509Certificate2[] roots, params (string Issuer, string Subject)[] publishers)
    {
        var trust = BuildMaterial(roots, publishers);
        var stub = new StubPerOrgTrustAnchorStore();
        var verifier = new PyPiProvenanceVerifier(stub, NullLogger<PyPiProvenanceVerifier>.Instance);
        return (verifier, trust);
    }

    // Builds PyPiTrustMaterial directly from certificates and publisher tuples — no config needed.
    internal static PyPiTrustMaterial BuildMaterial(
        X509Certificate2[] roots, (string Issuer, string Subject)[] publishers)
    {
        var rootColl = new X509Certificate2Collection();
        foreach (var root in roots)
        {
            rootColl.Add(root);
        }

        var pubList = publishers
            .Select(p => new TrustedPublisher(p.Issuer, p.Subject, TrustedPublisherMatchMode.Prefix))
            .ToList();

        return new PyPiTrustMaterial(rootColl, pubList, new List<RekorLogKey>());
    }

    // TrustStoreWith builds PyPiTrustMaterial to check IsConfigured in the configuration tests.
    private static PyPiTrustMaterial TrustStoreWith(
        X509Certificate2[] roots, (string Issuer, string Subject)[] publishers)
        => BuildMaterial(roots, publishers);
}
