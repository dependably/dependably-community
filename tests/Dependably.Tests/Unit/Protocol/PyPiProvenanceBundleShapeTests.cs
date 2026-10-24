using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The structural edges of PEP 740 attestation verification: how the Fulcio leaf is carried in the
/// bundle, statements that bind the wrong thing, leaves whose key or certificate extensions are
/// unusable, and Rekor inclusion proofs that are missing, blank or span more than one leaf. Each
/// malformed shape is a refusal (<see cref="ProvenanceStatus.Failed"/>), each well-formed variant
/// still verifies, so the refusals are not simply "everything fails".
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiProvenanceBundleShapeTests
{
    private const string FileName = "requests-2.32.3-py3-none-any.whl";
    private const string Issuer = "https://token.actions.githubusercontent.com";
    private const string Identity = "https://github.com/psf/requests/.github/workflows/publish.yml@refs/heads/main";
    private const string PublishPredicate = "https://docs.pypi.org/attestations/publish/v1";
    private const string FulcioIssuerV2 = "1.3.6.1.4.1.57264.1.8";
    private const string SanOid = "2.5.29.17";
    private static readonly string FileSha = Convert.ToHexString(SHA256.HashData("wheel-bytes"u8.ToArray())).ToLowerInvariant();
    private static readonly DateTimeOffset NotBefore = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly PyPiProvenanceVerifier _verifier =
        new(new StubPerOrgTrustAnchorStore(), NullLogger<PyPiProvenanceVerifier>.Instance);

    [Fact]
    public void TheInstanceLevelFlag_IsFalse_BecauseTrustIsPerOrg()
        => Assert.False(_verifier.IsConfigured);

    // ── how the leaf certificate is carried ─────────────────────────────────────

    [Fact]
    public void ACertificateAsAPlainBase64String_Verifies()
    {
        var (root, leaf) = Chain();
        string doc = Doc(Attestation(leaf, Statement(), vm: new JsonObject { ["certificate"] = B64(leaf) }));

        Assert.Equal(ProvenanceStatus.Verified, Verify(doc, root).Status);
    }

    [Fact]
    public void ACertificateObjectWithCamelCaseRawBytes_Verifies()
    {
        var (root, leaf) = Chain();
        string doc = Doc(Attestation(leaf, Statement(),
            vm: new JsonObject { ["certificate"] = new JsonObject { ["rawBytes"] = B64(leaf) } }));

        Assert.Equal(ProvenanceStatus.Verified, Verify(doc, root).Status);
    }

    [Fact]
    public void AnEmptyCertificateObject_FallsBackToTheChain_SkippingEntriesWithNoBytes()
    {
        var (root, leaf) = Chain();
        var vm = new JsonObject
        {
            ["certificate"] = new JsonObject(),
            ["x509CertificateChain"] = new JsonObject
            {
                ["certificates"] = new JsonArray(new JsonObject(), new JsonObject { ["rawBytes"] = B64(leaf) }),
            },
        };

        Assert.Equal(ProvenanceStatus.Verified, Verify(Doc(Attestation(leaf, Statement(), vm: vm)), root).Status);
    }

    [Theory]
    [InlineData("certificate-of-the-wrong-json-kind")]
    [InlineData("chain-with-no-bytes")]
    public void ACertificateThatCannotBeRead_IsRefused(string shape)
    {
        var (root, leaf) = Chain();
        var vm = shape == "certificate-of-the-wrong-json-kind"
            ? new JsonObject { ["certificate"] = 42 }
            : new JsonObject
            {
                ["x509_certificate_chain"] = new JsonObject { ["certificates"] = new JsonArray(new JsonObject(), "  ") },
            };

        Assert.Equal(ProvenanceStatus.Failed, Verify(Doc(Attestation(leaf, Statement(), vm: vm)), root).Status);
    }

    // ── the statement ───────────────────────────────────────────────────────────

    [Fact]
    public void AStatementWithAnUnexpectedPredicateType_IsRefused()
    {
        var (root, leaf) = Chain();
        string doc = Doc(Attestation(leaf, Statement(predicateType: "https://example.invalid/other-predicate/v1")));

        Assert.Equal(ProvenanceStatus.Failed, Verify(doc, root).Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AStatementWithNoSubjectList_IsRefused(bool subjectIsNotAnArray)
    {
        var (root, leaf) = Chain();
        var statement = new JsonObject { ["predicateType"] = PublishPredicate };
        if (subjectIsNotAnArray)
        {
            statement["subject"] = "requests";
        }

        Assert.Equal(ProvenanceStatus.Failed,
            Verify(Doc(Attestation(leaf, Encoding.UTF8.GetBytes(statement.ToJsonString()))), root).Status);
    }

    // ── the leaf ────────────────────────────────────────────────────────────────

    [Fact]
    public void ALeafWithARsaKey_IsNotASigstoreLeaf_AndIsRefused()
    {
        var (root, leaf) = Chain(rsaLeaf: true);
        string doc = Doc(Attestation(leaf, Statement(), signWithLeafKey: false));

        Assert.Equal(ProvenanceStatus.Failed, Verify(doc, root).Status);
    }

    [Fact]
    public void AMalformedOidcIssuerExtension_LeavesNoIssuerToMatch_AndIsRefused()
    {
        var (root, leaf) = Chain(issuer: new X509Extension(new Oid(FulcioIssuerV2), new byte[] { 0xFF, 0x01 }, false));

        Assert.Equal(ProvenanceStatus.Failed, Verify(Doc(Attestation(leaf, Statement())), root).Status);
    }

    [Fact]
    public void ALeafWithNoOidcIssuerExtension_IsRefused()
    {
        var (root, leaf) = Chain(issuer: null, includeIssuer: false);

        Assert.Equal(ProvenanceStatus.Failed, Verify(Doc(Attestation(leaf, Statement())), root).Status);
    }

    [Fact]
    public void ALeafWithNoSubjectAlternativeName_IsRefused()
    {
        var (root, leaf) = Chain(san: null, includeSan: false);

        Assert.Equal(ProvenanceStatus.Failed, Verify(Doc(Attestation(leaf, Statement())), root).Status);
    }

    [Fact]
    public void AMalformedSubjectAlternativeName_LeavesNoIdentityToMatch_AndIsRefused()
    {
        var (root, leaf) = Chain(san: new X509Extension(new Oid(SanOid), new byte[] { 0x30, 0x05, 0x01 }, false));

        Assert.Equal(ProvenanceStatus.Failed, Verify(Doc(Attestation(leaf, Statement())), root).Status);
    }

    [Fact]
    public void AnEmailNameBeforeTheUri_IsSkipped_AndTheUriIsTheSigner()
    {
        var (root, leaf) = Chain(san: SanWithEmailThenUri("release-bot@example.com", Identity));

        var result = Verify(Doc(Attestation(leaf, Statement())), root);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(Identity, result.Signer);
    }

    [Fact]
    public void ALeafSigningForAnUnpinnedPublisher_IsRefused_EvenWhenTheChainAndSignatureAreSound()
    {
        var (root, leaf) = Chain();
        var trust = Trust(root, ("https://token.actions.githubusercontent.com", "https://github.com/another-org/"));

        Assert.Equal(ProvenanceStatus.Failed,
            _verifier.VerifyAttestation(FileName, FileSha, Doc(Attestation(leaf, Statement())), trust).Status);
    }

    // ── Rekor inclusion proofs ──────────────────────────────────────────────────

    [Fact]
    public void AProofSpanningTwoLeaves_VerifiesAgainstTheSiblingHash()
    {
        using var rekor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = Chain();
        string doc = Doc(RekorAttestation(leaf, rekor, ProofShape.TwoLeaves));

        Assert.Equal(ProvenanceStatus.Verified, VerifyWithRekor(doc, root, rekor).Status);
    }

    [Theory]
    [InlineData(ProofShape.BlankRootHash)]
    [InlineData(ProofShape.NoHashesProperty)]
    [InlineData(ProofShape.BlankHashEntry)]
    [InlineData(ProofShape.WrongSibling)]
    public void AMalformedOrForgedProof_IsRefused(ProofShape shape)
    {
        using var rekor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (root, leaf) = Chain();
        string doc = Doc(RekorAttestation(leaf, rekor, shape));

        Assert.Equal(ProvenanceStatus.Failed, VerifyWithRekor(doc, root, rekor).Status);
    }

    // ── fixtures ────────────────────────────────────────────────────────────────

    public enum ProofShape
    {
        TwoLeaves,
        BlankRootHash,
        NoHashesProperty,
        BlankHashEntry,
        WrongSibling,
    }

    private ProvenanceResult Verify(string doc, X509Certificate2 root)
        => _verifier.VerifyAttestation(FileName, FileSha, doc, Trust(root, (Issuer, "https://github.com/psf/")));

    private ProvenanceResult VerifyWithRekor(string doc, X509Certificate2 root, ECDsa rekor)
        => _verifier.VerifyAttestation(FileName, FileSha, doc, Trust(root, rekor, (Issuer, "https://github.com/psf/")));

    private static PyPiTrustMaterial Trust(X509Certificate2 root, params (string Issuer, string Subject)[] publishers)
        => Trust(root, null, publishers);

    private static PyPiTrustMaterial Trust(
        X509Certificate2 root, ECDsa? rekor, params (string Issuer, string Subject)[] publishers)
    {
        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "root", AnchorKind = "sigstore_root", Material = Convert.ToBase64String(root.Export(X509ContentType.Cert)) },
        };
        foreach (var (issuer, subject) in publishers)
        {
            anchors.Add(new TrustAnchorMaterial
            {
                Id = Guid.NewGuid().ToString(),
                AnchorKind = "trusted_publisher",
                Material = JsonSerializer.Serialize(new { issuer, subject, match = "prefix" }),
            });
        }

        if (rekor is not null)
        {
            byte[] spki = rekor.ExportSubjectPublicKeyInfo();
            anchors.Add(new TrustAnchorMaterial
            {
                Id = "rekor",
                AnchorKind = "rekor_key",
                KeyId = Convert.ToBase64String(SHA256.HashData(spki)),
                Material = Convert.ToBase64String(spki),
            });
        }

        return PyPiSigstoreTrustStore.BuildFromAnchors(anchors, NullLogger.Instance);
    }

    private static string B64(X509Certificate2 cert) => Convert.ToBase64String(cert.Export(X509ContentType.Cert));

    private static string Doc(JsonObject attestation)
        => new JsonObject
        {
            ["version"] = 1,
            ["attestation_bundles"] = new JsonArray(new JsonObject { ["attestations"] = new JsonArray(attestation) }),
        }.ToJsonString();

    private static byte[] Statement(string predicateType = PublishPredicate)
        => Encoding.UTF8.GetBytes(new JsonObject
        {
            ["_type"] = "https://in-toto.io/Statement/v1",
            ["subject"] = new JsonArray(new JsonObject
            {
                ["name"] = FileName,
                ["digest"] = new JsonObject { ["sha256"] = FileSha },
            }),
            ["predicateType"] = predicateType,
            ["predicate"] = new JsonObject(),
        }.ToJsonString());

    private static byte[] Pae(byte[] payload)
    {
        const string payloadType = "application/vnd.in-toto+json";
        byte[] prefix = Encoding.ASCII.GetBytes($"DSSEv1 {payloadType.Length} {payloadType} {payload.Length} ");
        return [.. prefix, .. payload];
    }

    private static JsonObject Attestation(
        X509Certificate2 leaf, byte[] statement, JsonObject? vm = null, bool signWithLeafKey = true)
    {
        byte[] signature;
        if (signWithLeafKey)
        {
            using var key = leaf.GetECDsaPrivateKey()!;
            signature = key.SignData(Pae(statement), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        else
        {
            signature = RandomNumberGenerator.GetBytes(64);
        }

        return new JsonObject
        {
            ["version"] = 1,
            ["verification_material"] = vm ?? new JsonObject { ["certificate"] = new JsonObject { ["raw_bytes"] = B64(leaf) } },
            ["envelope"] = new JsonObject
            {
                ["statement"] = Convert.ToBase64String(statement),
                ["signature"] = Convert.ToBase64String(signature),
            },
        };
    }

    private static JsonObject RekorAttestation(X509Certificate2 leaf, ECDsa rekor, ProofShape shape)
    {
        byte[] body = Encoding.UTF8.GetBytes($"{{\"kind\":\"hashedrekord\",\"spec\":{{\"hash\":\"{FileSha}\"}}}}");
        string bodyB64 = Convert.ToBase64String(body);
        long integratedTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();
        byte[] logId = SHA256.HashData(rekor.ExportSubjectPublicKeyInfo());
        string logIdHex = Convert.ToHexString(logId).ToLowerInvariant();
        const long logIndex = 7;

        byte[] leafHash = RekorMerkle.LeafHash(body);
        byte[] sibling = SHA256.HashData("a sibling leaf"u8.ToArray());
        byte[] twoLeafInput = [0x01, .. leafHash, .. sibling];
        byte[] twoLeafRoot = SHA256.HashData(twoLeafInput);
        var proof = new JsonObject { ["log_index"] = 0, ["tree_size"] = 2, ["checkpoint"] = "test" };
        switch (shape)
        {
            case ProofShape.TwoLeaves:
                proof["root_hash"] = Convert.ToBase64String(twoLeafRoot);
                proof["hashes"] = new JsonArray(Convert.ToBase64String(sibling));
                break;
            case ProofShape.BlankRootHash:
                proof["root_hash"] = "  ";
                proof["hashes"] = new JsonArray(Convert.ToBase64String(sibling));
                break;
            case ProofShape.NoHashesProperty:
                proof["root_hash"] = Convert.ToBase64String(twoLeafRoot);
                break;
            case ProofShape.BlankHashEntry:
                proof["root_hash"] = Convert.ToBase64String(twoLeafRoot);
                proof["hashes"] = new JsonArray("");
                break;
            default:
                proof["root_hash"] = Convert.ToBase64String(twoLeafRoot);
                proof["hashes"] = new JsonArray(Convert.ToBase64String(SHA256.HashData("someone else"u8.ToArray())));
                break;
        }

        string set = $"{{\"body\":\"{bodyB64}\",\"integratedTime\":{integratedTime},\"logID\":\"{logIdHex}\",\"logIndex\":{logIndex}}}";
        byte[] setSignature = rekor.SignData(
            Encoding.UTF8.GetBytes(set), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var vm = new JsonObject
        {
            ["certificate"] = new JsonObject { ["raw_bytes"] = B64(leaf) },
            ["tlog_entries"] = new JsonArray(new JsonObject
            {
                ["canonicalized_body"] = bodyB64,
                ["integrated_time"] = integratedTime,
                ["log_index"] = logIndex,
                ["log_id"] = new JsonObject { ["key_id"] = Convert.ToBase64String(logId) },
                ["inclusion_proof"] = proof,
                ["inclusion_promise"] = new JsonObject { ["signed_entry_timestamp"] = Convert.ToBase64String(setSignature) },
            }),
        };
        return Attestation(leaf, Statement(), vm);
    }

    private static (X509Certificate2 Root, X509Certificate2 Leaf) Chain(
        bool rsaLeaf = false,
        X509Extension? issuer = null,
        bool includeIssuer = true,
        X509Extension? san = null,
        bool includeSan = true)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Dependably Test Sigstore Root", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));
        var root = rootReq.CreateSelfSigned(NotBefore, NotAfter);

        CertificateRequest leafReq;
        AsymmetricAlgorithm leafKey;
        if (rsaLeaf)
        {
            var rsa = RSA.Create(2048);
            leafKey = rsa;
            leafReq = new CertificateRequest("CN=sigstore-leaf", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            leafKey = ec;
            leafReq = new CertificateRequest("CN=sigstore-leaf", ec, HashAlgorithmName.SHA256);
        }

        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        if (includeSan)
        {
            leafReq.CertificateExtensions.Add(san ?? SanWithUri(Identity));
        }

        if (includeIssuer)
        {
            leafReq.CertificateExtensions.Add(issuer ?? OidcIssuer(Issuer));
        }

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        X509Certificate2 leafPublic;
        if (rsaLeaf)
        {
            using var issuerKey = root.GetECDsaPrivateKey()!;
            leafPublic = leafReq.Create(
                root.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey), NotBefore, NotAfter, serial);
        }
        else
        {
            leafPublic = leafReq.Create(root, NotBefore, NotAfter, serial);
        }

        var leaf = leafKey switch
        {
            RSA r => leafPublic.CopyWithPrivateKey(r),
            ECDsa e => leafPublic.CopyWithPrivateKey(e),
            _ => throw new InvalidOperationException("unexpected key type"),
        };
        return (root, leaf);
    }

    private static X509Extension OidcIssuer(string issuer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, issuer);
        return new X509Extension(new Oid(FulcioIssuerV2), writer.Encode(), false);
    }

    private static X509Extension SanWithUri(string uri)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, uri, new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        return new X509Extension(new Oid(SanOid), writer.Encode(), false);
    }

    private static X509Extension SanWithEmailThenUri(string email, string uri)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, email, new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteCharacterString(UniversalTagNumber.IA5String, uri, new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        return new X509Extension(new Oid(SanOid), writer.Encode(), false);
    }
}
