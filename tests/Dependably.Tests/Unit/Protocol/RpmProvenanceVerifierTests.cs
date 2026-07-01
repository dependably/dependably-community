using System.Buffers.Binary;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="RpmProvenanceVerifier"/> end-to-end with self-generated OpenPGP keys
/// and hand-crafted RPM binary fixtures. The verifier resolves the per-org trust ring from
/// <see cref="StubPerOrgTrustAnchorStore"/> and confirms key-pinning on the extracted
/// OpenPGP blob; the test constructs minimal RPM lead + signature header structures with the
/// <c>RPMSIGTAG_GPG</c> (1005) tag.
///
/// The verifier's security note explicitly states that full content-over-bytes verification
/// is bounded by UpstreamClient's SHA-256 hash-and-stage; here we verify the key-pinning
/// and format-parsing paths only.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmProvenanceVerifierTests
{
    // Minimal payload — actual content doesn't affect key-pinning verification.
    private static readonly byte[] SamplePayload = Encoding.UTF8.GetBytes("rpm-header-payload-stub");

    // Org ID used in per-org tests.
    private const string TestOrgId = "test-org";

    // ── happy path ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidGpgTag_FromPinnedKey_Verifies()
    {
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpbBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, rpbBlob);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
        Assert.Matches("^[0-9a-f]+$", result.Signer);
    }

    [Fact]
    public async Task ValidPgpTag_FromPinnedKey_Verifies()
    {
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagPgp, sigBlob);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── failure paths ───────────────────────────────────────────────────────────

    [Fact]
    public async Task WrongKey_KeyNotPinned_Fails()
    {
        var (secretKey, _) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, sigBlob);
        // Pin a DIFFERENT key — signature is well-formed but keyid is not in the pinned ring.
        var (_, differentPublicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(differentPublicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task NoSignatureTag_IsUnsigned()
    {
        // RPM with a valid lead + signature header but NO OpenPGP tag entries.
        byte[] rpmBytes = BuildRpmWithNoSigTag();
        var (_, publicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    [Fact]
    public async Task MalformedRpmLead_Fails()
    {
        // Bytes that don't start with the RPM lead magic.
        byte[] notRpm = Encoding.UTF8.GetBytes("not an RPM file at all");
        var (_, publicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(notRpm), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task TruncatedRpm_Fails()
    {
        // RPM truncated mid-signature-header.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, sigBlob);
        // Keep only the lead + 8 bytes of the sig header.
        byte[] truncated = rpmBytes[..(LeadSize + 8)];
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(truncated), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task MalformedSigBlob_NotPgpData_Fails()
    {
        // Embed garbage bytes as the signature blob — OpenPGP parsing must fail gracefully.
        byte[] garbage = Encoding.UTF8.GetBytes("not an OpenPGP signature");
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, garbage);
        var (_, publicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task NotConfigured_ReturnsNotApplicable()
    {
        // No anchors in the store → org has no trust ring → NotApplicable.
        var verifier = new RpmProvenanceVerifier(
            new StubPerOrgTrustAnchorStore(),
            NullLogger<RpmProvenanceVerifier>.Instance);

        var (secretKey, _) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, sigBlob);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    // ── mixed / partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task Mixed_TwoRpms_OneSignedByPinnedKey_OtherByUnpinnedKey()
    {
        var (secretKeyA, publicKeyA) = GeneratePgpKeyPair();
        var (secretKeyB, _) = GeneratePgpKeyPair();

        byte[] sigBlobA = BuildRawPgpSignaturePacket(SamplePayload, secretKeyA);
        byte[] sigBlobB = BuildRawPgpSignaturePacket(SamplePayload, secretKeyB);

        byte[] rpmA = BuildRpmWithSigTag(SigTagGpg, sigBlobA);
        byte[] rpmB = BuildRpmWithSigTag(SigTagGpg, sigBlobB);

        // Pin only key A.
        var verifier = VerifierWithKey(publicKeyA);

        var resultA = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmA), maxBytes: 10 * 1024 * 1024);
        var resultB = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmB), maxBytes: 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.Equal(ProvenanceStatus.Failed, resultB.Status);
        Assert.NotNull(resultA.Signer);
        Assert.Null(resultB.Signer);
    }

    [Fact]
    public async Task Mixed_OneUnsigned_OneVerified_OneKeyNotPinned()
    {
        var (secretKeyPinned, publicKeyPinned) = GeneratePgpKeyPair();
        var (secretKeyUnpinned, _) = GeneratePgpKeyPair();

        byte[] sigPinned = BuildRawPgpSignaturePacket(SamplePayload, secretKeyPinned);
        byte[] sigUnpinned = BuildRawPgpSignaturePacket(SamplePayload, secretKeyUnpinned);

        byte[] rpmVerified = BuildRpmWithSigTag(SigTagGpg, sigPinned);
        byte[] rpmFailed = BuildRpmWithSigTag(SigTagGpg, sigUnpinned);
        byte[] rpmUnsigned = BuildRpmWithNoSigTag();

        var verifier = VerifierWithKey(publicKeyPinned);

        var verified = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmVerified), 10 * 1024 * 1024);
        var failed = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmFailed), 10 * 1024 * 1024);
        var unsigned = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmUnsigned), 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, verified.Status);
        Assert.Equal(ProvenanceStatus.Failed, failed.Status);
        Assert.Equal(ProvenanceStatus.Unsigned, unsigned.Status);
    }

    // ── VerifyBytes internal static (direct access) ──────────────────────────────

    [Fact]
    public void VerifyBytes_ValidGpgTag_Verifies()
    {
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, sigBlob);
        var keyRing = KeyRingFor(publicKey);

        var result = RpmProvenanceVerifier.VerifyBytes(rpmBytes, keyRing);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public void VerifyBytes_NoSigTag_ReturnsUnsigned()
    {
        byte[] rpmBytes = BuildRpmWithNoSigTag();
        var (_, publicKey) = GeneratePgpKeyPair();
        var keyRing = KeyRingFor(publicKey);

        var result = RpmProvenanceVerifier.VerifyBytes(rpmBytes, keyRing);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    // ── multi-entry signature-header scan ────────────────────────────────────────

    [Fact]
    public async Task ValidRsaTag_FromPinnedKey_Verifies()
    {
        // RPMSIGTAG_RSA (268) is accepted alongside GPG/PGP.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] rpmBytes = BuildRpmWithEntries((SigTagRsa, sigBlob));
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task NonSignatureEntryBeforeSigTag_IsSkipped_ThenVerifies()
    {
        // A leading non-OpenPGP tag entry must be scanned past to reach the GPG signature.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKey);
        byte[] filler = Encoding.UTF8.GetBytes("non-signature header blob");
        byte[] rpmBytes = BuildRpmWithEntries((NonSigTag, filler), (SigTagGpg, sigBlob));
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task MultipleSignatureTags_FirstInIndexOrderIsSelected()
    {
        // Selection is positional: the first OpenPGP tag in index order is the one verified.
        // Entry 1 (PGP) is signed by an UNPINNED key; entry 2 (GPG) by the PINNED key. First-match
        // picks entry 1 and fails — proving the scan does not prefer a later GPG over an earlier tag.
        var (secretPinned, publicPinned) = GeneratePgpKeyPair();
        var (secretUnpinned, _) = GeneratePgpKeyPair();
        byte[] firstPgp = BuildRawPgpSignaturePacket(SamplePayload, secretUnpinned);
        byte[] secondGpg = BuildRawPgpSignaturePacket(SamplePayload, secretPinned);
        byte[] rpmBytes = BuildRpmWithEntries((SigTagPgp, firstPgp), (SigTagGpg, secondGpg));
        var verifier = VerifierWithKey(publicPinned);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── RPM binary builder ───────────────────────────────────────────────────────

    // RPM lead magic bytes.
    private const byte Lead0 = 0xED;
    private const byte Lead1 = 0xAB;
    private const byte Lead2 = 0xEE;
    private const byte Lead3 = 0xDB;

    // Header intro magic bytes (shared by signature header and main header).
    private const byte HdrMagic0 = 0x8E;
    private const byte HdrMagic1 = 0xAD;
    private const byte HdrMagic2 = 0xE8;
    private const byte HdrVersion = 0x01;

    // Lead size; header intro is 16 bytes.
    private const int LeadSize = 96;
    private const int HdrIntroSize = 16;
    private const int IndexEntrySize = 16;

    // TypeBin used for OpenPGP signature blobs.
    private const int TypeBin = 7;

    // OpenPGP signature tag numbers.
    private const int SigTagGpg = 1005;
    private const int SigTagPgp = 1002;
    private const int SigTagRsa = 268;

    // A non-OpenPGP signature-header tag (RPMSIGTAG_SIZE) — scanned past, never selected.
    private const int NonSigTag = 1000;

    // Builds a minimal RPM binary with a single index entry carrying tag <paramref name="tag"/>
    // and the given <paramref name="sigBlob"/> in the store region. The rest of the RPM
    // (after the sig header) is a stub — it is not read by VerifyBytes.
    private static byte[] BuildRpmWithSigTag(int tag, byte[] sigBlob)
    {
        int nindex = 1;
        int hsize = sigBlob.Length;

        // index offset is 0 (relative to store start).
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // Lead: 96 bytes. Magic in first 4 bytes; rest zero.
        w.Write(Lead0); w.Write(Lead1); w.Write(Lead2); w.Write(Lead3);
        w.Write(new byte[LeadSize - 4]);

        // Signature header intro: magic(4) + reserved(4) + nindex(4 BE) + hsize(4 BE).
        w.Write(HdrMagic0); w.Write(HdrMagic1); w.Write(HdrMagic2); w.Write(HdrVersion);
        w.Write(new byte[4]); // reserved
        WriteInt32Be(w, nindex);
        WriteInt32Be(w, hsize);

        // One index entry: tag(4 BE) + type(4 BE) + offset(4 BE) + count(4 BE).
        WriteInt32Be(w, tag);
        WriteInt32Be(w, TypeBin);
        WriteInt32Be(w, 0); // offset in store
        WriteInt32Be(w, sigBlob.Length);

        // Store region: the sig blob bytes.
        w.Write(sigBlob);

        // Append minimal stub for the remainder (avoids any bounds check failures).
        w.Write(new byte[16]);

        return ms.ToArray();
    }

    // Builds a minimal RPM with an empty signature header (no index entries, no sig tags).
    private static byte[] BuildRpmWithNoSigTag()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write(Lead0); w.Write(Lead1); w.Write(Lead2); w.Write(Lead3);
        w.Write(new byte[LeadSize - 4]);

        // Sig header with 0 entries and 0 hsize.
        w.Write(HdrMagic0); w.Write(HdrMagic1); w.Write(HdrMagic2); w.Write(HdrVersion);
        w.Write(new byte[4]);
        WriteInt32Be(w, 0); // nindex = 0
        WriteInt32Be(w, 0); // hsize = 0

        // No index entries, no store. Add minimal stub.
        w.Write(new byte[16]);

        return ms.ToArray();
    }

    // Builds a minimal RPM whose signature header carries multiple index entries (each typed
    // TypeBin) in order, with their blobs concatenated in the store region. Lets a test place a
    // non-signature or earlier signature tag ahead of the one under test.
    private static byte[] BuildRpmWithEntries(params (int Tag, byte[] Blob)[] entries)
    {
        int nindex = entries.Length;
        int hsize = 0;
        foreach (var (_, blob) in entries)
        {
            hsize += blob.Length;
        }

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write(Lead0); w.Write(Lead1); w.Write(Lead2); w.Write(Lead3);
        w.Write(new byte[LeadSize - 4]);

        w.Write(HdrMagic0); w.Write(HdrMagic1); w.Write(HdrMagic2); w.Write(HdrVersion);
        w.Write(new byte[4]); // reserved
        WriteInt32Be(w, nindex);
        WriteInt32Be(w, hsize);

        int offset = 0;
        foreach (var (tag, blob) in entries)
        {
            WriteInt32Be(w, tag);
            WriteInt32Be(w, TypeBin);
            WriteInt32Be(w, offset); // offset into the store region
            WriteInt32Be(w, blob.Length);
            offset += blob.Length;
        }

        foreach (var (_, blob) in entries)
        {
            w.Write(blob);
        }

        w.Write(new byte[16]); // trailing stub
        return ms.ToArray();
    }

    private static void WriteInt32Be(BinaryWriter w, int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        w.Write(buf.ToArray());
    }

    // ── OpenPGP helpers ──────────────────────────────────────────────────────────

    private static (PgpSecretKey SecretKey, PgpPublicKey PublicKey) GeneratePgpKeyPair()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new SecureRandom(), 1024, 12));  // 1024-bit for test speed
        var kp = gen.GenerateKeyPair();

        var pgpPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp,
            new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification,
            pgpPair,
            "test-rpm-signer@example.com",
            SymmetricKeyAlgorithmTag.Null,
            passPhrase: null,
            useSha1: true,
            null, null,
            new SecureRandom());

        return (secretKey, secretKey.PublicKey);
    }

    // Produces a raw (non-armored) OpenPGP binary signature packet over the given data.
    // This matches what RPM embeds in the RPMSIGTAG_GPG tag.
    private static byte[] BuildRawPgpSignaturePacket(byte[] data, PgpSecretKey secretKey)
    {
        var privateKey = secretKey.ExtractPrivateKey(passPhrase: null);
        var sigGen = new PgpSignatureGenerator(
            secretKey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        sigGen.InitSign(PgpSignature.BinaryDocument, privateKey);
        sigGen.Update(data);

        using var ms = new MemoryStream();
        // Encode directly (no ArmoredOutputStream) to get raw binary OpenPGP packets.
        sigGen.Generate().Encode(ms);
        return ms.ToArray();
    }

    // Builds a PgpPublicKeyRingBundle containing the single given key.
    private static PgpPublicKeyRingBundle KeyRingFor(PgpPublicKey publicKey)
        => new([new PgpPublicKeyRing(publicKey.GetEncoded())]);

    // Constructs an RpmProvenanceVerifier with the given public key seeded as a per-org
    // trust anchor in the stub store under TestOrgId.
    private static RpmProvenanceVerifier VerifierWithKey(PgpPublicKey publicKey)
    {
        using var armoredMs = new MemoryStream();
        using (var ao = new ArmoredOutputStream(armoredMs))
        {
            publicKey.Encode(ao);
        }
        string armoredKey = Encoding.ASCII.GetString(armoredMs.ToArray());

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(TestOrgId, "rpm", new TrustAnchorMaterial
        {
            Id = "test-anchor",
            AnchorKind = "pgp",
            Material = armoredKey,
        });

        return new RpmProvenanceVerifier(store, NullLogger<RpmProvenanceVerifier>.Instance);
    }

    // ── per-org isolation ────────────────────────────────────────────────────────

    [Fact]
    public async Task PerOrgIsolation_OrgWithAnchor_BlocksUnsigned_OrgWithoutAnchor_IsNotApplicable()
    {
        // Org A has a trust anchor → unsigned RPM returns Unsigned (verification active).
        // Org B has no anchor → same RPM returns NotApplicable (verification not active).
        // Both observations from the same shared verifier instance, proving per-org scoping
        // with no restart between them.
        const string orgA = "org-with-anchor";
        const string orgB = "org-without-anchor";

        var (_, publicKey) = GeneratePgpKeyPair();
        byte[] unsignedRpm = BuildRpmWithNoSigTag();

        using var armoredMs = new MemoryStream();
        using (var ao = new ArmoredOutputStream(armoredMs))
        {
            publicKey.Encode(ao);
        }
        string armoredKey = Encoding.ASCII.GetString(armoredMs.ToArray());

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(orgA, "rpm", new TrustAnchorMaterial
        {
            Id = "anchor-a",
            AnchorKind = "pgp",
            Material = armoredKey,
        });
        // orgB intentionally has no anchor seeded.

        var verifier = new RpmProvenanceVerifier(store, NullLogger<RpmProvenanceVerifier>.Instance);

        var resultA = await verifier.VerifyPackageAsync(orgA, new MemoryStream(unsignedRpm), 10 * 1024 * 1024);
        var resultB = await verifier.VerifyPackageAsync(orgB, new MemoryStream(unsignedRpm), 10 * 1024 * 1024);

        // Org A has a trust anchor: verification is active and the unsigned package is flagged.
        Assert.Equal(ProvenanceStatus.Unsigned, resultA.Status);
        // Org B has no anchor: verification is not configured and result is not-applicable.
        Assert.Equal(ProvenanceStatus.NotApplicable, resultB.Status);
    }

    [Fact]
    public async Task PerOrgIsolation_OrgWithAnchor_AcceptsSigned_OrgWithDifferentAnchor_RejectsSamePackage()
    {
        // Org A trusts key A. Org B trusts key B. A package signed by key A:
        //   - Verifies for org A (key A matches anchor).
        //   - Fails for org B (key A not in org B's anchor ring).
        // Validates that each org's trust ring is independent.
        const string orgA = "org-a";
        const string orgB = "org-b";

        var (secretKeyA, publicKeyA) = GeneratePgpKeyPair();
        var (_, publicKeyB) = GeneratePgpKeyPair();

        byte[] sigBlob = BuildRawPgpSignaturePacket(SamplePayload, secretKeyA);
        byte[] rpmBytes = BuildRpmWithSigTag(SigTagGpg, sigBlob);

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(orgA, "rpm", AnchorFor(publicKeyA, "anchor-a"));
        store.AddAnchor(orgB, "rpm", AnchorFor(publicKeyB, "anchor-b"));

        var verifier = new RpmProvenanceVerifier(store, NullLogger<RpmProvenanceVerifier>.Instance);

        var resultA = await verifier.VerifyPackageAsync(orgA, new MemoryStream(rpmBytes), 10 * 1024 * 1024);
        var resultB = await verifier.VerifyPackageAsync(orgB, new MemoryStream(rpmBytes), 10 * 1024 * 1024);

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.Equal(ProvenanceStatus.Failed, resultB.Status);
    }

    private static TrustAnchorMaterial AnchorFor(PgpPublicKey publicKey, string id)
    {
        using var ms = new MemoryStream();
        using (var ao = new ArmoredOutputStream(ms))
        {
            publicKey.Encode(ao);
        }
        return new TrustAnchorMaterial
        {
            Id = id,
            AnchorKind = "pgp",
            Material = Encoding.ASCII.GetString(ms.ToArray()),
        };
    }
}
