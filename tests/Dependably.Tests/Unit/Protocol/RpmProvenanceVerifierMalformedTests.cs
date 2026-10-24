using System.Buffers.Binary;
using System.Security.Cryptography;
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
/// Hostile and degenerate RPM packages against <see cref="RpmProvenanceVerifier"/>: declared
/// header sizes beyond the bounds, truncation at each stage, signature-header entries that are
/// mistyped or point outside the store, unusable signature packets, payload-digest tags that are
/// absent or malformed, and a stream that fails mid-read. Each resolves to a refusal
/// (<see cref="ProvenanceStatus.Failed"/>, or <see cref="ProvenanceStatus.Unsigned"/> when no
/// OpenPGP entry is usable) and never to <see cref="ProvenanceStatus.Verified"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmProvenanceVerifierMalformedTests
{
    private const string OrgId = "org-rpm";
    private const long Cap = 10 * 1024 * 1024;
    private const int Lead = 96;
    private const int TypeBin = 7;
    private const int TypeInt32 = 4;
    private const int TypeStringArray = 8;
    private const int TagGpg = 1005;
    private const int TagPgp = 1002;
    private const int TagRsa = 268;
    private const int PayloadDigestTag = 5092;
    private const int PayloadDigestAlgoTag = 5093;

    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("rpm-cpio-payload-stub");

    // ── the verifier's own surface ──────────────────────────────────────────────

    [Fact]
    public async Task TheInstanceLevelSurface_NeverReportsAVerdict()
    {
        var verifier = new RpmProvenanceVerifier(new StubPerOrgTrustAnchorStore(), NullLogger<RpmProvenanceVerifier>.Instance);

        Assert.Equal("rpm", verifier.Ecosystem);
        Assert.False(verifier.IsConfigured);
        Assert.Equal(ProvenanceResult.NotApplicable, await verifier.VerifyAsync(
            new ProvenanceInput("rpm", "openssl", "3.2.2", null, [])));
    }

    [Fact]
    public async Task IsConfiguredFor_IsTrueOnlyForAnOrgWithAPinnedRpmAnchor()
    {
        var (_, publicKey) = Key();
        var verifier = Verifier(publicKey);

        Assert.True(await verifier.IsConfiguredForAsync(OrgId));
        Assert.False(await verifier.IsConfiguredForAsync("another-org"));
    }

    // ── declared sizes and truncation ───────────────────────────────────────────

    [Fact]
    public async Task ASignatureHeaderDeclaringMoreThanTheBound_IsRefusedWithoutReadingIt()
    {
        var (_, publicKey) = Key();
        byte[] rpm = Concat(LeadBytes(), Intro(nindex: 3_000_000, hsize: 0));

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ASignatureHeaderCutShort_IsRefused()
    {
        var (_, publicKey) = Key();
        byte[] rpm = Concat(LeadBytes(), Intro(nindex: 1, hsize: 64), new byte[20]);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task APackageEndingInsideTheAlignmentPadding_IsRefused()
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeader();
        byte[] blob = Sign(secret, Concat(main, Payload));
        // The store is not a multiple of 8, so padding follows it; the stream stops right at it.
        byte[] store = Concat(blob, new byte[blob.Length % 8 == 0 ? 3 : 0]);
        byte[] rpm = SigHeader([(TagGpg, TypeBin, 0, blob.Length)], store, padToEight: false);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.NotEqual(0, store.Length % 8);
        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(15)]
    public async Task AMainHeaderCutShortOrCorrupt_IsRefused(int mainHeaderBytes)
    {
        var (secret, publicKey) = Key();
        byte[] blob = Sign(secret, Concat(MainHeader(), Payload));
        byte[] rpm = Concat(SigHeader([(TagGpg, TypeBin, 0, blob.Length)], blob), new byte[mainHeaderBytes]);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task AMainHeaderWithoutTheHeaderMagic_IsRefused()
    {
        var (secret, publicKey) = Key();
        byte[] blob = Sign(secret, Concat(MainHeader(), Payload));
        byte[] rpm = Concat(SigHeader([(TagGpg, TypeBin, 0, blob.Length)], blob), new byte[16], Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── signature-header entries ────────────────────────────────────────────────

    [Fact]
    public async Task EntriesThatAreMistypedEmptyNegativeOrOutOfRange_AreSkipped_LeavingThePackageUnsigned()
    {
        var (_, publicKey) = Key();
        byte[] store = new byte[64];
        byte[] rpm = Concat(
            SigHeader(
            [
                (TagGpg, TypeInt32, 0, 8),
                (TagGpg, TypeBin, 0, 0),
                (TagGpg, TypeBin, -4, 8),
                (TagGpg, TypeBin, 60, 32),
                (1000, TypeBin, 0, 8),
            ], store),
            MainHeader(), Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    [Fact]
    public async Task GpgIsPreferredOverPgp_SoAForgedGpgBlobCannotBeMaskedByAValidPgpOne()
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeader();
        byte[] pgp = Sign(secret, Concat(main, Payload));
        byte[] garbageGpg = Encoding.UTF8.GetBytes("this is not a signature");
        byte[] store = Concat(pgp, garbageGpg);
        byte[] rpm = Concat(
            SigHeader([(TagPgp, TypeBin, 0, pgp.Length), (TagGpg, TypeBin, pgp.Length, garbageGpg.Length)], store),
            main, Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task APgpTag_IsPreferredOverTheHeaderOnlyRsaTag()
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeader();
        byte[] pgp = Sign(secret, Concat(main, Payload));
        byte[] garbageRsa = Encoding.UTF8.GetBytes("not a signature either");
        byte[] store = Concat(garbageRsa, pgp);
        byte[] rpm = Concat(
            SigHeader([(TagRsa, TypeBin, 0, garbageRsa.Length), (TagPgp, TypeBin, garbageRsa.Length, pgp.Length)], store),
            main, Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task ACompressedSignaturePacket_IsDecodedAndVerified()
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeader();
        byte[] raw = Sign(secret, Concat(main, Payload));
        byte[] compressed = Compress(raw);
        byte[] rpm = Concat(SigHeader([(TagGpg, TypeBin, 0, compressed.Length)], compressed), main, Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task AnOpenPgpObjectThatIsNotASignature_IsRefused()
    {
        var (_, publicKey) = Key();
        byte[] notASignature = publicKey.GetEncoded();
        byte[] rpm = Concat(
            SigHeader([(TagGpg, TypeBin, 0, notASignature.Length)], notASignature), MainHeader(), Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ASignatureFromAKeyOutsideThePinnedRing_IsRefused_EvenWhenItIsMathematicallyValid()
    {
        var (attacker, _) = Key();
        var (_, pinned) = Key();
        byte[] main = MainHeader();
        byte[] blob = Sign(attacker, Concat(main, Payload));
        byte[] rpm = Concat(SigHeader([(TagGpg, TypeBin, 0, blob.Length)], blob), main, Payload);

        var result = await Verifier(pinned).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── header-only (RSA) packages ──────────────────────────────────────────────

    [Fact]
    public async Task AHeaderOnlyPackage_DeclaringAnOversizedMainHeaderIndex_IsRefused()
    {
        var (secret, publicKey) = Key();
        byte[] blob = Sign(secret, [1, 2, 3]);
        byte[] oversizedIntro = Intro(nindex: 300_000, hsize: 0);
        byte[] rpm = Concat(SigHeader([(TagRsa, TypeBin, 0, blob.Length)], blob), oversizedIntro);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task AHeaderOnlyPackage_WhoseMainHeaderIndexIsCutShort_IsRefused()
    {
        var (secret, publicKey) = Key();
        byte[] blob = Sign(secret, [1, 2, 3]);
        byte[] rpm = Concat(
            SigHeader([(TagRsa, TypeBin, 0, blob.Length)], blob), Intro(nindex: 5, hsize: 0), new byte[10]);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Theory]
    [InlineData(TypeStringArray, 9999)]
    [InlineData(6, 0)]
    public async Task AHeaderOnlyPackage_WhosePayloadDigestEntryIsUnusable_IsRefused(int type, int offset)
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeaderWith(
            [(PayloadDigestTag, type, offset, 1)], Encoding.ASCII.GetBytes("filler-store\0"));
        byte[] blob = Sign(secret, main);
        byte[] rpm = Concat(SigHeader([(TagRsa, TypeBin, 0, blob.Length)], blob), main, Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task AHeaderOnlyPackage_WhoseDigestHasTheRightLengthButIsNotHex_IsRefused()
    {
        var (secret, publicKey) = Key();
        byte[] digest = Encoding.ASCII.GetBytes(new string('g', 64) + "\0");
        byte[] algo = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(algo, 8);
        byte[] main = MainHeaderWith(
            [(PayloadDigestTag, TypeStringArray, 0, 1), (PayloadDigestAlgoTag, TypeInt32, digest.Length, 1)],
            Concat(digest, algo));
        byte[] blob = Sign(secret, main);
        byte[] rpm = Concat(SigHeader([(TagRsa, TypeBin, 0, blob.Length)], blob), main, Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task AHeaderOnlyPackage_WithAGenuineDigest_Verifies_ButNotWhenTheStreamRunsPastTheCap()
    {
        var (secret, publicKey) = Key();
        string hex = Convert.ToHexString(SHA256.HashData(Payload)).ToLowerInvariant();
        byte[] digest = Encoding.ASCII.GetBytes(hex + "\0");
        byte[] algo = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(algo, 8);
        byte[] main = MainHeaderWith(
            [(PayloadDigestTag, TypeStringArray, 0, 1), (PayloadDigestAlgoTag, TypeInt32, digest.Length, 1)],
            Concat(digest, algo));
        byte[] blob = Sign(secret, main);
        byte[] rpm = Concat(SigHeader([(TagRsa, TypeBin, 0, blob.Length)], blob), main, Payload);
        var verifier = Verifier(publicKey);

        var whole = await verifier.VerifyPackageAsync(OrgId, new MemoryStream(rpm), rpm.Length);
        var capped = await verifier.VerifyPackageAsync(OrgId, new MemoryStream(rpm), rpm.Length - 1);

        Assert.Equal(ProvenanceStatus.Verified, whole.Status);
        Assert.Equal(ProvenanceStatus.Failed, capped.Status);
    }

    [Fact]
    public async Task ANonPositiveCap_MeansUnboundedRatherThanZeroBytes()
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeader();
        byte[] blob = Sign(secret, Concat(main, Payload));
        byte[] rpm = Concat(SigHeader([(TagGpg, TypeBin, 0, blob.Length)], blob), main, Payload);

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), 0);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    // ── a failing stream ────────────────────────────────────────────────────────

    [Fact]
    public async Task AStreamThatFailsMidRead_IsReportedUnverifiable_NotThrown()
    {
        var (_, publicKey) = Key();

        var result = await Verifier(publicKey).VerifyPackageAsync(OrgId, new FaultingStream(), Cap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task ACancelledVerification_Propagates_RatherThanBecomingAVerdict()
    {
        var (secret, publicKey) = Key();
        byte[] main = MainHeader();
        byte[] blob = Sign(secret, Concat(main, Payload));
        byte[] rpm = Concat(SigHeader([(TagGpg, TypeBin, 0, blob.Length)], blob), main, Payload);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Verifier(publicKey).VerifyPackageAsync(OrgId, new MemoryStream(rpm), Cap, cts.Token));
    }

    // ── fixtures ────────────────────────────────────────────────────────────────

    private static byte[] LeadBytes()
    {
        byte[] lead = new byte[Lead];
        lead[0] = 0xED;
        lead[1] = 0xAB;
        lead[2] = 0xEE;
        lead[3] = 0xDB;
        return lead;
    }

    private static byte[] Intro(int nindex, int hsize)
    {
        byte[] intro = new byte[16];
        intro[0] = 0x8E;
        intro[1] = 0xAD;
        intro[2] = 0xE8;
        intro[3] = 0x01;
        BinaryPrimitives.WriteInt32BigEndian(intro.AsSpan(8, 4), nindex);
        BinaryPrimitives.WriteInt32BigEndian(intro.AsSpan(12, 4), hsize);
        return intro;
    }

    // Lead + signature header (intro, entries, store, optional 8-byte alignment padding).
    private static byte[] SigHeader((int Tag, int Type, int Offset, int Count)[] entries, byte[] store, bool padToEight = true)
    {
        using var ms = new MemoryStream();
        ms.Write(LeadBytes());
        ms.Write(Intro(entries.Length, store.Length));
        foreach (var (tag, type, offset, count) in entries)
        {
            byte[] entry = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(0, 4), tag);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(4, 4), type);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(8, 4), offset);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(12, 4), count);
            ms.Write(entry);
        }

        ms.Write(store);
        if (padToEight)
        {
            ms.Write(new byte[(8 - store.Length % 8) % 8]);
        }

        return ms.ToArray();
    }

    private static byte[] MainHeader() => MainHeaderWith([(1000, TypeBin, 0, 8)], Encoding.UTF8.GetBytes("mainhdr!"));

    private static byte[] MainHeaderWith((int Tag, int Type, int Offset, int Count)[] entries, byte[] store)
    {
        using var ms = new MemoryStream();
        ms.Write(Intro(entries.Length, store.Length));
        foreach (var (tag, type, offset, count) in entries)
        {
            byte[] entry = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(0, 4), tag);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(4, 4), type);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(8, 4), offset);
            BinaryPrimitives.WriteInt32BigEndian(entry.AsSpan(12, 4), count);
            ms.Write(entry);
        }

        ms.Write(store);
        return ms.ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        using var ms = new MemoryStream();
        foreach (byte[] part in parts)
        {
            ms.Write(part);
        }

        return ms.ToArray();
    }

    private static (PgpSecretKey Secret, PgpPublicKey Public) Key()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001), new SecureRandom(), 1024, 12));
        var kp = gen.GenerateKeyPair();
        var pair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp, new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secret = new PgpSecretKey(
            PgpSignature.DefaultCertification, pair, "releng@fedoraproject.example",
            SymmetricKeyAlgorithmTag.Null, passPhrase: null, useSha1: true, null, null, new SecureRandom());
        return (secret, secret.PublicKey);
    }

    private static byte[] Sign(PgpSecretKey secret, byte[] data)
    {
        var gen = new PgpSignatureGenerator(secret.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        gen.InitSign(PgpSignature.BinaryDocument, secret.ExtractPrivateKey(passPhrase: null));
        gen.Update(data);
        using var ms = new MemoryStream();
        gen.Generate().Encode(ms);
        return ms.ToArray();
    }

    private static byte[] Compress(byte[] rawPackets)
    {
        using var ms = new MemoryStream();
        var compressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
        using (var packets = compressor.Open(ms))
        {
            packets.Write(rawPackets);
        }

        return ms.ToArray();
    }

    private static RpmProvenanceVerifier Verifier(PgpPublicKey publicKey)
    {
        var store = new StubPerOrgTrustAnchorStore();
        using var armored = new MemoryStream();
        using (var output = new ArmoredOutputStream(armored))
        {
            publicKey.Encode(output);
        }

        store.AddAnchor(OrgId, "rpm", new TrustAnchorMaterial
        {
            Id = "anchor-1",
            AnchorKind = "pgp",
            Material = Encoding.UTF8.GetString(armored.ToArray()),
            Label = "fedora-40",
            KeyId = null,
        });
        return new RpmProvenanceVerifier(store, NullLogger<RpmProvenanceVerifier>.Instance);
    }

    private sealed class FaultingStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("disk read error");

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new IOException("disk read error");

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
