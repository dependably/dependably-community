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
/// Exercises <see cref="RpmProvenanceVerifier"/> end-to-end with self-generated OpenPGP keys
/// and hand-crafted RPM binary fixtures. Fixtures are built the way rpm builds them: the main
/// header and payload are laid out first, the detached signature is computed over the region
/// the chosen tag actually covers, and only then is it embedded in the signature header.
///
/// The security property under test is that a verdict of
/// <see cref="ProvenanceStatus.Verified"/> requires the signature to verify mathematically over
/// those bytes under a pinned key — not merely that the packet's issuer key-id resolves in the
/// pinned ring. The key-id is unauthenticated attacker-controlled metadata, so the fixtures
/// include a packet whose key-id is rewritten to a pinned key's id and a package whose bytes
/// were altered after signing; both must come back non-Verified.
///
/// The header-only tag (<c>RPMSIGTAG_RSA</c>) carries a second property: the payload sits outside
/// the signed region and is bound to it only by <c>RPMTAG_PAYLOADDIGEST</c> inside the signed
/// header. Fixtures therefore build that tag the way rpm does — the digest is computed over the
/// payload before signing — and the suite pins both directions: a package whose payload still
/// matches the signed digest verifies, and one whose payload was altered, truncated, extended,
/// or left undigested does not.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmProvenanceVerifierTests
{
    // Stand-in for the compressed cpio payload that follows the main header.
    private static readonly byte[] SamplePayload = Encoding.UTF8.GetBytes("rpm-cpio-payload-stub");

    // Org ID used in per-org tests.
    private const string TestOrgId = "test-org";

    private const long TestCap = 10 * 1024 * 1024;

    // ── happy path ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(SigTagGpg)]
    [InlineData(SigTagPgp)]
    [InlineData(SigTagRsa)]
    public async Task GenuineSignature_OverCoveredRegion_FromPinnedKey_Verifies(int tag)
    {
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(tag, secretKey);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
        Assert.Matches("^[0-9a-f]+$", result.Signer);
    }

    // ── #415 regression: key-id match is not a verdict ──────────────────────────

    [Theory]
    [InlineData(SigTagGpg)]
    [InlineData(SigTagPgp)]
    [InlineData(SigTagRsa)]
    public async Task ForgedKeyId_ResolvesPinnedKey_ButSignatureIsInvalid_IsNotVerified(int tag)
    {
        // The exact attacker capability: a syntactically valid OpenPGP signature packet stamped
        // with a PINNED key's issuer key-id, carrying signature material the pinned key never
        // produced. Resolving that key-id in the ring must not, on its own, yield Verified.
        var (attackerKey, _) = GeneratePgpKeyPair();
        var (_, pinnedPublicKey) = GeneratePgpKeyPair();

        byte[] rpmBytes = BuildRpmWithForgedKeyId(tag, attackerKey, pinnedPublicKey.KeyId);

        // Precondition: the embedded packet really does name the pinned key, so the key-id lookup
        // in the verifier succeeds and the test is not passing for some unrelated parse failure.
        Assert.Equal(pinnedPublicKey.KeyId, ExtractEmbeddedSignature(rpmBytes).KeyId);

        var verifier = VerifierWithKey(pinnedPublicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.NotEqual(ProvenanceStatus.Verified, result.Status);
        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task PayloadTamperedAfterSigning_IsNotVerified()
    {
        // Mirror-swap shape: the distro's genuine header+payload signature is kept verbatim and
        // the payload bytes are replaced. RPMSIGTAG_GPG covers the payload, so this must fail.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey, tamperPayloadAfterSigning: true);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Theory]
    [InlineData(SigTagGpg)]
    [InlineData(SigTagRsa)]
    public async Task MainHeaderTamperedAfterSigning_IsNotVerified(int tag)
    {
        // Every accepted tag covers the main header, so altering it invalidates all of them.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(tag, secretKey, tamperMainHeaderAfterSigning: true);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    // ── header-only tag: payload coverage via RPMTAG_PAYLOADDIGEST ──────────────

    [Fact]
    public async Task RsaTag_PayloadTamperedAfterSigning_IsNotVerified()
    {
        // The header-only tag signs the main header, not the payload. The payload is bound to that
        // header by RPMTAG_PAYLOADDIGEST, which the verifier recomputes — so substituting the
        // payload while keeping the genuine signed header intact must be rejected.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, tamperPayloadAfterSigning: true);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Fact]
    public async Task RsaTag_PayloadMatchesSignedDigest_Verifies()
    {
        // Adversarial twin of the case above: an untouched RSA-only package, whose payload still
        // hashes to the digest in the signed header, must still verify. The digest check tightens
        // the verdict, it does not reject genuine packages.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
        Assert.NotNull(result.Signer);
    }

    [Theory]
    [InlineData(4)]    // payload truncated after signing
    [InlineData(-6)]   // payload extended after signing
    public async Task RsaTag_PayloadLengthChangedAfterSigning_IsNotVerified(int trimBytes)
    {
        // Length changes are the cheapest payload substitution: neither shortening nor appending
        // touches the signed header, so only the recomputed digest catches them.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey);
        byte[] altered = trimBytes > 0
            ? rpmBytes[..^trimBytes]
            : Concat(rpmBytes, new byte[-trimBytes]);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(altered), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task RsaTag_NoPayloadDigest_IsNotVerified()
    {
        // Fail-closed: the signature is genuine and covers the main header, but nothing in that
        // header binds the payload. Stripping the digest tag is exactly how an attacker would
        // re-open the substitution hole, so an undigested payload is unverifiable, not verified.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, payloadDigest: PayloadDigest.None);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
        Assert.Null(result.Signer);
    }

    [Theory]
    [InlineData(SigTagGpg)]
    [InlineData(SigTagPgp)]
    public async Task HeaderAndPayloadTag_NoPayloadDigest_StillVerifies(int tag)
    {
        // Adversarial twin of the fail-closed rule: it is scoped to the header-only tag. GPG/PGP
        // sign the payload directly, so a package carrying no payload-digest tag at all — the
        // shape every pre-rpm-4.14 package has — must keep verifying.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(tag, secretKey, payloadDigest: PayloadDigest.None);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task RsaTag_OnlyAlternatePayloadDigest_IsNotVerified()
    {
        // RPMTAG_PAYLOADDIGESTALT digests the UNCOMPRESSED archive, so it cannot be checked
        // against the payload as stored without decompressing it. It does not substitute for
        // RPMTAG_PAYLOADDIGEST, and its presence alone must not read as payload coverage.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, payloadDigest: PayloadDigest.AlternateOnly);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Theory]
    [InlineData(HashAlgoSha256)]
    [InlineData(HashAlgoSha384)]
    [InlineData(HashAlgoSha512)]
    public async Task RsaTag_SupportedDigestAlgorithms_Verify(int algo)
    {
        // RPMTAG_PAYLOADDIGESTALGO selects the hash; all three collision-resistant ids rpm can
        // emit must be honoured, not just the SHA-256 default.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, digestAlgo: algo);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Theory]
    [InlineData(1)]    // MD5
    [InlineData(2)]    // SHA-1
    [InlineData(99)]   // unassigned
    public async Task RsaTag_WeakOrUnknownDigestAlgorithm_IsNotVerified(int algo)
    {
        // The payload digest is the only thing binding the payload here, so a collision-prone or
        // unrecognised algorithm id yields no usable binding — unverifiable, not verified.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, digestAlgo: algo);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task RsaTag_NoAlgorithmTag_DefaultsToSha256_Verifies()
    {
        // rpm omits RPMTAG_PAYLOADDIGESTALGO when the digest is its SHA-256 default.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, payloadDigest: PayloadDigest.NoAlgorithmTag);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task RsaTag_MalformedPayloadDigest_IsNotVerified()
    {
        // A digest string that is not hex of the algorithm's length cannot be compared, so the
        // payload is unbound — the same fail-closed answer as no digest at all.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey, payloadDigest: PayloadDigest.Malformed);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task Mixed_TwoRsaOnlyRpms_OneIntact_OnePayloadSwapped()
    {
        // Partial-failure shape: the same pinned key signed both headers, both signatures verify,
        // and only the recomputed payload digest separates them.
        var (secretKey, publicKey) = GeneratePgpKeyPair();

        byte[] intact = BuildSignedRpm(SigTagRsa, secretKey);
        byte[] swapped = BuildSignedRpm(SigTagRsa, secretKey, tamperPayloadAfterSigning: true);

        var verifier = VerifierWithKey(publicKey);

        var intactResult = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(intact), TestCap);
        var swappedResult = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(swapped), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, intactResult.Status);
        Assert.Equal(ProvenanceStatus.Failed, swappedResult.Status);
        Assert.NotNull(intactResult.Signer);
        Assert.Null(swappedResult.Signer);
    }

    // ── failure paths ───────────────────────────────────────────────────────────

    [Fact]
    public async Task WrongKey_KeyNotPinned_Fails()
    {
        var (secretKey, _) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);
        // Pin a DIFFERENT key — signature is genuine but its key-id is not in the pinned ring.
        var (_, differentPublicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(differentPublicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

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

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    [Fact]
    public async Task MalformedRpmLead_Fails()
    {
        // Bytes that don't start with the RPM lead magic.
        byte[] notRpm = Encoding.UTF8.GetBytes("not an RPM file at all");
        var (_, publicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(notRpm), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task TruncatedRpm_Fails()
    {
        // RPM truncated mid-signature-header.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);
        byte[] truncated = rpmBytes[..(LeadSize + 8)];
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(truncated), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task TruncatedPayload_UnderHeaderAndPayloadTag_Fails()
    {
        // The covered region is cut short after signing: the bytes that remain are a strict
        // prefix of what was signed, so the digest cannot match.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);
        byte[] truncated = rpmBytes[..^4];
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(truncated), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task TruncatedMainHeader_UnderHeaderOnlyTag_Fails()
    {
        // Header-only coverage has a fixed length: a stream that ends before the covered region
        // is complete must never be treated as verified.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagRsa, secretKey);
        // Cut inside the main header (which begins right after the aligned signature header).
        byte[] truncated = rpmBytes[..(rpmBytes.Length - SamplePayload.Length - 4)];
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(truncated), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task MalformedSigBlob_NotPgpData_Fails()
    {
        // Embed garbage bytes as the signature blob — OpenPGP parsing must fail gracefully.
        byte[] garbage = Encoding.UTF8.GetBytes("not an OpenPGP signature");
        byte[] rpmBytes = BuildRpm([(SigTagGpg, garbage)], MainHeader(), SamplePayload);
        var (_, publicKey) = GeneratePgpKeyPair();
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task PackageLargerThanCap_Fails()
    {
        // The cap bounds how much of the package the verifier will read; a package that runs past
        // it is unverifiable, never verified-by-default.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(
            TestOrgId, new MemoryStream(rpmBytes), maxBytes: rpmBytes.Length - 1);

        Assert.Equal(ProvenanceStatus.Failed, result.Status);
    }

    [Fact]
    public async Task PackageExactlyAtCap_Verifies()
    {
        // Boundary twin of the case above: a package whose last byte lands exactly on the cap is
        // fully read and verifies. The bound must not shave the final chunk.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(
            TestOrgId, new MemoryStream(rpmBytes), maxBytes: rpmBytes.Length);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task NotConfigured_ReturnsNotApplicable()
    {
        // No anchors in the store → org has no trust ring → NotApplicable.
        var verifier = new RpmProvenanceVerifier(
            new StubPerOrgTrustAnchorStore(),
            NullLogger<RpmProvenanceVerifier>.Instance);

        var (secretKey, _) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.NotApplicable, result.Status);
    }

    // ── mixed / partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task Mixed_TwoRpms_OneSignedByPinnedKey_OtherByUnpinnedKey()
    {
        var (secretKeyA, publicKeyA) = GeneratePgpKeyPair();
        var (secretKeyB, _) = GeneratePgpKeyPair();

        byte[] rpmA = BuildSignedRpm(SigTagGpg, secretKeyA);
        byte[] rpmB = BuildSignedRpm(SigTagGpg, secretKeyB);

        // Pin only key A.
        var verifier = VerifierWithKey(publicKeyA);

        var resultA = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmA), TestCap);
        var resultB = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmB), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, resultA.Status);
        Assert.Equal(ProvenanceStatus.Failed, resultB.Status);
        Assert.NotNull(resultA.Signer);
        Assert.Null(resultB.Signer);
    }

    [Fact]
    public async Task Mixed_OneUnsigned_OneVerified_OneForgedKeyId()
    {
        var (secretKeyPinned, publicKeyPinned) = GeneratePgpKeyPair();
        var (attackerKey, _) = GeneratePgpKeyPair();

        byte[] rpmVerified = BuildSignedRpm(SigTagGpg, secretKeyPinned);
        byte[] rpmForged = BuildRpmWithForgedKeyId(SigTagGpg, attackerKey, publicKeyPinned.KeyId);
        byte[] rpmUnsigned = BuildRpmWithNoSigTag();

        var verifier = VerifierWithKey(publicKeyPinned);

        var verified = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmVerified), TestCap);
        var forged = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmForged), TestCap);
        var unsigned = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmUnsigned), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, verified.Status);
        Assert.Equal(ProvenanceStatus.Failed, forged.Status);
        Assert.Equal(ProvenanceStatus.Unsigned, unsigned.Status);
    }

    // ── VerifyBytesAsync internal static (direct access) ─────────────────────────

    [Fact]
    public async Task VerifyBytesAsync_ValidGpgTag_Verifies()
    {
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKey);
        var keyRing = KeyRingFor(publicKey);

        var result = await RpmProvenanceVerifier.VerifyBytesAsync(rpmBytes, keyRing);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task VerifyBytesAsync_NoSigTag_ReturnsUnsigned()
    {
        byte[] rpmBytes = BuildRpmWithNoSigTag();
        var (_, publicKey) = GeneratePgpKeyPair();
        var keyRing = KeyRingFor(publicKey);

        var result = await RpmProvenanceVerifier.VerifyBytesAsync(rpmBytes, keyRing);

        Assert.Equal(ProvenanceStatus.Unsigned, result.Status);
    }

    // ── multi-entry signature-header scan ────────────────────────────────────────

    [Fact]
    public async Task NonSignatureEntryBeforeSigTag_IsSkipped_ThenVerifies()
    {
        // A leading non-OpenPGP tag entry must be scanned past to reach the GPG signature.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        byte[] main = MainHeader();
        byte[] sigBlob = SignRegion(Concat(main, SamplePayload), secretKey);
        byte[] filler = Encoding.UTF8.GetBytes("non-signature header blob");
        byte[] rpmBytes = BuildRpm([(NonSigTag, filler), (SigTagGpg, sigBlob)], main, SamplePayload);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
    }

    [Fact]
    public async Task MultipleSignatureTags_WidestCoverageWins_NotIndexOrder()
    {
        // rpm writes RPMSIGTAG_RSA (268, main header only) ahead of RPMSIGTAG_GPG (1005, main
        // header + payload) because the index is tag-ordered. Selection is by coverage, not
        // position: the GPG entry is chosen even though the RSA entry comes first.
        var (secretKey, publicKey) = GeneratePgpKeyPair();
        var (otherKey, _) = GeneratePgpKeyPair();
        byte[] main = MainHeader();
        // The RSA entry is signed by an UNPINNED key: if selection were positional it would be
        // picked and the result would be Failed.
        byte[] rsaBlob = SignRegion(main, otherKey);
        byte[] gpgBlob = SignRegion(Concat(main, SamplePayload), secretKey);
        byte[] rpmBytes = BuildRpm([(SigTagRsa, rsaBlob), (SigTagGpg, gpgBlob)], main, SamplePayload);
        var verifier = VerifierWithKey(publicKey);

        var result = await verifier.VerifyPackageAsync(TestOrgId, new MemoryStream(rpmBytes), TestCap);

        Assert.Equal(ProvenanceStatus.Verified, result.Status);
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
    private const int IndexEntrySize = 16;

    // TypeBin used for OpenPGP signature blobs.
    private const int TypeBin = 7;

    // OpenPGP signature tag numbers.
    private const int SigTagGpg = 1005;
    private const int SigTagPgp = 1002;
    private const int SigTagRsa = 268;

    // A non-OpenPGP signature-header tag (RPMSIGTAG_SIZE) — scanned past, never selected.
    private const int NonSigTag = 1000;

    // Main-header tags binding the payload to the signed header, and their index-entry types.
    private const int MainTagPayloadDigest = 5092;
    private const int MainTagPayloadDigestAlgo = 5093;
    private const int MainTagPayloadDigestAlt = 5097;
    private const int TypeInt32 = 4;
    private const int TypeStringArray = 8;

    // OpenPGP hash-algorithm ids rpm writes into RPMTAG_PAYLOADDIGESTALGO.
    private const int HashAlgoSha256 = 8;
    private const int HashAlgoSha384 = 9;
    private const int HashAlgoSha512 = 10;

    /// <summary>Shape of the payload-digest tags a fixture's main header carries.</summary>
    private enum PayloadDigest
    {
        /// <summary>RPMTAG_PAYLOADDIGEST + RPMTAG_PAYLOADDIGESTALGO, as rpm 4.14+ writes them.</summary>
        Standard,

        /// <summary>No payload-digest tags at all — the shape of a pre-rpm-4.14 package.</summary>
        None,

        /// <summary>The uncompressed-archive digest only; no digest over the payload as stored.</summary>
        AlternateOnly,

        /// <summary>Digest present, algorithm tag omitted (rpm's SHA-256 default implied).</summary>
        NoAlgorithmTag,

        /// <summary>Digest present but not hex of the algorithm's length.</summary>
        Malformed,
    }

    // A minimal but structurally valid main header: intro + index entries + their store.
    // Non-empty so the header-only (RSA) covered length is a real computed span, not zero.
    private static byte[] MainHeader()
        => MainHeaderFor(SamplePayload, PayloadDigest.None, HashAlgoSha256);

    // Builds a main header carrying the requested payload-digest shape over <paramref name="payload"/>.
    private static byte[] MainHeaderFor(byte[] payload, PayloadDigest digest, int digestAlgo)
    {
        var entries = new List<(int Tag, int Type, int Count, byte[] Value)>
        {
            (NonSigTag, TypeBin, 8, Encoding.UTF8.GetBytes("mainhdr!")),
        };

        switch (digest)
        {
            case PayloadDigest.Standard:
                entries.Add((MainTagPayloadDigest, TypeStringArray, 1, NulTerminated(PayloadDigestHex(payload, digestAlgo))));
                entries.Add((MainTagPayloadDigestAlgo, TypeInt32, 1, Int32Be(digestAlgo)));
                break;
            case PayloadDigest.NoAlgorithmTag:
                entries.Add((MainTagPayloadDigest, TypeStringArray, 1, NulTerminated(PayloadDigestHex(payload, HashAlgoSha256))));
                break;
            case PayloadDigest.AlternateOnly:
                entries.Add((MainTagPayloadDigestAlt, TypeStringArray, 1, NulTerminated(PayloadDigestHex(payload, HashAlgoSha256))));
                entries.Add((MainTagPayloadDigestAlgo, TypeInt32, 1, Int32Be(HashAlgoSha256)));
                break;
            case PayloadDigest.Malformed:
                entries.Add((MainTagPayloadDigest, TypeStringArray, 1, NulTerminated("not-a-hex-digest")));
                entries.Add((MainTagPayloadDigestAlgo, TypeInt32, 1, Int32Be(HashAlgoSha256)));
                break;
            default:
                break;
        }

        int hsize = 0;
        foreach (var (_, _, _, value) in entries)
        {
            hsize += value.Length;
        }

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write(HdrMagic0); w.Write(HdrMagic1); w.Write(HdrMagic2); w.Write(HdrVersion);
        w.Write(new byte[4]);            // reserved
        WriteInt32Be(w, entries.Count);  // nindex
        WriteInt32Be(w, hsize);          // hsize

        int offset = 0;
        foreach (var (tag, type, count, value) in entries)
        {
            WriteInt32Be(w, tag);
            WriteInt32Be(w, type);
            WriteInt32Be(w, offset);
            WriteInt32Be(w, count);
            offset += value.Length;
        }

        foreach (var (_, _, _, value) in entries)
        {
            w.Write(value);
        }

        w.Flush();
        return ms.ToArray();
    }

    // Hex digest of the payload under the given algorithm id. Ids the verifier does not accept
    // (MD5, SHA-1, unassigned) fall back to SHA-256 bytes: those fixtures exercise the algorithm
    // gate, which rejects before any comparison happens.
    private static string PayloadDigestHex(byte[] payload, int algo)
    {
        byte[] hash = algo switch
        {
            HashAlgoSha384 => SHA384.HashData(payload),
            HashAlgoSha512 => SHA512.HashData(payload),
            _ => SHA256.HashData(payload),
        };
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static byte[] NulTerminated(string value) => Encoding.ASCII.GetBytes(value + '\0');

    private static byte[] Int32Be(int value)
    {
        byte[] buf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        return buf;
    }

    // Builds a genuinely signed RPM: the signature is computed over exactly the region the tag
    // covers (main header + payload for GPG/PGP, main header alone for RSA), with the payload
    // digest embedded in the header before signing the way rpm does. The optional tamper switches
    // mutate the package AFTER signing, the way a hostile mirror would.
    private static byte[] BuildSignedRpm(
        int tag, PgpSecretKey secretKey,
        bool tamperPayloadAfterSigning = false,
        bool tamperMainHeaderAfterSigning = false,
        PayloadDigest payloadDigest = PayloadDigest.Standard,
        int digestAlgo = HashAlgoSha256)
    {
        byte[] payload = SamplePayload;
        byte[] main = MainHeaderFor(payload, payloadDigest, digestAlgo);
        byte[] covered = tag == SigTagRsa ? main : Concat(main, payload);
        byte[] sigBlob = SignRegion(covered, secretKey);

        if (tamperMainHeaderAfterSigning)
        {
            main = (byte[])main.Clone();
            main[^1] ^= 0xFF;
        }

        if (tamperPayloadAfterSigning)
        {
            payload = (byte[])payload.Clone();
            payload[^1] ^= 0xFF;
        }

        return BuildRpm([(tag, sigBlob)], main, payload);
    }

    // Builds an RPM whose signature packet was produced by <paramref name="attackerKey"/> but
    // whose issuer key-id bytes are rewritten to <paramref name="pinnedKeyId"/>. The key-id lives
    // in the packet's unhashed area, so rewriting it leaves a parseable packet that names a
    // trusted key while the signature material stays the attacker's.
    private static byte[] BuildRpmWithForgedKeyId(int tag, PgpSecretKey attackerKey, long pinnedKeyId)
    {
        // Carries a genuine payload digest, so the only thing wrong with the package is the
        // signature material — the verdict cannot be reached through the payload-coverage gate.
        byte[] main = MainHeaderFor(SamplePayload, PayloadDigest.Standard, HashAlgoSha256);
        byte[] covered = tag == SigTagRsa ? main : Concat(main, SamplePayload);
        byte[] sigBlob = SignRegion(covered, attackerKey);

        Span<byte> attackerId = stackalloc byte[8];
        Span<byte> pinnedId = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(attackerId, attackerKey.KeyId);
        BinaryPrimitives.WriteInt64BigEndian(pinnedId, pinnedKeyId);

        byte[] forged = (byte[])sigBlob.Clone();
        for (int i = 0; i + 8 <= forged.Length; i++)
        {
            if (forged.AsSpan(i, 8).SequenceEqual(attackerId))
            {
                pinnedId.CopyTo(forged.AsSpan(i, 8));
            }
        }

        return BuildRpm([(tag, forged)], main, SamplePayload);
    }

    // Re-reads the OpenPGP signature packet a fixture embedded, so a test can assert on what the
    // verifier will see (notably: which key-id the packet claims).
    private static PgpSignature ExtractEmbeddedSignature(byte[] rpmBytes)
    {
        // The signature blob starts after lead + sig-header intro + one index entry.
        int blobStart = LeadSize + HdrIntroSize + IndexEntrySize;
        int blobLength = BinaryPrimitives.ReadInt32BigEndian(
            rpmBytes.AsSpan(LeadSize + HdrIntroSize + 12, 4));
        var factory = new PgpObjectFactory(new MemoryStream(rpmBytes, blobStart, blobLength));
        return ((PgpSignatureList)factory.NextPgpObject())[0];
    }

    private const int HdrIntroSize = 16;

    // Assembles lead + signature header (entries + store, 8-byte aligned) + main header + payload.
    private static byte[] BuildRpm((int Tag, byte[] Blob)[] entries, byte[] mainHeader, byte[] payload)
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

        // Signature header intro: magic(4) + reserved(4) + nindex(4 BE) + hsize(4 BE).
        w.Write(HdrMagic0); w.Write(HdrMagic1); w.Write(HdrMagic2); w.Write(HdrVersion);
        w.Write(new byte[4]);
        WriteInt32Be(w, nindex);
        WriteInt32Be(w, hsize);

        int offset = 0;
        foreach (var (tag, blob) in entries)
        {
            WriteInt32Be(w, tag);
            WriteInt32Be(w, TypeBin);
            WriteInt32Be(w, offset);
            WriteInt32Be(w, blob.Length);
            offset += blob.Length;
        }

        foreach (var (_, blob) in entries)
        {
            w.Write(blob);
        }

        // The signature header's store is padded so the main header starts 8-byte aligned.
        w.Write(new byte[(8 - hsize % 8) % 8]);

        w.Write(mainHeader);
        w.Write(payload);
        w.Flush();
        return ms.ToArray();
    }

    // Builds a minimal RPM with an empty signature header (no index entries, no sig tags).
    private static byte[] BuildRpmWithNoSigTag()
        => BuildRpm([], MainHeader(), SamplePayload);

    private static void WriteInt32Be(BinaryWriter w, int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        w.Write(buf.ToArray());
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
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

    // Produces a raw (non-armored) OpenPGP detached signature over the given region.
    // This matches what RPM embeds in the RPMSIGTAG_GPG / _PGP / _RSA tags.
    private static byte[] SignRegion(byte[] data, PgpSecretKey secretKey)
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
        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(TestOrgId, "rpm", AnchorFor(publicKey, "test-anchor"));
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

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(orgA, "rpm", AnchorFor(publicKey, "anchor-a"));
        // orgB intentionally has no anchor seeded.

        var verifier = new RpmProvenanceVerifier(store, NullLogger<RpmProvenanceVerifier>.Instance);

        var resultA = await verifier.VerifyPackageAsync(orgA, new MemoryStream(unsignedRpm), TestCap);
        var resultB = await verifier.VerifyPackageAsync(orgB, new MemoryStream(unsignedRpm), TestCap);

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

        byte[] rpmBytes = BuildSignedRpm(SigTagGpg, secretKeyA);

        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(orgA, "rpm", AnchorFor(publicKeyA, "anchor-a"));
        store.AddAnchor(orgB, "rpm", AnchorFor(publicKeyB, "anchor-b"));

        var verifier = new RpmProvenanceVerifier(store, NullLogger<RpmProvenanceVerifier>.Instance);

        var resultA = await verifier.VerifyPackageAsync(orgA, new MemoryStream(rpmBytes), TestCap);
        var resultB = await verifier.VerifyPackageAsync(orgB, new MemoryStream(rpmBytes), TestCap);

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
