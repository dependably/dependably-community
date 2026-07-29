using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Verifies the per-package GPG/OpenPGP signature embedded in an RPM package's signature
/// header against the per-org trust anchors stored in <c>signature_trust_anchor</c>.
///
/// RPM package layout:
/// <code>
///   Lead (96 bytes)
///   Signature header  — carries per-package signature tag(s)
///   (8-byte alignment padding)
///   Main header       — carries name/version/arch/…
///   Compressed payload (cpio)
/// </code>
///
/// The signature header contains typed index entries keyed by tag number. The meaningful
/// OpenPGP signature tags are:
/// <list type="bullet">
///   <item><c>RPMSIGTAG_GPG</c> (1005) — OpenPGP signature over main header + payload.</item>
///   <item><c>RPMSIGTAG_PGP</c> (1002) — legacy PGP/RSA signature over main header + payload.</item>
///   <item><c>RPMSIGTAG_RSA</c> (268) — RSA/OpenPGP signature over the main header alone.</item>
/// </list>
///
/// Tag selection is preference-ordered, not positional: <c>GPG</c> then <c>PGP</c> then
/// <c>RSA</c>, so the widest covered region available in the package is the one verified.
/// The selected blob is decoded as a detached OpenPGP signature via BouncyCastle, the signing
/// key is located in the per-org trust ring, and the signature is mathematically verified
/// (<c>InitVerify</c> / <c>Update</c> / <c>Verify</c>) against the region the tag covers:
/// main header + payload for GPG/PGP, the main header alone for RSA. The issuer key-id inside
/// the packet is unauthenticated attacker-controlled metadata — it selects a candidate key, it
/// never constitutes a verdict on its own.
///
/// The covered region is streamed into the verifier in fixed-size chunks, so a package of any
/// size verifies in constant memory; <c>maxBytes</c> bounds the total number of bytes read
/// (a package exceeding it is reported unverifiable rather than verified).
///
/// A package carrying only <c>RPMSIGTAG_RSA</c> has its payload authenticated indirectly: the
/// signature covers the main header, and the main header carries <c>RPMTAG_PAYLOADDIGEST</c>
/// (5092) over the compressed payload. That transitive chain is completed here rather than
/// assumed — the payload is streamed through <c>RPMTAG_PAYLOADDIGESTALGO</c>'s hash and compared
/// against the digest inside the signed header, so altering the payload of a header-only-signed
/// package is rejected. The digest string and the algorithm id are captured out of the header
/// data store as it streams past, so completing the chain adds no payload-sized allocation.
/// An RSA-only package that carries no payload digest is <b>fail-closed</b>: the signature
/// verifies but nothing binds the payload, so the verdict is <see cref="ProvenanceStatus.Failed"/>
/// (unverifiable), never <see cref="ProvenanceStatus.Verified"/>. <c>RPMTAG_PAYLOADDIGESTALT</c>
/// (5097) digests the <i>uncompressed</i> archive, so it cannot substitute without decompressing
/// the payload and does not satisfy the requirement.
///
/// The trust root is always the per-org operator-pinned ring (never the upstream-fetched
/// GPG key from the repo — using an upstream-fetched key would be circular against a MITM,
/// the same posture <see cref="RpmUpstreamProxy"/> uses for repomd verification).
///
/// Result mapping: signature that verifies under a key in the pinned ring →
/// <see cref="ProvenanceStatus.Verified"/> (signer = key fingerprint); signature that fails to
/// verify, is signed by an unpinned key, or sits in a malformed/truncated package →
/// <see cref="ProvenanceStatus.Failed"/>; no OpenPGP signature tag in the signature header →
/// <see cref="ProvenanceStatus.Unsigned"/>; no per-org trust anchor configured →
/// <see cref="ProvenanceStatus.NotApplicable"/>. Never throws.
/// </summary>
public sealed class RpmProvenanceVerifier : IArtifactProvenanceVerifier
{
    // RPM file layout constants (mirrors RpmHeaderParser private constants).
    private const int LeadSize = 96;
    private const int HeaderIntroSize = 16;
    private const int IndexEntrySize = 16;
    private const byte HeaderMagic0 = 0x8E;
    private const byte HeaderMagic1 = 0xAD;
    private const byte HeaderMagic2 = 0xE8;
    private const byte HeaderVersionByte = 0x01;
    private const int Int32Size = sizeof(int);

    // The signature header's data store is padded so the main header starts on an 8-byte boundary.
    private const int HeaderAlignment = 8;

    // RPM header intro field offsets within the 16-byte intro block (after the 8-byte magic+version).
    // Bytes 0-7: magic (4) + version (1) + reserved (3). Bytes 8-11: nindex. Bytes 12-15: hsize.
    private const int HeaderIntroNindexOffset = 8;
    private const int HeaderIntroHsizeOffset = 12;

    // RPM header index-entry field offsets within each 16-byte index record.
    // Bytes 0-3: tag. Bytes 4-7: type. Bytes 8-11: offset. Bytes 12-15: count.
    private const int IndexEntryTypeOffset = 4;
    private const int IndexEntryOffsetOffset = 8;
    private const int IndexEntryCountOffset = 12;

    // Byte indices for the third and fourth bytes of any RPM 4-byte magic/version prefix
    // (applies to both the lead magic and the signature-header magic+version fields).
    private const int Magic4ByteByte2Index = 2;
    private const int Magic4ByteByte3Index = 3;

    // RPM signature-header tag IDs carrying OpenPGP signatures.
    private const int SigTagRsa = 268;   // RPMSIGTAG_RSA — OpenPGP sig over main-header digest
    private const int SigTagPgp = 1002;  // RPMSIGTAG_PGP — legacy PGP sig over main header + payload
    private const int SigTagGpg = 1005;  // RPMSIGTAG_GPG — OpenPGP sig over main header + payload

    // TypeBin (7) is the only valid type for OpenPGP binary blobs in the signature header.
    private const int TypeBin = 7;

    // Main-header tag IDs that bind the payload to the signed header.
    private const int MainTagPayloadDigest = 5092;      // RPMTAG_PAYLOADDIGEST — hex digest of the compressed payload
    private const int MainTagPayloadDigestAlgo = 5093;  // RPMTAG_PAYLOADDIGESTALGO — OpenPGP hash-algorithm id

    // Main-header index-entry types for those tags: the digest is a string array, the algorithm an int32.
    private const int TypeInt32 = 4;
    private const int TypeStringArray = 8;

    // OpenPGP hash-algorithm ids (RFC 4880 §9.4) accepted for the payload digest. The payload
    // digest is the only thing binding the payload of a header-only-signed package, so the
    // collision-prone ids (MD5, SHA-1) are rejected rather than trusted.
    private const int HashAlgoSha256 = 8;
    private const int HashAlgoSha384 = 9;
    private const int HashAlgoSha512 = 10;

    // rpm's default when RPMTAG_PAYLOADDIGESTALGO is absent but RPMTAG_PAYLOADDIGEST is present.
    private const int DefaultPayloadDigestAlgo = HashAlgoSha256;

    // Upper bound on the main header's index array (entry records only, not the data store) held
    // in memory while the payload-digest entries are located. Real main headers carry hundreds of
    // entries; a declared count beyond this is treated as malformed rather than allocated.
    private const int MaxMainHeaderIndexBytes = 4 * 1024 * 1024;

    // Widest byte range captured out of the header data store for the payload-digest string.
    // A SHA-512 hex digest plus its NUL terminator is 129 bytes.
    private const int MaxPayloadDigestStringBytes = 160;

    // Upper bound on the signature header (index entries + data store) held in memory while the
    // signature blob is extracted. Real signature headers are kilobytes; IMA file-signature blobs
    // push a large package into the low megabytes. A declared size beyond this is treated as
    // malformed rather than allocated.
    private const int MaxSignatureHeaderBytes = 32 * 1024 * 1024;

    // Streaming chunk fed into the OpenPGP verifier. Fixed, so covered-region size does not
    // translate into resident memory.
    private const int VerifyChunkBytes = 81920;

    private readonly IPerOrgTrustAnchorStore _trustStore;
    private readonly ILogger<RpmProvenanceVerifier> _logger;

    public RpmProvenanceVerifier(IPerOrgTrustAnchorStore trustStore, ILogger<RpmProvenanceVerifier> logger)
    {
        _trustStore = trustStore;
        _logger = logger;
    }

    public string Ecosystem => "rpm";

    /// <summary>
    /// Always false at the instance level — RPM trust anchors are per-org, not instance-wide.
    /// Use <see cref="IsConfiguredForAsync"/> to test whether a specific org has anchors.
    /// This property exists only to satisfy the <see cref="IArtifactProvenanceVerifier"/> interface
    /// contract; code that needs the per-org gate must call <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one RPM PGP trust anchor is configured for <paramref name="orgId"/>.
    /// Fail-closed: an org with no anchors cannot enable signature verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _trustStore.IsConfiguredForAsync(orgId, "rpm", ct);

    /// <summary>
    /// Metadata-driven verification does not apply to RPM: the signature lives inside the RPM
    /// binary, not the registration metadata. The RPM proxy ingest path calls
    /// <see cref="VerifyPackageAsync"/> with the staged bytes instead. Returning
    /// <see cref="ProvenanceResult.NotApplicable"/> keeps the uniform interface usable for
    /// generic resolution without implying an unsigned/failed verdict.
    /// </summary>
    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(ProvenanceResult.NotApplicable);

    /// <summary>
    /// Verifies the OpenPGP signature in the RPM signature header against the per-org
    /// trust ring for <paramref name="orgId"/>. Reads at most <paramref name="maxBytes"/> from
    /// <paramref name="rpm"/> (an RPM exceeding that size returns
    /// <see cref="ProvenanceStatus.Failed"/> rather than reading without bound).
    /// Returns <see cref="ProvenanceStatus.NotApplicable"/> when no anchors are configured
    /// for the org. Never throws.
    /// </summary>
    public async Task<ProvenanceResult> VerifyPackageAsync(
        string orgId, Stream rpm, long maxBytes, CancellationToken ct = default)
    {
        var keyRing = await _trustStore.GetRpmKeyRingAsync(orgId, ct);
        if (keyRing is null)
        {
            return Record(ProvenanceResult.NotApplicable);
        }

        try
        {
            return Record(await VerifyStreamAsync(rpm, keyRing, maxBytes, _logger, ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "RPM signature verification failed ({ExceptionType}); treating as unverifiable.",
                ex.GetType().Name);
            return Record(ProvenanceResult.Failed);
        }
    }

    /// <summary>
    /// Core verification over a forward-only RPM stream: parses the lead and signature header,
    /// selects the widest-covering OpenPGP signature tag, then streams the region that tag covers
    /// through <see cref="PgpSignature.Verify"/>. Returns <see cref="ProvenanceStatus.Unsigned"/>
    /// when the signature header carries no OpenPGP tag.
    /// </summary>
    internal static async Task<ProvenanceResult> VerifyStreamAsync(
        Stream rpm, PgpPublicKeyRingBundle keyRing, long maxBytes, ILogger? logger, CancellationToken ct)
    {
        var reader = new BoundedReader(rpm, maxBytes <= 0 ? long.MaxValue : maxBytes);

        byte[]? prologue = await reader.ReadExactlyAsync(LeadSize + HeaderIntroSize, ct);
        if (prologue is null || !HasLeadMagic(prologue) ||
            !TryReadHeaderIntro(prologue, LeadSize, out int sigNindex, out int sigHsize))
        {
            return ProvenanceResult.Failed;
        }

        long sigRegionLength = (long)sigNindex * IndexEntrySize + sigHsize;
        if (sigRegionLength > MaxSignatureHeaderBytes)
        {
            return ProvenanceResult.Failed;
        }

        byte[]? sigRegion = await reader.ReadExactlyAsync((int)sigRegionLength, ct);
        if (sigRegion is null)
        {
            return ProvenanceResult.Failed;
        }

        var selected = SelectSignatureBlob(sigRegion, sigNindex, sigHsize);
        if (selected is null)
        {
            return ProvenanceResult.Unsigned;
        }

        // Skip the padding that aligns the main header to an 8-byte boundary.
        int padding = (HeaderAlignment - sigHsize % HeaderAlignment) % HeaderAlignment;
        return padding > 0 && await reader.ReadExactlyAsync(padding, ct) is null
            ? ProvenanceResult.Failed
            : await VerifyCoveredRegionAsync(reader, selected.Value.Tag, selected.Value.Blob, keyRing, logger, ct);
    }

    /// <summary>
    /// Convenience overload over an in-memory RPM. Exists for callers and tests that already hold
    /// the bytes; the streaming overload is the one the ingest path uses.
    /// </summary>
    internal static Task<ProvenanceResult> VerifyBytesAsync(byte[] data, PgpPublicKeyRingBundle keyRing)
        => VerifyStreamAsync(new MemoryStream(data, writable: false), keyRing, data.Length, null, CancellationToken.None);

    // Validates the 4-byte RPM lead magic.
    private static bool HasLeadMagic(byte[] data)
    {
        const byte leadMagic0 = 0xED;
        const byte leadMagic1 = 0xAB;
        const byte leadMagic2 = 0xEE;
        const byte leadMagic3 = 0xDB;

        return data[0] == leadMagic0 && data[1] == leadMagic1 &&
               data[Magic4ByteByte2Index] == leadMagic2 && data[Magic4ByteByte3Index] == leadMagic3;
    }

    // Scans the RPM signature-header index entries and returns the OpenPGP signature blob whose tag
    // covers the widest region: GPG (main header + payload), else PGP (main header + payload), else
    // RSA (main header only). Returns null when no OpenPGP tag is present.
    private static (int Tag, byte[] Blob)? SelectSignatureBlob(byte[] sigRegion, int sigNindex, int sigHsize)
    {
        int storeStart = sigNindex * IndexEntrySize;
        (int Tag, byte[] Blob)? best = null;

        for (int i = 0; i < sigNindex; i++)
        {
            int entryOff = i * IndexEntrySize;
            int tag = BinaryPrimitives.ReadInt32BigEndian(sigRegion.AsSpan(entryOff, Int32Size));
            int type = BinaryPrimitives.ReadInt32BigEndian(sigRegion.AsSpan(entryOff + IndexEntryTypeOffset, Int32Size));
            int offset = BinaryPrimitives.ReadInt32BigEndian(sigRegion.AsSpan(entryOff + IndexEntryOffsetOffset, Int32Size));
            int count = BinaryPrimitives.ReadInt32BigEndian(sigRegion.AsSpan(entryOff + IndexEntryCountOffset, Int32Size));

            if (type != TypeBin || count <= 0 || offset < 0 || tag is not (SigTagGpg or SigTagPgp or SigTagRsa))
            {
                continue;
            }

            long blobStart = (long)storeStart + offset;
            if (blobStart + count > (long)storeStart + sigHsize)
            {
                continue;
            }

            if (best is null || TagCoverageRank(tag) > TagCoverageRank(best.Value.Tag))
            {
                best = (tag, sigRegion.AsSpan((int)blobStart, count).ToArray());
            }
        }

        return best;
    }

    // Higher rank = wider covered region. GPG and PGP both cover main header + payload; RSA
    // covers the main header alone, so it is only selected when neither of the others is present.
    private static int TagCoverageRank(int tag) => tag switch
    {
        SigTagGpg => 2,
        SigTagPgp => 1,
        _ => 0,
    };

    // Streams the region the selected tag covers through the OpenPGP verifier and returns the
    // mathematical verdict. The signing key must resolve in the pinned ring AND the signature must
    // verify over the bytes; a key-id match alone is never sufficient. Under the header-only tag
    // the payload sits outside the signed region, so the verdict additionally requires the
    // payload to match the digest the signed header declares.
    private static async Task<ProvenanceResult> VerifyCoveredRegionAsync(
        BoundedReader reader, int tag, byte[] sigBlob, PgpPublicKeyRingBundle keyRing,
        ILogger? logger, CancellationToken ct)
    {
        var sig = ParseDetachedSignature(sigBlob);
        if (sig is null)
        {
            return ProvenanceResult.Failed;
        }

        // The key-id inside the packet is unauthenticated: it only names which pinned key to test.
        var publicKey = keyRing.GetPublicKey(sig.KeyId);
        if (publicKey is null)
        {
            // Signed by a key not in the operator ring — untrusted.
            return ProvenanceResult.Failed;
        }

        sig.InitVerify(publicKey);

        byte[]? intro = await reader.ReadExactlyAsync(HeaderIntroSize, ct);
        if (intro is null || !TryReadHeaderIntro(intro, 0, out int nindex, out int hsize))
        {
            return ProvenanceResult.Failed;
        }

        sig.Update(intro, 0, intro.Length);

        if (tag == SigTagRsa)
        {
            return await VerifyHeaderOnlyTagAsync(reader, sig, publicKey, nindex, hsize, logger, ct);
        }

        // GPG/PGP cover the main header and the payload, so the signed region runs to EOF. The
        // covered region must be complete AND the signature must verify over it. Either failing
        // yields Failed — a key-id that resolved in the ring is never a verdict by itself.
        return await FeedAsync(reader, sig, long.MaxValue, ct) && sig.Verify()
            ? ProvenanceResult.Verified(ToHexFingerprint(publicKey.GetFingerprint()))
            : ProvenanceResult.Failed;
    }

    // Header-only coverage (RPMSIGTAG_RSA): the signature covers the main header's index and data
    // store, and the payload is bound to that header by RPMTAG_PAYLOADDIGEST. The store is fed to
    // the signature as it streams past while the two byte ranges the payload-digest tags occupy
    // are captured out of the passing chunks, so no payload-sized (or store-sized) buffer is held.
    private static async Task<ProvenanceResult> VerifyHeaderOnlyTagAsync(
        BoundedReader reader, PgpSignature sig, PgpPublicKey publicKey,
        int nindex, int hsize, ILogger? logger, CancellationToken ct)
    {
        long indexLength = (long)nindex * IndexEntrySize;
        if (indexLength > MaxMainHeaderIndexBytes)
        {
            return ProvenanceResult.Failed;
        }

        byte[]? index = await reader.ReadExactlyAsync((int)indexLength, ct);
        if (index is null)
        {
            return ProvenanceResult.Failed;
        }

        sig.Update(index, 0, index.Length);

        var digestWindow = OpenStoreWindow(index, nindex, hsize, MainTagPayloadDigest, TypeStringArray, MaxPayloadDigestStringBytes);
        var algoWindow = OpenStoreWindow(index, nindex, hsize, MainTagPayloadDigestAlgo, TypeInt32, Int32Size);

        // The signed region must be complete AND verify before the payload digest inside it is
        // worth anything — an unverified header's digest is attacker-chosen.
        return !await FeedStoreAsync(reader, sig, hsize, digestWindow, algoWindow, ct) || !sig.Verify()
            ? ProvenanceResult.Failed
            : await VerifyPayloadDigestAsync(reader, publicKey, digestWindow, algoWindow, logger, ct);
    }

    // Completes the transitive chain the signed header asserts: hashes the payload (everything
    // after the main header, i.e. the compressed cpio archive as stored) and compares it with the
    // digest the signed header declares. Fail-closed on an absent, unreadable, or weak-algorithm
    // digest — the signature says nothing about the payload without it.
    private static async Task<ProvenanceResult> VerifyPayloadDigestAsync(
        BoundedReader reader, PgpPublicKey publicKey, StoreWindow? digestWindow, StoreWindow? algoWindow,
        ILogger? logger, CancellationToken ct)
    {
        if (digestWindow is not { IsComplete: true })
        {
            logger?.LogWarning(
                "RPM header-only signature verified but the package declares no payload digest; " +
                "the payload is unauthenticated, treating as unverifiable.");
            return ProvenanceResult.Failed;
        }

        int algo = algoWindow is { IsComplete: true }
            ? BinaryPrimitives.ReadInt32BigEndian(algoWindow.Bytes)
            : DefaultPayloadDigestAlgo;

        HashAlgorithmName? algorithm = algo switch
        {
            HashAlgoSha256 => HashAlgorithmName.SHA256,
            HashAlgoSha384 => HashAlgorithmName.SHA384,
            HashAlgoSha512 => HashAlgorithmName.SHA512,
            _ => null,
        };

        if (algorithm is null)
        {
            logger?.LogWarning(
                "RPM payload digest declares unsupported hash algorithm id {PayloadDigestAlgorithm}; " +
                "treating as unverifiable.",
                algo);
            return ProvenanceResult.Failed;
        }

        using var hash = IncrementalHash.CreateHash(algorithm.Value);
        byte[] chunk = new byte[VerifyChunkBytes];
        int read;
        while ((read = await reader.ReadAsync(chunk, chunk.Length, ct)) > 0)
        {
            hash.AppendData(chunk, 0, read);
        }

        byte[] actual = hash.GetCurrentHash();
        if (!TryDecodeDigestString(digestWindow.Bytes, actual.Length, out byte[]? expected))
        {
            logger?.LogWarning("RPM payload digest is malformed; treating as unverifiable.");
            return ProvenanceResult.Failed;
        }

        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            logger?.LogWarning(
                "RPM payload does not match the digest in the signed header; treating as unverifiable.");
            return ProvenanceResult.Failed;
        }

        return ProvenanceResult.Verified(ToHexFingerprint(publicKey.GetFingerprint()));
    }

    // Locates a main-header index entry and returns the byte range of its value within the data
    // store, clamped to the store's end. Returns null when the tag is absent, carries the wrong
    // type, or points outside the store.
    private static StoreWindow? OpenStoreWindow(
        byte[] index, int nindex, int hsize, int tag, int type, int maxLength)
    {
        for (int i = 0; i < nindex; i++)
        {
            int entryOff = i * IndexEntrySize;
            if (BinaryPrimitives.ReadInt32BigEndian(index.AsSpan(entryOff, Int32Size)) != tag ||
                BinaryPrimitives.ReadInt32BigEndian(index.AsSpan(entryOff + IndexEntryTypeOffset, Int32Size)) != type ||
                BinaryPrimitives.ReadInt32BigEndian(index.AsSpan(entryOff + IndexEntryCountOffset, Int32Size)) <= 0)
            {
                continue;
            }

            int offset = BinaryPrimitives.ReadInt32BigEndian(index.AsSpan(entryOff + IndexEntryOffsetOffset, Int32Size));
            if (offset < 0 || offset >= hsize)
            {
                continue;
            }

            int length = Math.Min(maxLength, hsize - offset);
            if (length > 0)
            {
                return new StoreWindow(offset, length);
            }
        }

        return null;
    }

    // Feeds exactly `hsize` bytes of the main header's data store into the signature, capturing
    // the requested windows out of each chunk on the way through. Returns false when the stream
    // ends before the store is complete.
    private static async Task<bool> FeedStoreAsync(
        BoundedReader reader, PgpSignature sig, int hsize,
        StoreWindow? digestWindow, StoreWindow? algoWindow, CancellationToken ct)
    {
        byte[] chunk = new byte[VerifyChunkBytes];
        int fed = 0;
        while (fed < hsize)
        {
            int want = Math.Min(chunk.Length, hsize - fed);
            int read = await reader.ReadAsync(chunk, want, ct);
            if (read == 0)
            {
                return false;
            }

            sig.Update(chunk, 0, read);
            digestWindow?.Absorb(fed, chunk.AsSpan(0, read));
            algoWindow?.Absorb(fed, chunk.AsSpan(0, read));
            fed += read;
        }

        return true;
    }

    // Reads the first element of an RPM string-array value (NUL-terminated ASCII hex) and decodes
    // it into `expectedLength` bytes. Returns false when the string is unterminated within the
    // captured window, is not the right length for the algorithm, or is not valid hex.
    private static bool TryDecodeDigestString(ReadOnlySpan<byte> window, int expectedLength, out byte[]? digest)
    {
        digest = null;

        int terminator = window.IndexOf((byte)0);
        if (terminator != expectedLength * 2)
        {
            return false;
        }

        Span<char> chars = stackalloc char[MaxPayloadDigestStringBytes];
        for (int i = 0; i < terminator; i++)
        {
            chars[i] = (char)window[i];
        }

        byte[] decoded = new byte[expectedLength];
        if (Convert.FromHexString(chars[..terminator], decoded, out _, out int written) != OperationStatus.Done ||
            written != expectedLength)
        {
            return false;
        }

        digest = decoded;
        return true;
    }

    // Decodes a raw (non-armored) OpenPGP detached signature blob. Returns null when the bytes are
    // not a well-formed OpenPGP signature.
    private static PgpSignature? ParseDetachedSignature(byte[] sigBlob)
    {
        try
        {
            var factory = new PgpObjectFactory(new MemoryStream(sigBlob, writable: false));
            var obj = factory.NextPgpObject();

            if (obj is PgpCompressedData compressed)
            {
                obj = new PgpObjectFactory(compressed.GetDataStream()).NextPgpObject();
            }

            return obj is PgpSignatureList { Count: > 0 } sigList ? sigList[0] : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    // Feeds up to `limit` further bytes into the signature. Returns false when the stream ends
    // before `limit` is reached (a truncated covered region is never treated as verified);
    // long.MaxValue means "to EOF", which any amount of data satisfies.
    private static async Task<bool> FeedAsync(
        BoundedReader reader, PgpSignature sig, long limit, CancellationToken ct)
    {
        byte[] chunk = new byte[VerifyChunkBytes];
        long fed = 0;
        while (fed < limit)
        {
            int want = (int)Math.Min(chunk.Length, limit - fed);
            int read = await reader.ReadAsync(chunk, want, ct);
            if (read == 0)
            {
                return limit == long.MaxValue;
            }

            sig.Update(chunk, 0, read);
            fed += read;
        }

        return true;
    }

    private static bool TryReadHeaderIntro(byte[] data, int offset, out int nindex, out int hsize)
    {
        nindex = 0;
        hsize = 0;
        if (offset + HeaderIntroSize > data.Length)
        {
            return false;
        }

        if (data[offset] != HeaderMagic0 || data[offset + 1] != HeaderMagic1 ||
            data[offset + Magic4ByteByte2Index] != HeaderMagic2 || data[offset + Magic4ByteByte3Index] != HeaderVersionByte)
        {
            return false;
        }

        nindex = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + HeaderIntroNindexOffset, Int32Size));
        hsize = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + HeaderIntroHsizeOffset, Int32Size));
        return nindex >= 0 && hsize >= 0;
    }

    private static string ToHexFingerprint(byte[] fingerprint)
        => Convert.ToHexString(fingerprint).ToLowerInvariant();

    // Emits the OTel result counter (ecosystem + result only — no per-package labels).
    private static ProvenanceResult Record(ProvenanceResult result)
    {
        DependablyMeter.ProvenanceVerified.Add(1,
            new KeyValuePair<string, object?>("ecosystem", "rpm"),
            new KeyValuePair<string, object?>("result", ResultLabel(result.Status)));
        return result;
    }

    private static string ResultLabel(ProvenanceStatus status) => status switch
    {
        ProvenanceStatus.Verified => "verified",
        ProvenanceStatus.Failed => "failed",
        ProvenanceStatus.Unsigned => "unsigned",
        _ => "not_applicable",
    };

    /// <summary>
    /// A fixed byte range of the main header's data store, filled from the chunks that stream past
    /// on their way into the signature. Lets a small value (the payload digest, its algorithm id)
    /// be read out of an arbitrarily large store without buffering the store.
    /// </summary>
    private sealed class StoreWindow
    {
        private readonly int _start;
        private readonly byte[] _bytes;
        private int _filled;

        public StoreWindow(int start, int length)
        {
            _start = start;
            _bytes = new byte[length];
        }

        /// <summary>True once every byte of the range has been seen.</summary>
        public bool IsComplete => _filled == _bytes.Length;

        public ReadOnlySpan<byte> Bytes => _bytes;

        /// <summary>
        /// Copies whatever part of <paramref name="chunk"/> — which starts at store offset
        /// <paramref name="chunkStart"/> — overlaps this window. The store is read forward-only in
        /// one pass, so no byte is offered twice.
        /// </summary>
        public void Absorb(int chunkStart, ReadOnlySpan<byte> chunk)
        {
            int from = Math.Max(_start, chunkStart);
            int to = Math.Min(_start + _bytes.Length, chunkStart + chunk.Length);
            if (to <= from)
            {
                return;
            }

            chunk.Slice(from - chunkStart, to - from).CopyTo(_bytes.AsSpan(from - _start));
            _filled += to - from;
        }
    }

    /// <summary>
    /// Forward-only reader that refuses to hand out more than a fixed total number of bytes.
    /// The signature verifier consumes the RPM in one pass, so the bound is on bytes read from
    /// the stream rather than on a buffer that holds them.
    /// </summary>
    private sealed class BoundedReader
    {
        private readonly Stream _stream;
        private long _remaining;

        public BoundedReader(Stream stream, long maxBytes)
        {
            _stream = stream;
            _remaining = maxBytes;
        }

        /// <summary>
        /// Reads exactly <paramref name="count"/> bytes, or returns null when the stream ends
        /// early or the read would exceed the byte budget.
        /// </summary>
        public async Task<byte[]?> ReadExactlyAsync(int count, CancellationToken ct)
        {
            if (count < 0 || count > _remaining)
            {
                return null;
            }

            byte[] buffer = new byte[count];
            int filled = 0;
            while (filled < count)
            {
                int read = await _stream.ReadAsync(buffer.AsMemory(filled, count - filled), ct);
                if (read == 0)
                {
                    return null;
                }

                filled += read;
            }

            _remaining -= count;
            return buffer;
        }

        /// <summary>
        /// Reads up to <paramref name="count"/> bytes into <paramref name="buffer"/>. Returns 0 at
        /// end of stream; throws when the stream still holds data past the byte budget, so an
        /// oversized package is reported unverifiable instead of verifying a truncated region.
        /// </summary>
        public async Task<int> ReadAsync(byte[] buffer, int count, CancellationToken ct)
        {
            if (_remaining <= 0)
            {
                // Budget spent. One probe byte distinguishes "package ends exactly at the cap"
                // (verifiable) from "package continues past the cap" (unverifiable).
                byte[] probe = new byte[1];
                return await _stream.ReadAsync(probe.AsMemory(0, 1), ct) > 0
                    ? throw new InvalidOperationException("RPM package exceeds the verification size cap.")
                    : 0;
            }

            int want = (int)Math.Min(count, _remaining);
            int read = await _stream.ReadAsync(buffer.AsMemory(0, want), ct);
            _remaining -= read;
            return read;
        }
    }
}
