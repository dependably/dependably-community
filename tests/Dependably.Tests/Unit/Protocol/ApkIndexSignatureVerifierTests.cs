using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="ApkIndexSignatureVerifier"/> against both the committed real-format
/// fixture (built with genuine <c>tar</c>/<c>gzip</c>/<c>openssl</c>) and hand-crafted
/// two-gzip-member payloads that isolate the parser's edge cases. The fixture-based structural
/// test pins the exact byte boundary between the two gzip members — the detail this parser
/// exists to get right — so a regression in the trailer-scan boundary detection fails loudly.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ApkIndexSignatureVerifierTests
{
    private static readonly string FixtureIndexPath =
        Path.Combine(FixtureManifest.FixturesRoot, "apk", "APKINDEX-signed.tar.gz");
    private static readonly string FixtureKeyPath =
        Path.Combine(FixtureManifest.FixturesRoot, "apk", "test-signing-key.pub.pem");

    // ── Real fixture: structural parse ───────────────────────────────────────────

    [Fact]
    public void TryParse_RealFixture_SplitsAtTheExpectedBoundary()
    {
        byte[] apkindex = File.ReadAllBytes(FixtureIndexPath);

        var parsed = ApkIndexSignatureVerifier.TryParse(apkindex, NullLogger.Instance);

        Assert.NotNull(parsed);
        Assert.Single(parsed!.Signatures);
        var sig = parsed.Signatures[0];
        Assert.Equal(ApkSignatureAlgorithm.Sha1, sig.Algorithm);
        Assert.Equal("dependably-test@example.com-aabbccdd.rsa.pub", sig.KeyName);
        Assert.Equal(256, sig.SignatureBytes.Length);
        Assert.Equal(394, parsed.SignedPayload.Length);
    }

    // ── Real fixture: end-to-end verification ────────────────────────────────────

    [Fact]
    public void Verify_RealFixture_WithMatchingAnchor_Succeeds()
    {
        byte[] apkindex = File.ReadAllBytes(FixtureIndexPath);
        string pem = File.ReadAllText(FixtureKeyPath);
        Assert.True(ApkTrustAnchorKeyStore.TryParseRsaPublicKey(pem, out var rsa, NullLogger.Instance));

        bool verified = ApkIndexSignatureVerifier.Verify(apkindex, [rsa!], NullLogger.Instance);

        Assert.True(verified);
        rsa!.Dispose();
    }

    [Fact]
    public void Verify_RealFixture_WithUnrelatedAnchor_Fails()
    {
        byte[] apkindex = File.ReadAllBytes(FixtureIndexPath);
        using var unrelated = RSA.Create(2048);

        var (verified, reason) = ApkIndexSignatureVerifier.VerifyWithReason(apkindex, [unrelated], NullLogger.Instance);

        Assert.False(verified);
        Assert.Equal("bad_signature", reason);
    }

    [Fact]
    public void Verify_RealFixture_TamperedPayloadByte_Fails()
    {
        byte[] apkindex = File.ReadAllBytes(FixtureIndexPath);
        string pem = File.ReadAllText(FixtureKeyPath);
        Assert.True(ApkTrustAnchorKeyStore.TryParseRsaPublicKey(pem, out var rsa, NullLogger.Instance));

        // Flip a byte deep inside the signed payload (member 2, well after the boundary).
        byte[] tampered = (byte[])apkindex.Clone();
        tampered[^10] ^= 0xFF;

        bool verified = ApkIndexSignatureVerifier.Verify(tampered, [rsa!], NullLogger.Instance);

        Assert.False(verified);
        rsa!.Dispose();
    }

    // ── Hand-crafted payloads: parser edge cases ─────────────────────────────────

    [Fact]
    public void Verify_HandCraftedRsa256Signature_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(
            "APKINDEX content"u8.ToArray(), rsa, "test@example.com-deadbeef.rsa.pub", ApkSignatureAlgorithm.Sha256);

        bool verified = ApkIndexSignatureVerifier.Verify(apkindex, [rsa], NullLogger.Instance);

        Assert.True(verified);
    }

    [Fact]
    public void Verify_HandCraftedRsa512Signature_Succeeds()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(
            "APKINDEX content"u8.ToArray(), rsa, "test@example.com-deadbeef.rsa.pub", ApkSignatureAlgorithm.Sha512);

        bool verified = ApkIndexSignatureVerifier.Verify(apkindex, [rsa], NullLogger.Instance);

        Assert.True(verified);
    }

    [Fact]
    public void Verify_NoAnchors_Fails()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(
            "APKINDEX content"u8.ToArray(), rsa, "test@example.com-deadbeef.rsa.pub", ApkSignatureAlgorithm.Sha1);

        var (verified, reason) = ApkIndexSignatureVerifier.VerifyWithReason(apkindex, [], NullLogger.Instance);

        Assert.False(verified);
        Assert.Equal("no_trusted_key", reason);
    }

    [Fact]
    public void Verify_MalformedGzip_ReturnsFalseWithoutThrowing()
    {
        byte[] garbage = [0x00, 0x01, 0x02, 0x03, 0x04];
        using var rsa = RSA.Create(2048);

        var (verified, reason) = ApkIndexSignatureVerifier.VerifyWithReason(garbage, [rsa], NullLogger.Instance);

        Assert.False(verified);
        Assert.Equal("malformed_index", reason);
    }

    [Fact]
    public void Verify_TruncatedInput_ReturnsFalseWithoutThrowing()
    {
        using var rsa = RSA.Create(2048);
        byte[] apkindex = BuildSignedApkIndex(
            "APKINDEX content"u8.ToArray(), rsa, "test@example.com-deadbeef.rsa.pub", ApkSignatureAlgorithm.Sha1);
        byte[] truncated = apkindex[..(apkindex.Length / 2)];

        var (verified, reason) = ApkIndexSignatureVerifier.VerifyWithReason(truncated, [rsa], NullLogger.Instance);

        Assert.False(verified);
        Assert.Equal("malformed_index", reason);
    }

    [Fact]
    public void Verify_SignatureMemberMissingSignEntry_ReturnsMissingSignature()
    {
        byte[] member1 = BuildGzipTarMember("not-a-signature.txt", "hello"u8.ToArray());
        byte[] member2 = BuildGzipMember("APKINDEX content"u8.ToArray());
        byte[] apkindex = [.. member1, .. member2];
        using var rsa = RSA.Create(2048);

        var (verified, reason) = ApkIndexSignatureVerifier.VerifyWithReason(apkindex, [rsa], NullLogger.Instance);

        Assert.False(verified);
        Assert.Equal("missing_signature", reason);
    }

    [Fact]
    public void Verify_MultipleSigners_AcceptsWhenAnyAnchorMatches()
    {
        using var signerA = RSA.Create(2048);
        using var signerB = RSA.Create(2048);
        byte[] payload = "APKINDEX content"u8.ToArray();
        byte[] member2 = BuildGzipMember(payload);

        byte[] sigA = signerA.SignData(member2, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        byte[] sigB = signerB.SignData(member2, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, ".SIGN.RSA.signer-a") { DataStream = new MemoryStream(sigA) });
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, ".SIGN.RSA.signer-b") { DataStream = new MemoryStream(sigB) });
        }
        byte[] member1 = ms.ToArray();
        byte[] apkindex = [.. member1, .. member2];

        // Only signer B is a trusted anchor; verification must still succeed because the
        // codebase's anchor semantics accept a signature verified by *any* configured anchor.
        bool verified = ApkIndexSignatureVerifier.Verify(apkindex, [signerB], NullLogger.Instance);

        Assert.True(verified);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] BuildSignedApkIndex(
        byte[] indexContent, RSA signingKey, string keyName, ApkSignatureAlgorithm algorithm)
    {
        byte[] member2 = BuildGzipMember(indexContent);
        var hash = algorithm switch
        {
            ApkSignatureAlgorithm.Sha1 => HashAlgorithmName.SHA1,
            ApkSignatureAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            ApkSignatureAlgorithm.Sha512 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
        byte[] sig = signingKey.SignData(member2, hash, RSASignaturePadding.Pkcs1);

        string prefix = algorithm switch
        {
            ApkSignatureAlgorithm.Sha256 => ".SIGN.RSA256.",
            ApkSignatureAlgorithm.Sha512 => ".SIGN.RSA512.",
            _ => ".SIGN.RSA.",
        };
        byte[] member1 = BuildGzipTarMember(prefix + keyName, sig);
        return [.. member1, .. member2];
    }

    private static byte[] BuildGzipTarMember(string entryName, byte[] entryContent)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName) { DataStream = new MemoryStream(entryContent) };
            tw.WriteEntry(entry);
        }
        return ms.ToArray();
    }

    private static byte[] BuildGzipMember(byte[] content)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(content);
        }
        return ms.ToArray();
    }
}
