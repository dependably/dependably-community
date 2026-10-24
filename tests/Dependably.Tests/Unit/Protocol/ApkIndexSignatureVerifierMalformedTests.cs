using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using Dependably.Protocol.Provenance;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The hostile-input arms of the apk index parser: every malformed gzip header, an unlocatable
/// member boundary, a decompression bomb, and a signature member stuffed with oversized,
/// empty, mis-named or excess entries. Each resolves to a refusal with a machine-readable
/// reason and never to a pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ApkIndexSignatureVerifierMalformedTests
{
    private static readonly byte[] IndexContent = "C:Q1abc\nP:openssl\nV:3.3.2-r0\n"u8.ToArray();

    private static (bool Verified, string Reason) Check(byte[] apkindex, params RSA[] anchors)
        => ApkIndexSignatureVerifier.VerifyWithReason(apkindex, anchors, NullLogger.Instance);

    // ── gzip header ─────────────────────────────────────────────────────────────

    [Fact]
    public void AHeaderCarryingEveryOptionalField_StillParsesAndVerifies()
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] sig = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] member1 = WithOptionalHeaderFields(
            GzipTar((".SIGN.RSA256.alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub", sig)),
            extra: [1, 2, 3], name: "SIGN", comment: "signature", headerCrc: true);

        var (verified, reason) = Check([.. member1, .. payload], rsa);

        Assert.True(verified);
        Assert.Equal("", reason);
    }

    [Theory]
    [InlineData(0x04)]
    [InlineData(0x08)]
    [InlineData(0x10)]
    [InlineData(0x02)]
    public void ATruncatedOptionalHeaderField_IsMalformed(int flag)
    {
        using var rsa = RSA.Create(2048);
        byte[] header = [0x1f, 0x8b, 0x08, (byte)flag, 0, 0, 0, 0, 0, 0xff];

        var (verified, reason) = Check(header, rsa);

        Assert.False(verified);
        Assert.Equal("malformed_index", reason);
    }

    [Fact]
    public void AnExtraFieldLongerThanTheInput_IsMalformed()
    {
        using var rsa = RSA.Create(2048);
        byte[] bytes = [0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 1, 2, 3];

        Assert.Equal("malformed_index", Check(bytes, rsa).Reason);
    }

    [Fact]
    public void ANameFieldWhoseTerminatorEndsTheInput_IsMalformedForWantOfABody()
    {
        using var rsa = RSA.Create(2048);
        byte[] bytes = [0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0, 0xff, (byte)'a', 0];

        Assert.Equal("malformed_index", Check(bytes, rsa).Reason);
    }

    [Fact]
    public void ANonDeflateCompressionMethod_IsMalformed()
    {
        using var rsa = RSA.Create(2048);
        byte[] bytes = Gzip(IndexContent);
        bytes[2] = 0x07;

        Assert.Equal("malformed_index", Check(bytes, rsa).Reason);
    }

    [Fact]
    public void ACorruptDeflateBody_IsMalformed()
    {
        using var rsa = RSA.Create(2048);
        byte[] bytes = [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        Assert.Equal("malformed_index", Check(bytes, rsa).Reason);
    }

    [Fact]
    public void AFirstMemberThatInflatesPastTheSignatureCap_IsMalformed()
    {
        using var rsa = RSA.Create(2048);
        byte[] bomb = Gzip(new byte[(int)ApkIndexSignatureLimits.MaxSignatureMemberDecompressedBytes + 1024]);

        var (verified, reason) = Check([.. bomb, .. Gzip(IndexContent)], rsa);

        Assert.False(verified);
        Assert.Equal("malformed_index", reason);
    }

    // ── member boundary ─────────────────────────────────────────────────────────

    [Fact]
    public void AnIndexWithOnlyTheSignatureMember_HasNoSignedPayloadAndIsMalformed()
    {
        using var rsa = RSA.Create(2048);
        byte[] member1 = GzipTar((".SIGN.RSA256.k.rsa.pub", new byte[256]));

        Assert.Equal("malformed_index", Check(member1, rsa).Reason);
    }

    [Fact]
    public void TrailingBytesThatAreNotAnotherGzipMember_LeaveTheBoundaryUnlocatable()
    {
        using var rsa = RSA.Create(2048);
        byte[] member1 = GzipTar((".SIGN.RSA256.k.rsa.pub", new byte[256]));

        var (verified, reason) = Check([.. member1, 0xAA, 0xBB, 0xCC], rsa);

        Assert.False(verified);
        Assert.Equal("malformed_index", reason);
    }

    [Fact]
    public void ASignatureMemberThatIsGzipButNotATar_IsMalformed()
    {
        using var rsa = RSA.Create(2048);
        byte[] notATar = Gzip(Enumerable.Repeat((byte)'x', 1024).ToArray());

        var (verified, reason) = Check([.. notATar, .. Gzip(IndexContent)], rsa);

        Assert.False(verified);
        Assert.Equal("malformed_index", reason);
    }

    // ── signature entries ───────────────────────────────────────────────────────

    [Fact]
    public void ADotSlashPrefixedEntry_IsRecognisedAndVerifies()
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] sig = rsa.SignData(payload, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        byte[] member1 = GzipTar(("./.SIGN.RSA512.builder.rsa.pub", sig));

        Assert.True(Check([.. member1, .. payload], rsa).Verified);
    }

    [Fact]
    public void OnlyEntriesThatCannotBeUsed_ReportMissingSignature()
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] member1 = GzipTar(
            (".SIGN.RSA256.", new byte[256]),
            (".SIGN.RSA256.empty.rsa.pub", []),
            (".SIGN.DSA.legacy.pub", new byte[64]),
            ("README", "hello"u8.ToArray()),
            (".SIGN.RSA512.oversize.rsa.pub", new byte[ApkIndexSignatureLimits.MaxSignatureBytes + 1]));

        var (verified, reason) = Check([.. member1, .. payload], rsa);

        Assert.False(verified);
        Assert.Equal("missing_signature", reason);
    }

    [Fact]
    public void ADirectoryEntryAmongTheSignatures_IsSkipped_AndTheRealSignatureStillVerifies()
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] sig = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "keys/"));
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, ".SIGN.RSA256.builder.rsa.pub")
            {
                DataStream = new MemoryStream(sig),
            });
        }

        Assert.True(Check([.. ms.ToArray(), .. payload], rsa).Verified);
    }

    [Fact]
    public void EntriesBeyondTheScanCap_AreNeverReached()
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] sig = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var entries = new List<(string, byte[])>();
        for (int i = 0; i < ApkIndexSignatureLimits.MaxSignatureEntries; i++)
        {
            entries.Add(($"filler-{i}.txt", [1]));
        }

        entries.Add((".SIGN.RSA256.too-late.rsa.pub", sig));
        byte[] member1 = GzipTar([.. entries]);

        var (verified, reason) = Check([.. member1, .. payload], rsa);

        Assert.False(verified);
        Assert.Equal("missing_signature", reason);
    }

    [Fact]
    public void AnOversizedEntryIsSkipped_WithoutDiscardingALaterValidSignature()
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] sig = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] member1 = GzipTar(
            (".SIGN.RSA256.bloated.rsa.pub", new byte[ApkIndexSignatureLimits.MaxSignatureBytes + 100]),
            (".SIGN.RSA256.builder.rsa.pub", sig));

        Assert.True(Check([.. member1, .. payload], rsa).Verified);
    }

    [Theory]
    [InlineData(10)]
    [InlineData(256)]
    public void ASignatureOfTheWrongContent_IsABadSignature_NotAnException(int length)
    {
        using var rsa = RSA.Create(2048);
        byte[] payload = Gzip(IndexContent);
        byte[] member1 = GzipTar((".SIGN.RSA256.builder.rsa.pub", Enumerable.Repeat((byte)0x5a, length).ToArray()));

        var (verified, reason) = Check([.. member1, .. payload], rsa);

        Assert.False(verified);
        Assert.Equal("bad_signature", reason);
    }

    [Fact]
    public void ASignatureOverADifferentPayload_IsRefused_EvenWithTheCorrectAnchor()
    {
        using var rsa = RSA.Create(2048);
        byte[] signedPayload = Gzip(IndexContent);
        byte[] servedPayload = Gzip("C:Q1evil\nP:openssl\nV:9.9.9-r0\n"u8.ToArray());
        byte[] sig = rsa.SignData(signedPayload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        byte[] member1 = GzipTar((".SIGN.RSA256.builder.rsa.pub", sig));

        var (verified, reason) = Check([.. member1, .. servedPayload], rsa);

        Assert.False(verified);
        Assert.Equal("bad_signature", reason);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────

    private static byte[] Gzip(byte[] content)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(content);
        }

        return ms.ToArray();
    }

    private static byte[] GzipTar(params (string Name, byte[] Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(content) });
            }
        }

        return ms.ToArray();
    }

    // Rewrites a plain gzip member's header to carry the optional FEXTRA/FNAME/FCOMMENT/FHCRC
    // fields; the deflate body and trailer are untouched.
    private static byte[] WithOptionalHeaderFields(
        byte[] member, byte[] extra, string name, string comment, bool headerCrc)
    {
        byte[] header = member[..10];
        byte flags = 0;
        var added = new List<byte>();
        flags |= 0x04;
        added.Add((byte)(extra.Length & 0xff));
        added.Add((byte)(extra.Length >> 8));
        added.AddRange(extra);
        flags |= 0x08;
        added.AddRange(System.Text.Encoding.ASCII.GetBytes(name));
        added.Add(0);
        flags |= 0x10;
        added.AddRange(System.Text.Encoding.ASCII.GetBytes(comment));
        added.Add(0);
        if (headerCrc)
        {
            flags |= 0x02;
            added.AddRange(new byte[] { 0, 0 });
        }

        header[3] = flags;
        return [.. header, .. added, .. member[10..]];
    }
}
