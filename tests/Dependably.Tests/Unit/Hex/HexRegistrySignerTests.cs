using System.IO.Compression;
using System.Security.Cryptography;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

[Trait("Category", "Unit")]
public sealed class HexRegistrySignerTests
{
    private static string Fixture(string name) => Path.Combine(FixtureManifest.FixturesRoot, "hex", name);

    [Fact]
    public void RealHexpmResource_VerifiesAgainstTheRealHexpmKey()
    {
        using var key = HexRegistrySigner.ParsePublicKeyPem(File.ReadAllText(Fixture("hexpm-public-key.pem")));
        byte[] resource = File.ReadAllBytes(Fixture("decimal.package.signed.gz"));

        byte[] payload = HexRegistrySigner.OpenResource(resource, key);

        Assert.Equal("decimal", HexRegistryCodec.DecodePackage(payload).Name);
    }

    [Fact]
    public void RealHexpmResource_TamperedPayload_FailsVerification()
    {
        using var key = HexRegistrySigner.ParsePublicKeyPem(File.ReadAllText(Fixture("hexpm-public-key.pem")));
        byte[] envelope = HexRegistrySigner.Gunzip(File.ReadAllBytes(Fixture("decimal.package.signed.gz")));
        var signed = HexRegistryCodec.DecodeSigned(envelope);
        signed.Payload[^1] ^= 0x01;
        byte[] tampered = HexRegistrySigner.Gzip(HexRegistryCodec.EncodeSigned(signed));

        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.OpenResource(tampered, key));
    }

    [Fact]
    public void RealHexpmResource_WrongKey_FailsVerification()
    {
        using var otherKey = RSA.Create(2048);
        byte[] resource = File.ReadAllBytes(Fixture("decimal.package.signed.gz"));

        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.OpenResource(resource, otherKey));
    }

    [Fact]
    public void BuildAndOpen_RoundTrips_AndIsDeterministic()
    {
        using var key = RSA.Create(2048);
        byte[] payload = HexRegistryCodec.EncodeNames(new HexNames("acme", new[] { new HexNameEntry("alpha") }));

        byte[] first = HexRegistrySigner.BuildResource(payload, key);
        byte[] second = HexRegistrySigner.BuildResource(payload, key);

        Assert.Equal(first, second);
        Assert.Equal(payload, HexRegistrySigner.OpenResource(first, key));
        Assert.Equal(0x1F, first[0]);
        Assert.Equal(0x8B, first[1]);
    }

    [Fact]
    public void UnsignedEnvelope_IsRefused()
    {
        using var key = RSA.Create(2048);
        byte[] unsigned = HexRegistrySigner.Gzip(HexRegistryCodec.EncodeSigned(new HexSigned(new byte[] { 1, 2, 3 }, null)));

        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.OpenResource(unsigned, key));
    }

    [Fact]
    public void SignatureIsPkcs1v15OverSha512()
    {
        // The exact primitive hex_core verifies with public_key:verify(Payload, sha512, Sig, Key):
        // PKCS#1 v1.5, not PSS. A PSS signature over the same digest must not verify.
        using var key = RSA.Create(2048);
        byte[] payload = "payload"u8.ToArray();

        byte[] signature = HexRegistrySigner.Sign(payload, key);

        Assert.True(key.VerifyData(payload, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
        byte[] pss = key.SignData(payload, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        Assert.False(HexRegistrySigner.Verify(payload, pss, key));
    }

    [Fact]
    public void Gunzip_IsBoundedAgainstDecompressionBombs()
    {
        // 80 MiB of zeros compresses to a few KiB; the cap must stop the expansion.
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        {
            byte[] zeros = new byte[1024 * 1024];
            for (int i = 0; i < 80; i++)
            {
                gz.Write(zeros);
            }
        }

        Assert.ThrowsAny<Exception>(() => HexRegistrySigner.Gunzip(ms.ToArray()));
    }

    [Fact]
    public void NotGzip_IsRefused()
    {
        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.Gunzip("not gzip at all"u8));
    }

    [Fact]
    public void PublicKeyPem_ExportsAndParses()
    {
        using var key = RSA.Create(2048);
        string pem = HexRegistrySigner.ExportPublicKeyPem(key);

        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pem);
        Assert.EndsWith("-----END PUBLIC KEY-----\n", pem);
        using var parsed = HexRegistrySigner.ParsePublicKeyPem(pem);
        Assert.Equal(key.ExportParameters(false).Modulus, parsed.ExportParameters(false).Modulus);
    }

    [Fact]
    public void GarbagePem_IsRefused()
    {
        Assert.Throws<HexProtocolException>(() => HexRegistrySigner.ParsePublicKeyPem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"));
    }
}
