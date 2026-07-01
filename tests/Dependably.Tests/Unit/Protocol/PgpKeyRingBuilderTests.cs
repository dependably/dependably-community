using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Exercises <see cref="PgpKeyRingBuilder"/> — the shared helper that parses ASCII-armored
/// or base64-encoded OpenPGP public keys and merges multiple <see cref="TrustAnchorMaterial"/>
/// rows into a single key-ring bundle.
///
/// Test coverage:
///  - Valid ASCII-armored key: TryParse returns a non-null bundle.
///  - Plaintext garbage: TryParse returns null (does not throw).
///  - Mixed batch: BuildFromAnchors with one parseable + one garbage anchor — parseable entry
///    is included, garbage entry is skipped with no exception (partial-success isolation).
///  - Empty anchor list: BuildFromAnchors returns null (no valid rings).
///  - FirstFingerprint: returns a non-empty lowercase hex string for a valid bundle.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PgpKeyRingBuilderTests
{
    private readonly ILogger _logger = NullLogger.Instance;

    [Fact]
    public void TryParse_ValidArmoredKey_ReturnsBundle()
    {
        byte[] armoredKey = GenerateArmoredPublicKey();
        string material = Encoding.ASCII.GetString(armoredKey);

        var bundle = PgpKeyRingBuilder.TryParse(material, _logger, "test");

        Assert.NotNull(bundle);
    }

    [Fact]
    public void TryParse_Garbage_ReturnsNull()
    {
        var bundle = PgpKeyRingBuilder.TryParse("not a PGP key block at all", _logger, "test");

        Assert.Null(bundle);
    }

    [Fact]
    public void TryParse_NullMaterial_ReturnsNull()
    {
        var bundle = PgpKeyRingBuilder.TryParse(null, _logger, "test");

        Assert.Null(bundle);
    }

    [Fact]
    public void TryParse_EmptyString_ReturnsNull()
    {
        var bundle = PgpKeyRingBuilder.TryParse("", _logger, "test");

        Assert.Null(bundle);
    }

    [Fact]
    public void FirstFingerprint_ValidBundle_ReturnsLowercaseHex()
    {
        byte[] armoredKey = GenerateArmoredPublicKey();
        string material = Encoding.ASCII.GetString(armoredKey);
        var bundle = PgpKeyRingBuilder.TryParse(material, _logger, "test");

        string? fp = PgpKeyRingBuilder.FirstFingerprint(bundle!);

        Assert.NotNull(fp);
        Assert.Matches("^[0-9a-f]+$", fp!);
    }

    // ── BuildFromAnchors: partial-failure isolation ───────────────────────────

    [Fact]
    public void BuildFromAnchors_MixedGoodAndBadAnchors_IncludesOnlyParseable()
    {
        // One valid key and one garbage entry in the same batch. BuildFromAnchors must
        // include the valid entry and skip the garbage with no exception — so a single
        // malformed anchor row does not invalidate the entire org's trust ring.
        byte[] armoredKey = GenerateArmoredPublicKey();
        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "good", AnchorKind = "pgp", Material = Encoding.ASCII.GetString(armoredKey) },
            new() { Id = "bad",  AnchorKind = "pgp", Material = "totally invalid not a pgp key" },
        };

        var bundle = PgpKeyRingBuilder.BuildFromAnchors(anchors, _logger, "rpm");

        // The good entry must produce a usable bundle.
        Assert.NotNull(bundle);
        // The bundle must contain exactly one key ring (from the one valid anchor).
        // GetKeyRings returns System.Collections.IEnumerable over PgpPublicKeyRing objects.
        var rings = bundle!.GetKeyRings().Cast<Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKeyRing>().ToList();
        Assert.Single(rings);
    }

    [Fact]
    public void BuildFromAnchors_AllBadAnchors_ReturnsNull()
    {
        var anchors = new List<TrustAnchorMaterial>
        {
            new() { Id = "bad1", AnchorKind = "pgp", Material = "garbage1" },
            new() { Id = "bad2", AnchorKind = "pgp", Material = "garbage2" },
        };

        var bundle = PgpKeyRingBuilder.BuildFromAnchors(anchors, _logger, "rpm");

        Assert.Null(bundle);
    }

    [Fact]
    public void BuildFromAnchors_EmptyList_ReturnsNull()
    {
        var bundle = PgpKeyRingBuilder.BuildFromAnchors([], _logger, "rpm");

        Assert.Null(bundle);
    }

    // ── helper ───────────────────────────────────────────────────────────────

    private static byte[] GenerateArmoredPublicKey()
    {
        var gen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new SecureRandom(), 1024, 12));
        var kp = gen.GenerateKeyPair();

        var pgpPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp,
            new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secretKey = new PgpSecretKey(
            PgpSignature.DefaultCertification, pgpPair,
            "test@example.com", SymmetricKeyAlgorithmTag.Null,
            passPhrase: null, useSha1: true, null, null, new SecureRandom());

        using var ms = new MemoryStream();
        using (var ao = new ArmoredOutputStream(ms))
        {
            secretKey.PublicKey.Encode(ao);
        }
        return ms.ToArray();
    }
}
