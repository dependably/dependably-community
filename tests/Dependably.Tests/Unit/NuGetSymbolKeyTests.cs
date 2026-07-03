using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the SSQP key derivation for Portable PDBs. The GUID byte order is the classic correctness
/// trap: the symstore spec's worked example fixes the exact mapping, so this test locks it against
/// a future refactor silently swapping endianness.
/// </summary>
public sealed class NuGetSymbolKeyTests
{
    [Fact]
    public void PortableKey_MatchesSymstoreWorkedExample()
    {
        // symstore SSQP_Key_Conventions worked example:
        // signature {0x497B72F6,0x390A,0x44FC,{0x87,0x8E,0x5A,0x2D,0x63,0xB6,0xCC,0x4B}}
        // → GUID "N" format 497b72f6390a44fc878e5a2d63b6cc4b, age FFFFFFFF for Portable PDBs.
        var signature = new Guid(0x497B72F6, 0x390A, 0x44FC, 0x87, 0x8E, 0x5A, 0x2D, 0x63, 0xB6, 0xCC, 0x4B);

        string key = NuGetSymbolKey.PortableKey(signature);

        Assert.Equal("497b72f6390a44fc878e5a2d63b6cc4bffffffff", key);
    }

    [Fact]
    public void PortableKey_IsLowercaseWithFixedAgeSuffix()
    {
        var signature = Guid.Parse("A1B2C3D4-E5F6-4788-99AA-BBCCDDEEFF00");

        string key = NuGetSymbolKey.PortableKey(signature);

        Assert.Equal(40, key.Length);
        Assert.EndsWith("ffffffff", key);
        Assert.Equal(key, key.ToLowerInvariant());
        Assert.StartsWith("a1b2c3d4e5f6478899aabbccddeeff00", key);
    }

    [Fact]
    public void LookupPath_LowercasesFilenameAtBothPositions()
    {
        string path = NuGetSymbolKey.LookupPath("MyLib.PDB", "497B72F6390A44FC878E5A2D63B6CC4BFFFFFFFF");

        Assert.Equal(
            "mylib.pdb/497b72f6390a44fc878e5a2d63b6cc4bffffffff/mylib.pdb",
            path);
    }

    [Fact]
    public void TryReadPortableKey_RoundTripsSignatureFromRealPortablePdb()
    {
        // A real Portable PDB built with a forced signature must read back to the same SSQP key,
        // confirming the DebugMetadataHeader.Id → Guid extraction agrees with the writer.
        var signature = new Guid(0x497B72F6, 0x390A, 0x44FC, 0x87, 0x8E, 0x5A, 0x2D, 0x63, 0xB6, 0xCC, 0x4B);
        byte[] pdb = NuGetFixtures.BuildPortablePdb(signature);

        using var stream = new MemoryStream(pdb);
        string? key = NuGetSymbolKey.TryReadPortableKey(stream);

        Assert.Equal("497b72f6390a44fc878e5a2d63b6cc4bffffffff", key);
    }

    [Fact]
    public void TryReadPortableKey_ReturnsNullForNonPortablePdb()
    {
        // Garbage / native-PDB bytes are not indexable and must be skipped, not throw.
        using var stream = new MemoryStream("this is not a portable pdb"u8.ToArray());

        Assert.Null(NuGetSymbolKey.TryReadPortableKey(stream));
    }

    [Fact]
    public void ExtractPortablePdbs_IndexesValidAndSkipsInvalid()
    {
        // Mixed archive: one valid Portable PDB and one unreadable PDB entry. Only the valid one
        // is indexed; the invalid one is skipped without failing the extraction.
        var signature = Guid.Parse("11112222-3333-4444-5555-666677778888");
        byte[] validPdb = NuGetFixtures.BuildPortablePdb(signature);
        byte[] junkPdb = "not a pdb"u8.ToArray();
        byte[] snupkg = NuGetFixtures.BuildSnupkgWithPdbs(
            "MixPkg", "1.0.0", ("valid.pdb", validPdb), ("broken.pdb", junkPdb));

        using var stream = new MemoryStream(snupkg);
        var symbols = NuGetSymbolKey.ExtractPortablePdbs(stream);

        var only = Assert.Single(symbols);
        Assert.Equal("valid.pdb", only.PdbFileName);
        Assert.Equal(NuGetSymbolKey.PortableKey(signature), only.SsqpKey);
        Assert.Equal("lib/netstandard2.0/valid.pdb", only.EntryPath);
    }
}
