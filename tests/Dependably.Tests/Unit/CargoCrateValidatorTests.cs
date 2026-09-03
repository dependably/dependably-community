using System.Text;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Publish-time cross-check of a <c>.crate</c>'s embedded <c>Cargo.toml</c> against the
/// coordinates the publish frame declared. The control (a matching crate passes) sits beside each
/// refusal so the refusals are shown to discriminate rather than to reject everything.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CargoCrateValidatorTests
{
    private static ValidationResult Check(byte[] crate, string name, string version)
        => CargoCrateValidator.Validate(new MemoryStream(crate), name, version);

    [Fact]
    public void MatchingManifest_Passes()
    {
        var result = Check(CargoFixtures.BuildCrate("demo-crate", "1.2.3"), "demo-crate", "1.2.3");
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public void MatchingManifest_WithExtraPackageKeysAndOtherSections_Passes()
    {
        byte[] crate = CargoFixtures.BuildCrate("demo-crate", "1.2.3",
            extraPackageLines: "license = \"MIT\"\nauthors = [\"A <a@x>\"]\ndescription = \"x\"");
        Assert.True(Check(crate, "demo-crate", "1.2.3").IsValid);
    }

    [Fact]
    public void NameMismatch_RefusedNamingBothSides()
    {
        byte[] crate = CargoFixtures.BuildCrate("demo-crate", "1.2.3", manifestName: "other-crate");
        var result = Check(crate, "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
        Assert.Equal("name", result.FieldName);
        Assert.Contains("'other-crate'", result.Message);
        Assert.Contains("'demo-crate'", result.Message);
    }

    [Fact]
    public void VersionMismatch_RefusedNamingBothSides()
    {
        byte[] crate = CargoFixtures.BuildCrate("demo-crate", "1.2.3", manifestVersion: "9.9.9");
        var result = Check(crate, "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
        Assert.Equal("vers", result.FieldName);
        Assert.Contains("'9.9.9'", result.Message);
        Assert.Contains("'1.2.3'", result.Message);
    }

    [Fact]
    public void NameComparisonIsOrdinal_CaseAndSeparatorVariantsRefused()
    {
        // crates.io treats `-`/`_` and case as the same crate for uniqueness, but cargo writes the
        // manifest's exact spelling into the frame; a variant means the frame was not produced
        // from this archive.
        Assert.False(Check(CargoFixtures.BuildCrate("demo-crate", "1.0.0", manifestName: "demo_crate"), "demo-crate", "1.0.0").IsValid);
        Assert.False(Check(CargoFixtures.BuildCrate("demo-crate", "1.0.0", manifestName: "Demo-Crate"), "demo-crate", "1.0.0").IsValid);
    }

    [Fact]
    public void RootDirectoryDisagreesWithCoordinates_Refused()
    {
        // Manifest agrees, but the archive unpacks somewhere cargo would refuse to read.
        byte[] crate = CargoFixtures.BuildCrate("demo-crate", "1.2.3", rootDir: "demo-crate-0.0.1");
        var result = Check(crate, "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
        Assert.Contains("demo-crate-1.2.3/", result.Message);
    }

    [Fact]
    public void NoRootCargoToml_Refused()
    {
        byte[] crate = CargoFixtures.BuildTarGz(("demo-crate-1.2.3/src/lib.rs", "// no manifest"));
        var result = Check(crate, "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
        Assert.Contains("missing a root Cargo.toml", result.Message);
    }

    [Fact]
    public void NestedCargoTomlOnly_IsNotTheCratesManifest_Refused()
    {
        byte[] crate = CargoFixtures.BuildTarGz(
            ("demo-crate-1.2.3/vendor/dep/Cargo.toml", "[package]\nname = \"demo-crate\"\nversion = \"1.2.3\"\n"));
        Assert.False(Check(crate, "demo-crate", "1.2.3").IsValid);
    }

    [Fact]
    public void ManifestWithoutPackageNameOrVersion_Refused()
    {
        byte[] crate = CargoFixtures.BuildTarGz(
            ("demo-crate-1.2.3/Cargo.toml", "[package]\nedition = \"2021\"\n\n[dependencies]\nname = \"demo-crate\"\nversion = \"1.2.3\"\n"));
        var result = Check(crate, "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
        Assert.Contains("no parseable [package]", result.Message);
    }

    [Fact]
    public void OpaqueBytes_NotAnArchive_Refused()
    {
        var result = Check("real-crate-bytes-for-publish"u8.ToArray(), "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
        Assert.Contains("Invalid gzip tar", result.Message);
    }

    [Fact]
    public void ManifestLargerThanTheManifestCap_Refused()
    {
        // A 4 MiB + 1 manifest compresses to a few KiB; the entry cap, not the total cap, must
        // stop it, and a refusal must come back rather than an exception.
        var sb = new StringBuilder("[package]\nname = \"demo-crate\"\nversion = \"1.2.3\"\n# ");
        sb.Append('x', (int)TarScanLimits.MaxManifestBytes);
        byte[] crate = CargoFixtures.BuildTarGz(("demo-crate-1.2.3/Cargo.toml", sb.ToString()));
        var result = Check(crate, "demo-crate", "1.2.3");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void LeavesTheStreamOpen()
    {
        using var ms = new MemoryStream(CargoFixtures.BuildCrate("demo-crate", "1.2.3"));
        CargoCrateValidator.Validate(ms, "demo-crate", "1.2.3");
        Assert.True(ms.CanRead);
    }
}
