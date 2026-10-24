using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// npm extracts with last-write-wins, so a tarball with several top-level manifests installs a
/// different one than a first-match reader inspects. Every reader must refuse to pick one.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmAmbiguousManifestTests
{
    private const string Clean = """{"name":"ambig","version":"1.0.0","license":"MIT"}""";

    private const string Evil =
        """{"name":"ambig","version":"1.0.0","license":"GPL-3.0-only","scripts":{"postinstall":"echo pwn"}}""";

    public static TheoryData<string, string> AmbiguousLayouts => new()
    {
        { "package/package.json", "package/package.json" },
        { "package/package.json", "other/package.json" },
        { "package/package.json", "package/PACKAGE.JSON" },
        { "package.json", "package/package.json" },
        { "./package.json", "package/package.json" },
        { "package/package.json", "package/./package.json" },
        { "package/package.json", "package//package.json" },
        { "package/package.json", "package\\package.json" },
        { "package/package.json", "package/../package.json" },
        { "package/package.json", "package/C:package.json" },
        { "package/package.json", "package/C:/package.json" },
        { "package/package.json", "package/C:\\package.json" },
        { "package/package.json", "package///?/C:/package.json" },
        { "package/package.json", "package/C:/D:package.json" },
        { "package/package.json", "package///package.json" },
        { "package/package.json", "./package/../package.json" },
        { "package/package.json", "package/\\\\server\\share\\package.json" },
        { "package/package.json", "x\\y/package.json" },
    };

    [Theory]
    [MemberData(nameof(AmbiguousLayouts))]
    public void Validator_RejectsMultipleTopLevelManifests_InEitherOrder(string first, string second)
    {
        foreach (byte[] bytes in new[]
        {
            NpmFixtures.BuildTarballFromEntries((first, Clean), (second, Evil)),
            NpmFixtures.BuildTarballFromEntries((first, Evil), (second, Clean)),
        })
        {
            var parsed = NpmTarballValidator.Validate(bytes);

            Assert.False(parsed.Validation.IsValid);
            Assert.Contains("more than one top-level package.json", parsed.Validation.Message);
            Assert.Null(parsed.Manifest);
        }
    }

    [Theory]
    [MemberData(nameof(AmbiguousLayouts))]
    public void ScriptDetector_ReportsInstallScript_WhenFirstManifestIsClean(string first, string second)
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries((first, Clean), (second, Evil));

        var result = ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", bytes);

        Assert.True(result.HasScript);
    }

    [Theory]
    [MemberData(nameof(AmbiguousLayouts))]
    public void LicenceExtractor_ReportsUnknown_NotTheFirstManifestsLicence(string first, string second)
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries((first, Clean), (second, Evil));

        var result = LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes));

        Assert.Empty(result.Spdx);
    }

    [Fact]
    public void ScriptDetector_ScriptedManifestFollowedByEntryPadding_StillReportsScript()
    {
        byte[] bytes = NpmFixtures.BuildPaddedTarball(
            [("package/package.json", Evil)], TarScanLimits.MaxEntries + 1, []);

        var result = ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", bytes);

        Assert.True(result.HasScript);
    }

    [Fact]
    public void ScriptDetector_CleanManifestPaddingThenScriptedSecondManifest_ReportsScript()
    {
        byte[] bytes = NpmFixtures.BuildPaddedTarball(
            [("package/package.json", Clean)], TarScanLimits.MaxEntries + 1, [("other/package.json", Evil)]);

        var result = ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", bytes);

        Assert.True(result.HasScript);
    }

    [Fact]
    public void ScriptDetector_UnreadableArchive_FailsClosed()
    {
        var result = ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", "not a tarball"u8.ToArray());

        Assert.True(result.HasScript);
    }

    [Fact]
    public void LicenceExtractor_PaddingBeforeSecondManifest_ReportsUnknown()
    {
        byte[] bytes = NpmFixtures.BuildPaddedTarball(
            [("package/package.json", Clean)], TarScanLimits.MaxEntries + 1, [("other/package.json", Evil)]);

        Assert.Empty(LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes)).Spdx);
    }

    [Fact]
    public void EcosystemDetector_RejectsAmbiguousNpmTarball()
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries(
            ("package/package.json", Clean), ("package/./package.json", Evil));

        var (ok, err) = EcosystemDetector.Detect("ambig-1.0.0.tgz", bytes);

        Assert.Null(ok);
        Assert.Equal("tarball_invalid", err!.Code);
        Assert.Contains("more than one top-level package.json", err.Message);
    }

    [Theory]
    [InlineData("package/package.json", true)]
    [InlineData("package/./package.json", true)]
    [InlineData("package//package.json", true)]
    [InlineData("package\\package.json", true)]
    [InlineData("package/C:package.json", true)]
    [InlineData("package/C:/package.json", true)]
    [InlineData("package/C:\\package.json", true)]
    [InlineData("package///?/C:/package.json", true)]
    [InlineData("package/C:/C:package.json", true)]
    [InlineData("/package/package.json", false)]
    [InlineData("package///server/share/package.json", false)]
    [InlineData("package/\\\\server\\share\\package.json", true)]
    [InlineData("x\\y/package.json", true)]
    [InlineData("package/C:/x/package.json", false)]
    [InlineData("./package.json", true)]
    [InlineData("react v18.3/package.json", true)]
    [InlineData("package.json", true)]
    [InlineData("./x/package.json", false)]
    [InlineData("./package/package.json", false)]
    [InlineData("package/x/package.json", false)]
    [InlineData("package/package.json/", false)]
    [InlineData("package/../package.json", false)]
    public void ClassifyEntry_MatchesNodeTarStripOneThenStripAbsolutePath(string entryName, bool expected)
    {
        Assert.Equal(expected, NpmTarballValidator.IsTopLevelPackageJson(entryName));
    }

    [Fact]
    public void TraversalManifest_AloneIsRejected()
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries(("package/../package.json", Clean));

        Assert.False(NpmTarballValidator.Validate(bytes).Validation.IsValid);
    }

    [Theory]
    [InlineData("package/package.json")]
    [InlineData("react v18.3/package.json")]
    [InlineData("package.json")]
    public void SingleManifest_StillPasses_WithNestedManifestsIgnored(string manifestPath)
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries(
            ("package/node_modules/x/package.json", Evil), (manifestPath, Clean));

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.True(parsed.Validation.IsValid);
        Assert.Equal("ambig", parsed.Name);
        Assert.False(ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", bytes).HasScript);
        Assert.Equal(new[] { "MIT" }, LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes)).Spdx);
    }

    [Fact]
    public void SingleZeroBlockThenSecondManifest_IsUnscannable_AndNotReadAsTheFirst()
    {
        byte[] bytes = NpmFixtures.BuildTarballWithZeroBlocks(
            ("package/package.json", Clean), zeroBlocks: 1, second: ("package/package.json", Evil));

        Assert.Equal(NpmManifestScanOutcome.Unscannable,
            NpmTarballManifestScanner.ScanOrUnscannable(new MemoryStream(bytes), leaveOpen: false).Outcome);
        Assert.False(NpmTarballValidator.Validate(bytes).Validation.IsValid);
        Assert.True(ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", bytes).HasScript);
        Assert.Empty(LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes)).Spdx);
    }

    [Fact]
    public void TwoZeroBlocksThenJunk_IsOrdinaryEndOfArchive()
    {
        byte[] bytes = NpmFixtures.BuildTarballWithZeroBlocks(
            ("package/package.json", Clean), zeroBlocks: 2, trailingJunk: "trailing junk after the end marker"u8.ToArray());

        var scan = NpmTarballManifestScanner.ScanOrUnscannable(new MemoryStream(bytes), leaveOpen: false);

        Assert.Equal(NpmManifestScanOutcome.Found, scan.Outcome);
        Assert.True(NpmTarballValidator.Validate(bytes).Validation.IsValid);
    }

    [Fact]
    public void Scan_StreamIoFailure_IsReadFailed_WhileMalformedArchivesAreUnscannable()
    {
        byte[] good = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean));

        var failing = NpmTarballManifestScanner.ScanClassified(new ThrowingStream(good, good.Length / 2), leaveOpen: false);
        var truncated = NpmTarballManifestScanner.ScanClassified(new MemoryStream(good[..(good.Length / 2)]), leaveOpen: false);
        var junk = NpmTarballManifestScanner.ScanClassified(new MemoryStream("not gzip"u8.ToArray()), leaveOpen: false);

        Assert.Equal(NpmManifestScanOutcome.ReadFailed, failing.Outcome);
        Assert.Equal(NpmManifestScanOutcome.Unscannable, truncated.Outcome);
        Assert.Equal(NpmManifestScanOutcome.Unscannable, junk.Outcome);
        Assert.Equal(NpmManifestScanOutcome.Unscannable,
            NpmTarballManifestScanner.ScanOrUnscannable(new ThrowingStream(good, 10), leaveOpen: false).Outcome);
    }

    [Fact]
    public void OversizedPaxHeader_IsUnscannable_WhateverExceptionTypeTheTarReaderThrows()
    {
        byte[] bytes = NpmFixtures.BuildTarballWithOversizedPaxHeader(Evil);

        Assert.Equal(NpmManifestScanOutcome.Unscannable,
            NpmTarballManifestScanner.ScanClassified(new MemoryStream(bytes), leaveOpen: false).Outcome);
        Assert.False(NpmTarballValidator.Validate(bytes).Validation.IsValid);
        Assert.True(ScriptDetectionService.Detect("npm", "ambig-1.0.0.tgz", bytes).HasScript);
    }
}
