using System.Text;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The npm manifest scan must read an archive the way npm installs it: node-tar's non-strict
/// parser under pacote's <c>strip: 1</c> extraction. Each fixture under Fixtures/packages/npm
/// carries a clean top-level manifest a System.Formats.Tar walk sees, plus a scripted manifest that
/// node-tar 7.5.19 installs instead (regenerate with npm-tar-fixtures.py, confirm with
/// npm-tar-differential.mjs). Every reader built on the scan must refuse them.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmTarNodeTarParityTests
{
    private const string Clean = """{"name":"x","version":"1.0.0"}""";

    private const string Evil =
        """{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo pwned"},"license":"AGPL-3.0"}""";

    public static TheoryData<string, NpmManifestScanOutcome> NodeTarDifferentials => new()
    {
        { "npm-hidden-header-bad-checksum.tgz", NpmManifestScanOutcome.Unscannable },
        { "npm-hidden-header-linkpath.tgz", NpmManifestScanOutcome.Unscannable },
        { "npm-hidden-header-empty-pax-path.tgz", NpmManifestScanOutcome.Unscannable },
        { "npm-hidden-header-directory-size.tgz", NpmManifestScanOutcome.Ambiguous },
        { "npm-hidden-header-trailing-slash-file.tgz", NpmManifestScanOutcome.Ambiguous },
        { "npm-backslash-in-wrapper.tgz", NpmManifestScanOutcome.Ambiguous },
        { "npm-backslash-unc-root.tgz", NpmManifestScanOutcome.Ambiguous },
        { "npm-hidden-member-after-zero-padding.tgz", NpmManifestScanOutcome.Unscannable },
    };

    [Theory]
    [MemberData(nameof(NodeTarDifferentials))]
    public void Fixture_NodeTarInstallsAHiddenManifest_EveryReaderRefuses(string fixture, NpmManifestScanOutcome expected)
    {
        byte[] bytes = File.ReadAllBytes(Path.Combine(FixtureManifest.FixturesRoot, "npm", fixture));

        var scan = NpmTarballManifestScanner.ScanOrUnscannable(new MemoryStream(bytes), leaveOpen: false);

        Assert.Equal(expected, scan.Outcome);
        Assert.True(NpmTarballManifestScanner.IsRefusable(scan.Outcome));
        Assert.False(NpmTarballValidator.Validate(bytes).Validation.IsValid);
        Assert.True(ScriptDetectionService.Detect("npm", "x-1.0.0.tgz", bytes).HasScript);
        Assert.Empty(LicenseExtractor.FromNpmTarballPackageJson(new MemoryStream(bytes)).Spdx);
    }

    [Fact]
    public void RealNpmPackFixture_StillScansClean()
    {
        byte[] bytes = File.ReadAllBytes(Path.Combine(FixtureManifest.FixturesRoot, "npm", "is-odd-3.0.1.tgz"));

        var scan = NpmTarballManifestScanner.ScanOrUnscannable(new MemoryStream(bytes), leaveOpen: false);

        Assert.Equal(NpmManifestScanOutcome.Found, scan.Outcome);
        Assert.Equal("package/package.json", scan.EntryName);
        Assert.True(NpmTarballValidator.Validate(bytes).Validation.IsValid);
    }

    [Theory]
    [InlineData("x\\y/package.json", true)]
    [InlineData("..\\x/package.json", true)]
    [InlineData("package/\\\\server\\share\\package.json", true)]
    [InlineData("package/\\\\?\\C:\\package.json", true)]
    [InlineData("package/\\/server/share/package.json", true)]
    [InlineData("package/\\package.json", true)]
    [InlineData("x\\y/z/package.json", false)]
    [InlineData("package/\\\\server\\share\\x\\package.json", false)]
    public void ClassifyEntry_CountsAManifestUnderEitherThePosixOrTheWin32Reading(string entryName, bool expected)
    {
        Assert.Equal(expected, NpmTarballValidator.IsTopLevelPackageJson(entryName));
    }

    [Theory]
    [InlineData("package/..\\package.json")]
    [InlineData("x\\..\\y/package.json")]
    [InlineData("a\\../package.json")]
    public void ClassifyEntry_TraversalUnderEitherReading_IsTraversal(string entryName)
    {
        Assert.Equal(NpmTarballValidator.ManifestEntryKind.Traversal, NpmTarballValidator.ClassifyEntry(entryName));
    }

    // Expected values are node-tar 7.5.19's stripAbsolutePath (path.win32.parse under Node 26).
    [Theory]
    [InlineData("package.json", "package.json")]
    [InlineData("/package.json", "package.json")]
    [InlineData("//package.json", "package.json")]
    [InlineData("\\package.json", "package.json")]
    [InlineData("\\\\server\\share\\package.json", "package.json")]
    [InlineData("\\\\server\\share", "")]
    [InlineData("\\\\server\\\\share\\x", "x")]
    [InlineData("\\\\server", "server")]
    [InlineData("//server/share/package.json", "server/share/package.json")]
    [InlineData("//?/C:/package.json", "package.json")]
    [InlineData("\\\\?\\C:\\package.json", "package.json")]
    [InlineData("C:package.json", "package.json")]
    [InlineData("C:/D:package.json", "package.json")]
    [InlineData("/\\server\\share\\x", "server\\share\\x")]
    [InlineData("\\/server/share/x", "x")]
    [InlineData("\\\\.\\pipe\\x", "x")]
    [InlineData("\\\\a\\b\\", "")]
    [InlineData("1:x", "1:x")]
    [InlineData("c:..\\x", "..\\x")]
    [InlineData("//?/", "?/")]
    [InlineData("//?/x", "")]
    [InlineData("x\\y", "x\\y")]
    public void StripAbsolutePath_MatchesNodeTar(string input, string expected)
    {
        Assert.Equal(expected, NpmTarballValidator.StripAbsolutePath(input));
    }

    [Fact]
    public void ChecksumValidOnlyAsASignedSum_IsUnscannable()
    {
        // node-tar compares the unsigned byte sum only, so it skips this header; tar readers that
        // also accept the historical signed sum treat it as an entry.
        byte[] readme = RawTar.Header("package/r\u00e9sum\u00e9.md", 0, signedChecksum: true);
        byte[] tar = [.. RawTar.Entry("package/package.json", Clean), .. readme, .. RawTar.End];

        Assert.Equal(NpmManifestScanOutcome.Unscannable, Scan(tar).Outcome);
    }

    [Fact]
    public void HeaderNodeTarCannotDecode_IsUnscannable()
    {
        byte[] bad = RawTar.Header("package/README.md", 0);
        bad[108] = 0x81;
        RawTar.FixChecksum(bad);
        byte[] tar = [.. RawTar.Entry("package/package.json", Clean), .. bad, .. RawTar.End];

        Assert.Equal(NpmManifestScanOutcome.Unscannable, Scan(tar).Outcome);
    }

    [Fact]
    public void GnuLongName_NamesTheNextEntry()
    {
        byte[] tar =
        [
            .. RawTar.Entry("package/package.json", Clean),
            .. RawTar.Entry("././@LongLink", "package/package.json\0", typeflag: (byte)'L'),
            .. RawTar.Entry("package/README.md", Evil),
            .. RawTar.End,
        ];

        Assert.Equal(NpmManifestScanOutcome.Ambiguous, Scan(tar).Outcome);
    }

    [Fact]
    public void UstarPrefix_IsJoinedToTheName()
    {
        byte[] prefixed = RawTar.Header("package.json", Encoding.UTF8.GetByteCount(Evil), prefix: "package");
        byte[] tar =
        [
            .. RawTar.Entry("package/package.json", Clean),
            .. prefixed, .. RawTar.Pad(Encoding.UTF8.GetBytes(Evil)),
            .. RawTar.End,
        ];

        Assert.Equal(NpmManifestScanOutcome.Ambiguous, Scan(tar).Outcome);
    }

    [Fact]
    public void PaxPath_NamesTheNextEntryOnly()
    {
        byte[] tar =
        [
            .. RawTar.Pax('x', ("path", "package/package.json")),
            .. RawTar.Entry("package/placeholder", Clean),
            .. RawTar.Entry("package/README.md", Evil),
            .. RawTar.End,
        ];

        var scan = Scan(tar);

        Assert.Equal(NpmManifestScanOutcome.Found, scan.Outcome);
        Assert.Equal("package/package.json", scan.EntryName);
        Assert.Equal(Clean, Encoding.UTF8.GetString(scan.Bytes!));
    }

    [Fact]
    public void GlobalPaxPath_IsIgnored_LikeNodeTar()
    {
        byte[] tar =
        [
            .. RawTar.Pax('g', ("path", "package/package.json")),
            .. RawTar.Entry("package/package.json", Clean),
            .. RawTar.Entry("package/README.md", Evil),
            .. RawTar.End,
        ];

        var scan = Scan(tar);

        Assert.Equal(NpmManifestScanOutcome.Found, scan.Outcome);
        Assert.Equal(Clean, Encoding.UTF8.GetString(scan.Bytes!));
    }

    [Fact]
    public void GlobalPaxSize_IsUnscannable()
    {
        // node-tar applies a global size to every later file header; other readers do not.
        byte[] tar =
        [
            .. RawTar.Pax('g', ("size", "1024")),
            .. RawTar.Entry("package/package.json", Clean),
            .. RawTar.End,
        ];

        Assert.Equal(NpmManifestScanOutcome.Unscannable, Scan(tar).Outcome);
    }

    [Fact]
    public void PaxSize_OverridesTheHeaderSize()
    {
        byte[] body = Encoding.UTF8.GetBytes(Clean);
        byte[] tar =
        [
            .. RawTar.Pax('x', ("size", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture))),
            .. RawTar.Header("package/package.json", 0), .. RawTar.Pad(body),
            .. RawTar.End,
        ];

        var scan = Scan(tar);

        Assert.Equal(NpmManifestScanOutcome.Found, scan.Outcome);
        Assert.Equal(Clean, Encoding.UTF8.GetString(scan.Bytes!));
    }

    [Fact]
    public void Base256Size_IsDecoded()
    {
        byte[] body = Encoding.UTF8.GetBytes(Clean);
        byte[] header = RawTar.Header("package/package.json", 0);
        Array.Clear(header, 124, 12);
        header[124] = 0x80;
        header[135] = (byte)body.Length;
        RawTar.FixChecksum(header);
        byte[] tar = [.. header, .. RawTar.Pad(body), .. RawTar.End];

        var scan = Scan(tar);

        Assert.Equal(NpmManifestScanOutcome.Found, scan.Outcome);
        Assert.Equal(Clean, Encoding.UTF8.GetString(scan.Bytes!));
    }

    [Fact]
    public void TruncatedEntryBody_IsUnscannable()
    {
        byte[] tar = RawTar.Entry("package/package.json", Clean);

        Assert.Equal(NpmManifestScanOutcome.Unscannable, Scan(tar[..600]).Outcome);
    }

    [Fact]
    public void ArchiveWithoutEndMarker_IsUnscannable()
    {
        // Without two null blocks node-tar keeps parsing whatever a later gzip member decodes to,
        // and whether zlib reads that member depends on how the stream was chunked.
        byte[] tar = RawTar.Entry("package/package.json", Clean);

        Assert.Equal(NpmManifestScanOutcome.Unscannable, Scan(tar).Outcome);
        Assert.Equal(NpmManifestScanOutcome.Unscannable, Scan([.. tar, .. new byte[512]]).Outcome);
        Assert.Equal(NpmManifestScanOutcome.Found, Scan([.. tar, .. RawTar.End]).Outcome);
    }

    [Theory]
    [InlineData("package/package.json.")]
    [InlineData("package/package.json ")]
    [InlineData("package/package.json. .")]
    [InlineData("package/PACKAG~1.JSO")]
    [InlineData("package/packag~12.jso")]
    [InlineData("package/PACKAG~1.JSO.")]
    public void ClassifyEntry_WindowsFilenameAliasesOfTheManifest_AreManifestNames(string entryName)
    {
        Assert.True(NpmTarballValidator.IsTopLevelPackageJson(entryName));
        byte[] bytes = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), (entryName, Evil));
        Assert.Equal(NpmManifestScanOutcome.Ambiguous,
            NpmTarballManifestScanner.ScanOrUnscannable(new MemoryStream(bytes), leaveOpen: false).Outcome);
    }

    [Theory]
    [InlineData("package/package.json.bak")]
    [InlineData("package/PACKAG~.JSO")]
    [InlineData("package/PACKAG~1.JSON")]
    [InlineData("package/PACKAG~x.JSO")]
    [InlineData("package/.package.json")]
    public void ClassifyEntry_NearMissesOfTheManifestName_AreNotManifestNames(string entryName)
    {
        Assert.False(NpmTarballValidator.IsTopLevelPackageJson(entryName));
    }

    [Fact]
    public void Validator_DuplicateKeyManifest_IsNotReportedAsMissing()
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries(
            ("package/package.json", """{"name":"x","version":"1.0.0","scripts":{},"scripts":{"postinstall":"echo pwned"}}"""));

        var parsed = NpmTarballValidator.Validate(bytes);

        Assert.False(parsed.Validation.IsValid);
        Assert.DoesNotContain("missing", parsed.Validation.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("could not be scanned", parsed.Validation.Message);
    }

    [Fact]
    public void Validator_NoManifest_IsStillReportedAsMissing()
    {
        byte[] bytes = NpmFixtures.BuildTarballFromEntries(("package/index.js", "{}"));

        Assert.Contains("missing a top-level package.json", NpmTarballValidator.Validate(bytes).Validation.Message);
    }

    private static NpmManifestScan Scan(byte[] tar) =>
        NpmTarballManifestScanner.ScanOrUnscannable(new MemoryStream(NpmFixtures.Gzip(tar)), leaveOpen: false);

    // Writes raw ustar blocks so a test controls every header byte.
    private static class RawTar
    {
        public static readonly byte[] End = new byte[1024];

        public static byte[] Header(
            string name, long size, byte typeflag = (byte)'0', string prefix = "", bool signedChecksum = false)
        {
            byte[] block = new byte[512];
            Encoding.UTF8.GetBytes(name).CopyTo(block, 0);
            Octal("644", 8).CopyTo(block, 100);
            Octal("0", 8).CopyTo(block, 108);
            Octal("0", 8).CopyTo(block, 116);
            Octal(Convert.ToString(size, 8), 12).CopyTo(block, 124);
            Octal("0", 12).CopyTo(block, 136);
            block[156] = typeflag;
            "ustar\0"u8.ToArray().CopyTo(block, 257);
            "00"u8.ToArray().CopyTo(block, 263);
            Encoding.UTF8.GetBytes(prefix).CopyTo(block, 345);
            FixChecksum(block, signedChecksum);
            return block;
        }

        public static void FixChecksum(byte[] block, bool signed = false)
        {
            Array.Fill(block, (byte)' ', 148, 8);
            int sum = signed ? block.Sum(b => (int)(sbyte)b) : block.Sum(b => b);
            Encoding.ASCII.GetBytes(Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ").CopyTo(block, 148);
        }

        public static byte[] Entry(string name, string body, byte typeflag = (byte)'0')
        {
            byte[] data = Encoding.UTF8.GetBytes(body);
            return [.. Header(name, data.Length, typeflag), .. Pad(data)];
        }

        public static byte[] Pax(char type, params (string Key, string Value)[] records)
        {
            var body = new StringBuilder();
            foreach (var (key, value) in records)
            {
                string rest = $" {key}={value}\n";
                int length = Encoding.UTF8.GetByteCount(rest) + 1;
                while ((length.ToString(System.Globalization.CultureInfo.InvariantCulture).Length + Encoding.UTF8.GetByteCount(rest)) != length)
                {
                    length++;
                }

                body.Append(length.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(rest);
            }

            return Entry("PaxHeader/x", body.ToString(), (byte)type);
        }

        public static byte[] Pad(byte[] data)
        {
            byte[] padded = new byte[(data.Length + 511) / 512 * 512];
            data.CopyTo(padded, 0);
            return padded;
        }

        private static byte[] Octal(string digits, int width) =>
            Encoding.ASCII.GetBytes(digits.PadLeft(width - 1, '0') + "\0");
    }
}
