using System.Buffers.Binary;
using System.Text;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// Coverage-extension tests for <see cref="RpmHeaderParser"/> focused on the malformed /
/// boundary branches the happy-path tests don't reach: truncation at every layer, header
/// magic / version mismatches, signature-header skip arithmetic, optional-tag type
/// mismatches, composite extractor short-circuits (missing companion tags, ragged
/// array lengths), dependency flag combinations, ghost / dir file classification,
/// and string-array iteration past sparse terminators.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmHeaderParserExtendedTests
{
    // ── String-array allocation bound (#437 item 5) ────────────────────────────

    [Fact]
    public void ReadStringArray_CountAboveCeiling_RejectedBeforeAllocation()
    {
        // The store is deliberately large enough that the bytes-available guard (1 byte per
        // string) would PASS — so it is specifically the absolute ceiling that must reject the
        // inflated count, before `new string[count]` allocates ~8 bytes per claimed entry. This
        // asserts the bound is enforced without materialising the multi-GB reference array.
        int count = RpmHeaderParser.MaxStringArrayCount + 1;
        byte[] data = new byte[count + 8]; // enough backing bytes to clear the per-byte guard

        var ex = Assert.Throws<RpmParseException>(
            () => RpmHeaderParser.ReadStringArray(data, offset: 0, count: count));
        Assert.Contains("maximum permitted", ex.Message);
    }

    [Fact]
    public void ReadStringArray_LegitimateCount_ParsesNormally()
    {
        // Adversarial twin: a normal-sized string array (well under the ceiling) is parsed
        // correctly — the new bound must not over-reject a real RPM's arrays.
        byte[] data = Concat(NullTerm("glibc"), NullTerm("bash"), NullTerm("coreutils"));

        string[] result = RpmHeaderParser.ReadStringArray(data, offset: 0, count: 3);

        Assert.Equal(new[] { "glibc", "bash", "coreutils" }, result);
    }

    // ── Top-level guard clauses ────────────────────────────────────────────────

    [Fact]
    public void Parse_NullData_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => RpmHeaderParser.Parse(null!));
    }

    [Fact]
    public void Parse_TooShort_ForLeadAndIntro_Throws()
    {
        // Lead is 96 bytes + 16-byte intro = 112 minimum. Give it less than that.
        byte[] bytes = new byte[100];
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("too short", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(0, 0x00, 0xAB, 0xEE, 0xDB)] // wrong byte 0
    [InlineData(1, 0xED, 0x00, 0xEE, 0xDB)] // wrong byte 1
    [InlineData(2, 0xED, 0xAB, 0x00, 0xDB)] // wrong byte 2
    [InlineData(3, 0xED, 0xAB, 0xEE, 0x00)] // wrong byte 3
    public void Parse_RejectsEachLeadMagicByte(int _, byte b0, byte b1, byte b2, byte b3)
    {
        byte[] bytes = new byte[200];
        bytes[0] = b0; bytes[1] = b1; bytes[2] = b2; bytes[3] = b3;
        bytes[4] = 3;
        // Even if the signature intro would be valid, the lead check is first.
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("lead magic", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_Accepts_Major4()
    {
        // major == 4 is the modern branch — exercise the alternate accepted value.
        byte[] bytes = BuildRpmWithMainHeader(
            new List<TagWrite>
            {
                TagWrite.Str(1000, "p"), TagWrite.Str(1001, "1"),
                TagWrite.Str(1002, "1"), TagWrite.Str(1022, "x"),
            },
            majorVersion: 4);
        var info = RpmHeaderParser.Parse(bytes);
        Assert.Equal("p", info.Name);
    }

    // ── Signature / main header intro malformations ────────────────────────────

    [Fact]
    public void Parse_BadSignatureHeaderMagic_Throws()
    {
        // Lead OK, but signature intro magic bytes wrong.
        byte[] bytes = new byte[200];
        bytes[0] = 0xED; bytes[1] = 0xAB; bytes[2] = 0xEE; bytes[3] = 0xDB;
        bytes[4] = 3;
        // signature header starts at offset 96 — leave magic zeroed.
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("header magic", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_UnsupportedHeaderVersion_Throws()
    {
        // Valid lead, valid sig magic, but the version byte after magic is 0x02 (only 0x01 supported).
        byte[] bytes = new byte[200];
        bytes[0] = 0xED; bytes[1] = 0xAB; bytes[2] = 0xEE; bytes[3] = 0xDB;
        bytes[4] = 3;
        bytes[96] = 0x8E; bytes[97] = 0xAD; bytes[98] = 0xE8; bytes[99] = 0x02; // version bumped
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NegativeSignatureNindex_Throws()
    {
        // Signature intro with negative nindex — caught in ReadHeaderIntro.
        byte[] bytes = new byte[200];
        bytes[0] = 0xED; bytes[1] = 0xAB; bytes[2] = 0xEE; bytes[3] = 0xDB;
        bytes[4] = 3;
        bytes[96] = 0x8E; bytes[97] = 0xAD; bytes[98] = 0xE8; bytes[99] = 0x01;
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(104, 4), -1); // nindex
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(108, 4), 0);  // hsize
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("negative", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NegativeMainHsize_Throws()
    {
        // Empty signature, then main header intro with negative hsize.
        byte[] lead = MakeLead();
        byte[] sig = HeaderIntro(0, 0);
        byte[] main = HeaderIntro(0, -5);
        byte[] bytes = Concat(lead, sig, main);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("negative", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_TruncatedBeforeMainHeader_Throws()
    {
        // Sig header intro fits exactly at EOF (nindex=0, hsize=0), but there are no
        // trailing bytes left for the main header intro that should follow it.
        byte[] lead = MakeLead();
        byte[] sig = HeaderIntro(nindex: 0, hsize: 0);
        byte[] bytes = Concat(lead, sig);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("truncated", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_SignatureHeaderExtendsPastEof_Throws()
    {
        // Sig header claims a huge hsize that pushes its own end past the buffer —
        // caught directly at the signature-header bound check rather than surfacing
        // downstream as a misleading "truncated before main header".
        byte[] lead = MakeLead();
        byte[] sig = HeaderIntro(nindex: 0, hsize: 10_000);
        byte[] bytes = Concat(lead, sig);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("extends past eof", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_MainStoreExtendsPastEof_Throws()
    {
        // Empty sig, then main intro that claims a giant hsize but the store bytes
        // aren't actually there.
        byte[] lead = MakeLead();
        byte[] sig = HeaderIntro(0, 0);
        byte[] mainIntro = HeaderIntro(nindex: 0, hsize: 5_000);
        byte[] bytes = Concat(lead, sig, mainIntro);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("past eof", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_SignatureWithIndexEntries_AdvancesMainHeaderStart()
    {
        // Real RPMs include signature index entries; we don't read them but they shift
        // mainHeaderStart forward. Build sig with 2 fake entries + 16 hsize bytes, then
        // pad to 8 and lay a proper main header behind it.
        var tags = new List<TagWrite>
        {
            TagWrite.Str(1000, "n"), TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"), TagWrite.Str(1022, "x"),
        };

        byte[] lead = MakeLead();
        int sigNindex = 2;
        int sigHsize = 16;
        byte[] sigIntro = HeaderIntro(sigNindex, sigHsize);
        byte[] sigIndex = new byte[sigNindex * 16]; // arbitrary opaque bytes — we never parse them
        byte[] sigStore = new byte[sigHsize];
        int sigEndOffset = 96 + 16 + sigIndex.Length + sigStore.Length;
        byte[] pad = new byte[(8 - (sigEndOffset % 8)) % 8];

        var (index, store) = BuildMainHeader(tags);
        byte[] mainIntro = HeaderIntro(tags.Count, store.Length);
        byte[] bytes = Concat(lead, sigIntro, sigIndex, sigStore, pad, mainIntro, index, store);

        var info = RpmHeaderParser.Parse(bytes);
        Assert.Equal("n", info.Name);
        Assert.True(info.HeaderStart > 96 + 16); // shifted past sig entries
    }

    // ── Mandatory tag validation ───────────────────────────────────────────────

    [Fact]
    public void Parse_TagPresentButWrongType_IsTreatedAsMissing()
    {
        // NAME tag present but typed as Int32 instead of String — RequireString rejects.
        var tags = new List<TagWrite>
        {
            TagWrite.Int32(1000, 42), // bogus type for NAME
            TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"),
            TagWrite.Str(1022, "x"),
        };
        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("RPMTAG_NAME", ex.Message);
    }

    [Theory]
    [InlineData(1001, "RPMTAG_VERSION")]
    [InlineData(1002, "RPMTAG_RELEASE")]
    [InlineData(1022, "RPMTAG_ARCH")]
    public void Parse_MissingIndividualMandatoryTag_Throws(int omit, string label)
    {
        var tags = new List<TagWrite>
        {
            TagWrite.Str(1000, "n"),
            TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"),
            TagWrite.Str(1022, "x"),
        };
        tags.RemoveAll(t => t.Tag == omit);
        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains(label, ex.Message);
    }

    [Fact]
    public void Parse_AcceptsI18nStringForMandatoryTag()
    {
        // RequireString accepts both TypeString (6) and TypeI18nString (9).
        var tags = new List<TagWrite>
        {
            new(1000, Type: 9, Count: 1, Bytes: NullTerm("zlib")), // I18n string
            TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"),
            TagWrite.Str(1022, "x"),
        };
        byte[] bytes = BuildRpmWithMainHeader(tags);
        var info = RpmHeaderParser.Parse(bytes);
        Assert.Equal("zlib", info.Name);
    }

    // ── Optional readers: type/count branches ──────────────────────────────────

    [Fact]
    public void OptionalString_TypeStringArray_ReturnsFirst()
    {
        // SUMMARY (1004) written as a StringArray with 2 entries — reader returns first.
        byte[] summaryBytes = Concat(NullTerm("first"), NullTerm("second"));
        var tags = new List<TagWrite>
        {
            TagWrite.Str(1000, "n"), TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"), TagWrite.Str(1022, "x"),
            new(1004, Type: 8, Count: 2, Bytes: summaryBytes),
        };
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal("first", info.Summary);
    }

    [Fact]
    public void OptionalString_TypeStringArrayCountZero_ReturnsNull()
    {
        // count == 0 short-circuits to the null branch.
        var tags = new List<TagWrite>
        {
            TagWrite.Str(1000, "n"), TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"), TagWrite.Str(1022, "x"),
            new(1004, Type: 8, Count: 0, Bytes: Array.Empty<byte>()),
        };
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Null(info.Summary);
    }

    [Fact]
    public void OptionalString_UnknownType_FallsThroughToNull()
    {
        // SUMMARY typed as Int8 (2) — not a string variant; reader returns null.
        var tags = new List<TagWrite>
        {
            TagWrite.Str(1000, "n"), TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"), TagWrite.Str(1022, "x"),
            new(1004, Type: 2, Count: 1, Bytes: new byte[] { 0x01 }),
        };
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Null(info.Summary);
    }

    [Fact]
    public void OptionalInt32_WrongType_ReturnsNull()
    {
        // INSTALLED_SIZE (1009) typed as String — reader rejects, default 0 surfaces.
        var tags = new List<TagWrite>
        {
            TagWrite.Str(1000, "n"), TagWrite.Str(1001, "1"),
            TagWrite.Str(1002, "1"), TagWrite.Str(1022, "x"),
            TagWrite.Str(1009, "not-an-int"),
        };
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal(0, info.InstalledSize);
        Assert.Null(info.Epoch);
    }

    // ── File extractor: partial / out-of-range / ghost branches ────────────────

    [Fact]
    public void Files_MissingBasenames_ReturnsEmpty()
    {
        // Only DIRNAMES present — extractor short-circuits at the first lookup.
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/usr/bin/")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Empty(info.Files);
    }

    [Fact]
    public void Files_MissingDirnames_ReturnsEmpty()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("ls")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Empty(info.Files);
    }

    [Fact]
    public void Files_MissingDirIndexes_ReturnsEmpty()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("ls")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/usr/bin/")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Empty(info.Files);
    }

    [Fact]
    public void Files_WithDirIndexOutOfRange_FallsBackToEmptyDir()
    {
        // dirIndexes[0] = 99 (no such dir) — BuildFileEntry's range guard returns "".
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("ls")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/usr/bin/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(99)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Single(info.Files);
        Assert.Equal("ls", info.Files[0].Path); // dir resolved to ""
        Assert.Equal("file", info.Files[0].Type);
    }

    [Fact]
    public void Files_NegativeDirIndex_FallsBackToEmptyDir()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("ls")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/usr/bin/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(-1)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal("ls", info.Files[0].Path);
    }

    [Fact]
    public void Files_DirIndexesShorterThanBasenames_UsesZeroFallback()
    {
        // 2 basenames but only 1 dirIndex — second entry hits the `i < dirIndexes.Length` else branch.
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 2, Bytes: Concat(NullTerm("a"), NullTerm("b"))));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/d/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(0)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal(2, info.Files.Count);
        Assert.Equal("/d/a", info.Files[0].Path);
        Assert.Equal("/d/b", info.Files[1].Path); // fallback dirIdx 0
    }

    [Fact]
    public void Files_EmptyBasename_ClassifiedAsDir()
    {
        // Empty basename is the dnf convention for a directory entry.
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/etc/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(0)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal("dir", info.Files[0].Type);
    }

    [Fact]
    public void Files_GhostFlag_ClassifiedAsGhost()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("doc")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/var/log/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(0)));
        tags.Add(new TagWrite(1037, Type: 4, Count: 1, Bytes: BeInt32(0x40))); // FileFlagGhost
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal("ghost", info.Files[0].Type);
    }

    // ── Dependency extractor: flag combinations + ragged arrays ────────────────

    [Fact]
    public void Deps_NoRequireName_ReturnsEmpty()
    {
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(MandatoryTags()));
        Assert.Empty(info.Requires);
        Assert.Empty(info.Provides);
        Assert.Empty(info.Conflicts);
        Assert.Empty(info.Obsoletes);
    }

    [Fact]
    public void Deps_NamesCountZero_ReturnsEmpty()
    {
        // Count == 0 short-circuits the second guard in ExtractDeps.
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: 0, Bytes: Array.Empty<byte>()));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Empty(info.Requires);
    }

    [Fact]
    public void Deps_AllFlagBits_RenderAsLTGTEQ()
    {
        // SenseLess(0x02) | SenseGreater(0x04) | SenseEqual(0x08) = 0x0E
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: 1, Bytes: NullTerm("glibc")));
        tags.Add(new TagWrite(1048, Type: 4, Count: 1, Bytes: BeInt32(0x0E)));
        tags.Add(new TagWrite(1050, Type: 8, Count: 1, Bytes: NullTerm("2.34")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Single(info.Requires);
        Assert.Equal("LTGTEQ", info.Requires[0].Flags);
        Assert.Equal("2.34", info.Requires[0].Version);
    }

    [Theory]
    [InlineData(0x02, "LT")]
    [InlineData(0x04, "GT")]
    [InlineData(0x08, "EQ")]
    [InlineData(0x00, "")]
    public void Deps_SingleFlagBit_RendersExpected(int bits, string expectedSymbol)
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: 1, Bytes: NullTerm("glibc")));
        tags.Add(new TagWrite(1048, Type: 4, Count: 1, Bytes: BeInt32(bits)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal(expectedSymbol, info.Requires[0].Flags);
    }

    [Fact]
    public void Deps_FlagsArrayShorterThanNames_FallsBackToZero()
    {
        // 2 names, 1 flag — second dependency uses the `0` default branch.
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: 2, Bytes: Concat(NullTerm("a"), NullTerm("b"))));
        tags.Add(new TagWrite(1048, Type: 4, Count: 1, Bytes: BeInt32(0x02)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal(2, info.Requires.Count);
        Assert.Equal("LT", info.Requires[0].Flags);
        Assert.Equal("", info.Requires[1].Flags); // fallback to 0
    }

    [Fact]
    public void Deps_NoVersionsTag_DefaultsToEmpty()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: 1, Bytes: NullTerm("glibc")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal("", info.Requires[0].Version);
    }

    [Fact]
    public void Deps_VersionsArrayShorterThanNames_FallsBackToEmpty()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: 2, Bytes: Concat(NullTerm("a"), NullTerm("b"))));
        tags.Add(new TagWrite(1050, Type: 8, Count: 1, Bytes: NullTerm("1.0")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal("1.0", info.Requires[0].Version);
        Assert.Equal("", info.Requires[1].Version);
    }

    // ── Changelog extractor ────────────────────────────────────────────────────

    [Fact]
    public void Changelogs_NoNames_ReturnsEmpty()
    {
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(MandatoryTags()));
        Assert.Empty(info.Changelogs);
    }

    [Fact]
    public void Changelogs_NamesCountZero_ReturnsEmpty()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1081, Type: 8, Count: 0, Bytes: Array.Empty<byte>()));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Empty(info.Changelogs);
    }

    [Fact]
    public void Changelogs_TakeMinOfThreeArrays()
    {
        // 3 names, 2 times, 1 text => only 1 changelog produced (min).
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1081, Type: 8, Count: 3,
            Bytes: Concat(NullTerm("a@x"), NullTerm("b@x"), NullTerm("c@x"))));
        tags.Add(new TagWrite(1080, Type: 4, Count: 2, Bytes: Concat(BeInt32(100), BeInt32(200))));
        tags.Add(new TagWrite(1082, Type: 8, Count: 1, Bytes: NullTerm("first entry")));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Single(info.Changelogs);
        Assert.Equal("a@x", info.Changelogs[0].Author);
        Assert.Equal(100, info.Changelogs[0].Date);
        Assert.Equal("first entry", info.Changelogs[0].Text);
    }

    [Fact]
    public void Changelogs_AllFieldsPresent_AreMerged()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1081, Type: 8, Count: 2, Bytes: Concat(NullTerm("a"), NullTerm("b"))));
        tags.Add(new TagWrite(1080, Type: 4, Count: 2, Bytes: Concat(BeInt32(10), BeInt32(20))));
        tags.Add(new TagWrite(1082, Type: 8, Count: 2, Bytes: Concat(NullTerm("first"), NullTerm("second"))));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Equal(2, info.Changelogs.Count);
        Assert.Equal("b", info.Changelogs[1].Author);
        Assert.Equal(20, info.Changelogs[1].Date);
        Assert.Equal("second", info.Changelogs[1].Text);
    }

    // ── ReadNullTerminated with no terminator before EOF ──────────────────────

    [Fact]
    public void StringArray_UnterminatedEntry_ReadsUntilNextNul()
    {
        // The basename has no trailing NUL of its own — ReadNullTerminated keeps
        // walking until it hits the NUL at the end of the *next* contiguous store
        // entry (dirname). This is the documented behaviour for malformed strings:
        // the reader doesn't synthesise a terminator, it just stops at the first
        // NUL or buffer end. Asserts the reader doesn't crash and produces the
        // concatenated bytes.
        byte[] basenameBytes = Encoding.UTF8.GetBytes("noterm"); // no NUL
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: basenameBytes));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(0)));
        var info = RpmHeaderParser.Parse(BuildRpmWithMainHeader(tags));
        Assert.Single(info.Files);
        Assert.StartsWith("/noterm", info.Files[0].Path);
        Assert.Equal("file", info.Files[0].Type);
    }

    // ── DetectScriptlets ──────────────────────────────────────────────────────

    [Theory]
    [InlineData(1023, "%pre")]
    [InlineData(1024, "%post")]
    [InlineData(1025, "%preun")]
    [InlineData(1026, "%postun")]
    [InlineData(1151, "%pretrans")]
    [InlineData(1152, "%posttrans")]
    public void DetectScriptlets_SinglePhase_ReturnsItsName(int tag, string expectedPhase)
    {
        var tags = MandatoryTags();
        tags.Add(TagWrite.Str(tag, "echo hello"));
        byte[] bytes = BuildRpmWithMainHeader(tags);

        var phases = RpmHeaderParser.DetectScriptlets(bytes);

        Assert.Single(phases);
        Assert.Equal(expectedPhase, phases[0]);
    }

    [Fact]
    public void DetectScriptlets_NoScriptletTags_ReturnsEmpty()
    {
        byte[] bytes = BuildRpmWithMainHeader(MandatoryTags());
        var phases = RpmHeaderParser.DetectScriptlets(bytes);
        Assert.Empty(phases);
    }

    [Fact]
    public void DetectScriptlets_EmptyStringScriptlet_NotCounted()
    {
        // An empty-string scriptlet value must not be counted as present.
        var tags = MandatoryTags();
        tags.Add(TagWrite.Str(1024, ""));     // %post with empty body
        tags.Add(TagWrite.Str(1023, "   ")); // %pre with whitespace-only body
        byte[] bytes = BuildRpmWithMainHeader(tags);

        var phases = RpmHeaderParser.DetectScriptlets(bytes);

        Assert.Empty(phases);
    }

    [Fact]
    public void DetectScriptlets_MultiplePhases_ReturnsAll()
    {
        var tags = MandatoryTags();
        tags.Add(TagWrite.Str(1023, "echo pre"));
        tags.Add(TagWrite.Str(1024, "echo post"));
        tags.Add(TagWrite.Str(1026, "echo postun"));
        byte[] bytes = BuildRpmWithMainHeader(tags);

        var phases = RpmHeaderParser.DetectScriptlets(bytes);

        Assert.Equal(3, phases.Count);
        Assert.Contains("%pre", phases);
        Assert.Contains("%post", phases);
        Assert.Contains("%postun", phases);
    }

    [Fact]
    public void DetectScriptlets_NullData_Throws_ArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => RpmHeaderParser.DetectScriptlets(null!));
    }

    [Fact]
    public void DetectScriptlets_TooShort_Throws_RpmParseException()
    {
        byte[] bytes = new byte[50];
        Assert.Throws<RpmParseException>(() => RpmHeaderParser.DetectScriptlets(bytes));
    }

    // ── Bounds checks: attacker-controlled Count field ────────────────────────

    /// <summary>
    /// A crafted Int32-array tag whose index entry Count claims Int32.MaxValue entries
    /// but the store contains only 4 real bytes. The parser must reject it with
    /// RpmParseException instead of attempting to allocate ~8 GiB.
    /// </summary>
    [Fact]
    public void ReadInt32Array_OversizedCount_ThrowsRpmParseException()
    {
        // Build an RPM whose DIRINDEXES (1116) index entry has Count = Int32.MaxValue
        // but the store only contains 4 bytes (one real int). The Count is injected
        // via a raw TagWrite that bypasses the normal builder's count inference.
        var tags = MandatoryTags();
        // Provide minimal legitimate file-list tags so ExtractFiles is reached.
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("ls")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/bin/")));
        // DIRINDEXES as Int32 array: actual store has 4 bytes but claims MaxValue entries.
        tags.Add(new TagWrite(1116, Type: 4, Count: int.MaxValue, Bytes: BeInt32(0)));

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("extends past", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A crafted string-array tag whose Count claims far more strings than the store
    /// holds bytes. The parser must reject it rather than allocating a string[] with
    /// billions of elements.
    /// </summary>
    [Fact]
    public void ReadStringArray_OversizedCount_ThrowsRpmParseException()
    {
        // RPMTAG_REQUIRENAME (1049) typed as StringArray with Count = Int32.MaxValue
        // but the store only contains the bytes for one short name.
        var tags = MandatoryTags();
        // Count deliberately exceeds the bytes actually in the store.
        tags.Add(new TagWrite(1049, Type: 8, Count: int.MaxValue, Bytes: NullTerm("glibc")));

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("exceeds", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A crafted FILEFLAGS Int32 array whose Count claims more entries than store bytes.
    /// This covers the fileFlags path inside ExtractFiles (separate branch from dirIndexes).
    /// </summary>
    [Fact]
    public void ReadInt32Array_FileFlags_OversizedCount_ThrowsRpmParseException()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1117, Type: 8, Count: 1, Bytes: NullTerm("ls")));
        tags.Add(new TagWrite(1118, Type: 8, Count: 1, Bytes: NullTerm("/bin/")));
        tags.Add(new TagWrite(1116, Type: 4, Count: 1, Bytes: BeInt32(0)));
        // FILEFLAGS (1037) with oversized Count — only 4 bytes in store.
        tags.Add(new TagWrite(1037, Type: 4, Count: int.MaxValue, Bytes: BeInt32(0)));

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("extends past", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Partial-failure scenario: the RPM has two dependency arrays (requires + conflicts).
    /// Requires has a valid count; conflicts carries an oversized Count. The parser must
    /// reject the file entirely (not silently succeed on just the valid dependency).
    /// </summary>
    [Fact]
    public void Parse_PartiallyMalformed_MixedValidAndOversizedArrays_Throws()
    {
        var tags = MandatoryTags();
        // Requires: 1 valid name + 1 valid flag + 1 valid version — all well-formed.
        tags.Add(new TagWrite(1049, Type: 8, Count: 1, Bytes: NullTerm("glibc")));
        tags.Add(new TagWrite(1048, Type: 4, Count: 1, Bytes: BeInt32(0x08)));
        tags.Add(new TagWrite(1050, Type: 8, Count: 1, Bytes: NullTerm("2.34")));
        // Conflicts: valid name bytes but Count = Int32.MaxValue — oversized.
        tags.Add(new TagWrite(1054, Type: 8, Count: int.MaxValue, Bytes: NullTerm("bad-pkg")));

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.True(
            ex.Message.Contains("exceeds", StringComparison.OrdinalIgnoreCase),
            $"Expected 'exceeds' in message but got: {ex.Message}");
    }

    /// <summary>
    /// A crafted string-array tag whose Count field is negative (e.g. an attacker-set
    /// 0xFFFFFFFF, which reads back as -1). Because a negative count is never ">" the
    /// positive maxPossibleStrings bound, the oversized-count guard alone lets it through
    /// to `new string[count]`, which throws an unhandled OverflowException instead of the
    /// intended validated RpmParseException.
    /// </summary>
    [Fact]
    public void ReadStringArray_NegativeCount_ThrowsRpmParseException()
    {
        var tags = MandatoryTags();
        tags.Add(new TagWrite(1049, Type: 8, Count: -1, Bytes: NullTerm("glibc")));

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("negative", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Mixed partial-failure scenario mirroring <see cref="Parse_PartiallyMalformed_MixedValidAndOversizedArrays_Throws"/>:
    /// one dependency array (requires) is entirely well-formed while the sibling array
    /// (conflicts) carries a negative Count. The parser must reject the whole file rather
    /// than silently accepting the valid array and crashing (or worse, succeeding) on the
    /// malformed one.
    /// </summary>
    [Fact]
    public void Parse_PartiallyMalformed_MixedValidAndNegativeCountArrays_Throws()
    {
        var tags = MandatoryTags();
        // Requires: 1 valid name + 1 valid flag + 1 valid version — all well-formed.
        tags.Add(new TagWrite(1049, Type: 8, Count: 1, Bytes: NullTerm("glibc")));
        tags.Add(new TagWrite(1048, Type: 4, Count: 1, Bytes: BeInt32(0x08)));
        tags.Add(new TagWrite(1050, Type: 8, Count: 1, Bytes: NullTerm("2.34")));
        // Conflicts: negative Count.
        tags.Add(new TagWrite(1054, Type: 8, Count: -1, Bytes: NullTerm("bad-pkg")));

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
        Assert.Contains("negative", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── Overflow / offset-bounds regression tests ─────────────────────────────

    /// <summary>
    /// A crafted signature header intro whose Nindex is large enough that
    /// Nindex * IndexEntrySize overflows int32 (wraps negative), which previously drove
    /// sigEnd/mainHeaderStart negative and slipped past the "past EOF" guard. The parser
    /// must reject this as malformed input instead of crashing with an unhandled
    /// IndexOutOfRangeException while indexing the wrapped-negative offset.
    /// </summary>
    [Fact]
    public void Parse_SignatureNindexOverflowsInt32Multiplication_ThrowsRpmParseException()
    {
        byte[] lead = MakeLead();
        // 200,000,000 * 16 (IndexEntrySize) = 3,200,000,000, which overflows int32.
        byte[] sig = HeaderIntro(nindex: 200_000_000, hsize: 0);
        byte[] bytes = Concat(lead, sig);

        var ex = Record.Exception(() => RpmHeaderParser.Parse(bytes));
        Assert.IsType<RpmParseException>(ex);
    }

    /// <summary>
    /// Same overflow shape but exercised via DetectScriptlets, which duplicates the
    /// signature-header-skip arithmetic.
    /// </summary>
    [Fact]
    public void DetectScriptlets_SignatureNindexOverflowsInt32Multiplication_ThrowsRpmParseException()
    {
        byte[] lead = MakeLead();
        byte[] sig = HeaderIntro(nindex: 200_000_000, hsize: 0);
        byte[] bytes = Concat(lead, sig);

        var ex = Record.Exception(() => RpmHeaderParser.DetectScriptlets(bytes));
        Assert.IsType<RpmParseException>(ex);
    }

    /// <summary>
    /// A string array tag whose Count claims one more element than the store actually
    /// holds NUL-terminated strings for: the last real string has no trailing NUL, so the
    /// walk consumes through EOF and the next iteration starts past the buffer. Previously
    /// this reached <c>Encoding.UTF8.GetString</c> with a start index past <c>data.Length</c>
    /// and threw an unhandled <see cref="ArgumentOutOfRangeException"/>; it must now surface
    /// as <see cref="RpmParseException"/>.
    /// </summary>
    [Fact]
    public void ReadStringArray_MissingTerminatorOnLastRealString_ThrowsRpmParseException()
    {
        var tags = MandatoryTags();
        // Two real strings ("first", "second") but only "second" is missing its NUL, and
        // Count claims 3 entries — the third read starts past the end of the buffer.
        byte[] noTrailingNul = Concat(NullTerm("first"), Encoding.UTF8.GetBytes("second"));
        tags.Add(new TagWrite(1049, Type: 8, Count: 3, Bytes: noTrailingNul)); // RPMTAG_REQUIRENAME

        byte[] bytes = BuildRpmWithMainHeader(tags);
        var ex = Record.Exception(() => RpmHeaderParser.Parse(bytes));
        Assert.IsType<RpmParseException>(ex);
    }

    /// <summary>
    /// A mandatory STRING tag (RPMTAG_NAME) whose index entry Offset is corrupted to point
    /// far past the end of the data store. Previously <c>ReadNullTerminated</c> dereferenced
    /// <c>storeStart + entry.Offset</c> unchecked, which reached
    /// <c>Encoding.UTF8.GetString</c> with an out-of-range start index. The parser must now
    /// reject it as malformed input.
    /// </summary>
    [Fact]
    public void Parse_TagOffsetPointsPastEof_ThrowsRpmParseException()
    {
        var tags = MandatoryTags();
        byte[] bytes = BuildRpmWithMainHeader(tags);

        // MandatoryTags()[0] is RPMTAG_NAME (1000) — the first index entry written by
        // BuildMainHeader. Lead(96) + empty sig intro(16, no padding needed since 112 is
        // already 8-byte aligned) + main intro(16) = index start at byte 128; the Offset
        // field sits 8 bytes into each 16-byte index entry.
        const int IndexStart = 96 + 16 + 16;
        const int OffsetFieldPos = IndexStart + 8;
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(OffsetFieldPos, 4), int.MaxValue);

        var ex = Record.Exception(() => RpmHeaderParser.Parse(bytes));
        Assert.IsType<RpmParseException>(ex);
    }

    // ── Builder helpers ────────────────────────────────────────────────────────

    private static List<TagWrite> MandatoryTags() => new()
    {
        TagWrite.Str(1000, "n"),
        TagWrite.Str(1001, "1"),
        TagWrite.Str(1002, "1"),
        TagWrite.Str(1022, "x"),
    };

    private static byte[] MakeLead(byte major = 3)
    {
        byte[] lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = major;
        return lead;
    }

    private static byte[] HeaderIntro(int nindex, int hsize)
    {
        byte[] b = new byte[16];
        b[0] = 0x8E; b[1] = 0xAD; b[2] = 0xE8; b[3] = 0x01;
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), nindex);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), hsize);
        return b;
    }

    private static byte[] NullTerm(string s)
    {
        byte[] raw = Encoding.UTF8.GetBytes(s);
        byte[] withNul = new byte[raw.Length + 1];
        Array.Copy(raw, withNul, raw.Length);
        return withNul;
    }

    private static byte[] BeInt32(int value)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(b, value);
        return b;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts)
        {
            total += p.Length;
        }

        byte[] result = new byte[total];
        int pos = 0;
        foreach (byte[] p in parts)
        {
            Buffer.BlockCopy(p, 0, result, pos, p.Length);
            pos += p.Length;
        }
        return result;
    }

    private static byte[] BuildRpmWithMainHeader(List<TagWrite> tags, byte majorVersion = 3)
    {
        byte[] lead = MakeLead(majorVersion);
        byte[] sig = HeaderIntro(0, 0);
        int sigEnd = 96 + sig.Length;
        byte[] pad = new byte[(8 - (sigEnd % 8)) % 8];
        var (index, store) = BuildMainHeader(tags);
        byte[] mainIntro = HeaderIntro(tags.Count, store.Length);
        return Concat(lead, sig, pad, mainIntro, index, store);
    }

    private static (byte[] Index, byte[] Store) BuildMainHeader(List<TagWrite> tags)
    {
        var indexBytes = new List<byte>();
        var storeBytes = new List<byte>();
        foreach (var t in tags)
        {
            int offset = storeBytes.Count;
            indexBytes.AddRange(WriteIndexEntry(t.Tag, t.Type, offset, t.Count));
            storeBytes.AddRange(t.Bytes);
        }
        return (indexBytes.ToArray(), storeBytes.ToArray());
    }

    private static byte[] WriteIndexEntry(int tag, int type, int offset, int count)
    {
        byte[] b = new byte[16];
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(0, 4), tag);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(4, 4), type);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), offset);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), count);
        return b;
    }

    private sealed record TagWrite(int Tag, int Type, int Count, byte[] Bytes)
    {
        public static TagWrite Str(int tag, string value)
        {
            byte[] raw = Encoding.UTF8.GetBytes(value);
            byte[] withNul = new byte[raw.Length + 1];
            Array.Copy(raw, withNul, raw.Length);
            return new TagWrite(tag, Type: 6, Count: 1, withNul);
        }

        public static TagWrite Int32(int tag, int value)
        {
            byte[] b = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(b, value);
            return new TagWrite(tag, Type: 4, Count: 1, b);
        }
    }
}
