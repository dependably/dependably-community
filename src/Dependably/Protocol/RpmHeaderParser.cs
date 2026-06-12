using System.Buffers.Binary;
using System.Text;

namespace Dependably.Protocol;

/// <summary>
/// Parses the RPM v3 / v4 header structure from a .rpm file's leading bytes.
///
/// File layout reference (RPM Package Format Wiki / rpm-software-management/rpm headerlib.c):
/// <code>
/// +------------------+  offset 0
/// |    Lead           |  96 bytes, fixed size
/// +------------------+  offset 96
/// |  Signature Header |  variable, 8-byte aligned trailer
/// +------------------+
/// |  Main Header      |  variable
/// +------------------+
/// |  Compressed Payload (gzip/xz/zstd cpio) — not parsed by this class.
/// +------------------+
/// </code>
///
/// Both headers share the same intro (16 bytes) + N×16-byte index entries + variable-size
/// data store; the index entries carry typed tags pointing into the store. This class
/// only reads what dnf/yum need to render <c>primary.xml</c>, <c>filelists.xml</c>, and
/// <c>other.xml</c> — see <see cref="RpmHeaderInfo"/> for the surface.
/// </summary>
public static class RpmHeaderParser
{
    private const byte LeadMagic0 = 0xED;
    private const byte LeadMagic1 = 0xAB;
    private const byte LeadMagic2 = 0xEE;
    private const byte LeadMagic3 = 0xDB;
    private const int LeadSize = 96;

    private const byte HeaderMagic0 = 0x8E;
    private const byte HeaderMagic1 = 0xAD;
    private const byte HeaderMagic2 = 0xE8;
    private const int HeaderIntroSize = 16;
    private const int IndexEntrySize = 16;

    // RPM tag IDs we care about. Full list lives in rpm/rpmtag.h upstream; we only pull
    // the columns the repodata XML needs.
    private const int TagName = 1000;
    private const int TagVersion = 1001;
    private const int TagRelease = 1002;
    private const int TagEpoch = 1003;
    private const int TagSummary = 1004;
    private const int TagDescription = 1005;
    private const int TagBuildTime = 1006;
    private const int TagBuildHost = 1007;
    private const int TagInstalledSize = 1009;
    private const int TagVendor = 1011;
    private const int TagLicense = 1014;
    private const int TagPackager = 1015;
    private const int TagGroup = 1016;
    private const int TagUrl = 1020;
    private const int TagArch = 1022;
    private const int TagFileFlags = 1037;
    private const int TagSourceRpm = 1044;
    private const int TagArchiveSize = 1046;
    private const int TagProvideName = 1047;
    private const int TagRequireFlags = 1048;
    private const int TagRequireName = 1049;
    private const int TagRequireVersion = 1050;
    private const int TagConflictFlags = 1053;
    private const int TagConflictName = 1054;
    private const int TagConflictVersion = 1055;
    private const int TagChangelogTime = 1080;
    private const int TagChangelogName = 1081;
    private const int TagChangelogText = 1082;
    private const int TagObsoleteName = 1090;
    private const int TagProvideFlags = 1112;
    private const int TagProvideVersion = 1113;
    private const int TagObsoleteFlags = 1114;
    private const int TagObsoleteVersion = 1115;
    private const int TagDirIndexes = 1116;
    private const int TagBaseNames = 1117;
    private const int TagDirNames = 1118;

    // Data type tags from header intro (per rpm headerlib.c). The full enum is retained
    // so the spec mapping is obvious to readers; the parser only branches on the subset
    // dnf/yum repodata actually needs (Int32 / String / StringArray / I18nString).
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "RPM header tag type constant from rpm headerlib.c — retained for spec documentation alongside the types actively read.")]
    private const int TypeNull = 0;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "RPM header tag type constant from rpm headerlib.c — retained for spec documentation alongside the types actively read.")]
    private const int TypeChar = 1;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "RPM header tag type constant from rpm headerlib.c — retained for spec documentation alongside the types actively read.")]
    private const int TypeInt8 = 2;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "RPM header tag type constant from rpm headerlib.c — retained for spec documentation alongside the types actively read.")]
    private const int TypeInt16 = 3;
    private const int TypeInt32 = 4;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "RPM header tag type constant from rpm headerlib.c — retained for spec documentation alongside the types actively read.")]
    private const int TypeInt64 = 5;
    private const int TypeString = 6;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "RPM header tag type constant from rpm headerlib.c — retained for spec documentation alongside the types actively read.")]
    private const int TypeBin = 7;
    private const int TypeStringArray = 8;
    private const int TypeI18nString = 9;

    // RPMSENSE_* dependency flag bits.
    private const int SenseLess = 0x02;
    private const int SenseGreater = 0x04;
    private const int SenseEqual = 0x08;

    private const int FileFlagGhost = 0x40;

    /// <summary>
    /// Parses <paramref name="data"/> (the leading bytes of a .rpm file — typically the
    /// first few MB are enough; the compressed cpio payload is not read) and returns the
    /// header information dnf/yum need. Throws <see cref="RpmParseException"/> on a
    /// malformed input.
    /// </summary>
    public static RpmHeaderInfo Parse(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length < LeadSize + HeaderIntroSize)
        {
            throw new RpmParseException("RPM file too short to contain a lead + header intro.");
        }

        // ── Lead ────────────────────────────────────────────────────────────────
        if (!(data[0] == LeadMagic0 && data[1] == LeadMagic1 &&
              data[2] == LeadMagic2 && data[3] == LeadMagic3))
        {
            throw new RpmParseException("Invalid RPM lead magic.");
        }

        byte major = data[4];
        if (major is not 3 and not 4)
        {
            throw new RpmParseException($"Unsupported RPM major version: {major}.");
        }

        // ── Signature header (skip; just need its end to align main header) ───
        int sigStart = LeadSize;
        var (sigNindex, sigHsize) = ReadHeaderIntro(data, sigStart);
        int sigEnd = sigStart + HeaderIntroSize + sigNindex * IndexEntrySize + sigHsize;
        // Signature is 8-byte aligned; main header starts at the next 8-byte boundary.
        int mainHeaderStart = (sigEnd + 7) & ~7;
        if (mainHeaderStart + HeaderIntroSize > data.Length)
        {
            throw new RpmParseException("RPM truncated before main header.");
        }

        // ── Main header ─────────────────────────────────────────────────────────
        var (nindex, hsize) = ReadHeaderIntro(data, mainHeaderStart);
        int indexStart = mainHeaderStart + HeaderIntroSize;
        int indexEnd = indexStart + nindex * IndexEntrySize;
        int storeStart = indexEnd;
        int storeEnd = storeStart + hsize;
        if (storeEnd > data.Length)
        {
            throw new RpmParseException("RPM main header data store extends past EOF.");
        }

        // Collect raw values keyed by tag — most are scalars or short string arrays we
        // pull out in one pass and then assemble into the strongly-typed record below.
        var raw = new Dictionary<int, IndexEntry>();
        for (int i = 0; i < nindex; i++)
        {
            var entry = ReadIndex(data, indexStart + i * IndexEntrySize);
            raw[entry.Tag] = entry;
        }

        // Mandatory tags first so we fail fast.
        string name = RequireString(data, storeStart, raw, TagName, "RPMTAG_NAME");
        string version = RequireString(data, storeStart, raw, TagVersion, "RPMTAG_VERSION");
        string release = RequireString(data, storeStart, raw, TagRelease, "RPMTAG_RELEASE");
        string arch = RequireString(data, storeStart, raw, TagArch, "RPMTAG_ARCH");

        // Files reconstructed from basenames + dirnames + dirindexes triples.
        var files = ExtractFiles(data, storeStart, raw);

        // Dependency triples (name + flags + version).
        var requires = ExtractDeps(data, storeStart, raw, TagRequireName, TagRequireFlags, TagRequireVersion);
        var provides = ExtractDeps(data, storeStart, raw, TagProvideName, TagProvideFlags, TagProvideVersion);
        var conflicts = ExtractDeps(data, storeStart, raw, TagConflictName, TagConflictFlags, TagConflictVersion);
        var obsoletes = ExtractDeps(data, storeStart, raw, TagObsoleteName, TagObsoleteFlags, TagObsoleteVersion);

        var changelogs = ExtractChangelogs(data, storeStart, raw);

        return new RpmHeaderInfo
        {
            Name = name,
            Epoch = ReadOptionalInt32(data, storeStart, raw, TagEpoch),
            Version = version,
            Release = release,
            Arch = arch,
            Summary = ReadOptionalString(data, storeStart, raw, TagSummary),
            Description = ReadOptionalString(data, storeStart, raw, TagDescription),
            License = ReadOptionalString(data, storeStart, raw, TagLicense),
            Url = ReadOptionalString(data, storeStart, raw, TagUrl),
            Vendor = ReadOptionalString(data, storeStart, raw, TagVendor),
            Packager = ReadOptionalString(data, storeStart, raw, TagPackager),
            Group = ReadOptionalString(data, storeStart, raw, TagGroup),
            SourceRpm = ReadOptionalString(data, storeStart, raw, TagSourceRpm),
            BuildHost = ReadOptionalString(data, storeStart, raw, TagBuildHost),
            BuildTime = ReadOptionalInt32(data, storeStart, raw, TagBuildTime),
            InstalledSize = ReadOptionalInt32(data, storeStart, raw, TagInstalledSize) ?? 0,
            ArchiveSize = ReadOptionalInt32(data, storeStart, raw, TagArchiveSize) ?? 0,
            HeaderStart = mainHeaderStart,
            HeaderEnd = storeEnd,
            Requires = requires,
            Provides = provides,
            Conflicts = conflicts,
            Obsoletes = obsoletes,
            Files = files,
            Changelogs = changelogs,
        };
    }

    // ── Index / type readers ───────────────────────────────────────────────────

    private static (int Nindex, int Hsize) ReadHeaderIntro(byte[] data, int offset)
    {
        if (data[offset] != HeaderMagic0 || data[offset + 1] != HeaderMagic1 || data[offset + 2] != HeaderMagic2)
        {
            throw new RpmParseException("Invalid RPM header magic.");
        }

        if (data[offset + 3] != 0x01)
        {
            throw new RpmParseException("Unsupported RPM header version.");
        }
        // 4 bytes reserved at offset+4..7, then nindex + hsize as big-endian int32.
        int nindex = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + 8, 4));
        int hsize = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + 12, 4));
        return nindex < 0 || hsize < 0 ? throw new RpmParseException("Negative nindex / hsize in RPM header intro.") : ((int Nindex, int Hsize))(nindex, hsize);
    }

    private static IndexEntry ReadIndex(byte[] data, int offset)
    {
        return new IndexEntry(
            Tag: BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset, 4)),
            Type: BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + 4, 4)),
            Offset: BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + 8, 4)),
            Count: BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + 12, 4)));
    }

    private readonly record struct IndexEntry(int Tag, int Type, int Offset, int Count);

    private static string RequireString(byte[] data, int storeStart, Dictionary<int, IndexEntry> raw, int tag, string label)
    {
        return !raw.TryGetValue(tag, out var entry) || (entry.Type != TypeString && entry.Type != TypeI18nString)
            ? throw new RpmParseException($"Missing required RPM tag: {label}")
            : ReadNullTerminated(data, storeStart + entry.Offset);
    }

    private static string? ReadOptionalString(byte[] data, int storeStart, Dictionary<int, IndexEntry> raw, int tag)
    {
        return !raw.TryGetValue(tag, out var entry)
            ? null
            : entry.Type switch
            {
                TypeString or TypeI18nString => ReadNullTerminated(data, storeStart + entry.Offset),
                TypeStringArray => entry.Count > 0 ? ReadStringArray(data, storeStart + entry.Offset, 1)[0] : null,
                _ => null,
            };
    }

    private static int? ReadOptionalInt32(byte[] data, int storeStart, Dictionary<int, IndexEntry> raw, int tag)
    {
        return !raw.TryGetValue(tag, out var entry)
            ? null
            : entry.Type != TypeInt32 ? null : BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(storeStart + entry.Offset, 4));
    }

    private static int[] ReadInt32Array(byte[] data, int storeStart, IndexEntry entry)
    {
        if (entry.Type != TypeInt32 || entry.Count <= 0)
        {
            return Array.Empty<int>();
        }

        int[] arr = new int[entry.Count];
        for (int i = 0; i < entry.Count; i++)
        {
            arr[i] = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(storeStart + entry.Offset + i * 4, 4));
        }

        return arr;
    }

    private static string[] ReadStringArray(byte[] data, int offset, int count)
    {
        string[] result = new string[count];
        int pos = offset;
        for (int i = 0; i < count; i++)
        {
            result[i] = ReadNullTerminated(data, pos);
            pos += result[i].Length + 1; // skip past the NUL terminator
        }
        return result;
    }

    private static string ReadNullTerminated(byte[] data, int offset)
    {
        int end = offset;
        while (end < data.Length && data[end] != 0)
        {
            end++;
        }

        return Encoding.UTF8.GetString(data, offset, end - offset);
    }

    // ── Composite extractors ────────────────────────────────────────────────────

    private static RpmFileEntry[] ExtractFiles(byte[] data, int storeStart, Dictionary<int, IndexEntry> raw)
    {
        if (!raw.TryGetValue(TagBaseNames, out var basenamesEntry))
        {
            return Array.Empty<RpmFileEntry>();
        }

        if (!raw.TryGetValue(TagDirNames, out var dirnamesEntry))
        {
            return Array.Empty<RpmFileEntry>();
        }

        if (!raw.TryGetValue(TagDirIndexes, out var dirIndexesEntry))
        {
            return Array.Empty<RpmFileEntry>();
        }

        string[] basenames = ReadStringArray(data, storeStart + basenamesEntry.Offset, basenamesEntry.Count);
        string[] dirnames = ReadStringArray(data, storeStart + dirnamesEntry.Offset, dirnamesEntry.Count);
        int[] dirIndexes = ReadInt32Array(data, storeStart, dirIndexesEntry);
        int[] fileFlags = raw.TryGetValue(TagFileFlags, out var ff) ? ReadInt32Array(data, storeStart, ff) : Array.Empty<int>();

        var files = new RpmFileEntry[basenames.Length];
        for (int i = 0; i < basenames.Length; i++)
        {
            files[i] = BuildFileEntry(i, basenames, dirnames, dirIndexes, fileFlags);
        }
        return files;
    }

    private static RpmFileEntry BuildFileEntry(int i, string[] basenames, string[] dirnames, int[] dirIndexes, int[] fileFlags)
    {
        int dirIdx = i < dirIndexes.Length ? dirIndexes[i] : 0;
        string dir = dirIdx >= 0 && dirIdx < dirnames.Length ? dirnames[dirIdx] : "";
        string basename = basenames[i];
        string path = dir + basename;
        string type = ClassifyFileType(basename, i, fileFlags);
        return new RpmFileEntry(path, type);
    }

    private static string ClassifyFileType(string basename, int i, int[] fileFlags)
    {
        return string.IsNullOrEmpty(basename) ? "dir" : i < fileFlags.Length && (fileFlags[i] & FileFlagGhost) != 0 ? "ghost" : "file";
    }

    private static RpmDependency[] ExtractDeps(
        byte[] data, int storeStart, Dictionary<int, IndexEntry> raw,
        int nameTag, int flagsTag, int versionTag)
    {
        if (!raw.TryGetValue(nameTag, out var namesEntry) || namesEntry.Count == 0)
        {
            return Array.Empty<RpmDependency>();
        }

        string[] names = ReadStringArray(data, storeStart + namesEntry.Offset, namesEntry.Count);
        int[] flags = raw.TryGetValue(flagsTag, out var flagsEntry) ? ReadInt32Array(data, storeStart, flagsEntry) : Array.Empty<int>();
        string[] versions = raw.TryGetValue(versionTag, out var versionsEntry)
            ? ReadStringArray(data, storeStart + versionsEntry.Offset, versionsEntry.Count)
            : Array.Empty<string>();

        var deps = new RpmDependency[names.Length];
        for (int i = 0; i < names.Length; i++)
        {
            int flag = i < flags.Length ? flags[i] : 0;
            deps[i] = new RpmDependency(
                Name: names[i],
                Flags: FlagsToSymbol(flag),
                Epoch: 0,
                Version: i < versions.Length ? versions[i] : "",
                Release: "");
        }
        return deps;
    }

    private static RpmChangelog[] ExtractChangelogs(byte[] data, int storeStart, Dictionary<int, IndexEntry> raw)
    {
        if (!raw.TryGetValue(TagChangelogName, out var namesEntry) || namesEntry.Count == 0)
        {
            return Array.Empty<RpmChangelog>();
        }

        string[] names = ReadStringArray(data, storeStart + namesEntry.Offset, namesEntry.Count);
        int[] times = raw.TryGetValue(TagChangelogTime, out var t) ? ReadInt32Array(data, storeStart, t) : Array.Empty<int>();
        string[] texts = raw.TryGetValue(TagChangelogText, out var txt) ? ReadStringArray(data, storeStart + txt.Offset, txt.Count) : Array.Empty<string>();

        int n = Math.Min(names.Length, Math.Min(times.Length, texts.Length));
        var entries = new RpmChangelog[n];
        for (int i = 0; i < n; i++)
        {
            entries[i] = new RpmChangelog(names[i], times[i], texts[i]);
        }

        return entries;
    }

    private static string FlagsToSymbol(int flags)
    {
        var parts = new List<string>(2);
        if ((flags & SenseLess) != 0)
        {
            parts.Add("LT");
        }

        if ((flags & SenseGreater) != 0)
        {
            parts.Add("GT");
        }

        if ((flags & SenseEqual) != 0)
        {
            parts.Add("EQ");
        }

        return parts.Count == 0 ? "" : string.Join("", parts);
    }
}

/// <summary>Strongly-typed view of an RPM header. <see cref="RpmHeaderParser"/> populates this.</summary>
public sealed record RpmHeaderInfo
{
    public required string Name { get; init; }
    public int? Epoch { get; init; }
    public required string Version { get; init; }
    public required string Release { get; init; }
    public required string Arch { get; init; }
    public string? Summary { get; init; }
    public string? Description { get; init; }
    public string? License { get; init; }
    public string? Url { get; init; }
    public string? Vendor { get; init; }
    public string? Packager { get; init; }
    public string? Group { get; init; }
    public string? SourceRpm { get; init; }
    public string? BuildHost { get; init; }
    public int? BuildTime { get; init; }
    public long InstalledSize { get; init; }
    public long ArchiveSize { get; init; }
    public int HeaderStart { get; init; }
    public int HeaderEnd { get; init; }
    public IReadOnlyList<RpmDependency> Requires { get; init; } = Array.Empty<RpmDependency>();
    public IReadOnlyList<RpmDependency> Provides { get; init; } = Array.Empty<RpmDependency>();
    public IReadOnlyList<RpmDependency> Conflicts { get; init; } = Array.Empty<RpmDependency>();
    public IReadOnlyList<RpmDependency> Obsoletes { get; init; } = Array.Empty<RpmDependency>();
    public IReadOnlyList<RpmFileEntry> Files { get; init; } = Array.Empty<RpmFileEntry>();
    public IReadOnlyList<RpmChangelog> Changelogs { get; init; } = Array.Empty<RpmChangelog>();
}

public sealed record RpmDependency(string Name, string Flags, int Epoch, string Version, string Release);
public sealed record RpmFileEntry(string Path, string Type);
public sealed record RpmChangelog(string Author, int Date, string Text);

/// <summary>Thrown when an RPM cannot be parsed (bad magic, truncated, missing required tag).</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain.")]
public sealed class RpmParseException : Exception
{
    public RpmParseException(string message) : base(message) { }
}
