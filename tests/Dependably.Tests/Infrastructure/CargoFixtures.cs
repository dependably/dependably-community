using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Generates synthetic Cargo crates and publish frames. A crate built here is shaped the way
/// <c>cargo package</c> shapes one — a gzipped tar whose entries sit under
/// <c>{name}-{version}/</c> with a normalized <c>Cargo.toml</c> at that root — because the publish
/// path cross-checks that manifest against the frame and refuses anything else.
/// </summary>
public static class CargoFixtures
{
    /// <summary>
    /// Builds a <c>.crate</c> whose root manifest declares <paramref name="manifestName"/> /
    /// <paramref name="manifestVersion"/> (defaulting to the coordinates that also name the root
    /// directory). Pass different manifest coordinates to build a crate whose archive disagrees
    /// with its directory, or <paramref name="rootDir"/> to move the manifest under another root.
    /// <paramref name="extraPackageLines"/> is appended verbatim inside <c>[package]</c>.
    /// </summary>
    public static byte[] BuildCrate(
        string name, string version,
        string? manifestName = null, string? manifestVersion = null,
        string? rootDir = null, string? extraPackageLines = null)
    {
        string root = rootDir ?? $"{name}-{version}";
        string toml = $"""
            [package]
            name = "{manifestName ?? name}"
            version = "{manifestVersion ?? version}"
            edition = "2021"
            {extraPackageLines ?? string.Empty}

            [dependencies]
            """;
        return BuildTarGz(
            ($"{root}/Cargo.toml", toml),
            ($"{root}/src/lib.rs", "pub fn answer() -> u32 { 42 }\n"));
    }

    /// <summary>A gzipped tar of the given (entryName, text) pairs, in order.</summary>
    public static byte[] BuildTarGz(params (string EntryName, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            foreach (var (entryName, content) in entries)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
                };
                tw.WriteEntry(entry);
            }
        }
        return ms.ToArray();
    }

    /// <summary>The crates.io publish-envelope JSON for a crate with no dependencies.</summary>
    public static string MetadataJson(string name, string version, string? license = null)
    {
        string licenseField = license is null ? string.Empty : $",\"license\":\"{license}\"";
        return $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"features":{},"description":"a test crate"{{licenseField}}}""";
    }

    /// <summary>
    /// The binary publish frame <c>cargo publish</c> sends: LE u32 metadata length, JSON metadata,
    /// LE u32 crate length, crate bytes. <paramref name="declaredCrateLen"/> lets a test lie about
    /// the crate size to exercise the pre-storage 413 gate.
    /// </summary>
    public static byte[] BuildPublishFrame(string metadataJson, byte[] crateBytes, uint? declaredCrateLen = null)
    {
        byte[] meta = Encoding.UTF8.GetBytes(metadataJson);
        byte[] buf = new byte[4 + meta.Length + 4 + crateBytes.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)meta.Length);
        meta.CopyTo(buf, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(
            buf.AsSpan(4 + meta.Length), declaredCrateLen ?? (uint)crateBytes.Length);
        crateBytes.CopyTo(buf, 4 + meta.Length + 4);
        return buf;
    }

    /// <summary>A complete, well-formed publish frame for <paramref name="name"/>@<paramref name="version"/>.</summary>
    public static ByteArrayContent PublishContent(string name, string version, byte[]? crate = null)
        => FrameContent(BuildPublishFrame(MetadataJson(name, version), crate ?? BuildCrate(name, version)));

    public static ByteArrayContent FrameContent(byte[] frame)
    {
        var content = new ByteArrayContent(frame);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return content;
    }
}
