using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Dependably.Tests.Infrastructure;

/// <summary>Generates synthetic npm packages for edge-case testing.</summary>
public static class NpmFixtures
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    /// <summary>
    /// Builds a minimal .tgz (gzip'd tar) suitable for npm publish.
    /// Contains package/package.json as required by the npm registry protocol.
    /// Pass <paramref name="tarballLicense"/>=null to omit the license field from package.json.
    /// </summary>
    public static (byte[] Bytes, string Sha256Hex, string IntegrityHash) BuildTarball(
        string name, string version, string? tarballLicense = "MIT")
    {
        var fields = new Dictionary<string, object>
        {
            ["name"] = name,
            ["version"] = version,
            ["description"] = "Synthetic test package",
            ["main"] = "index.js",
        };
        if (tarballLicense is not null)
        {
            fields["license"] = tarballLicense;
        }

        string packageJson = JsonSerializer.Serialize(fields, IndentedJson);
        byte[] jsonBytes = Encoding.UTF8.GetBytes(packageJson);

        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, "package/package.json")
            {
                DataStream = new MemoryStream(jsonBytes)
            };
            tw.WriteEntry(entry);
        }

        byte[] bytes = ms.ToArray();
        byte[] sha256 = SHA256.HashData(bytes);
        string sha256Hex = Convert.ToHexString(sha256).ToLowerInvariant();
        string integrityHash = $"sha512-{Convert.ToBase64String(System.Security.Cryptography.SHA512.HashData(bytes))}";
        return (bytes, sha256Hex, integrityHash);
    }

    /// <summary>
    /// Builds the JSON body required by npm publish PUT. Defaults reproduce the npm
    /// CLI shape circa npm ≥7: tarball package.json carries the license; the packument
    /// per-version object does not. Set <paramref name="tarballLicense"/>=null to omit
    /// the license from the tarball, and <paramref name="packumentLicense"/>=non-null
    /// to inject it into the packument's per-version object.
    /// </summary>
    public static string BuildPublishBody(
        string name, string version,
        string? tarballLicense = "MIT",
        string? packumentLicense = null)
    {
        var (tarball, _, integrity) = BuildTarball(name, version, tarballLicense);
        string base64 = Convert.ToBase64String(tarball);
        string filename = $"{name}-{version}.tgz";

        var versionFields = new Dictionary<string, object>
        {
            ["name"] = name,
            ["version"] = version,
            ["description"] = "Synthetic test package",
            ["dist"] = new { tarball = $"https://registry.npmjs.org/{name}/-/{filename}", integrity },
        };
        if (packumentLicense is not null)
        {
            versionFields["license"] = packumentLicense;
        }

        return JsonSerializer.Serialize(new
        {
            name,
            versions = new Dictionary<string, object> { [version] = versionFields },
            _attachments = new Dictionary<string, object>
            {
                [filename] = new
                {
                    content_type = "application/octet-stream",
                    data = base64,
                    length = tarball.Length
                }
            }
        });
    }

    /// <summary>
    /// Builds a high-ratio gzip-bomb tarball: a single tar entry of <paramref name="entrySize"/>
    /// zero bytes (gzip compresses ~1000:1, so the on-wire fixture stays small) followed by a
    /// valid <c>package/package.json</c>. Streams the zeros — no large allocation.
    /// </summary>
    public static byte[] BuildBombTarball(string entryName, long entrySize)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, entryName)
            {
                DataStream = new ZeroStream(entrySize)
            });
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "package/package.json")
            {
                DataStream = new MemoryStream("""{"name":"bomb","version":"1.0.0"}"""u8.ToArray())
            });
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Builds a tarball with <paramref name="count"/> empty entries (plus no package.json),
    /// for exercising entry-count caps. Ustar entries keep the headers compact.
    /// </summary>
    public static byte[] BuildManyEntryTarball(int count)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            for (int i = 0; i < count; i++)
            {
                tw.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, $"package/f{i}"));
            }
        }
        return ms.ToArray();
    }

    /// <summary>Seekable read-only stream of zeros — lets TarWriter emit a giant entry without allocating it.</summary>
    private sealed class ZeroStream : Stream
    {
        private readonly long _length;
        private long _position;

        public ZeroStream(long length) => _length = length;

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _position; set => _position = value; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = (int)Math.Min(count, _length - _position);
            if (n <= 0)
            {
                return 0;
            }
            Array.Clear(buffer, offset, n);
            _position += n;
            return n;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            _position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => _position + offset,
                _ => _length + offset,
            };
            return _position;
        }

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Loads the real is-odd tarball fixture.</summary>
    public static (byte[] Bytes, string Sha256Hex) RealTarball()
    {
        string path = Path.Combine(FixtureManifest.FixturesRoot, "npm", "is-odd-3.0.1.tgz");
        byte[] bytes = File.ReadAllBytes(path);
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }
}
