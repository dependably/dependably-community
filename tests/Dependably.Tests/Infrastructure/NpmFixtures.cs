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
        if (tarballLicense is not null) fields["license"] = tarballLicense;

        var packageJson = JsonSerializer.Serialize(fields, IndentedJson);
        var jsonBytes = Encoding.UTF8.GetBytes(packageJson);

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

        var bytes = ms.ToArray();
        var sha256 = SHA256.HashData(bytes);
        var sha256Hex = Convert.ToHexString(sha256).ToLowerInvariant();
        var integrityHash = $"sha512-{Convert.ToBase64String(System.Security.Cryptography.SHA512.HashData(bytes))}";
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
        var base64 = Convert.ToBase64String(tarball);
        var filename = $"{name}-{version}.tgz";

        var versionFields = new Dictionary<string, object>
        {
            ["name"] = name,
            ["version"] = version,
            ["description"] = "Synthetic test package",
            ["dist"] = new { tarball = $"https://registry.npmjs.org/{name}/-/{filename}", integrity },
        };
        if (packumentLicense is not null) versionFields["license"] = packumentLicense;

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

    /// <summary>Loads the real is-odd tarball fixture.</summary>
    public static (byte[] Bytes, string Sha256Hex) RealTarball()
    {
        var path = Path.Combine(FixtureManifest.FixturesRoot, "npm", "is-odd-3.0.1.tgz");
        var bytes = File.ReadAllBytes(path);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }
}
