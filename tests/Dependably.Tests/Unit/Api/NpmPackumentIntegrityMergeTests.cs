using System.Text.Json.Nodes;
using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// #437 item 7: on a version collision between the merged upstream packument and a locally hosted
/// row, the packument must advertise the LOCAL integrity/shasum — the tarball route serves the
/// local bytes, so keeping the upstream digest hands npm an SRI it can never satisfy (EINTEGRITY).
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmPackumentIntegrityMergeTests
{
    private const string TarballBase = "https://acme.dependably.example/npm";

    private static JsonObject UpstreamPackumentWithVersion(string version, string upstreamIntegrity, string upstreamShasum)
        => new()
        {
            ["name"] = "left-pad",
            ["versions"] = new JsonObject
            {
                [version] = new JsonObject
                {
                    ["name"] = "left-pad",
                    ["version"] = version,
                    ["dist"] = new JsonObject
                    {
                        ["tarball"] = $"https://registry.npmjs.org/left-pad/-/left-pad-{version}.tgz",
                        ["shasum"] = upstreamShasum,
                        ["integrity"] = upstreamIntegrity,
                    },
                },
            },
        };

    [Fact]
    public void Collision_ReplacesUpstreamIntegrityWithLocalRow()
    {
        const string version = "1.3.0";
        var packument = UpstreamPackumentWithVersion(
            version,
            upstreamIntegrity: "sha512-UPSTREAMdigestThatLocalBytesCannotSatisfy==",
            upstreamShasum: "1111111111111111111111111111111111111111");

        var localPkg = new Package { Id = "p1", Name = "left-pad", OrgId = "org1", Ecosystem = "npm", PurlName = "left-pad" };
        var localVersion = new PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = version,
            Origin = "uploaded",
            Filename = $"left-pad-{version}.tgz",
            BlobKey = "hosted/npm/left-pad-1.3.0.tgz",
            ChecksumSha1 = "2222222222222222222222222222222222222222",
            UpstreamIntegrityValue = "sha512-LOCALdigestForTheBytesWeActuallyServe==",
            UpstreamIntegrityAlgorithm = "sha512-sri",
        };

        NpmPackumentHandler.MergeLocalVersionsIntoPackument(
            TarballBase, packument, localPkg, new[] { localVersion },
            new OrgSettings { OrgId = "org1" },
            new Dictionary<string, VulnGateSignals>(),
            DateTimeOffset.UnixEpoch);

        var dist = packument["versions"]![version]!["dist"]!;
        Assert.Equal("sha512-LOCALdigestForTheBytesWeActuallyServe==", (string?)dist["integrity"]);
        Assert.Equal("2222222222222222222222222222222222222222", (string?)dist["shasum"]);
        // The tarball points at this registry (local bytes).
        Assert.StartsWith(TarballBase, (string?)dist["tarball"]);
    }

    [Fact]
    public void Collision_YankedLocalRow_LeavesUpstreamObjectUntouched()
    {
        // Adversarial twin: a yanked local row is never served, so the merge must not overwrite
        // the upstream object with a local integrity for bytes that will 403.
        const string version = "1.3.0";
        var packument = UpstreamPackumentWithVersion(
            version,
            upstreamIntegrity: "sha512-UPSTREAMdigest==",
            upstreamShasum: "1111111111111111111111111111111111111111");

        var localPkg = new Package { Id = "p1", Name = "left-pad", OrgId = "org1", Ecosystem = "npm", PurlName = "left-pad" };
        var yanked = new PackageVersion
        {
            Id = "v1",
            PackageId = "p1",
            Version = version,
            Origin = "uploaded",
            Yanked = true,
            Filename = $"left-pad-{version}.tgz",
            BlobKey = "hosted/npm/left-pad-1.3.0.tgz",
            UpstreamIntegrityValue = "sha512-LOCALdigest==",
            UpstreamIntegrityAlgorithm = "sha512-sri",
        };

        NpmPackumentHandler.MergeLocalVersionsIntoPackument(
            TarballBase, packument, localPkg, new[] { yanked },
            new OrgSettings { OrgId = "org1" },
            new Dictionary<string, VulnGateSignals>(),
            DateTimeOffset.UnixEpoch);

        var dist = packument["versions"]![version]!["dist"]!;
        Assert.Equal("sha512-UPSTREAMdigest==", (string?)dist["integrity"]);
    }
}
