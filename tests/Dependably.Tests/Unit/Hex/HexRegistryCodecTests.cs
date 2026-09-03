using System.Security.Cryptography;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The hand-written proto2 codec, checked against bytes hex.pm actually serves: the decoded
/// view must carry what the real client reads, and re-encoding it must reproduce the upstream
/// payload byte for byte — which is what makes the re-signing proxy's output canonical.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexRegistryCodecTests
{
    private static string Fixture(string name) => Path.Combine(FixtureManifest.FixturesRoot, "hex", name);

    private static RSA HexpmKey() => HexRegistrySigner.ParsePublicKeyPem(File.ReadAllText(Fixture("hexpm-public-key.pem")));

    private static byte[] OpenFixture(string name) =>
        HexRegistrySigner.OpenResource(File.ReadAllBytes(Fixture(name)), HexpmKey());

    [Fact]
    public void RealDecimalPackage_DecodesReleasesChecksumsAndTimestamps()
    {
        var package = HexRegistryCodec.DecodePackage(OpenFixture("decimal.package.signed.gz"));

        Assert.Equal("decimal", package.Name);
        Assert.Equal("hexpm", package.Repository);
        Assert.True(package.Releases.Count >= 30, "decimal has dozens of releases");

        var release = Assert.Single(package.Releases, r => r.Version == "2.3.0");
        // The inner checksum is the tarball's CHECKSUM entry; the outer one is SHA-256 of the whole .tar.
        Assert.Equal(
            "3AD6255AA77B4A3C4F818171B12D237500E63525C2FD056699967A3E7EA20F62",
            Convert.ToHexString(release.InnerChecksum));
        Assert.Equal(
            FixtureManifest.HexDecimalTarballSha256,
            Convert.ToHexString(release.OuterChecksum!).ToLowerInvariant());
        Assert.NotNull(release.PublishedAt);
        Assert.Equal(2024, release.PublishedAt!.ToDateTimeOffset().Year);
        Assert.Empty(release.Dependencies);
        Assert.Null(release.Retired);
    }

    [Fact]
    public void RealPhoenixPackage_DecodesDependenciesWithOptionalAndApp()
    {
        var package = HexRegistryCodec.DecodePackage(OpenFixture("phoenix.package.signed.gz"));

        Assert.Equal("phoenix", package.Name);
        var latest = package.Releases[^1];
        Assert.NotEmpty(latest.Dependencies);
        // plug_cowboy is an optional dependency of every modern phoenix release.
        var optional = Assert.Single(latest.Dependencies, d => d.Package == "plug_cowboy");
        Assert.True(optional.Optional);
        Assert.All(latest.Dependencies, d => Assert.False(string.IsNullOrWhiteSpace(d.Requirement)));
    }

    [Theory]
    [InlineData("decimal.package.signed.gz")]
    [InlineData("phoenix.package.signed.gz")]
    public void ReEncodingARealPayload_IsByteIdentical(string fixture)
    {
        byte[] payload = OpenFixture(fixture);
        var decoded = HexRegistryCodec.DecodePackage(payload);

        byte[] reencoded = HexRegistryCodec.EncodePackage(decoded);

        Assert.Equal(payload, reencoded);
    }

    [Fact]
    public void Names_RoundTrips()
    {
        var names = new HexNames("acme", new[]
        {
            new HexNameEntry("alpha", new HexTimestamp(1_700_000_000, 123)),
            new HexNameEntry("beta"),
        });

        var decoded = HexRegistryCodec.DecodeNames(HexRegistryCodec.EncodeNames(names));

        Assert.Equal(names.Repository, decoded.Repository);
        Assert.Equal(names.Packages.Select(p => p.Name), decoded.Packages.Select(p => p.Name));
        Assert.Equal(new HexTimestamp(1_700_000_000, 123), decoded.Packages[0].UpdatedAt);
        Assert.Null(decoded.Packages[1].UpdatedAt);
    }

    [Fact]
    public void Versions_RoundTrips_WithPackedIndexSets()
    {
        var versions = new HexVersions("acme", new[]
        {
            new HexVersionsEntry("alpha", new[] { "1.0.0", "1.1.0", "2.0.0" }, new[] { 1 }, new[] { 0, 2 }),
            new HexVersionsEntry("beta", new[] { "0.1.0" }, Array.Empty<int>(), Array.Empty<int>()),
        });

        var decoded = HexRegistryCodec.DecodeVersions(HexRegistryCodec.EncodeVersions(versions));

        Assert.Equal(new[] { 1 }, decoded.Packages[0].Retired);
        Assert.Equal(new[] { 0, 2 }, decoded.Packages[0].WithAdvisories);
        Assert.Empty(decoded.Packages[1].Retired);
        Assert.Equal(new[] { "0.1.0" }, decoded.Packages[1].Versions);
    }

    [Fact]
    public void Package_RoundTrips_EveryOptionalField()
    {
        var package = new HexPackage("alpha", "acme",
            new[]
            {
                new HexRelease("1.0.0", new byte[32], new[]
                    {
                        new HexDependency("jason", "~> 1.0", Optional: true, App: "jason", Repository: "hexpm"),
                        new HexDependency("plug", ">= 0.0.0"),
                    },
                    Retired: new HexRetirementStatus(HexRetirementReason.Security, "CVE"),
                    OuterChecksum: Enumerable.Repeat((byte)7, 32).ToArray(),
                    AdvisoryIndexes: new uint[] { 0, 1 },
                    PublishedAt: new HexTimestamp(1_600_000_000, 0)),
            },
            new[]
            {
                new HexSecurityAdvisory("GHSA-x", "summary", "https://osv.dev/vulnerability/GHSA-x",
                    "https://api.osv.dev/v1/vulns/GHSA-x", HexAdvisorySeverity.High, 7.5f, new[] { "CVE-2024-1" }),
                new HexSecurityAdvisory("GHSA-y", "s", "h", "a"),
            });

        var decoded = HexRegistryCodec.DecodePackage(HexRegistryCodec.EncodePackage(package));

        Assert.Equal(package, decoded with
        {
            Releases = decoded.Releases.Select(r => r with
            {
                InnerChecksum = r.InnerChecksum,
                OuterChecksum = r.OuterChecksum,
            }).ToList(),
        }, HexPackageComparer.Instance);
        Assert.Equal(HexAdvisorySeverity.High, decoded.Advisories[0].Severity);
        Assert.Equal(7.5f, decoded.Advisories[0].CvssScore);
        Assert.Null(decoded.Advisories[1].Severity);
        Assert.Null(decoded.Advisories[1].CvssScore);
        Assert.Null(decoded.Advisories[1].Aliases);
        Assert.Equal(new uint[] { 0, 1 }, decoded.Releases[0].AdvisoryIndexes);
        Assert.Equal(HexRetirementReason.Security, decoded.Releases[0].Retired!.Reason);
    }

    [Fact]
    public void Policy_RoundTrips()
    {
        var policy = new HexPolicy("acme", "default", HexVisibility.Public,
            new[]
            {
                new HexRepositoryPolicy("hexpm",
                    new HexRestriction(HexAdvisorySeverity.High,
                        new[] { HexRetirementReason.Security, HexRetirementReason.Invalid }, "7d"),
                    new[]
                    {
                        new HexOverride(HexOverrideAction.Deny, new HexPackageRef("evil")),
                        new HexOverride(HexOverrideAction.Advisory, new HexPackageRef("plug", "~> 1.0"),
                            AdvisoryId: "GHSA-1", Comment: "accepted"),
                        new HexOverride(HexOverrideAction.Retirement, new HexPackageRef("old"),
                            RetirementReason: HexRetirementReason.Deprecated),
                    }),
                new HexRepositoryPolicy("acme", null, Array.Empty<HexOverride>()),
            },
            "Org policy");

        var decoded = HexRegistryCodec.DecodePolicy(HexRegistryCodec.EncodePolicy(policy));

        Assert.Equal("Org policy", decoded.Description);
        Assert.Equal(HexVisibility.Public, decoded.Visibility);
        Assert.Equal("7d", decoded.Repositories[0].Restriction!.Cooldown);
        Assert.Equal(new[] { HexRetirementReason.Security, HexRetirementReason.Invalid },
            decoded.Repositories[0].Restriction!.RetirementReasons);
        Assert.Equal(3, decoded.Repositories[0].Overrides.Count);
        Assert.Equal("~> 1.0", decoded.Repositories[0].Overrides[1].Ref.Requirement);
        Assert.Equal(HexRetirementReason.Deprecated, decoded.Repositories[0].Overrides[2].RetirementReason);
        Assert.Null(decoded.Repositories[1].Restriction);
    }

    [Fact]
    public void Policy_VisibilityIsRequired_MissingFieldIsRefused()
    {
        // Policy{repository=1, name=2} with no visibility field.
        byte[] bytes = { 0x0A, 0x04, (byte)'a', (byte)'c', (byte)'m', (byte)'e', 0x12, 0x01, (byte)'p' };
        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePolicy(bytes));
        Assert.Contains("Policy.visibility", ex.Message);
    }

    [Fact]
    public void UnknownEnumValue_RoundTripsAsItsInteger()
    {
        var package = new HexPackage("a", "r", new[]
        {
            new HexRelease("1.0.0", new byte[32], Array.Empty<HexDependency>(),
                Retired: new HexRetirementStatus((HexRetirementReason)9)),
        }, Array.Empty<HexSecurityAdvisory>());

        var decoded = HexRegistryCodec.DecodePackage(HexRegistryCodec.EncodePackage(package));

        Assert.Equal((HexRetirementReason)9, decoded.Releases[0].Retired!.Reason);
    }

    [Fact]
    public void UnknownField_IsSkipped()
    {
        // Names{ packages=1{name="a"}, repository=2 "r", (unknown) field 9 varint 5, field 10 bytes "zz" }
        byte[] bytes =
        {
            0x0A, 0x03, 0x0A, 0x01, (byte)'a',
            0x12, 0x01, (byte)'r',
            0x48, 0x05,
            0x52, 0x02, (byte)'z', (byte)'z',
        };

        var names = HexRegistryCodec.DecodeNames(bytes);

        Assert.Equal("r", names.Repository);
        Assert.Equal("a", names.Packages[0].Name);
    }

    [Fact]
    public void RepeatedInt32_AcceptsUnpackedEncoding()
    {
        // Versions.Package with retired written one tag per element (field 3, varint) instead of packed.
        byte[] entry = { 0x0A, 0x01, (byte)'a', 0x18, 0x01, 0x18, 0x03 };
        byte[] bytes = new byte[] { 0x0A, (byte)entry.Length }.Concat(entry).Concat(new byte[] { 0x12, 0x01, (byte)'r' }).ToArray();

        var versions = HexRegistryCodec.DecodeVersions(bytes);

        Assert.Equal(new[] { 1, 3 }, versions.Packages[0].Retired);
    }

    [Fact]
    public void MissingRequiredField_IsRefused()
    {
        // Package with name but no repository.
        byte[] bytes = { 0x12, 0x01, (byte)'a' };
        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(bytes));
        Assert.Contains("Package.repository", ex.Message);
    }

    [Fact]
    public void Release_InnerChecksumIsRequired()
    {
        // Package{ releases=1{ version=1 "1.0.0" }, name, repository } — the release lacks inner_checksum.
        byte[] release = { 0x0A, 0x05, (byte)'1', (byte)'.', (byte)'0', (byte)'.', (byte)'0' };
        byte[] bytes = new byte[] { 0x0A, (byte)release.Length }.Concat(release)
            .Concat(new byte[] { 0x12, 0x01, (byte)'a', 0x1A, 0x01, (byte)'r' }).ToArray();

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(bytes));
        Assert.Contains("inner_checksum", ex.Message);
    }

    [Fact]
    public void LengthPrefixBeyondInput_IsRefusedBeforeAllocation()
    {
        // field 2 (repository), length 0xFFFFFFFF, no bytes follow.
        byte[] bytes = { 0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F };
        Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(bytes));
    }

    [Fact]
    public void TruncatedVarint_IsRefused()
    {
        byte[] bytes = { 0x08, 0x80 };
        Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(bytes));
    }

    [Fact]
    public void GroupWireTypes_AreRefused()
    {
        byte[] bytes = { 0x0B };
        Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(bytes));
    }

    [Fact]
    public void InvalidUtf8String_IsRefused()
    {
        // Names.repository = 0xFF 0xFE (not UTF-8), no packages.
        byte[] bytes = { 0x12, 0x02, 0xFF, 0xFE };
        Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(bytes));
    }

    [Fact]
    public void Timestamp_ConvertsBothWays()
    {
        var instant = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.Zero).AddTicks(1234567);
        var ts = HexTimestamp.FromDateTimeOffset(instant);

        Assert.Equal(instant.ToUnixTimeSeconds(), ts.Seconds);
        Assert.Equal(123456700, ts.Nanos);
        Assert.Equal(instant, ts.ToDateTimeOffset());
    }

    /// <summary>Record equality is reference-based for arrays; this compares the content.</summary>
    private sealed class HexPackageComparer : IEqualityComparer<HexPackage>
    {
        public static readonly HexPackageComparer Instance = new();

        public bool Equals(HexPackage? x, HexPackage? y)
        {
            return x is null || y is null
                ? x is null && y is null
                : x.Name == y.Name && x.Repository == y.Repository
                && x.Releases.Count == y.Releases.Count
                && x.Releases.Zip(y.Releases).All(p => ReleaseEquals(p.First, p.Second))
                && x.Advisories.Count == y.Advisories.Count
                && x.Advisories.Zip(y.Advisories).All(p => AdvisoryEquals(p.First, p.Second));
        }

        private static bool ReleaseEquals(HexRelease a, HexRelease b) =>
            a.Version == b.Version
            && a.InnerChecksum.AsSpan().SequenceEqual(b.InnerChecksum)
            && ((a.OuterChecksum is null && b.OuterChecksum is null)
                || (a.OuterChecksum is not null && b.OuterChecksum is not null
                    && a.OuterChecksum.AsSpan().SequenceEqual(b.OuterChecksum)))
            && a.Dependencies.SequenceEqual(b.Dependencies)
            && Equals(a.Retired, b.Retired)
            && Equals(a.PublishedAt, b.PublishedAt)
            && (a.AdvisoryIndexes ?? Array.Empty<uint>()).SequenceEqual(b.AdvisoryIndexes ?? Array.Empty<uint>());

        private static bool AdvisoryEquals(HexSecurityAdvisory a, HexSecurityAdvisory b) =>
            a.Id == b.Id && a.Summary == b.Summary && a.HtmlUrl == b.HtmlUrl && a.ApiUrl == b.ApiUrl
            && a.Severity == b.Severity && a.CvssScore == b.CvssScore
            && (a.Aliases ?? Array.Empty<string>()).SequenceEqual(b.Aliases ?? Array.Empty<string>());

        public int GetHashCode(HexPackage obj) => HashCode.Combine(obj.Name, obj.Repository);
    }
}
