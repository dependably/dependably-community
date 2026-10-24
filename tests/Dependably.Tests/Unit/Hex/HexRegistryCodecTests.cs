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
    public void Signed_RoundTripsWithAndWithoutASignature()
    {
        var signed = HexRegistryCodec.DecodeSigned(HexRegistryCodec.EncodeSigned(new HexSigned(new byte[] { 1, 2, 3 }, new byte[] { 9, 8 })));
        var unsigned = HexRegistryCodec.DecodeSigned(HexRegistryCodec.EncodeSigned(new HexSigned(new byte[] { 4 }, null)));

        Assert.Equal(new byte[] { 1, 2, 3 }, signed.Payload);
        Assert.Equal(new byte[] { 9, 8 }, signed.Signature);
        Assert.Equal(new byte[] { 4 }, unsigned.Payload);
        Assert.Null(unsigned.Signature);
    }

    [Fact]
    public void Signed_PayloadIsRequired_AndFieldsOfTheWrongWireTypeAreSkipped()
    {
        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeSigned(Pb.Cat(Pb.Vint(1, 5), Pb.Vint(2, 6), Pb.Vint(9, 1))));

        Assert.Contains("Signed.payload", ex.Message);
        var ok = HexRegistryCodec.DecodeSigned(Pb.Cat(Pb.Vint(2, 6), Pb.Bytes(1, new byte[] { 7 }), Pb.Fixed32(9, 1.5f)));
        Assert.Equal(new byte[] { 7 }, ok.Payload);
        Assert.Null(ok.Signature);
    }

    [Fact]
    public void Names_RoundTripWithUpdatedAtTimestamps()
    {
        var names = new HexNames("acme", new[]
        {
            new HexNameEntry("jason", new HexTimestamp(1_700_000_000, 5)),
            new HexNameEntry("plug"),
        });

        var decoded = HexRegistryCodec.DecodeNames(HexRegistryCodec.EncodeNames(names));

        Assert.Equal("acme", decoded.Repository);
        Assert.Equal(new HexTimestamp(1_700_000_000, 5), decoded.Packages[0].UpdatedAt);
        Assert.Null(decoded.Packages[1].UpdatedAt);
        Assert.Equal(new[] { "jason", "plug" }, decoded.Packages.Select(p => p.Name));
    }

    [Theory]
    [InlineData("name", "Names.Package.name")]
    [InlineData("seconds", "Timestamp.seconds")]
    [InlineData("nanos", "Timestamp.nanos")]
    public void NameEntry_MissingRequiredPieces_AreRefusedByName(string missing, string expectedField)
    {
        byte[] entry = missing switch
        {
            "name" => Pb.Cat(Pb.Vint(1, 3), Pb.Msg(3, Pb.Vint(1, 1), Pb.Vint(2, 2))),
            "seconds" => Pb.Cat(Pb.Str(1, "jason"), Pb.Msg(3, Pb.Vint(2, 2))),
            _ => Pb.Cat(Pb.Str(1, "jason"), Pb.Msg(3, Pb.Vint(1, 1))),
        };

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(Pb.Cat(Pb.Msg(1, entry), Pb.Str(2, "hexpm"))));

        Assert.Contains(expectedField, ex.Message);
    }

    [Fact]
    public void Names_RepositoryIsRequired_AndUnknownFieldsInsideEntriesAreSkipped()
    {
        byte[] entry = Pb.Cat(Pb.Str(1, "jason"), Pb.Fixed32(4, 1f), Pb.Vint(8, 3), Pb.Msg(3, Pb.Vint(1, 10), Pb.Vint(2, 20), Pb.Str(3, "x")));

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(Pb.Msg(1, entry)));
        var ok = HexRegistryCodec.DecodeNames(Pb.Cat(Pb.Msg(1, entry), Pb.Str(2, "hexpm")));

        Assert.Contains("Names.repository", ex.Message);
        Assert.Equal(new HexTimestamp(10, 20), ok.Packages[0].UpdatedAt);
    }

    [Fact]
    public void Versions_RequireRepositoryAndPackageName_AndSkipMismatchedWireTypes()
    {
        var noRepo = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeVersions(Pb.Msg(1, Pb.Str(1, "jason"))));
        var noName = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeVersions(
            Pb.Cat(Pb.Msg(1, Pb.Vint(1, 1), Pb.Str(2, "1.0.0")), Pb.Str(2, "hexpm"))));
        var tolerant = HexRegistryCodec.DecodeVersions(Pb.Cat(
            Pb.Msg(1, Pb.Str(1, "jason"), Pb.Vint(2, 1), Pb.Str(2, "1.4.1"), Pb.Str(4, "ignored"), Pb.Str(3, "\u0000"), Pb.Vint(5, 0)),
            Pb.Vint(1, 0),
            Pb.Vint(2, 0),
            Pb.Str(2, "hexpm")));

        Assert.Contains("Versions.repository", noRepo.Message);
        Assert.Contains("Versions.Package.name", noName.Message);
        var entry = Assert.Single(tolerant.Packages);
        Assert.Equal(new[] { "1.4.1" }, entry.Versions);
        Assert.Equal(new[] { 0 }, entry.WithAdvisories);
        Assert.Equal(new[] { 0 }, entry.Retired);
    }

    [Fact]
    public void Package_DependencyWithOptionalFalse_KeepsTheExplicitFalse()
    {
        var package = new HexPackage("phoenix", "hexpm", new[]
        {
            new HexRelease("1.7.0", new byte[32], new[] { new HexDependency("plug", "~> 1.14", Optional: false) }),
        }, Array.Empty<HexSecurityAdvisory>());

        var decoded = HexRegistryCodec.DecodePackage(HexRegistryCodec.EncodePackage(package));

        Assert.False(Assert.Single(Assert.Single(decoded.Releases).Dependencies).Optional);
        Assert.Null(decoded.Releases[0].AdvisoryIndexes);
        Assert.Null(decoded.Releases[0].Retired);
    }

    [Fact]
    public void Package_RetirementWithoutAMessage_RoundTripsWithANullMessage()
    {
        var package = new HexPackage("phoenix", "hexpm", new[]
        {
            new HexRelease("1.7.0", new byte[32], Array.Empty<HexDependency>(), new HexRetirementStatus(HexRetirementReason.Renamed)),
        }, Array.Empty<HexSecurityAdvisory>());

        var retired = HexRegistryCodec.DecodePackage(HexRegistryCodec.EncodePackage(package)).Releases[0].Retired;

        Assert.Equal(HexRetirementReason.Renamed, retired!.Reason);
        Assert.Null(retired.Message);
    }

    [Fact]
    public void Release_AdvisoryIndexes_AcceptPackedAndUnpackedRuns()
    {
        byte[] release = Pb.Cat(Pb.Str(1, "1.0.0"), Pb.Bytes(2, new byte[32]), Pb.Vint(6, 4), Pb.Bytes(6, new byte[] { 0x01, 0x02 }));
        byte[] package = Pb.Cat(Pb.Msg(1, release), Pb.Str(2, "jason"), Pb.Str(3, "hexpm"));

        var decoded = HexRegistryCodec.DecodePackage(package);

        Assert.Equal(new uint[] { 4, 1, 2 }, decoded.Releases[0].AdvisoryIndexes);
    }

    [Theory]
    [InlineData("version", "Release.version")]
    [InlineData("checksum", "Release.inner_checksum")]
    public void Release_MissingRequiredFields_AreRefusedByName(string missing, string expectedField)
    {
        byte[] release = missing == "version"
            ? Pb.Bytes(2, new byte[32])
            : Pb.Str(1, "1.0.0");

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(
            Pb.Cat(Pb.Msg(1, release), Pb.Str(2, "jason"), Pb.Str(3, "hexpm"))));

        Assert.Contains(expectedField, ex.Message);
    }

    [Fact]
    public void Package_WrongWireTypesAndUnknownFields_AreSkippedInsideReleases()
    {
        byte[] release = Pb.Cat(
            Pb.Vint(1, 1), Pb.Str(1, "2.0.0"),
            Pb.Vint(2, 1), Pb.Bytes(2, new byte[32]),
            Pb.Vint(3, 1), Pb.Vint(4, 1), Pb.Vint(5, 1), Pb.Vint(7, 1),
            Pb.Fixed32(30, 2f));
        byte[] package = Pb.Cat(Pb.Vint(1, 1), Pb.Msg(1, release), Pb.Vint(2, 1), Pb.Str(2, "jason"), Pb.Vint(3, 1), Pb.Str(3, "hexpm"), Pb.Vint(4, 1));

        var decoded = HexRegistryCodec.DecodePackage(package);

        Assert.Equal("jason", decoded.Name);
        var only = Assert.Single(decoded.Releases);
        Assert.Equal("2.0.0", only.Version);
        Assert.Empty(only.Dependencies);
        Assert.Null(only.Retired);
        Assert.Null(only.OuterChecksum);
        Assert.Null(only.PublishedAt);
        Assert.Empty(decoded.Advisories);
    }

    [Theory]
    [InlineData("package", "Dependency.package")]
    [InlineData("requirement", "Dependency.requirement")]
    public void Dependency_MissingRequiredFields_AreRefusedByName(string missing, string expectedField)
    {
        byte[] dependency = missing == "package"
            ? Pb.Cat(Pb.Str(2, "~> 1.0"), Pb.Vint(1, 1), Pb.Str(3, "not-a-varint"))
            : Pb.Cat(Pb.Str(1, "jason"), Pb.Vint(2, 1));
        byte[] release = Pb.Cat(Pb.Str(1, "1.0.0"), Pb.Bytes(2, new byte[32]), Pb.Msg(3, dependency));

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(
            Pb.Cat(Pb.Msg(1, release), Pb.Str(2, "phoenix"), Pb.Str(3, "hexpm"))));

        Assert.Contains(expectedField, ex.Message);
    }

    [Fact]
    public void Retirement_MissingReason_IsRefused()
    {
        byte[] release = Pb.Cat(Pb.Str(1, "1.0.0"), Pb.Bytes(2, new byte[32]), Pb.Msg(4, Pb.Str(1, "x"), Pb.Str(2, "gone"), Pb.Vint(9, 1)));

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(
            Pb.Cat(Pb.Msg(1, release), Pb.Str(2, "phoenix"), Pb.Str(3, "hexpm"))));

        Assert.Contains("RetirementStatus.reason", ex.Message);
    }

    [Theory]
    [InlineData(1, "SecurityAdvisory.id")]
    [InlineData(2, "SecurityAdvisory.summary")]
    [InlineData(3, "SecurityAdvisory.html_url")]
    [InlineData(6, "SecurityAdvisory.api_url")]
    public void Advisory_MissingRequiredFields_AreRefusedByName(int omittedField, string expectedField)
    {
        var fields = new List<byte[]>();
        foreach (int field in new[] { 1, 2, 3, 6 })
        {
            fields.Add(field == omittedField ? Pb.Vint(field, 1) : Pb.Str(field, "v"));
        }

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(
            Pb.Cat(Pb.Str(2, "phoenix"), Pb.Str(3, "hexpm"), Pb.Msg(4, fields.ToArray()))));

        Assert.Contains(expectedField, ex.Message);
    }

    [Fact]
    public void Advisory_MismatchedWireTypesForOptionalFields_AreSkipped()
    {
        byte[] advisory = Pb.Cat(
            Pb.Str(1, "GHSA-aaaa"), Pb.Str(2, "summary"), Pb.Str(3, "https://osv.dev/x"), Pb.Str(6, "https://api.osv.dev/x"),
            Pb.Str(4, "high"), Pb.Vint(5, 7), Pb.Vint(7, 1), Pb.Fixed32(40, 1f));

        var decoded = HexRegistryCodec.DecodePackage(Pb.Cat(Pb.Str(2, "phoenix"), Pb.Str(3, "hexpm"), Pb.Msg(4, advisory)));

        var only = Assert.Single(decoded.Advisories);
        Assert.Null(only.Severity);
        Assert.Null(only.CvssScore);
        Assert.Null(only.Aliases);
    }

    [Fact]
    public void Policy_RoundTripsRestrictionsOverridesAndEveryOptionalField()
    {
        var policy = new HexPolicy("acme", "strict", HexVisibility.Public, new[]
        {
            new HexRepositoryPolicy(
                "hexpm",
                new HexRestriction(HexAdvisorySeverity.High, new[] { HexRetirementReason.Security, HexRetirementReason.Invalid }, "P7D"),
                new[]
                {
                    new HexOverride(HexOverrideAction.Allow, new HexPackageRef("jason", "~> 1.4"), "GHSA-aaaa", HexRetirementReason.Deprecated, "known-safe"),
                    new HexOverride(HexOverrideAction.Deny, new HexPackageRef("plug")),
                }),
            new HexRepositoryPolicy("acme", null, Array.Empty<HexOverride>()),
        }, "A strict policy");

        var decoded = HexRegistryCodec.DecodePolicy(HexRegistryCodec.EncodePolicy(policy));

        Assert.Equal("A strict policy", decoded.Description);
        Assert.Equal(HexVisibility.Public, decoded.Visibility);
        var hexpm = decoded.Repositories[0];
        Assert.Equal(HexAdvisorySeverity.High, hexpm.Restriction!.AdvisoryMinSeverity);
        Assert.Equal(new[] { HexRetirementReason.Security, HexRetirementReason.Invalid }, hexpm.Restriction.RetirementReasons);
        Assert.Equal("P7D", hexpm.Restriction.Cooldown);
        Assert.Equal(HexOverrideAction.Allow, hexpm.Overrides[0].Action);
        Assert.Equal("~> 1.4", hexpm.Overrides[0].Ref.Requirement);
        Assert.Equal("GHSA-aaaa", hexpm.Overrides[0].AdvisoryId);
        Assert.Equal(HexRetirementReason.Deprecated, hexpm.Overrides[0].RetirementReason);
        Assert.Equal("known-safe", hexpm.Overrides[0].Comment);
        Assert.Equal(HexOverrideAction.Deny, hexpm.Overrides[1].Action);
        Assert.Null(hexpm.Overrides[1].Ref.Requirement);
        Assert.Null(hexpm.Overrides[1].AdvisoryId);
        Assert.Null(hexpm.Overrides[1].RetirementReason);
        Assert.Null(hexpm.Overrides[1].Comment);
        Assert.Null(decoded.Repositories[1].Restriction);
        Assert.Empty(decoded.Repositories[1].Overrides);
    }

    [Fact]
    public void Policy_WithoutOptionalPieces_RoundTripsAsNulls()
    {
        var policy = new HexPolicy("acme", "open", HexVisibility.Private, new[]
        {
            new HexRepositoryPolicy("hexpm", new HexRestriction(null, Array.Empty<HexRetirementReason>(), null), Array.Empty<HexOverride>()),
        });

        var decoded = HexRegistryCodec.DecodePolicy(HexRegistryCodec.EncodePolicy(policy));

        Assert.Null(decoded.Description);
        var restriction = decoded.Repositories[0].Restriction!;
        Assert.Null(restriction.AdvisoryMinSeverity);
        Assert.Empty(restriction.RetirementReasons);
        Assert.Null(restriction.Cooldown);
    }

    [Theory]
    [InlineData("repository", "Policy.repository")]
    [InlineData("name", "Policy.name")]
    public void Policy_MissingTopLevelFields_AreRefusedByName(string missing, string expectedField)
    {
        byte[] bytes = missing == "repository"
            ? Pb.Cat(Pb.Vint(1, 1), Pb.Str(2, "p"), Pb.Vint(4, 1))
            : Pb.Cat(Pb.Str(1, "acme"), Pb.Vint(2, 1), Pb.Vint(4, 1));

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePolicy(bytes));

        Assert.Contains(expectedField, ex.Message);
    }

    [Theory]
    [InlineData("repo", "RepositoryPolicy.repository")]
    [InlineData("action", "Override.action")]
    [InlineData("ref", "Override.ref")]
    [InlineData("refpackage", "PackageRef.package")]
    public void Policy_MissingNestedFields_AreRefusedByName(string missing, string expectedField)
    {
        byte[] overrideBody = missing switch
        {
            "action" => Pb.Msg(2, Pb.Str(1, "jason")),
            "ref" => Pb.Vint(1, 0),
            "refpackage" => Pb.Cat(Pb.Vint(1, 0), Pb.Msg(2, Pb.Str(2, "~> 1.0"), Pb.Vint(1, 1))),
            _ => Pb.Cat(Pb.Vint(1, 0), Pb.Msg(2, Pb.Str(1, "jason"))),
        };
        byte[] repoPolicy = missing == "repo"
            ? Pb.Cat(Pb.Vint(1, 1), Pb.Msg(3, overrideBody))
            : Pb.Cat(Pb.Str(1, "hexpm"), Pb.Msg(3, overrideBody));
        byte[] bytes = Pb.Cat(Pb.Str(1, "acme"), Pb.Str(2, "p"), Pb.Vint(4, 0), Pb.Msg(5, repoPolicy));

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePolicy(bytes));

        Assert.Contains(expectedField, ex.Message);
    }

    [Fact]
    public void Policy_WrongWireTypesAndUnknownFields_AreSkippedAtEveryLevel()
    {
        byte[] overrideBody = Pb.Cat(
            Pb.Str(1, "x"), Pb.Vint(1, 1), Pb.Vint(2, 1), Pb.Msg(2, Pb.Str(1, "jason"), Pb.Vint(2, 1), Pb.Vint(9, 1)),
            Pb.Vint(3, 1), Pb.Vint(5, 1), Pb.Str(4, "x"), Pb.Vint(9, 1));
        byte[] restriction = Pb.Cat(Pb.Str(1, "x"), Pb.Vint(2, 1), Pb.Vint(3, 1), Pb.Fixed32(9, 1f));
        byte[] repoPolicy = Pb.Cat(Pb.Vint(1, 1), Pb.Str(1, "hexpm"), Pb.Vint(2, 1), Pb.Msg(2, restriction), Pb.Vint(3, 1), Pb.Msg(3, overrideBody), Pb.Vint(9, 1));
        byte[] bytes = Pb.Cat(
            Pb.Vint(1, 1), Pb.Str(1, "acme"), Pb.Vint(2, 1), Pb.Str(2, "p"), Pb.Vint(3, 1), Pb.Str(4, "x"), Pb.Vint(4, 1),
            Pb.Vint(5, 1), Pb.Msg(5, repoPolicy), Pb.Vint(9, 1));

        var decoded = HexRegistryCodec.DecodePolicy(bytes);

        Assert.Null(decoded.Description);
        var repo = Assert.Single(decoded.Repositories);
        Assert.Equal("hexpm", repo.Repository);
        Assert.Null(repo.Restriction!.AdvisoryMinSeverity);
        Assert.Null(repo.Restriction.Cooldown);
        Assert.Equal(new[] { HexRetirementReason.Invalid }, repo.Restriction.RetirementReasons);
        var only = Assert.Single(repo.Overrides);
        Assert.Equal(HexOverrideAction.Deny, only.Action);
        Assert.Null(only.AdvisoryId);
        Assert.Null(only.RetirementReason);
        Assert.Null(only.Comment);
    }

    [Fact]
    public void Timestamp_MismatchedWireTypesAreSkipped_ThenRequiredFieldsAreEnforced()
    {
        byte[] entry = Pb.Cat(Pb.Str(1, "jason"), Pb.Msg(3, Pb.Str(1, "x"), Pb.Str(2, "y")));

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(Pb.Cat(Pb.Msg(1, entry), Pb.Str(2, "hexpm"))));

        Assert.Contains("Timestamp.seconds", ex.Message);
    }

    [Fact]
    public void RepeatedEntries_BeyondTheElementLimit_AreRefused()
    {
        byte[] entry = Pb.Msg(1, Pb.Str(1, "a"));
        byte[] payload = new byte[entry.Length * (HexRegistryCodec.MaxRepeatedElements + 1)];
        for (int i = 0; i <= HexRegistryCodec.MaxRepeatedElements; i++)
        {
            entry.CopyTo(payload, i * entry.Length);
        }

        var ex = Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(payload));

        Assert.Contains("repeated field exceeds the element limit", ex.Message);
    }

    [Fact]
    public void PayloadOverTheSizeLimit_IsRefusedByEveryDecoderBeforeWalking()
    {
        byte[] oversized = new byte[HexRegistryCodec.MaxPayloadBytes + 1];

        Assert.Contains("byte limit", Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeSigned(oversized)).Message);
        Assert.Contains("byte limit", Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeNames(oversized)).Message);
        Assert.Contains("byte limit", Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodeVersions(oversized)).Message);
        Assert.Contains("byte limit", Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePackage(oversized)).Message);
        Assert.Contains("byte limit", Assert.Throws<HexProtocolException>(() => HexRegistryCodec.DecodePolicy(oversized)).Message);
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

    /// <summary>Hand-assembled protobuf wire bytes, so a test controls the exact tag and wire type of every field.</summary>
    private static class Pb
    {
        public static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

        public static byte[] Varint(ulong value)
        {
            var bytes = new List<byte>();
            while (value >= 0x80)
            {
                bytes.Add((byte)(value | 0x80));
                value >>= 7;
            }

            bytes.Add((byte)value);
            return bytes.ToArray();
        }

        public static byte[] Tag(int field, int wire) => Varint(((ulong)field << 3) | (uint)wire);

        public static byte[] Vint(int field, ulong value) => Cat(Tag(field, 0), Varint(value));

        public static byte[] Bytes(int field, byte[] body) => Cat(Tag(field, 2), Varint((ulong)body.Length), body);

        public static byte[] Str(int field, string value) => Bytes(field, System.Text.Encoding.UTF8.GetBytes(value));

        public static byte[] Msg(int field, params byte[][] parts) => Bytes(field, Cat(parts));

        public static byte[] Fixed32(int field, float value) => Cat(Tag(field, 5), BitConverter.GetBytes(value));
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
