using System.Xml.Linq;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class MavenMetadataBuilderTests
{
    private static readonly DateTimeOffset Stamp =
        new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Fact]
    public void Build_SingleVersion_EmitsLatestReleaseAndVersions()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, Stamp);
        var doc = XDocument.Parse(xml);

        Assert.Equal("com.example", doc.Root!.Element("groupId")!.Value);
        Assert.Equal("mylib", doc.Root.Element("artifactId")!.Value);

        var versioning = doc.Root.Element("versioning")!;
        Assert.Equal("1.0", versioning.Element("latest")!.Value);
        Assert.Equal("1.0", versioning.Element("release")!.Value);
        Assert.Single(versioning.Element("versions")!.Elements("version"));
    }

    [Fact]
    public void Build_MultipleVersions_LatestIsTheLast()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0", "3.0" }, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("3.0", versioning.Element("latest")!.Value);
        Assert.Equal("3.0", versioning.Element("release")!.Value);
        Assert.Equal(3, versioning.Element("versions")!.Elements("version").Count());
    }

    [Fact]
    public void Build_LatestSnapshot_ReleaseSkipsToPriorNonSnapshot()
    {
        // "latest" tracks the most recent publish (including SNAPSHOTs); "release" must
        // skip SNAPSHOTs so dependency resolvers asking for the latest stable build don't
        // accidentally land on an in-flight prerelease.
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0", "2.0", "2.1-SNAPSHOT" }, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("2.1-SNAPSHOT", versioning.Element("latest")!.Value);
        Assert.Equal("2.0", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_AllSnapshots_NoReleaseElement()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0-SNAPSHOT", "1.1-SNAPSHOT" }, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.NotNull(versioning.Element("latest"));
        Assert.Null(versioning.Element("release"));
    }

    [Fact]
    public void Build_EmitsLastUpdatedFromProvidedTimestamp()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, Stamp);
        var doc = XDocument.Parse(xml);
        string lu = doc.Root!.Element("versioning")!.Element("lastUpdated")!.Value;
        Assert.Equal("20260102030405", lu);
    }

    [Fact]
    public void Build_IsDeterministic_ForSameInputs()
    {
        // The body feeds a content-derived ETag and generated checksum sidecars; two builds
        // of the same version set must be byte-identical.
        string a = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0" }, Stamp);
        string b = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0", "2.0" }, Stamp);
        Assert.Equal(a, b);
    }

    // ── <latest>/<release> selection (version ordering, not list position) ──────

    [Fact]
    public void Build_LatestIsSemanticallyNewest_NotTheLastListEntry()
    {
        // The cache-plane backfill stamps one shared timestamp into every migrated row, so on an
        // upgraded deployment every proxied version of a coordinate ties on created_at and the
        // engine's tie order is unspecified — the list can arrive in any order. <latest> must be
        // the newest version in the set, never whatever landed last.
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "2.0", "1.10", "1.9" }, Stamp);
        var versioning = XDocument.Parse(xml).Root!.Element("versioning")!;

        Assert.Equal("2.0", versioning.Element("latest")!.Value);
        Assert.Equal("2.0", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_NumericSegments_CompareNumerically_Not_Lexically()
    {
        // 1.10 is newer than 1.9; an ordinal text sort inverts that ("1.10" < "1.9"), so a naive
        // string tiebreak would ship 1.9 as <latest> and look plausible doing it.
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.10", "1.9" }, Stamp);
        var versioning = XDocument.Parse(xml).Root!.Element("versioning")!;

        Assert.Equal("1.10", versioning.Element("latest")!.Value);
        Assert.Equal("1.10", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_Snapshot_RanksBelowItsRelease()
    {
        // Maven's qualifier ladder puts SNAPSHOT below the release it precedes: 1.0-SNAPSHOT
        // < 1.0. Passing the SNAPSHOT last must not promote it to <latest>.
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "1.0", "1.0-SNAPSHOT" }, Stamp);
        var versioning = XDocument.Parse(xml).Root!.Element("versioning")!;

        Assert.Equal("1.0", versioning.Element("latest")!.Value);
        Assert.Equal("1.0", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_HighestVersionIsSnapshot_LatestTakesIt_ReleaseSkipsIt()
    {
        // The <latest>/<release> distinction, driven by version ordering rather than position:
        // <latest> takes the newest version outright (a SNAPSHOT here), <release> takes the
        // newest non-SNAPSHOT — which is 2.0, not the 1.10 sitting later in the list.
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "2.1-SNAPSHOT", "2.0", "1.10" }, Stamp);
        var versioning = XDocument.Parse(xml).Root!.Element("versioning")!;

        Assert.Equal("2.1-SNAPSHOT", versioning.Element("latest")!.Value);
        Assert.Equal("2.0", versioning.Element("release")!.Value);
    }

    [Fact]
    public void Build_MixedVersionSet_LatestAndReleaseAreOrderIndependent()
    {
        // Mixed set spanning every ordering rule at once: numeric-segment width (1.9 vs 1.10),
        // the qualifier ladder (alpha < beta < rc < snapshot < release), and a release/SNAPSHOT
        // pair of the same version. Whatever order the rows arrive in, the resolved pair — and
        // the rendered bytes for <latest>/<release> — must not move.
        string[] set = ["1.9", "1.10", "2.0-alpha-1", "2.0-rc1", "2.0-SNAPSHOT", "2.0", "1.0"];
        string[] shuffled = ["2.0", "1.0", "2.0-SNAPSHOT", "1.10", "2.0-rc1", "1.9", "2.0-alpha-1"];
        string[] reversed = [.. set.Reverse()];

        foreach (string[] order in new[] { set, shuffled, reversed })
        {
            var versioning = XDocument.Parse(
                MavenMetadataBuilder.Build("com.example", "mylib", order, Stamp))
                .Root!.Element("versioning")!;

            Assert.Equal("2.0", versioning.Element("latest")!.Value);
            Assert.Equal("2.0", versioning.Element("release")!.Value);
        }
    }

    [Fact]
    public void Build_VersionsList_RendersInCallerOrder()
    {
        // The builder resolves <latest>/<release> by version comparison but does not reorder
        // <versions> — ordering that list is the caller's job (MavenController orders by
        // created_at, then by Maven version within a tie).
        string xml = MavenMetadataBuilder.Build("com.example", "mylib",
            new[] { "2.0", "1.0", "1.9" }, Stamp);
        var versions = XDocument.Parse(xml).Root!.Element("versioning")!
            .Element("versions")!.Elements("version").Select(e => e.Value).ToList();

        Assert.Equal(new[] { "2.0", "1.0", "1.9" }, versions);
    }

    [Fact]
    public void Build_NullLastUpdated_OmitsElement()
    {
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, lastUpdated: null);
        var doc = XDocument.Parse(xml);
        Assert.Null(doc.Root!.Element("versioning")!.Element("lastUpdated"));
    }

    [Fact]
    public void Build_XmlDeclaration_MatchesUtf8ServedBytes()
    {
        // The controller serves the returned string as UTF-8 bytes (Encoding.UTF8.GetBytes).
        // The XML declaration must therefore advertise utf-8, not the utf-16 that a plain
        // StringWriter would emit — otherwise encoding-sniffing Maven/Gradle readers choke on
        // the declaration/byte mismatch and version resolution breaks.
        string xml = MavenMetadataBuilder.Build("com.example", "mylib", new[] { "1.0" }, Stamp);

        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>", xml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("utf-16", xml, StringComparison.OrdinalIgnoreCase);

        // The declared encoding must round-trip when the body is parsed from the exact UTF-8
        // bytes the controller sends — this fails on the old utf-16 declaration.
        byte[] served = System.Text.Encoding.UTF8.GetBytes(xml);
        using var ms = new MemoryStream(served);
        var reparsed = XDocument.Load(ms);
        Assert.Equal("mylib", reparsed.Root!.Element("artifactId")!.Value);
    }

    // ── BuildSnapshotVersion (version-level SNAPSHOT metadata) ──────────────────

    [Fact]
    public void BuildSnapshotVersion_TimestampedBuilds_EmitsSnapshotAndSnapshotVersions()
    {
        // A mixed jar+pom deploy of one timestamped build: both files share the same
        // timestamp/buildNumber. mvn/Gradle need the <snapshot> block to resolve
        // 1.0-SNAPSHOT to this build, and <snapshotVersions> to pick the right file per
        // extension/classifier.
        var files = new[]
        {
            new MavenSnapshotFile(null, "jar", "20240101.120000", 3, Stamp),
            new MavenSnapshotFile(null, "pom", "20240101.120000", 3, Stamp),
        };
        string xml = MavenMetadataBuilder.BuildSnapshotVersion(
            "com.example", "mylib", "1.0-SNAPSHOT", files, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("1.0-SNAPSHOT", doc.Root.Element("version")!.Value);
        var snapshot = versioning.Element("snapshot")!;
        Assert.Equal("20240101.120000", snapshot.Element("timestamp")!.Value);
        Assert.Equal("3", snapshot.Element("buildNumber")!.Value);

        var snapshotVersions = versioning.Element("snapshotVersions")!.Elements("snapshotVersion").ToList();
        Assert.Equal(2, snapshotVersions.Count);
        Assert.Contains(snapshotVersions, sv =>
            sv.Element("extension")!.Value == "jar" &&
            sv.Element("value")!.Value == "1.0-20240101.120000-3");
        Assert.Contains(snapshotVersions, sv =>
            sv.Element("extension")!.Value == "pom" &&
            sv.Element("value")!.Value == "1.0-20240101.120000-3");
    }

    [Fact]
    public void BuildSnapshotVersion_NewestBuild_DrivesTopLevelSnapshotElement()
    {
        // Pins the bug: the old code emitted no <snapshot> block at all, so a client resolving
        // multiple published builds under one SNAPSHOT version could not tell which is newest.
        // The top-level <snapshot> must reflect the highest buildNumber, not publish order.
        var files = new[]
        {
            new MavenSnapshotFile(null, "jar", "20240101.120000", 1, Stamp),
            new MavenSnapshotFile(null, "jar", "20240102.130000", 2, Stamp.AddMinutes(1)),
        };
        string xml = MavenMetadataBuilder.BuildSnapshotVersion(
            "com.example", "mylib", "1.0-SNAPSHOT", files, Stamp.AddMinutes(1));
        var doc = XDocument.Parse(xml);
        var snapshot = doc.Root!.Element("versioning")!.Element("snapshot")!;

        Assert.Equal("20240102.130000", snapshot.Element("timestamp")!.Value);
        Assert.Equal("2", snapshot.Element("buildNumber")!.Value);
    }

    [Fact]
    public void BuildSnapshotVersion_Classifier_IsEmittedWhenPresent()
    {
        var files = new[]
        {
            new MavenSnapshotFile("sources", "jar", "20240101.120000", 1, Stamp),
        };
        string xml = MavenMetadataBuilder.BuildSnapshotVersion(
            "com.example", "mylib", "1.0-SNAPSHOT", files, Stamp);
        var doc = XDocument.Parse(xml);
        var snapshotVersion = doc.Root!.Element("versioning")!.Element("snapshotVersions")!
            .Element("snapshotVersion")!;

        Assert.Equal("sources", snapshotVersion.Element("classifier")!.Value);
    }

    [Fact]
    public void BuildSnapshotVersion_NoClassifier_OmitsClassifierElement()
    {
        var files = new[] { new MavenSnapshotFile(null, "jar", "20240101.120000", 1, Stamp) };
        string xml = MavenMetadataBuilder.BuildSnapshotVersion(
            "com.example", "mylib", "1.0-SNAPSHOT", files, Stamp);
        var doc = XDocument.Parse(xml);
        var snapshotVersion = doc.Root!.Element("versioning")!.Element("snapshotVersions")!
            .Element("snapshotVersion")!;

        Assert.Null(snapshotVersion.Element("classifier"));
    }

    [Fact]
    public void BuildSnapshotVersion_OnlyLiteralFiles_OmitsSnapshotAndSnapshotVersions()
    {
        // A file published under the literal "-SNAPSHOT" filename carries no deploy
        // timestamp/buildNumber — nothing to report in <snapshot>/<snapshotVersions>. The
        // client still resolves it by requesting the literal filename directly.
        var files = new[] { new MavenSnapshotFile(null, "jar", null, null, Stamp) };
        string xml = MavenMetadataBuilder.BuildSnapshotVersion(
            "com.example", "mylib", "1.0-SNAPSHOT", files, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Null(versioning.Element("snapshot"));
        Assert.Null(versioning.Element("snapshotVersions"));
    }

    [Fact]
    public void BuildSnapshotVersion_MixedLiteralAndTimestamped_ExcludesLiteralFromBuildSelection()
    {
        // Mixed partial scenario: one file has a resolvable deploy timestamp, the other was
        // published under the literal filename. Only the timestamped file drives <snapshot>
        // and appears in <snapshotVersions>.
        var files = new[]
        {
            new MavenSnapshotFile(null, "jar", null, null, Stamp),
            new MavenSnapshotFile(null, "pom", "20240101.120000", 5, Stamp),
        };
        string xml = MavenMetadataBuilder.BuildSnapshotVersion(
            "com.example", "mylib", "1.0-SNAPSHOT", files, Stamp);
        var doc = XDocument.Parse(xml);
        var versioning = doc.Root!.Element("versioning")!;

        Assert.Equal("5", versioning.Element("snapshot")!.Element("buildNumber")!.Value);
        var snapshotVersions = versioning.Element("snapshotVersions")!.Elements("snapshotVersion").ToList();
        Assert.Single(snapshotVersions);
        Assert.Equal("pom", snapshotVersions[0].Element("extension")!.Value);
    }
}
