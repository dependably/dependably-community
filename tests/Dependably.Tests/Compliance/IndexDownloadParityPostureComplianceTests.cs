using System.Text;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins, per ecosystem, whether its version-listing surface consults the block gate — and, where it
/// does not, that the reason is recorded rather than merely true.
///
/// <para>
/// <c>ARCH-block-gate</c> states the invariant this exists to protect: <em>a registry must never
/// advertise a version its download path will 403</em>. That claim was false on eight of eleven
/// ecosystems, and it stayed false for months because nothing made it observable — every download
/// path was gated, every index was not, and both facts were individually unremarkable. The
/// asymmetry was only visible to someone who went looking for it.
/// </para>
///
/// <para>
/// This gate makes the answer per-ecosystem and explicit, so removing a listing filter flips an
/// entry here and the build says so. It deliberately asserts the WIRING, not the verdict: whether
/// each arm reaches the right decision is the behavioural tests' job, and duplicating that here
/// would only add a second thing to update when policy changes.
/// </para>
///
/// <para>
/// The coverage column matters as much as the boolean. A listing filter can only apply the arms
/// whose facts exist for the coordinate it is about to advertise, and what exists differs by plane
/// and by ecosystem — so "filters its index" is not one property. An ecosystem that gates rows it
/// holds but cannot decide an upstream-only coordinate is in a different position from one that can
/// do neither, and recording only the first bit would flatten a real distinction into a green tick.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class IndexDownloadParityPostureComplianceTests
{
    private readonly ITestOutputHelper _output;
    public IndexDownloadParityPostureComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// The recorded posture.
    ///
    /// <para><c>GatesItsIndex</c>: <c>true</c> = the listing surface consults the block gate for
    /// versions this org holds on either plane. <c>false</c> = it does not, and
    /// <c>Rationale</c> must say why that is a decision rather than an omission.</para>
    ///
    /// <para><c>GatesUpstreamOnlyEntries</c>: <c>true</c> = the surface can also decide a
    /// coordinate that exists only in an upstream's metadata, which requires that metadata to carry
    /// a publish timestamp or a deprecation marker. Meaningful only where the ecosystem merges
    /// upstream entries into its listing at all.</para>
    /// </summary>
    private static readonly ParityEntry[] Posture =
    [
        new("npm", "Api/Npm/NpmPackumentHandler.cs", true, true,
            "The packument carries time[] and a per-version deprecated marker, so an upstream-only "
            + "version is decidable without fetching it. npm established this shape."),

        new("pypi", "Api/PyPi/PyPiSimpleIndexHelper.cs", true, true,
            "PEP 503 HTML carries no dates, so the index fetch negotiates PEP 691 for its PEP 700 "
            + "upload-time and PEP 592 yanked. An upstream that answers only HTML leaves entries "
            + "dateless and the release-age arm fails open on them, which is the gate's own posture "
            + "for an unknown publish time."),

        new("nuget", "Api/NuGet/NuGetRegistrationHelpers.cs", true, true,
            "Registration leaves carry catalogEntry.published and listed. The flat-container "
            + "version list is upstream-unfilterable — that document is bare version strings with "
            + "no per-version metadata — so registration is where parity is achievable, and a "
            + "client resolving through flat-container alone is gated at first fetch."),

        new("maven", "Api/MavenController.Metadata.cs", true, false,
            "maven-metadata.xml carries only a document-level lastUpdated, and Maven's publish date "
            + "is observed solely as a Last-Modified header on an artifact fetch, so an upstream "
            + "version this org has never cached carries no fact to decide."),

        new("rpm", "Storage/RpmRepodataService.cs", true, false,
            "Upstream primary.xml supplies NEVRA and a checksum but no policy state, so merged-mode "
            + "upstream packages cannot be decided at index time. The local filter lives in the "
            + "shared row loader so all five documents and their packages=\"N\" counts describe one "
            + "filtered set."),

        new("go", "Api/GoController.cs", true, false,
            "@v/list is local-only — there is no upstream version list to merge — so there is no "
            + "upstream-only case here. @latest proxies upstream verbatim when nothing is cached."),

        new("cargo", "Api/CargoController.Serve.cs", true, false,
            "A crates.io sparse-index line carries name/vers/deps/cksum/features/yanked and no "
            + "timestamp or policy state, so an upstream-only version is undecidable at index time."),

        new("terraform", "Api/TerraformController.cs", true, false,
            "The registry protocol publishes a per-version publish date, but only from a "
            + "per-version document — one upstream round-trip per version — so screening a whole "
            + "upstream list at index time is not affordable."),

        new("oci", "Api/OciController.Tags.cs", false, false,
            "The tag list is a namespace listing, not a servable-artifact listing: a tag is a "
            + "mutable pointer whose digest can change between the listing and the pull, so a "
            + "verdict computed at list time would describe a different artifact than the one "
            + "fetched. OCI gates the manifest and blob paths instead, and applies release-age as a "
            + "tag-PROMOTION gate keyed on when a digest was first seen."),

        new("apk", "Api/ApkController.cs", false, false,
            "The index is upstream APKINDEX.tar.gz streamed verbatim and signature-verified against "
            + "the org's RSA trust anchors before serving. Any rewrite invalidates the signature the "
            + "client itself checks, so this index is ungateable by construction — not merely "
            + "unimplemented. APK is gated at download."),
    ];

    private sealed record ParityEntry(
        string Ecosystem,
        string ListingSource,
        bool GatesItsIndex,
        bool GatesUpstreamOnlyEntries,
        string Rationale);

    // Any of these in the listing source means the block gate is consulted there. Three spellings
    // because the planes carry their facts differently: stored PV rows, global-plane cache rows,
    // and the upstream-only projection that has no row at all.
    private static readonly string[] GateMarkers =
    [
        "IsHardBlockedByStoredState",
        "IsHardBlockedByCacheEntry",
        "VersionFacts.ForUpstreamOnly",
        "BlockGateService.Evaluate(",
    ];

    private const string UpstreamOnlyMarker = "VersionFacts.ForUpstreamOnly";

    [Fact]
    public void EachEcosystemsListingSurface_MatchesItsRecordedParityPosture()
    {
        var files = SourceRoots.AllCSharpFiles().ToList();
        var failures = new StringBuilder();
        int scanned = 0;

        foreach (var entry in Posture)
        {
            string? path = files.FirstOrDefault(
                f => f.Replace('\\', '/').EndsWith(entry.ListingSource, StringComparison.Ordinal));
            if (path is null)
            {
                failures.AppendLine(
                    $"{entry.Ecosystem}: listing source '{entry.ListingSource}' not found. If the file moved, "
                    + "update this entry — a posture pointing at nothing reads as recorded while checking nothing.");
                continue;
            }

            scanned++;
            string source = File.ReadAllText(path);
            bool gates = GateMarkers.Any(m => source.Contains(m, StringComparison.Ordinal));
            if (gates != entry.GatesItsIndex)
            {
                failures.AppendLine(
                    $"{entry.Ecosystem}: recorded GatesItsIndex={entry.GatesItsIndex} but {entry.ListingSource} "
                    + $"{(gates ? "does" : "does not")} consult the block gate. "
                    + "If this is deliberate, change the entry AND its rationale; if not, this is the "
                    + "advertise-then-403 asymmetry the entry exists to prevent.");
            }

            bool upstream = source.Contains(UpstreamOnlyMarker, StringComparison.Ordinal);
            if (upstream != entry.GatesUpstreamOnlyEntries)
            {
                failures.AppendLine(
                    $"{entry.Ecosystem}: recorded GatesUpstreamOnlyEntries={entry.GatesUpstreamOnlyEntries} but "
                    + $"{entry.ListingSource} {(upstream ? "does" : "does not")} project upstream-only facts via "
                    + $"{UpstreamOnlyMarker}.");
            }
        }

        // A posture table whose files all moved would otherwise pass while checking nothing.
        Assert.True(scanned >= Posture.Length - 1,
            $"Only {scanned} of {Posture.Length} listing sources were readable — the scan is not covering what it claims.");

        _output.WriteLine($"Scanned {scanned} listing surfaces across {Posture.Length} ecosystems.");
        Assert.True(failures.Length == 0, failures.ToString());
    }

    /// <summary>
    /// An ecosystem that does not gate its index must say why. The rationale is the whole value of a
    /// <c>false</c> entry: without one, the table records that something is not done without
    /// recording that anyone decided it, which is indistinguishable from the oversight this gate
    /// exists to surface.
    /// </summary>
    [Fact]
    public void EveryUngatedSurface_RecordsWhy()
    {
        var failures = new StringBuilder();

        foreach (var entry in Posture.Where(e => !e.GatesItsIndex || !e.GatesUpstreamOnlyEntries))
        {
            if (entry.Rationale.Length < 40)
            {
                failures.AppendLine(
                    $"{entry.Ecosystem}: has an ungated dimension but its rationale is too short to be one. "
                    + "State what the listing surface cannot know, not that it does not gate.");
            }
        }

        Assert.True(failures.Length == 0, failures.ToString());
    }
}
