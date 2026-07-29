using System.Reflection;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Cross-replica rendered-metadata invalidation, exercised through the same
/// <see cref="MetadataCacheKeys"/> formatters the render path reads with.
///
/// <para>Every eviction assertion is made twice: the entry that must go, and a neighbour that
/// must stay. An over-broad invalidation that flushed the whole cache would satisfy a naive
/// "the entry is gone" test while destroying the cache's reason to exist, so each ecosystem
/// gets a same-cache survivor — a different package, a different org, or the sibling variant
/// that a mutation genuinely does not touch.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetadataInvalidationCoordinatorTests
{
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    // ── npm: local + proxy, and nothing else ──────────────────────────────────

    [Fact]
    public void Npm_EvictsBothLocalAndProxyVariants()
    {
        var h = TestMetadataInvalidation.Build();
        var local = new NpmPackumentKey(OrgA, "@scope/pkg");
        var proxy = new NpmPackumentKey(OrgA, "@scope/pkg") { IsProxy = true };
        h.Npm.Set(local, [1], Ttl);
        h.Npm.Set(proxy, [2], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForNpm(OrgA, "@scope/pkg"));

        Assert.False(h.Npm.TryGet(local, out _));
        Assert.False(h.Npm.TryGet(proxy, out _));
    }

    [Fact]
    public void Npm_LeavesOtherPackagesAndOtherOrgsIntact()
    {
        var h = TestMetadataInvalidation.Build();
        var neighbour = new NpmPackumentKey(OrgA, "@scope/other");
        var neighbourProxy = new NpmPackumentKey(OrgA, "@scope/other") { IsProxy = true };
        var otherOrg = new NpmPackumentKey(OrgB, "@scope/pkg");
        h.Npm.Set(new NpmPackumentKey(OrgA, "@scope/pkg"), [1], Ttl);
        h.Npm.Set(neighbour, [2], Ttl);
        h.Npm.Set(neighbourProxy, [3], Ttl);
        h.Npm.Set(otherOrg, [4], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForNpm(OrgA, "@scope/pkg"));

        Assert.True(h.Npm.TryGet(neighbour, out _));
        Assert.True(h.Npm.TryGet(neighbourProxy, out _));
        Assert.True(h.Npm.TryGet(otherOrg, out _));
    }

    /// <summary>
    /// npm's rendered packument is not content-negotiated: the full and abbreviated
    /// ("corgi", <c>application/vnd.npm.install-v1+json</c>) documents are distinguished inside
    /// the upstream-fetch cache, keyed by URL + Accept, not in the rendered-response cache. This
    /// pins that assumption — if a rendered corgi variant is ever introduced it must appear as a
    /// new axis on the key record, which this assertion makes fail loudly rather than silently
    /// leaving an un-evicted representation behind.
    /// </summary>
    [Fact]
    public void NpmPackumentKey_HasExactlyOneVariantAxis()
        => AssertVariantAxes<NpmPackumentKey>("IsProxy");

    // ── PyPI: HTML + JSON, with PEP 503 normalization ─────────────────────────

    [Fact]
    public void PyPi_EvictsBothNegotiatedRepresentations()
    {
        var h = TestMetadataInvalidation.Build();
        var html = new PyPiSimpleIndexKey(OrgA, "My_Package");
        var json = new PyPiSimpleIndexKey(OrgA, "My_Package") { WantsJson = true };
        h.PyPi.Set(html, [1], Ttl);
        h.PyPi.Set(json, [2], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForPyPi(OrgA, "My_Package"));

        Assert.False(h.PyPi.TryGet(html, out _));
        Assert.False(h.PyPi.TryGet(json, out _));
    }

    /// <summary>
    /// The render path caches under the PEP 503-normalized name, so an invalidation naming a
    /// different spelling of the same project must still hit it — otherwise a <c>my_package</c>
    /// upload leaves the <c>my-package</c> index stale.
    /// </summary>
    [Fact]
    public void PyPi_NormalizesNameSoAlternateSpellingsHitTheSameEntry()
    {
        var h = TestMetadataInvalidation.Build();
        var cached = new PyPiSimpleIndexKey(OrgA, "my-package");
        h.PyPi.Set(cached, [1], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForPyPi(OrgA, "My_Package"));

        Assert.False(h.PyPi.TryGet(cached, out _));
    }

    [Fact]
    public void PyPi_LeavesOtherProjectsIntact()
    {
        var h = TestMetadataInvalidation.Build();
        var neighbour = new PyPiSimpleIndexKey(OrgA, "other-package");
        var neighbourJson = new PyPiSimpleIndexKey(OrgA, "other-package") { WantsJson = true };
        h.PyPi.Set(new PyPiSimpleIndexKey(OrgA, "my-package"), [1], Ttl);
        h.PyPi.Set(neighbour, [2], Ttl);
        h.PyPi.Set(neighbourJson, [3], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForPyPi(OrgA, "my-package"));

        Assert.True(h.PyPi.TryGet(neighbour, out _));
        Assert.True(h.PyPi.TryGet(neighbourJson, out _));
    }

    [Fact]
    public void PyPiSimpleIndexKey_HasExactlyOneVariantAxis()
        => AssertVariantAxes<PyPiSimpleIndexKey>("WantsJson");

    // ── NuGet: SemVer1/2 x local/proxy ────────────────────────────────────────

    [Fact]
    public void NuGet_EvictsAllFourVariants()
    {
        var h = TestMetadataInvalidation.Build();
        var keys = NuGetVariants(OrgA, "contoso.utils");
        foreach (var key in keys)
        {
            h.NuGet.Set(key, [1], Ttl);
        }

        // Mixed-case id: the registration key holds the lower-cased (normalized PURL) form.
        h.Coordinator.Invalidate(MetadataInvalidation.ForNuGet(OrgA, "Contoso.Utils"));

        Assert.All(keys, key => Assert.False(h.NuGet.TryGet(key, out _)));
    }

    [Fact]
    public void NuGet_LeavesOtherIdsIntact()
    {
        var h = TestMetadataInvalidation.Build();
        var survivors = NuGetVariants(OrgA, "contoso.other");
        foreach (var key in NuGetVariants(OrgA, "contoso.utils").Concat(survivors))
        {
            h.NuGet.Set(key, [1], Ttl);
        }

        h.Coordinator.Invalidate(MetadataInvalidation.ForNuGet(OrgA, "contoso.utils"));

        Assert.All(survivors, key => Assert.True(h.NuGet.TryGet(key, out _)));
    }

    [Fact]
    public void NuGetRegistrationKey_HasExactlyTwoVariantAxes()
        => AssertVariantAxes<NuGetRegistrationKey>("SemVer2", "IsProxy");

    // ── Maven: artifact-level always, version-level only for a SNAPSHOT ────────

    [Fact]
    public void Maven_SnapshotPublishEvictsArtifactLevelAndVersionLevelDocuments()
    {
        var h = TestMetadataInvalidation.Build();
        var artifactLevel = new MavenMetadataKey(OrgA, "com.example", "widget");
        var versionLevel = new MavenMetadataKey(OrgA, "com.example", "widget", "1.0-SNAPSHOT");
        h.Maven.Set(artifactLevel, [1], Ttl);
        h.Maven.Set(versionLevel, [2], Ttl);

        h.Coordinator.Invalidate(
            MetadataInvalidation.ForMaven(OrgA, "com.example", "widget", "1.0-SNAPSHOT"));

        Assert.False(h.Maven.TryGet(artifactLevel, out _));
        Assert.False(h.Maven.TryGet(versionLevel, out _));
    }

    /// <summary>
    /// A release publish changes the version list but no snapshot build list, so the
    /// version-level document of an unrelated in-flight SNAPSHOT must survive. The adversarial
    /// twin of the test above: "evict everything under this artifact" would pass that one and
    /// fail this.
    /// </summary>
    [Fact]
    public void Maven_ReleasePublishLeavesUnrelatedSnapshotVersionDocumentIntact()
    {
        var h = TestMetadataInvalidation.Build();
        var artifactLevel = new MavenMetadataKey(OrgA, "com.example", "widget");
        var snapshotDoc = new MavenMetadataKey(OrgA, "com.example", "widget", "2.0-SNAPSHOT");
        h.Maven.Set(artifactLevel, [1], Ttl);
        h.Maven.Set(snapshotDoc, [2], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForMaven(OrgA, "com.example", "widget"));

        Assert.False(h.Maven.TryGet(artifactLevel, out _));
        Assert.True(h.Maven.TryGet(snapshotDoc, out _));
    }

    [Fact]
    public void Maven_LeavesOtherCoordinatesIntact()
    {
        var h = TestMetadataInvalidation.Build();
        var sameGroupOtherArtifact = new MavenMetadataKey(OrgA, "com.example", "gadget");
        var otherGroupSameArtifact = new MavenMetadataKey(OrgA, "com.other", "widget");
        h.Maven.Set(new MavenMetadataKey(OrgA, "com.example", "widget"), [1], Ttl);
        h.Maven.Set(sameGroupOtherArtifact, [2], Ttl);
        h.Maven.Set(otherGroupSameArtifact, [3], Ttl);

        h.Coordinator.Invalidate(MetadataInvalidation.ForMaven(OrgA, "com.example", "widget"));

        Assert.True(h.Maven.TryGet(sameGroupOtherArtifact, out _));
        Assert.True(h.Maven.TryGet(otherGroupSameArtifact, out _));
    }

    // ── RPM: every local document type + the merged tuple, tenant-wide ─────────

    [Fact]
    public void Rpm_EvictsEveryLocalDocumentTypeAndTheMergedTuple()
    {
        var h = TestMetadataInvalidation.Build();
        foreach (string docType in MetadataCacheKeys.RpmRepodataDocTypes)
        {
            h.RpmLocal.Set(new RpmLocalRepodataKey(OrgA, docType), [1], Ttl);
        }

        h.RpmMerged.Set(new RpmMergedRepodataKey(OrgA), MergedFixture(), Ttl, size: 8);

        h.Coordinator.Invalidate(MetadataInvalidation.ForRpm(OrgA));

        Assert.All(
            MetadataCacheKeys.RpmRepodataDocTypes,
            docType => Assert.False(h.RpmLocal.TryGet(new RpmLocalRepodataKey(OrgA, docType), out _)));
        Assert.False(h.RpmMerged.TryGet(new RpmMergedRepodataKey(OrgA), out _));
    }

    [Fact]
    public void Rpm_LeavesAnotherTenantsRepodataIntact()
    {
        var h = TestMetadataInvalidation.Build();
        h.RpmLocal.Set(new RpmLocalRepodataKey(OrgA, "primary"), [1], Ttl);
        h.RpmLocal.Set(new RpmLocalRepodataKey(OrgB, "primary"), [2], Ttl);
        h.RpmMerged.Set(new RpmMergedRepodataKey(OrgB), MergedFixture(), Ttl, size: 8);

        h.Coordinator.Invalidate(MetadataInvalidation.ForRpm(OrgA));

        Assert.True(h.RpmLocal.TryGet(new RpmLocalRepodataKey(OrgB, "primary"), out _));
        Assert.True(h.RpmMerged.TryGet(new RpmMergedRepodataKey(OrgB), out _));
    }

    /// <summary>
    /// The document-type list is the one the render path enumerates. A fourth repodata document
    /// added to <see cref="MetadataCacheKeys.RpmRepodataDocTypes"/> is picked up by the
    /// coordinator automatically; this pins the list itself so the set cannot shrink unnoticed.
    /// </summary>
    [Fact]
    public void Rpm_DocumentTypeListIsTheFullRepodataSet()
        => Assert.Equal(
            new[] { "primary", "filelists", "other" }, MetadataCacheKeys.RpmRepodataDocTypes.ToArray());

    // ── One ecosystem's invalidation never touches another's cache ────────────

    [Fact]
    public void InvalidatingOneEcosystemLeavesEveryOtherEcosystemIntact()
    {
        var h = TestMetadataInvalidation.Build();
        SeedOneEntryPerEcosystem(h);

        h.Coordinator.Invalidate(MetadataInvalidation.ForNpm(OrgA, "pkg"));

        Assert.False(h.Npm.TryGet(new NpmPackumentKey(OrgA, "pkg"), out _));
        Assert.True(h.PyPi.TryGet(new PyPiSimpleIndexKey(OrgA, "pkg"), out _));
        Assert.True(h.NuGet.TryGet(new NuGetRegistrationKey(OrgA, "pkg", SemVer2: false), out _));
        Assert.True(h.Maven.TryGet(new MavenMetadataKey(OrgA, "com.example", "pkg"), out _));
        Assert.True(h.RpmLocal.TryGet(new RpmLocalRepodataKey(OrgA, "primary"), out _));
    }

    // ── Publishing side: the push broadcasts the coordinates ──────────────────

    [Fact]
    public void Invalidate_PublishesTheCoordinatesExactlyOnce()
    {
        var bus = new RecordingMetadataInvalidationBus();
        var h = TestMetadataInvalidation.Build(bus: bus);

        h.Coordinator.Invalidate(MetadataInvalidation.ForNpm(OrgA, "@scope/pkg"));
        h.Coordinator.Invalidate(MetadataInvalidation.ForMaven(OrgA, "com.example", "widget", "1.0-SNAPSHOT"));

        Assert.Collection(
            bus.Published,
            npm =>
            {
                Assert.Equal(MetadataInvalidationEcosystems.Npm, npm.Ecosystem);
                Assert.Equal(OrgA, npm.OrgId);
                Assert.Equal("@scope/pkg", npm.Name);
            },
            maven =>
            {
                Assert.Equal(MetadataInvalidationEcosystems.Maven, maven.Ecosystem);
                Assert.Equal("com.example", maven.GroupId);
                Assert.Equal("widget", maven.ArtifactId);
                Assert.Equal("1.0-SNAPSHOT", maven.Version);
            });
    }

    /// <summary>
    /// The subscriber path must not re-broadcast, or two replicas ping-pong the same message
    /// around the channel forever.
    /// </summary>
    [Fact]
    public void EvictLocal_DoesNotBroadcast()
    {
        var bus = new RecordingMetadataInvalidationBus();
        var h = TestMetadataInvalidation.Build(bus: bus);
        h.Npm.Set(new NpmPackumentKey(OrgA, "pkg"), [1], Ttl);

        h.Coordinator.EvictLocal(MetadataInvalidation.ForNpm(OrgA, "pkg"));

        Assert.False(h.Npm.TryGet(new NpmPackumentKey(OrgA, "pkg"), out _));
        Assert.Empty(bus.Published);
    }

    // ── Degrade-to-TTL: a failing transport never fails the mutation ──────────

    /// <summary>
    /// A bus that throws stands in for an unreachable broker at the transport boundary. The
    /// mutation must still complete and must still evict locally: a missed fan-out is a staleness
    /// bug bounded by the TTL, never a failed push.
    /// </summary>
    [Fact]
    public void Invalidate_StillEvictsLocally_WhenTheTransportThrows()
    {
        var h = TestMetadataInvalidation.Build(bus: new ThrowingMetadataInvalidationBus());
        h.Npm.Set(new NpmPackumentKey(OrgA, "pkg"), [1], Ttl);

        var thrown = Record.Exception(() => h.Coordinator.Invalidate(MetadataInvalidation.ForNpm(OrgA, "pkg")));

        Assert.NotNull(thrown);
        Assert.False(h.Npm.TryGet(new NpmPackumentKey(OrgA, "pkg"), out _));
    }

    /// <summary>
    /// With no fan-out transport configured — the standalone deployment — the mutation path is
    /// unchanged: local eviction happens, nothing throws, and peers are simply not a concept.
    /// </summary>
    [Fact]
    public void StandaloneNullBus_EvictsLocallyAndNeverThrows()
    {
        var h = TestMetadataInvalidation.Build(bus: new NullMetadataInvalidationBus());
        h.PyPi.Set(new PyPiSimpleIndexKey(OrgA, "pkg"), [1], Ttl);

        var thrown = Record.Exception(() => h.Coordinator.Invalidate(MetadataInvalidation.ForPyPi(OrgA, "pkg")));

        Assert.Null(thrown);
        Assert.False(h.PyPi.TryGet(new PyPiSimpleIndexKey(OrgA, "pkg"), out _));
    }

    /// <summary>
    /// Standalone must take on no broker dependency at all. The invalidation abstraction and the
    /// coordinator live in Core, whose reference closure is the one the edge image ships — and it
    /// contains no Redis client.
    /// </summary>
    [Fact]
    public void CoreAssemblyReferencesNoRedisClient()
    {
        var referenced = typeof(MetadataInvalidationCoordinator).Assembly
            .GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToList();

        Assert.DoesNotContain("StackExchange.Redis", referenced);
    }

    // ── Fan-out convergence still bounded by the TTL when nothing arrives ─────

    /// <summary>
    /// The fallback behaviour a dropped broadcast degrades to, asserted at exact instants on a
    /// frozen clock: an entry written with the local TTL is live one tick before expiry and gone
    /// at expiry, with no invalidation involved. This is what a peer replica that never received
    /// the message relies on.
    /// </summary>
    [Fact]
    public void EntryWithoutAnInvalidationExpiresExactlyAtItsTtl()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero));
        using var memory = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 1024 * 1024,
            Clock = new FakeSystemClock(clock),
        });
        var cache = new RenderedResponseCache<NpmPackumentKey>(memory, MetadataCacheKeys.NpmPackument);
        var key = new NpmPackumentKey(OrgA, "pkg");
        cache.Set(key, [1], Ttl);

        clock.SetUtcNow(new DateTimeOffset(2026, 3, 1, 12, 9, 59, TimeSpan.Zero));
        Assert.True(cache.TryGet(key, out _));

        clock.SetUtcNow(new DateTimeOffset(2026, 3, 1, 12, 10, 0, TimeSpan.Zero));
        Assert.False(cache.TryGet(key, out _));
    }

    // ── Receiver: apply, ignore-own, tolerate-unknown ─────────────────────────

    [Fact]
    public void Receiver_EvictsTheMatchingEntryAndLeavesNonMatchingEntriesIntact()
    {
        var h = TestMetadataInvalidation.Build();
        var receiver = new MetadataInvalidationReceiver(
            h.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance);
        SeedOneEntryPerEcosystem(h);
        h.NuGet.Set(new NuGetRegistrationKey(OrgA, "survivor", SemVer2: false), [9], Ttl);

        string payload = MetadataInvalidationCodec.Encode(
            MetadataInvalidation.ForNuGet(OrgA, "pkg"), origin: "publisher-replica");

        Assert.True(receiver.Apply(payload, selfOrigin: "receiving-replica"));

        Assert.False(h.NuGet.TryGet(new NuGetRegistrationKey(OrgA, "pkg", SemVer2: false), out _));
        Assert.True(h.NuGet.TryGet(new NuGetRegistrationKey(OrgA, "survivor", SemVer2: false), out _));
        Assert.True(h.Npm.TryGet(new NpmPackumentKey(OrgA, "pkg"), out _));
        Assert.True(h.PyPi.TryGet(new PyPiSimpleIndexKey(OrgA, "pkg"), out _));
        Assert.True(h.Maven.TryGet(new MavenMetadataKey(OrgA, "com.example", "pkg"), out _));
        Assert.True(h.RpmLocal.TryGet(new RpmLocalRepodataKey(OrgA, "primary"), out _));
    }

    [Fact]
    public void Receiver_IgnoresAMessageThisReplicaPublishedItself()
    {
        var h = TestMetadataInvalidation.Build();
        var receiver = new MetadataInvalidationReceiver(
            h.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance);
        h.Npm.Set(new NpmPackumentKey(OrgA, "pkg"), [1], Ttl);
        string payload = MetadataInvalidationCodec.Encode(
            MetadataInvalidation.ForNpm(OrgA, "pkg"), origin: "self");

        Assert.False(receiver.Apply(payload, selfOrigin: "self"));

        // Not re-evicted: the publish path already did it before broadcasting. Proving the entry
        // was untouched requires it to still be there, which it is because the seed above ran
        // after no local invalidation.
        Assert.True(h.Npm.TryGet(new NpmPackumentKey(OrgA, "pkg"), out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("{\"v\":99,\"ecosystem\":\"npm\",\"org_id\":\"org-a\",\"name\":\"pkg\"}")]
    [InlineData("{\"v\":1,\"ecosystem\":\"conan\",\"org_id\":\"org-a\",\"name\":\"pkg\"}")]
    [InlineData("{\"v\":1,\"ecosystem\":\"npm\",\"name\":\"pkg\"}")]
    public void Receiver_DropsUndecodableMessagesWithoutThrowingOrEvicting(string? payload)
    {
        var h = TestMetadataInvalidation.Build();
        var receiver = new MetadataInvalidationReceiver(
            h.Coordinator, NullLogger<MetadataInvalidationReceiver>.Instance);
        h.Npm.Set(new NpmPackumentKey(OrgA, "pkg"), [1], Ttl);

        Assert.False(receiver.Apply(payload, selfOrigin: "self"));
        Assert.True(h.Npm.TryGet(new NpmPackumentKey(OrgA, "pkg"), out _));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static NuGetRegistrationKey[] NuGetVariants(string orgId, string normalizedId) =>
    [
        new(orgId, normalizedId, SemVer2: false),
        new(orgId, normalizedId, SemVer2: true),
        new(orgId, normalizedId, SemVer2: false) { IsProxy = true },
        new(orgId, normalizedId, SemVer2: true) { IsProxy = true },
    ];

    private static MergedRepodataCache MergedFixture() =>
        new([1, 2, 3, 4], [5, 6, 7, 8], []);

    private static void SeedOneEntryPerEcosystem(TestInvalidationHarness h)
    {
        h.Npm.Set(new NpmPackumentKey(OrgA, "pkg"), [1], Ttl);
        h.PyPi.Set(new PyPiSimpleIndexKey(OrgA, "pkg"), [1], Ttl);
        h.NuGet.Set(new NuGetRegistrationKey(OrgA, "pkg", SemVer2: false), [1], Ttl);
        h.Maven.Set(new MavenMetadataKey(OrgA, "com.example", "pkg"), [1], Ttl);
        h.RpmLocal.Set(new RpmLocalRepodataKey(OrgA, "primary"), [1], Ttl);
    }

    // Every boolean property on a cache-key record is a variant axis the coordinator has to
    // expand across. Pinning the axis set turns "someone added a third variant and forgot the
    // eviction" from a silent stale-cache bug into a red test.
    private static void AssertVariantAxes<TKey>(params string[] expected)
    {
        string[] axes = typeof(TKey)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(bool))
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(expected.OrderBy(n => n, StringComparer.Ordinal).ToArray(), axes);
    }

    // A transport that faults on every send — the "broker unreachable" stand-in at the seam
    // where the coordinator hands off. The Redis implementation swallows its own failures
    // (RedisMetadataInvalidationBusTests); this asserts the coordinator evicts before it
    // delegates, so a transport that somehow escapes still cannot leave the local cache stale.
    private sealed class ThrowingMetadataInvalidationBus : IMetadataInvalidationBus
    {
        public void Publish(MetadataInvalidation invalidation) =>
            throw new InvalidOperationException("broker unreachable");
    }

    // Bridges FakeTimeProvider into MemoryCache's own expiry checks so TTL assertions land on
    // exact instants rather than tolerances.
    private sealed class FakeSystemClock(TimeProvider time) : Microsoft.Extensions.Internal.ISystemClock
    {
        public DateTimeOffset UtcNow => time.GetUtcNow();
    }
}
