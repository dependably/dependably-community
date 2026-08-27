using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// The scan pass's tracker-enrichment step. Three properties live here and nowhere else, because
/// the client cannot enforce any of them:
///
/// <para>
/// <b>The outbound payload is a deduplicated union.</b> The scan sweeps every tenant's packages
/// plus the shared proxy cache, so one purl appears once per holder. Deduplicating before the
/// request leaves is what stops the tracker attributing a package to a tenant — a disclosure
/// property, not a saving.
/// </para>
///
/// <para>
/// <b>An unreached lookup stamps nothing.</b> The enrichment stamps are what enable the dependent
/// gate arms, so advancing one on an outage turns a fail-closed unknown into a pass.
/// </para>
///
/// <para>
/// <b>Absence is never withdrawal.</b> An advisory missing from a reached response leaves its
/// stored row alone; only an explicit negative status clears it.
/// </para>
/// </summary>
// The deferral test below attaches a MeterListener to the process-wide static meter, so the
// class runs alone — see MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class VulnTrackerScanEnrichmentTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Doubles ───────────────────────────────────────────────────────────────

    /// <summary>Records every purl list it is handed, so the dedup property can be asserted directly.</summary>
    private sealed class RecordingEnrichmentSource : IVulnerabilityEnrichmentSource
    {
        private readonly Func<IReadOnlyList<string>, VulnerabilityEnrichmentBatchResult> _answer;

        /// <summary>Purls per request, for the deduplication assertions.</summary>
        public List<IReadOnlyList<string>> Requests { get; } = [];

        /// <summary>Every target as sent, so the CVE hints can be asserted too.</summary>
        public List<EnrichmentLookupTarget> Targets { get; } = [];

        public RecordingEnrichmentSource(
            Func<IReadOnlyList<string>, VulnerabilityEnrichmentBatchResult> answer) => _answer = answer;

        public Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
            IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
        {
            Requests.Add([.. targets.Select(t => t.Purl)]);
            Targets.AddRange(targets);
            return Task.FromResult(_answer([.. targets.Select(t => t.Purl)]));
        }
    }

    private static VulnerabilityEnrichmentBatchResult Reached(
        IReadOnlyList<string> purls,
        params AdvisoryEnrichment[] advisories)
        => new(
            results: purls.Select(_ => (IReadOnlyList<AdvisoryEnrichment>)advisories).ToList(),
            reached: true,
            checkedAt: TestTime.KnownNow,
            freshness: [new EnrichmentSourceFreshness("nvd", TestTime.KnownNow.AddDays(-1)),
                        new EnrichmentSourceFreshness("vulnrichment", TestTime.KnownNow.AddDays(-2))],
            reason: EnrichmentUnreachedReason.None);

    private static VulnerabilityEnrichmentBatchResult Unreached(IReadOnlyList<string> purls)
        => new(
            results: purls.Select(_ => (IReadOnlyList<AdvisoryEnrichment>)[]).ToList(),
            reached: false,
            checkedAt: null,
            freshness: [],
            reason: EnrichmentUnreachedReason.RateLimited);

    private static AdvisoryEnrichment Enriched(
        string id, string cve, EnrichmentAdvisoryStatus status = EnrichmentAdvisoryStatus.Active)
        => new(id, cve, status, new NvdBand("HIGH", 8.1), new SsvcDecision("active", "yes", "total"));

    private static IOsvSource OsvWith(params string[] cveAliases) =>
        TestOsvSource.Create(_ =>
        [
            new("GHSA-test-0001", cveAliases, "test advisory", "HIGH",
                CvssScore: 8.1, AffectedPackages: [], Published: null, Modified: null,
                IsHydrated: true),
        ]);

    // ── Harness ───────────────────────────────────────────────────────────────

    private VulnerabilityScanService BuildService(
        IOsvSource osv,
        IVulnerabilityEnrichmentSource enrichment,
        Dependably.Infrastructure.VulnTracker.InstanceVulnTrackerConfig tracker)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VULN_SCAN_BATCH_DELAY_MS"] = "0",
                ["VULN_RESCAN_AGE_HOURS"] = "24",
            })
            .Build();
        return new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, new VulnerabilityRepository(_db, _clock), new AuditRepository(_db),
            config, new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, _clock),
            new SbomComponentVulnRepository(_db, _clock),
            new SbomComponentScanner(osv, new VulnerabilityRepository(_db, _clock),
                new SbomComponentVulnRepository(_db, _clock), NullLogger<SbomComponentScanner>.Instance),
            TestSbomPolicy.Service(_db, _clock),
            enrichment,
            tracker));
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    /// <summary>Seeds one proxy-cache artefact — the global arm, so no org plumbing is needed.</summary>
    private async Task<string> SeedArtifactAsync(string name, string version = "1.0.0")
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@id, 'npm', @name, @version, @filename, @blobKey, @hash, 0, @purl)
            """,
            new
            {
                id,
                name,
                version,
                filename = $"{name}-{version}.tgz",
                blobKey = $"proxy/npm/{name}/{version}/{name}-{version}.tgz",
                hash = $"sha256:{Guid.NewGuid():N}",
                purl = $"pkg:npm/{name}@{version}",
            });
        return id;
    }

    /// <summary>
    /// Seeds the SAME purl under <paramref name="tenants"/> separate orgs. This is the plane the
    /// disclosure property is actually about: <c>cache_artifact</c> is one globally-unique row per
    /// artefact, so dedup there is structural and proves nothing, whereas <c>package_versions</c>
    /// legitimately carries one row per holding tenant.
    /// </summary>
    private async Task SeedSamePurlAcrossTenantsAsync(string name, int tenants)
    {
        for (int i = 0; i < tenants; i++)
        {
            string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
            string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", name);
            await PackageSeeder.InsertVersionAsync(
                _db, pkgId, "1.0.0", $"pkg:npm/{name}@1.0.0", blobKey: $"blob/{Guid.NewGuid():N}");
        }
    }

    /// <summary>The overlay columns for one advisory. A named shape rather than a tuple so the
    /// call sites read as assertions about fields, not about positions.</summary>
    private sealed record EnrichmentRow(
        string? NvdSeverity, double? NvdScore, string? NvdCheckedAt, string? NvdAssertedAt, string? SsvcExploitation);

    private async Task<EnrichmentRow> ReadEnrichmentAsync(string osvId)
    {
        await using var conn = await _db.OpenAsync();
        var (severity, score, checkedAt, assertedAt, exploitation) =
            await conn.QuerySingleAsync<(string?, double?, string?, string?, string?)>(
                """
                SELECT nvd_severity, nvd_score, nvd_checked_at, nvd_asserted_at, ssvc_exploitation
                FROM vulnerabilities WHERE osv_id = @osvId
                """,
                new { osvId });
        return new EnrichmentRow(severity, score, checkedAt, assertedAt, exploitation);
    }

    // ── The feature is off unless configured ─────────────────────────────────

    [Fact]
    public async Task NoConnectionConfigured_MakesNoRequestAtAll()
    {
        // TestEnrichment.Unused() throws if called. The assertion is that the pass completes:
        // "off" must mean no request, not a request whose result is discarded.
        await SeedArtifactAsync("lodash");

        await BuildService(OsvWith("CVE-2024-0001"), TestEnrichment.Unused(), TestEnrichment.NoConnection())
            .RunScanPassAsync(CancellationToken.None);

        var row = await ReadEnrichmentAsync("GHSA-test-0001");
        Assert.Null(row.NvdCheckedAt);
        Assert.Null(row.NvdSeverity);
    }

    [Fact]
    public async Task ConfiguredConnection_EnrichesTheAdvisory()
    {
        // The twin for every negative below: with a connection configured and a reached answer,
        // enrichment must actually land — otherwise a passing "does nothing" test would be
        // equally consistent with the feature being wired up wrong.
        await SeedArtifactAsync("lodash");
        var source = new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001")));

        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var row = await ReadEnrichmentAsync("GHSA-test-0001");
        Assert.Equal("HIGH", row.NvdSeverity);
        Assert.Equal(8.1, row.NvdScore);
        Assert.Equal("active", row.SsvcExploitation);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), row.NvdCheckedAt);
        // The producer's asserted as-of is stored beside our own stamp, not instead of it.
        Assert.Equal(TestTime.KnownNow.AddDays(-1).ToUtcIso(), row.NvdAssertedAt);
    }

    // ── The disclosure property ──────────────────────────────────────────────

    [Fact]
    public async Task ThePayloadIsADeduplicatedUnion_NotOneHolderPerPurl()
    {
        // Ten artefacts, one purl. The scan visits every row; the tracker must see the package
        // once. This is the attribution boundary the design's privacy argument rests on — the
        // producer learns the deployment holds it, and cannot count or attribute holders.
        await SeedSamePurlAcrossTenantsAsync("lodash", tenants: 10);

        var source = new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001")));
        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var sent = source.Requests.SelectMany(r => r).ToList();
        Assert.Equal(sent.Distinct(StringComparer.Ordinal).Count(), sent.Count);
        Assert.Single(sent);
    }

    [Fact]
    public async Task AnAdvisoryAlreadyResolvedThisPass_IsNotAskedAboutAgain()
    {
        // Two different packages carrying the same advisory: the overlay is a fact about the CVE,
        // so the second package adds nothing to ask about.
        await SeedArtifactAsync("lodash");
        await SeedArtifactAsync("underscore");

        var source = new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001")));
        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.Single(source.Requests.SelectMany(r => r));
    }

    [Fact]
    public async Task AdvisoriesWithNoCveAlias_AreNeverQueried()
    {
        // npm malware records carry no CVE, so NVD and Vulnrichment have nothing for them by
        // construction. Asking would spend a request on a knowably empty answer.
        await SeedArtifactAsync("evil-pkg");

        await BuildService(OsvWith(), TestEnrichment.Unused(), TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        // Unused() throws if called; reaching here is the assertion.
        Assert.Null((await ReadEnrichmentAsync("GHSA-test-0001")).NvdCheckedAt);
    }

    // ── CVE hints ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task ThePurlCarriesTheCvesTheScanAlreadyResolved()
    {
        // The producer resolves purl -> advisory through its own OSV corpus, which covers four
        // ecosystems, while its NVD mirror and Vulnrichment are ecosystem-agnostic. Without the
        // hints a Cargo, Go or Alpine purl comes back empty even though the enrichment is held,
        // so the overlay would be permanently dark for five of the nine ecosystems dependably
        // proxies — silently, because an empty answer is indistinguishable from "nothing known".
        await SeedArtifactAsync("lodash");
        var source = new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001")));

        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var target = Assert.Single(source.Targets);
        Assert.Equal("pkg:npm/lodash@1.0.0", target.Purl);
        Assert.Equal(["CVE-2024-0001"], target.Cves);
    }

    [Fact]
    public async Task OnlyCveAliasesAreSentAsHints()
    {
        // The twin: a GHSA id or any other alias is not a CVE, and the producer's hint lookup is
        // keyed by canonical CVE. Sending non-CVE aliases would be noise the producer cannot use.
        await SeedArtifactAsync("lodash");
        var source = new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001")));

        await BuildService(
                TestOsvSource.Create(_ =>
                [
                    new("GHSA-test-0001", ["CVE-2024-0001", "GHSA-aaaa-bbbb-cccc", "OSV-2024-1"],
                        "adv", "HIGH", 8.1, [], null, null, IsHydrated: true),
                ]),
                source,
                TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.Equal(["CVE-2024-0001"], Assert.Single(source.Targets).Cves);
    }

    // ── Never degrade to a false "checked" ───────────────────────────────────

    [Fact]
    public async Task UnreachedTracker_StampsNothing()
    {
        await SeedArtifactAsync("lodash");
        var source = new RecordingEnrichmentSource(Unreached);

        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        var row = await ReadEnrichmentAsync("GHSA-test-0001");
        Assert.Null(row.NvdCheckedAt);
        Assert.Null(row.NvdAssertedAt);
        Assert.Null(row.NvdSeverity);
    }

    [Fact]
    public async Task UnreachedTracker_RecordsTheDeferralSoAnOutageIsVisible()
    {
        // This is what the scan-level Reached check actually buys, and the reason it is not
        // redundant with the client's own guard.
        //
        // The end-to-end "nothing is stamped" property above is genuinely enforced twice: the
        // batch result's own Decide() returns NoSignal for every lookup against an unreached
        // result, so removing this service's check does NOT make that test fail — verified by
        // mutation. What removing it *does* destroy is the operator signal: an outage would then
        // look exactly like a pass where every advisory happened to be absent from the response.
        // A silent enrichment outage is precisely the state the staleness horizon exists to catch
        // late; the counter is what catches it early.
        long deferred = 0;
        using var listener = EnrichmentDeferredListener((pass, count) => deferred += count);

        await SeedArtifactAsync("lodash");
        await BuildService(OsvWith("CVE-2024-0001"), new RecordingEnrichmentSource(Unreached),
                TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.True(deferred > 0, "an unreached tracker must record a deferral");
    }

    [Fact]
    public async Task ReachedTracker_RecordsNoDeferral()
    {
        // The twin: a working tracker must leave the counter alone, or a sustained non-zero rate
        // would stop meaning anything.
        long deferred = 0;
        using var listener = EnrichmentDeferredListener((pass, count) => deferred += count);

        await SeedArtifactAsync("lodash");
        await BuildService(
                OsvWith("CVE-2024-0001"),
                new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001"))),
                TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.Equal(0, deferred);
    }

    private static MeterListener EnrichmentDeferredListener(Action<string, long> onDeferred)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName
                    && instrument.Name == "dependably.enrichment.deferred")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            },
        };

        listener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "pass" && tag.Value is string pass)
                {
                    onDeferred(pass, measurement);
                }
            }
        });

        listener.Start();
        return listener;
    }

    [Fact]
    public async Task UnreachedTracker_StillLeavesTheArtifactFullyScanned()
    {
        // Enrichment is an overlay, not the advisory source: its outage must not cost the scan.
        string caId = await SeedArtifactAsync("lodash");

        await BuildService(OsvWith("CVE-2024-0001"), new RecordingEnrichmentSource(Unreached),
                TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        await using var conn = await _db.OpenAsync();
        string? scanned = await conn.ExecuteScalarAsync<string>(
            "SELECT vuln_checked_at FROM cache_artifact WHERE id = @caId", new { caId });
        Assert.NotNull(scanned);
    }

    // ── Absence is never withdrawal ──────────────────────────────────────────

    [Fact]
    public async Task AdvisoryAbsentFromAReachedResponse_LeavesStoredEnrichmentIntact()
    {
        await SeedArtifactAsync("lodash");
        var osv = OsvWith("CVE-2024-0001");
        var tracker = TestEnrichment.ActiveConnection();

        // First pass enriches.
        await BuildService(osv, new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001"))), tracker)
            .RunScanPassAsync(CancellationToken.None);
        Assert.Equal("HIGH", (await ReadEnrichmentAsync("GHSA-test-0001")).NvdSeverity);

        // Second pass: reached, but the advisory is simply not in the response.
        _clock.Advance(TimeSpan.FromDays(2));
        await BuildService(osv, new RecordingEnrichmentSource(p => Reached(p)), tracker)
            .RunRescanPassAsync(CancellationToken.None);

        // Absence is not a withdrawal: the stored band survives untouched.
        Assert.Equal("HIGH", (await ReadEnrichmentAsync("GHSA-test-0001")).NvdSeverity);
    }

    [Fact]
    public async Task AdvisoryReturnedWithdrawn_ClearsStoredEnrichment()
    {
        // The twin: an EXPLICIT negative status is the only thing that clears. Without this, the
        // absence test above would be equally consistent with nothing ever clearing.
        await SeedArtifactAsync("lodash");
        var osv = OsvWith("CVE-2024-0001");
        var tracker = TestEnrichment.ActiveConnection();

        await BuildService(osv, new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001"))), tracker)
            .RunScanPassAsync(CancellationToken.None);
        Assert.Equal("HIGH", (await ReadEnrichmentAsync("GHSA-test-0001")).NvdSeverity);

        _clock.Advance(TimeSpan.FromDays(2));
        await BuildService(
                osv,
                new RecordingEnrichmentSource(p => Reached(p,
                    Enriched("GHSA-test-0001", "CVE-2024-0001", EnrichmentAdvisoryStatus.Withdrawn))),
                tracker)
            .RunRescanPassAsync(CancellationToken.None);

        var row = await ReadEnrichmentAsync("GHSA-test-0001");
        Assert.Null(row.NvdSeverity);
        Assert.Null(row.SsvcExploitation);
        // Cleared is still a thing the tracker told us, so the stamp advances.
        Assert.NotNull(row.NvdCheckedAt);
    }

    [Fact]
    public async Task DisputedAdvisory_IsSurfacedRatherThanDropped()
    {
        await SeedArtifactAsync("lodash");
        var source = new RecordingEnrichmentSource(p => Reached(p,
            Enriched("GHSA-test-0001", "CVE-2024-0001", EnrichmentAdvisoryStatus.Disputed)));

        await BuildService(OsvWith("CVE-2024-0001"), source, TestEnrichment.ActiveConnection())
            .RunScanPassAsync(CancellationToken.None);

        Assert.Equal("HIGH", (await ReadEnrichmentAsync("GHSA-test-0001")).NvdSeverity);
    }

    // ── The air-gap constraint ───────────────────────────────────────────────

    [Fact]
    public async Task OnDemandScanVersion_NeverEnriches_EvenWithAnActiveConnection()
    {
        // ScanVersionAsync is the one scan path that still runs in an AIR_GAPPED deployment
        // (publish, and the per-version rescan endpoint, against a sideloaded OSV dump). The
        // scheduled passes are returned at their gate, so enrichment inherits the air-gap block
        // from them — but only for as long as it hangs off those passes alone. Hanging it off this
        // path would put an outbound call inside the air gap, which is exactly what an operator
        // reaching for that switch is asking not to happen.
        //
        // TestEnrichment.Unused() throws if called, so this fails loudly the moment enrichment is
        // wired into the on-demand path — the constraint is currently true by construction, and
        // construction is only as durable as the next edit.
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "lodash");
        string versionId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", "pkg:npm/lodash@1.0.0");

        var service = BuildService(
            OsvWith("CVE-2024-0001"),
            TestEnrichment.Unused(),
            TestEnrichment.ActiveConnection());

        await service.ScanVersionAsync(
            "pkg:npm/lodash@1.0.0", versionId, "npm", "lodash", orgId, ct: CancellationToken.None);

        // Reaching here is the assertion: the advisory was scanned, and nothing asked the tracker.
        Assert.Null((await ReadEnrichmentAsync("GHSA-test-0001")).NvdCheckedAt);
    }

    // ── The chunking trap ────────────────────────────────────────────────────

    [Fact]
    public async Task AConnectionBatchSizeSmallerThanTheScanBatch_IsChunked_NotRefusedForever()
    {
        // The scan batch is sized for OSV. An operator configuring a smaller tracker batch must
        // not turn every pass into a permanent oversize refusal — a silent, total failure.
        for (int i = 0; i < 5; i++)
        {
            await SeedArtifactAsync($"pkg-{i}");
        }

        var source = new RecordingEnrichmentSource(p => Reached(p, Enriched("GHSA-test-0001", "CVE-2024-0001")));
        await BuildService(
                TestOsvSource.Create(purl =>
                [
                    new($"GHSA-{purl.GetHashCode(StringComparison.Ordinal):X}", ["CVE-2024-0001"],
                        "adv", "HIGH", 8.1, [], null, null, IsHydrated: true),
                ]),
                source,
                TestEnrichment.ActiveConnection(batchSize: 2))
            .RunScanPassAsync(CancellationToken.None);

        Assert.True(source.Requests.Count > 1, "a batch larger than the configured size must be chunked");
        Assert.All(source.Requests, r => Assert.True(r.Count <= 2));
    }
}
