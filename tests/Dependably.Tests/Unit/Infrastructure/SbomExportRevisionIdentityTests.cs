using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// CISA D6/D9 (SBOM Timestamp / SBOM Version): pins the revision-identity contract
/// <c>SbomExportService.Revision.cs</c> implements. Every test here discriminates in both
/// directions — exporting twice with no intervening change must be indistinguishable, and a
/// re-scan that changes findings must be distinguishable — and each test's own doc comment
/// records the mutant that turns it red against the fix and green against the pre-D6/D9
/// "fresh UUID and <c>version = 1</c> every render" behaviour, so a regression back to that
/// shape is caught here rather than only by inspection.
///
/// <para><b>Every timestamp-asserting test seeds its data, THEN advances the clock, THEN
/// renders.</b> A test that seeds and renders at the same instant cannot tell "stamped from the
/// data" apart from "stamped from the render clock" — they agree by construction. Advancing the
/// clock between seed and render is what makes <c>Assert.Equal(seededAtIso, timestamp)</c> a real
/// assertion rather than a decorative one.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomExportRevisionIdentityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SbomExportService _export;

    public SbomExportRevisionIdentityTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
    }

    // ── seeding helpers ──────────────────────────────────────────────────────

    private async Task<(string ProjectId, string VersionId)> SeedProjectVersionAsync(string orgId)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', 'revision-app', 'application', @now)
            """,
            new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
            """,
            new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
        return (projectId, versionId);
    }

    private async Task<string> InsertComponentAsync(
        string orgId, string versionId, string purl, string name, string version = "1.0.0",
        bool? isExternal = null, string dependencyScope = "unknown")
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_kind, dependency_scope, dependency_path, is_external, created_at)
            VALUES
                (@id, @orgId, @versionId, @purl, 'npm', @name, @version, @name,
                 'library', 'direct', @dependencyScope, @dependencyPath, @isExternal, @now)
            """,
            new
            {
                id,
                orgId,
                versionId,
                purl,
                name,
                version,
                dependencyScope,
                dependencyPath = JsonSerializer.Serialize(new[] { purl }),
                isExternal = isExternal.HasValue ? (isExternal.Value ? 1 : 0) : (int?)null,
                now = _clock.GetUtcNow().ToUtcIso(),
            });
        return id;
    }

    /// <summary>A hosted package/version row whose <c>checksum_sha256</c> is dependably's own digest for a component matched by ecosystem/purl_name/version.</summary>
    private async Task InsertHostedChecksumAsync(string orgId, string ecosystem, string purlName, string version, string checksumSha256)
    {
        string packageId = Guid.NewGuid().ToString("N");
        string versionRowId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, created_at)
            VALUES (@packageId, @orgId, @ecosystem, @purlName, @purlName, @now)
            """,
            new { packageId, orgId, ecosystem, purlName, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, checksum_sha256, origin, created_at)
            VALUES
                (@versionRowId, @packageId, @version, @purl, @blobKey, @checksumSha256, 'uploaded', @now)
            """,
            new
            {
                versionRowId,
                packageId,
                version,
                purl = $"pkg:{ecosystem}/{purlName}@{version}",
                blobKey = $"registry/{ecosystem}/{purlName}/{version}",
                checksumSha256,
                now = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    /// <summary>A purl-less component (BuildComponentProperties' D13a identifier-status condition needs one) with the given raw <c>additional_identifiers</c> JSON.</summary>
    private async Task<string> InsertPurlLessComponentAsync(string orgId, string versionId, string name, string? additionalIdentifiersJson)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_kind, dependency_scope, additional_identifiers, created_at)
            VALUES
                (@id, @orgId, @versionId, NULL, NULL, NULL, '1.0.0', @name,
                 'library', 'direct', 'unknown', @additionalIdentifiersJson, @now)
            """,
            new { id, orgId, versionId, name, additionalIdentifiersJson, now = _clock.GetUtcNow().ToUtcIso() });
        return id;
    }

    private async Task<string> InsertVulnerabilityAsync(
        string osvId, string ecosystem = "npm", string packageName = "left-pad", double cvssScore = 7.5)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, fetched_at)
            VALUES (@id, @osvId, @ecosystem, @packageName, 'HIGH', @cvssScore, @now)
            """,
            new { id, osvId, ecosystem, packageName, cvssScore, now = _clock.GetUtcNow().ToUtcIso() });
        return id;
    }

    private async Task LinkAsync(string componentId, string vulnId, DateTimeOffset checkedAt)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at) VALUES (@id, @componentId, @vulnId, @checkedAt)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId, checkedAt = checkedAt.ToUtcIso() });
    }

    private async Task MarkComponentScannedAsync(string componentId, DateTimeOffset checkedAt)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE sbom_components SET vuln_checked_at = @checkedAt WHERE id = @componentId",
            new { componentId, checkedAt = checkedAt.ToUtcIso() });
    }

    private async Task InsertAnalysisAsync(
        string orgId, string versionId, string purlKey, string vulnKey, string vexState, DateTimeOffset updatedAt)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source, updated_at)
            VALUES (@id, @orgId, @versionId, @purlKey, @vulnKey, @vexState, 'manual', @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                versionId,
                purlKey,
                vulnKey,
                vexState,
                now = updatedAt.ToUtcIso(),
            });
    }

    private static (string Serial, int Version, string Timestamp) Identity(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return (
            doc.RootElement.GetProperty("serialNumber").GetString()!,
            doc.RootElement.GetProperty("version").GetInt32(),
            doc.RootElement.GetProperty("metadata").GetProperty("timestamp").GetString()!);
    }

    /// <summary>The rendered <c>dependably:signature-state</c> property value, read off the emitted document.</summary>
    private static string? SignatureState(string json)
    {
        using var doc = JsonDocument.Parse(json);
        foreach (var prop in doc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray())
        {
            if (prop.GetProperty("name").GetString() == "dependably:signature-state")
            {
                return prop.GetProperty("value").GetString();
            }
        }

        return null;
    }

    // ── D6a: the timestamp is derived from the data, never the render clock ───

    /// <summary>
    /// Mutant that turns this red: in <c>BuildSbomDocumentAsync</c>, pass
    /// <c>_time.GetUtcNow().ToUtcIso()</c> instead of the <c>DeriveChangedAt(...)</c> result as
    /// <c>derivedChangedAtIso</c> — restoring "the first render's clock reading", which is exactly
    /// what this test seeds 30 days in the past specifically to catch: a render taken long after
    /// the data was created must report the DATA's instant, not its own. Verified by hand against
    /// this test (see the task report); not committed as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task FirstRender_ReportsWhenTheDataWasCreated_NotWhenTheRenderRan()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-clock-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        string seededAtIso = _clock.GetUtcNow().ToUtcIso();

        // The render happens long after the data was created. A render-clock stamp would read
        // today; the data-derived stamp must still read the seed instant.
        _clock.Advance(TimeSpan.FromDays(30));

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (_, _, timestamp1) = Identity(first);

        Assert.Equal(seededAtIso, timestamp1);
        Assert.NotEqual(_clock.GetUtcNow().ToUtcIso(), timestamp1);
    }

    // ── same data, twice: identical revision identity ─────────────────────────

    /// <summary>
    /// Mutant that turns this red: in <c>ResolveRevisionAsync</c>, drop the
    /// <c>content_fingerprint</c> equality check and always bump <c>revision</c>/re-stamp
    /// <c>changed_at</c> — restoring "version becomes a render counter", the exact defect D9
    /// exists to fix. Verified by hand against this test; not committed as a mutation-testing
    /// fixture.
    /// </summary>
    [Fact]
    public async Task ExportTwice_NoIntermediateChange_YieldsIdenticalSerialVersionAndTimestamp()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-nochange-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        string seededAtIso = _clock.GetUtcNow().ToUtcIso();

        _clock.Advance(TimeSpan.FromDays(30));

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, timestamp1) = Identity(first);
        Assert.Equal(seededAtIso, timestamp1);

        // A genuine re-render some time later, of unchanged data, must be indistinguishable from
        // the first — that is what separates "version" from a render counter.
        _clock.Advance(TimeSpan.FromDays(1));

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, timestamp2) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(timestamp1, timestamp2);
        Assert.Matches(
            "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", serial1);
    }

    // ── a re-scan that changes findings: same serial, new revision ────────────

    /// <summary>
    /// Mutant that turns this red: in <c>BuildSbomDocumentAsync</c>, pass <c>null</c> instead of
    /// <c>VdrVulnFingerprintFacts(...)</c> for the <c>vdr</c> variant (i.e. fingerprint the
    /// component set only, never the findings) — a re-scan that adds an advisory would then leave
    /// <c>version</c> at 1 forever, failing D9e. Verified by hand against this test; not committed
    /// as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task RescanThatChangesFindings_KeepsSerial_BumpsVersion_StampsNewTimestamp()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-rescan-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        string seededAtIso = _clock.GetUtcNow().ToUtcIso();
        var vdrOptions = SbomExportOptions.Default with { Variant = "vdr" };

        _clock.Advance(TimeSpan.FromDays(10));

        string first = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, vdrOptions, CancellationToken.None))!;
        var (serial1, version1, timestamp1) = Identity(first);
        Assert.Equal(1, version1);
        Assert.Equal(seededAtIso, timestamp1);

        // A re-scan that finds a NEW advisory is an edit to the data about the target component
        // (D9e) — the version must move, and the timestamp must report WHEN the link was made.
        _clock.Advance(TimeSpan.FromHours(6));
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8001");
        await LinkAsync(compId, vulnId, _clock.GetUtcNow());
        string linkedAtIso = _clock.GetUtcNow().ToUtcIso();
        await MarkComponentScannedAsync(compId, _clock.GetUtcNow());

        string second = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, vdrOptions, CancellationToken.None))!;
        var (serial2, version2, timestamp2) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(2, version2);
        Assert.NotEqual(timestamp1, timestamp2);
        Assert.Equal(linkedAtIso, timestamp2);
    }

    // ── a scan that finds nothing new: no bump, despite freshness stamps moving ─

    /// <summary>
    /// Mutant that turns this red: fold <c>ComponentRow.VulnCheckedAt</c> (or the vuln row's
    /// <c>NvdCheckedAt</c>/<c>SsvcCheckedAt</c>) into the fingerprint or the changed_at derivation
    /// — a nightly re-scan that finds nothing new would then bump <c>version</c>/<c>timestamp</c>
    /// every night regardless of whether the data changed, turning it back into a render counter
    /// for the coverage-only case D9 was written to exclude. Verified by hand against this test;
    /// not committed as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task RescanWithNoNewFindings_DoesNotBumpVersion_EvenThoughFreshnessStampsMoved()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-clean-rescan-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        string seededAtIso = _clock.GetUtcNow().ToUtcIso();
        var vdrOptions = SbomExportOptions.Default with { Variant = "vdr" };

        _clock.Advance(TimeSpan.FromDays(10));

        string first = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, vdrOptions, CancellationToken.None))!;
        var (serial1, version1, timestamp1) = Identity(first);
        Assert.Equal(seededAtIso, timestamp1);

        // A scan runs and finds nothing new: vuln_checked_at moves, and (via
        // BuildCoverageProperties) the document's own scanned/unscanned counters and lastScanAt
        // move with it — but no vulnerability was added, removed, or re-analyzed. This is not an
        // edit to the data ABOUT the target component (D9e), so the revision must not move.
        _clock.Advance(TimeSpan.FromHours(6));
        await MarkComponentScannedAsync(compId, _clock.GetUtcNow());

        string second = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, vdrOptions, CancellationToken.None))!;
        var (serial2, version2, timestamp2) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(timestamp1, timestamp2);
    }

    // ── export-options interaction: variant/scope are different documents ─────

    /// <summary>
    /// Mutant that turns this red: key <c>sbom_export_revisions</c> by
    /// <c>project_version_id</c> alone, dropping <c>scope_filter</c> from the row and the
    /// resolver's WHERE — a <c>scope=prod</c> and a <c>scope=all</c> render of the same version
    /// would then share one revision line despite asserting different component sets. Verified by
    /// hand against this test; not committed as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task DifferentScopeFilters_AreIndependentRevisionLines()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-scope-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        string all = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { Filter = SbomComponentFilter.All },
            CancellationToken.None))!;
        string prod = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { Filter = SbomComponentFilter.Prod },
            CancellationToken.None))!;

        var (serialAll, versionAll, _) = Identity(all);
        var (serialProd, versionProd, _) = Identity(prod);

        Assert.NotEqual(serialAll, serialProd);
        Assert.Equal(1, versionAll);
        Assert.Equal(1, versionProd);

        // Re-exporting "all" again must still land on the SAME line as the first "all" render —
        // scope partitions the key, it does not reset it on every call.
        string allAgain = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { Filter = SbomComponentFilter.All },
            CancellationToken.None))!;
        var (serialAllAgain, versionAllAgain, _) = Identity(allAgain);
        Assert.Equal(serialAll, serialAllAgain);
        Assert.Equal(versionAll, versionAllAgain);
    }

    /// <summary>
    /// Mutant that turns this red: key <c>sbom_export_revisions</c> without <c>doc_kind</c> — an
    /// <c>inventory</c> and a <c>vdr</c> render of the same version would then share one revision
    /// line despite the <c>vdr</c> render asserting a vulnerabilities array the <c>inventory</c>
    /// render omits entirely. Verified by hand against this test; not committed as a
    /// mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task InventoryAndVdrVariants_AreIndependentRevisionLines()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-variant-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        string inventory = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        string vdr = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { Variant = "vdr" }, CancellationToken.None))!;

        var (serialInventory, versionInventory, _) = Identity(inventory);
        var (serialVdr, versionVdr, _) = Identity(vdr);

        Assert.NotEqual(serialInventory, serialVdr);
        Assert.Equal(1, versionInventory);
        Assert.Equal(1, versionVdr);
    }

    // ── isExternal relocation: a 1.6 and a 1.7 render assert the SAME facts ────

    /// <summary>
    /// Mutant that turns this red: revert <c>BuildComponentProperties</c>'s <c>dependably:
    /// is-external</c> relocation (drop the <c>specVersion == "1.6"</c> branch) — a 1.6 render
    /// would then silently drop the <c>isExternal</c> fact instead of carrying it as a property,
    /// so the SAME <c>(serial, version)</c> this test asserts resolves to two documents that
    /// disagree on whether the component is external. Keeping <c>specVersion</c> out of the
    /// revision-identity key is only correct while this holds. Verified by hand against this test;
    /// not committed as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task DifferentSpecVersions_ShareOneRevisionLine_AndBothAssertIsExternal()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-specver-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad", isExternal: true);

        string json16 = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.6" }, CancellationToken.None))!;
        string json17 = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.7" }, CancellationToken.None))!;

        var (serial16, version16, _) = Identity(json16);
        var (serial17, version17, _) = Identity(json17);
        Assert.Equal(serial16, serial17);
        Assert.Equal(version16, version17);

        using var doc16 = JsonDocument.Parse(json16);
        var component16 = doc16.RootElement.GetProperty("components")[0];
        Assert.False(component16.TryGetProperty("isExternal", out _));
        var props16 = component16.GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!, StringComparer.Ordinal);
        Assert.Equal("true", props16[DependablyExportProperties.IsExternal]);

        using var doc17 = JsonDocument.Parse(json17);
        var component17 = doc17.RootElement.GetProperty("components")[0];
        Assert.True(component17.GetProperty("isExternal").GetBoolean());
    }

    // ── standalone VEX gets its own revision identity too ──────────────────────

    /// <summary>
    /// Mutant that turns this red: in <c>BuildVexDocumentAsync</c>, pass
    /// <c>_time.GetUtcNow().ToUtcIso()</c> instead of the derived changed_at, and/or drop the
    /// content_fingerprint equality check — the first render would report today instead of the
    /// seed instant, and the no-op re-render would still churn the identity. Verified by hand
    /// against this test; not committed as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task VexDocument_NoChange_IdenticalIdentity_ThenAnalysisChange_BumpsVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-vex-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string purl = "pkg:npm/left-pad@1.0.0";
        string compId = await InsertComponentAsync(orgId, versionId, purl, "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8002");
        await LinkAsync(compId, vulnId, _clock.GetUtcNow());

        string? purlKey = SbomPurlKey.ForComponent("npm", "left-pad", purl);
        Assert.NotNull(purlKey);
        await InsertAnalysisAsync(orgId, versionId, purlKey!, "CVE-2100-8002", "in_triage", _clock.GetUtcNow());
        string seededAtIso = _clock.GetUtcNow().ToUtcIso();

        _clock.Advance(TimeSpan.FromDays(5));

        string first = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial1, version1, timestamp1) = Identity(first);
        Assert.Equal(1, version1);
        Assert.Equal(seededAtIso, timestamp1);

        _clock.Advance(TimeSpan.FromHours(1));
        string second = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial2, version2, timestamp2) = Identity(second);
        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(timestamp1, timestamp2);

        // Triage resolves the finding as not affected — the analysis state changed, so the VEX
        // document's revision must move even though no component or SBOM-side fact did.
        _clock.Advance(TimeSpan.FromHours(1));
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE project_vuln_analysis SET vex_state = 'not_affected', updated_at = @now WHERE org_id = @orgId AND project_version_id = @versionId",
                new { orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });
        }

        string third = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial3, version3, timestamp3) = Identity(third);
        Assert.Equal(serial1, serial3);
        Assert.Equal(2, version3);
        Assert.NotEqual(timestamp2, timestamp3);
        Assert.Equal(_clock.GetUtcNow().ToUtcIso(), timestamp3);
    }

    /// <summary>
    /// F8: a VEX export makes the identical <c>["authors"] = org-slug</c> claim a signed SBOM
    /// export does (<see cref="SbomExportService.BuildAuthorsMetadata"/>), so it owes the same
    /// <c>dependably:signature-state</c> honesty duty — without it, a consumer who has only ever
    /// seen a signed SBOM cannot tell "this VEX was never signed by policy" from "no master key
    /// is configured", the exact ambiguity that property exists to remove.
    ///
    /// <para>Mutant: revert <c>BuildVexDocumentAsync</c> to resolve no signer at all (drop the
    /// <c>_signer.ResolveAsync</c> call, the <c>AddSignatureStateProperty</c> call, and the
    /// trailing <c>SbomAuthorSigner.Attach</c>) and this test goes red on both assertions — no
    /// <c>signature</c> member and no <c>dependably:signature-state</c> property at all, under a
    /// master key that IS configured.</para>
    /// </summary>
    [Fact]
    public async Task VexDocument_WithAMasterKeyConfigured_IsSigned_AndDeclaresSignedState()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-vex-sig-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string purl = "pkg:npm/left-pad@1.0.0";
        string compId = await InsertComponentAsync(orgId, versionId, purl, "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8099");
        await LinkAsync(compId, vulnId, _clock.GetUtcNow());
        string? purlKey = SbomPurlKey.ForComponent("npm", "left-pad", purl);
        Assert.NotNull(purlKey);
        await InsertAnalysisAsync(orgId, versionId, purlKey!, "CVE-2100-8099", "in_triage", _clock.GetUtcNow());

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string json = (await signedExport.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;

        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("signature", out var signature));
        Assert.Equal("ES256", signature.GetProperty("algorithm").GetString());

        var properties = doc.RootElement.GetProperty("metadata").GetProperty("properties");
        bool sawSignedState = false;
        foreach (var prop in properties.EnumerateArray())
        {
            if (prop.GetProperty("name").GetString() == "dependably:signature-state")
            {
                Assert.Equal("signed", prop.GetProperty("value").GetString());
                sawSignedState = true;
            }
        }

        Assert.True(sawSignedState, "dependably:signature-state property was not emitted");
    }

    /// <summary>
    /// The VEX equivalent of <c>UnsignedThenSigned_SameData_MovesRevision_KeepsSerial_AndDeclaresSignedState</c>
    /// — pins that <c>ComputeVexContentFingerprint</c> ACTUALLY folds in <c>orgHasActiveKey</c>.
    /// Before this test, removing <c>["orgHasActiveKey"] = orgHasActiveKey</c> from
    /// <c>ComputeVexContentFingerprint</c>'s payload left the full suite passing with an
    /// unchanged test count — the whole VEX signing-identity arm shipped with no coverage able to
    /// catch a regression there.
    ///
    /// <para>Mutant that turns this red: drop <c>["orgHasActiveKey"] = orgHasActiveKey</c> from
    /// <c>ComputeVexContentFingerprint</c>, or stop passing <c>orgHasActiveKey</c> at its call
    /// site in <c>BuildVexDocumentAsync</c> — <c>version2</c> stays at 1 instead of bumping to 2.
    /// Verified by hand against this test; not committed as a mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task VexDocument_UnsignedThenSigned_MovesRevision_KeepsSerial()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-vex-sig-on-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string purl = "pkg:npm/left-pad@1.0.0";
        string compId = await InsertComponentAsync(orgId, versionId, purl, "left-pad");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8098");
        await LinkAsync(compId, vulnId, _clock.GetUtcNow());
        string? purlKey = SbomPurlKey.ForComponent("npm", "left-pad", purl);
        Assert.NotNull(purlKey);
        await InsertAnalysisAsync(orgId, versionId, purlKey!, "CVE-2100-8098", "in_triage", _clock.GetUtcNow());

        // _export (this class' field) has no master key configured.
        string unsigned = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial1, version1, timestamp1) = Identity(unsigned);
        Assert.Equal(1, version1);
        using (var docUnsigned = JsonDocument.Parse(unsigned))
        {
            Assert.False(docUnsigned.RootElement.TryGetProperty("signature", out _));
        }

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string signed = (await signedExport.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial2, version2, timestamp2) = Identity(signed);
        using var docSigned = JsonDocument.Parse(signed);
        Assert.True(docSigned.RootElement.TryGetProperty("signature", out _));

        Assert.Equal(serial1, serial2);
        Assert.Equal(timestamp1, timestamp2);
        Assert.NotEqual(version1, version2);
        Assert.Equal(2, version2);
    }

    // ── the fingerprint reads what is RENDERED, not what is stored (#703) ─────

    /// <summary>
    /// A future ingest revision that starts capturing an identifier kind
    /// <c>BuildComponentObject</c>/<c>BuildComponentProperties</c> do not yet recognise must not
    /// bump <c>version</c> on its own — <c>ParseAdditionalIdentifiers</c> deliberately KEEPS an
    /// unrecognised kind (so a future export revision does not need to re-parse every stored
    /// row), but nothing renders it anywhere in the document today. Simulated by writing directly
    /// to the stored column, bypassing every write path this registry's own ingest code takes,
    /// the same way a hypothetical future ingest revision would land a new kind on an
    /// already-stored row without re-touching it. <b>The component here has a purl</b> — the
    /// case where an unrecognised kind changes ABSOLUTELY NOTHING about the render, not even the
    /// D13a <c>dependably:identifier-status</c> property (which only ever fires when
    /// <c>Purl is null</c>); see
    /// <see cref="PurlLessComponent_UnrecognisedIdentifierKindFlipsIdentifierStatus_BumpsVersion"/>
    /// immediately below for the purl-LESS case, where it does.
    ///
    /// <para>Mutant that turns this red: in <c>FingerprintComponent</c>, revert
    /// <c>FingerprintAdditionalIdentifiers(fullIdentifiers)</c> to
    /// <c>c.AdditionalIdentifiers</c> (the raw stored JSON) — the stored column changed, so the
    /// fingerprint changes, so <c>version</c> bumps despite the rendered document being
    /// byte-for-byte identical. Verified by hand against this test; not committed as a
    /// mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task UnrenderedIdentifierKindAddedToStorage_DoesNotBumpVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-ident-unread-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET additional_identifiers = @json WHERE id = @compId",
                new
                {
                    compId,
                    json = JsonSerializer.Serialize(new[] { new { kind = "future-kind", value = "whatever" } }),
                });
        }

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(first, second);
    }

    /// <summary>
    /// The purl-LESS counterpart to the test above: <c>BuildComponentProperties</c> decides the
    /// D13a <c>dependably:identifier-status</c> absence property from the FULL parsed identifier
    /// list's COUNT (<c>c.Purl is null &amp;&amp; additionalIdentifiers.Count == 0</c>), not the
    /// rendered subset <c>FingerprintAdditionalIdentifiers</c> hashes — so an unrecognised-kind
    /// entry, though it renders nowhere itself, changes whether that ABSENCE property appears at
    /// all on a purl-less component. This is a real rendered change the filtered array alone
    /// cannot see, and it must bump <c>version</c>.
    ///
    /// <para>Mutant that turns this red: in <c>FingerprintComponent</c>, drop the
    /// <c>obj["identifierStatusAbsent"] = …</c> line — the rendered document changes (this test's
    /// own <c>Assert.NotEqual(first, second)</c> proves it, and <c>identifier-status</c> is
    /// present in the first render, absent from the second) while <c>version</c> stays at 1.
    /// Verified by hand against this test; not committed as a mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task PurlLessComponent_UnrecognisedIdentifierKindFlipsIdentifierStatus_BumpsVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-ident-purlless-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertPurlLessComponentAsync(orgId, versionId, "no-purl-lib", additionalIdentifiersJson: null);

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);
        using (var doc1 = JsonDocument.Parse(first))
        {
            var props1 = doc1.RootElement.GetProperty("components")[0].GetProperty("properties")
                .EnumerateArray().Select(p => p.GetProperty("name").GetString()).ToList();
            Assert.Contains(DependablyExportProperties.IdentifierStatus, props1);
        }

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET additional_identifiers = @json " +
                "WHERE org_id = @orgId AND project_version_id = @versionId",
                new
                {
                    orgId,
                    versionId,
                    json = JsonSerializer.Serialize(new[] { new { kind = "future-kind", value = "whatever" } }),
                });
        }

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);
        using (var doc2 = JsonDocument.Parse(second))
        {
            var props2 = doc2.RootElement.GetProperty("components")[0].GetProperty("properties")
                .EnumerateArray().Select(p => p.GetProperty("name").GetString()).ToList();
            Assert.DoesNotContain(DependablyExportProperties.IdentifierStatus, props2);
        }

        Assert.Equal(serial1, serial2);
        Assert.NotEqual(version1, version2);
        Assert.Equal(2, version2);
        Assert.NotEqual(first, second);
    }

    /// <summary>
    /// Within-column array order is itself rendered: the FIRST asserted <c>cpe</c> takes the
    /// native <c>cpe</c> field (<c>BuildComponentObject</c>'s <c>identifiers.FirstOrDefault</c>),
    /// so swapping the stored order of two <c>cpe</c> entries changes WHICH VALUE a consumer
    /// resolves natively — a real rendered change a sorted fingerprint would hide.
    ///
    /// <para>Mutant that turns this red: reintroduce
    /// <c>.OrderBy(i => i.Kind, StringComparer.Ordinal).ThenBy(i => i.Value, StringComparer.Ordinal)</c>
    /// into <c>FingerprintAdditionalIdentifiers</c> — the two stored orderings sort to the SAME
    /// sequence, so the fingerprint stops seeing the swap and <c>version</c> stays at 1 while the
    /// rendered native <c>cpe</c> value changes. Verified by hand against this test; not committed
    /// as a mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task ReorderingStoredCpeEntries_ChangesRenderedNativeCpe_BumpsVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-ident-order-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET additional_identifiers = @json WHERE id = @compId",
                new
                {
                    compId,
                    json = JsonSerializer.Serialize(new[]
                    {
                        new { kind = "cpe", value = "cpe:2.3:a:aaa:aaa:1.0:*:*:*:*:*:*:*" },
                        new { kind = "cpe", value = "cpe:2.3:a:bbb:bbb:1.0:*:*:*:*:*:*:*" },
                    }),
                });
        }

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);
        using (var doc1 = JsonDocument.Parse(first))
        {
            Assert.Equal(
                "cpe:2.3:a:aaa:aaa:1.0:*:*:*:*:*:*:*",
                doc1.RootElement.GetProperty("components")[0].GetProperty("cpe").GetString());
        }

        // The SAME two entries, reordered — no entry added or removed.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET additional_identifiers = @json WHERE id = @compId",
                new
                {
                    compId,
                    json = JsonSerializer.Serialize(new[]
                    {
                        new { kind = "cpe", value = "cpe:2.3:a:bbb:bbb:1.0:*:*:*:*:*:*:*" },
                        new { kind = "cpe", value = "cpe:2.3:a:aaa:aaa:1.0:*:*:*:*:*:*:*" },
                    }),
                });
        }

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);
        using (var doc2 = JsonDocument.Parse(second))
        {
            Assert.Equal(
                "cpe:2.3:a:bbb:bbb:1.0:*:*:*:*:*:*:*",
                doc2.RootElement.GetProperty("components")[0].GetProperty("cpe").GetString());
        }

        Assert.Equal(serial1, serial2);
        Assert.NotEqual(version1, version2);
        Assert.Equal(2, version2);
    }

    /// <summary>
    /// Dependably's own digest (<c>package_versions.checksum_sha256</c>) is rendered only when it
    /// passes <c>IsAsciiHex</c> — <c>BuildComponentHashes</c>'s own doc comment notes a blank
    /// non-NULL <c>content_hash</c> legitimately reaches here and is invalid. Two different
    /// invalid values (blank vs. a non-hex string) both render nothing, so the fingerprint must
    /// not distinguish between them either — the same "stored ≠ rendered" gap as the identifier
    /// and asserted-hash cases above, on the OWN-hash input instead.
    ///
    /// <para>Mutant that turns this red: in <c>FingerprintComponent</c>, revert
    /// <c>ownHash is not null &amp;&amp; IsAsciiHex(ownHash) ? ownHash : null</c> to the bare
    /// <c>ownHashByComponentId.GetValueOrDefault(c.Id)</c> — the stored value changed from one
    /// invalid string to another, so the fingerprint changes, so <c>version</c> bumps despite the
    /// rendered document being byte-for-byte identical (neither value ever reaches
    /// <c>hashes[]</c>). Verified by hand against this test; not committed as a mutation-testing
    /// fixture.</para>
    /// </summary>
    [Fact]
    public async Task InvalidOwnDigestChangedToAnotherInvalidValue_DoesNotBumpVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-ownhash-unread-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        await InsertHostedChecksumAsync(orgId, "npm", "left-pad", "1.0.0", "");

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);
        using (var doc1 = JsonDocument.Parse(first))
        {
            Assert.False(doc1.RootElement.GetProperty("components")[0].TryGetProperty("hashes", out _));
        }

        // Still invalid (fails IsAsciiHex — odd length, non-hex characters), but a DIFFERENT
        // string than before.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE package_versions SET checksum_sha256 = @checksum " +
                "WHERE package_id IN (SELECT id FROM packages WHERE org_id = @orgId AND purl_name = 'left-pad')",
                new { orgId, checksum = "not-a-valid-digest!!" });
        }

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);
        using (var doc2 = JsonDocument.Parse(second))
        {
            Assert.False(doc2.RootElement.GetProperty("components")[0].TryGetProperty("hashes", out _));
        }

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(first, second);
    }

    /// <summary>
    /// Reordering stored hash entries so two NATIVE-eligible entries (an uppercase-spelled
    /// <c>SHA-256</c> and <c>SHA-1</c>, both <see cref="HashAlgEnum17"/> members) swap places
    /// RELATIVE to a disclosed-only entry (a lower-case <c>sha256</c> — <see cref="ParseAssertedHashes"/>
    /// does not validate the alg spelling, and <see cref="AssertedAlgAliases"/> is
    /// case-sensitive, so a realistic CISA-style lower-case spelling lands disclosed-only, never
    /// native) must NOT bump <c>version</c>, because <c>BuildComponentHashes</c> renders the two
    /// groups as two SEPARATE JSON outputs (native <c>hashes[]</c>, disclosed
    /// <c>dependably:asserted-hashes</c>) — only each output's OWN internal order is rendered, and
    /// neither output's internal order changes here. The rendered document is byte-for-byte
    /// identical.
    ///
    /// <para>Mutant that turns this red: in <c>FingerprintAssertedHashes</c>, fingerprint the
    /// asserted entries as ONE combined ordered list instead of two separately-ordered
    /// partitions (<c>native</c>/<c>disclosed</c>) — the combined sequence changes (the disclosed
    /// entry moves from the middle to the end), so <c>version</c> bumps despite nothing rendered
    /// changing. Verified by hand against this test; not committed as a mutation-testing
    /// fixture.</para>
    /// </summary>
    [Fact]
    public async Task ReorderingAcrossNativeAndDisclosedHashPartitions_DoesNotBumpVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-hash-partition-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET component_hashes = @json WHERE id = @compId",
                new
                {
                    compId,
                    json = JsonSerializer.Serialize(new[]
                    {
                        new { alg = "SHA-256", content = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                        new { alg = "sha256", content = "cccccccccccccccccccccccccccccccc" },
                        new { alg = "SHA-1", content = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
                    }),
                });
        }

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);

        // The SAME three entries — the two NATIVE-eligible ones (SHA-256, SHA-1) swap places
        // relative to the disclosed-only one (sha256); neither partition's own internal order
        // changes.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET component_hashes = @json WHERE id = @compId",
                new
                {
                    compId,
                    json = JsonSerializer.Serialize(new[]
                    {
                        new { alg = "SHA-256", content = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                        new { alg = "SHA-1", content = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
                        new { alg = "sha256", content = "cccccccccccccccccccccccccccccccc" },
                    }),
                });
        }

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(first, second);
    }

    /// <summary>
    /// A stored hash entry that fails ASCII-hex validation is dropped by
    /// <c>ParseAssertedHashes</c> before it ever reaches a render (native <c>hashes[]</c> or the
    /// <c>dependably:asserted-hashes</c> disclosure property) — so a row carrying one must not
    /// bump <c>version</c> either, the same "stored ≠ rendered" gap as the identifier case above.
    ///
    /// <para>Mutant: in <c>FingerprintComponent</c>, revert
    /// <c>FingerprintAssertedHashes(c.ComponentHashes, hasOwnHash: …)</c> to <c>c.ComponentHashes</c>
    /// (the raw stored JSON). Verified by hand against this test; not committed as a
    /// mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task InvalidAssertedHashAddedToStorage_DoesNotBumpVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-hash-unread-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string compId = await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        string first = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET component_hashes = @json WHERE id = @compId",
                new
                {
                    compId,
                    json = JsonSerializer.Serialize(new[] { new { alg = "sha256", content = "not-a-hex-value!!" } }),
                });
        }

        string second = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(first, second);
    }

    // ── signature identity is asserted content: it must move the revision too (#703) ──

    /// <summary>
    /// Reproduces GitLab #703's probe: an unsigned and a signed export of byte-identical
    /// underlying data must NOT publish under the same <c>(serialNumber, version)</c> — the
    /// "operator just set <c>DEPENDABLY_MASTER_KEY</c> on an existing install" shape. A consumer
    /// caching by that pair would otherwise never re-fetch the newly-signed document, and two
    /// recipients holding "revision 1" would disagree about whether the author signed.
    ///
    /// <para>Mutant that turns this red: drop the <c>signatureState</c>/<c>keyId</c> arguments
    /// from the two call sites of <c>ComputeContentFingerprint</c> (or drop the parameters from
    /// the method itself) — the fingerprint then depends on nothing either signer touches, and
    /// both renders land on version 1 under the same serial, exactly the bug this test pins.
    /// Verified by hand against this test; not committed as a mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task UnsignedThenSigned_SameData_MovesRevision_KeepsSerial_AndDeclaresSignedState()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-sig-on-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        // _export (this class' field) has no master key configured — the "before an operator set
        // DEPENDABLY_MASTER_KEY" shape.
        string unsigned = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serialUnsigned, versionUnsigned, _) = Identity(unsigned);
        Assert.Equal(1, versionUnsigned);
        using (var docUnsigned = JsonDocument.Parse(unsigned))
        {
            Assert.False(docUnsigned.RootElement.TryGetProperty("signature", out _));
        }

        // Same project/version, no intervening data change — only the operator's signing
        // posture changed, from "no key" to "can sign".
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string signed = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serialSigned, versionSigned, _) = Identity(signed);
        using var docSigned = JsonDocument.Parse(signed);
        Assert.True(docSigned.RootElement.TryGetProperty("signature", out _));

        Assert.Equal(serialUnsigned, serialSigned);
        Assert.NotEqual(versionUnsigned, versionSigned);
        Assert.Equal(2, versionSigned);
    }

    /// <summary>
    /// The mixed-fleet oscillation the corrected rule exists to prevent (the earlier "fold in the
    /// rendered STRING" attempt at this decision reproduced it): alternating which of two
    /// replicas — one with <c>DEPENDABLY_MASTER_KEY</c> configured, one without — answers an
    /// export for the SAME org's SAME data must NEVER move the revision, even though the rendered
    /// <c>dependably:signature-state</c> genuinely differs per replica (<c>signed</c> vs
    /// <c>unsigned-key-unavailable</c>). Asserted against the EMITTED document across five
    /// alternating renders (A, B, A, B, A), not against the fingerprint function directly — a
    /// probe against the fingerprint alone would not have caught the original defect, since it
    /// only manifests once two DIFFERENT <see cref="SbomExportService"/> instances (different
    /// signers, same store) actually render.
    ///
    /// <para>Mutant: in <c>BuildSbomDocumentAsync</c>, pass the rendered <c>signatureState</c>
    /// string (or <c>signingKey?.Id</c>) to <c>ComputeContentFingerprint</c> instead of
    /// <c>orgHasActiveKey</c> — every renders after the first goes red, with <c>version</c>
    /// incrementing on each alternation instead of staying at 1. Verified by hand against this
    /// test; not committed as a mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task AlternatingReplicas_SameOrgKey_NeverMovesRevision_DespiteDifferentSignatureStates()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-sig-oscillate-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var configuredExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        // Replica A mints the org's key on its first render.
        string a1 = (await configuredExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial, version1, timestamp1) = Identity(a1);
        Assert.Equal(1, version1);
        Assert.Equal(SbomAuthorSigner.SignedState, SignatureState(a1));

        // Replica B (this class' _export field, no master key of its own) sees the SAME org key
        // the shared store already carries — not "no key at all".
        string b1 = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serialB1, versionB1, timestampB1) = Identity(b1);
        Assert.Equal(serial, serialB1);
        Assert.Equal(version1, versionB1);
        Assert.Equal(timestamp1, timestampB1);
        Assert.Equal(SbomAuthorSigner.UnsignedKeyUnavailableState, SignatureState(b1));

        string a2 = (await configuredExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        Assert.Equal((serial, version1, timestamp1), Identity(a2));

        string b2 = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        Assert.Equal((serial, version1, timestamp1), Identity(b2));

        string a3 = (await configuredExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        Assert.Equal((serial, version1, timestamp1), Identity(a3));
    }

    /// <summary>
    /// Precondition the "signature identity" decision depends on: the rendered
    /// <c>dependably:signature-state</c> must be a fact about the ORG's key, not about this
    /// replica's own <c>DEPENDABLY_MASTER_KEY</c> — the mixed-fleet/rolling-rollout shape. An org
    /// whose active key was minted by one signer instance (standing in for a replica that HAS the
    /// master key configured) must not read as <c>unsigned-no-master-key</c> — "no key exists for
    /// this org" — from a second signer instance sharing the same store but with no master key of
    /// its own (standing in for a replica mid-rollout). It must read as the distinct
    /// <c>unsigned-key-unavailable</c> state instead.
    ///
    /// <para>Mutant: in <c>SbomAuthorSigner.ResolveAsync</c>, drop the
    /// <c>HasActiveKeyAsync</c> check and always return <c>UnsignedNoMasterKeyState</c> when this
    /// replica cannot sign — this test's <c>Assert.Equal(UnsignedKeyUnavailableState, ...)</c>
    /// goes red, reading <c>unsigned-no-master-key</c> instead: a false claim, since the org DOES
    /// have an active key. Verified by hand against this test; not committed as a
    /// mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task NodeCannotSign_ButOrgHasAnActiveKey_DeclaresKeyUnavailable_NotNoMasterKey()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-sig-mixed-fleet-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        // Mints the org's active key via a signing-capable signer — standing in for another
        // replica in the fleet that DOES have DEPENDABLY_MASTER_KEY configured.
        var mintingSigner = TestSbomAuthorSigner.Configured(_fixture.Store, _clock);
        var (mintedKey, mintedState, mintedOrgHasActiveKey) = await mintingSigner.ResolveAsync(orgId, CancellationToken.None);
        mintedKey?.Dispose();
        Assert.Equal(SbomAuthorSigner.SignedState, mintedState);
        Assert.True(mintedOrgHasActiveKey);

        // _export's signer (this class' field) has no master key configured — the SAME shared
        // store, but a replica that cannot itself read the org's now-active key.
        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("signature", out _));

        var properties = doc.RootElement.GetProperty("metadata").GetProperty("properties");
        string? state = null;
        foreach (var prop in properties.EnumerateArray())
        {
            if (prop.GetProperty("name").GetString() == "dependably:signature-state")
            {
                state = prop.GetProperty("value").GetString();
            }
        }

        Assert.Equal(SbomAuthorSigner.UnsignedKeyUnavailableState, state);
    }

    /// <summary>
    /// Decision (ADR-sbom-author-signature, "signature identity"): key rotation does NOT move
    /// the revision. <c>signature.keyId</c> is metadata about the attestation, not about the
    /// component/vulnerability data this revision line otherwise tracks — a rotation re-attests
    /// IDENTICAL facts under a new key, it does not edit data about the target component the way
    /// CISA's own D9e version trigger is written. The consequence this test pins deliberately: a
    /// document fetched before a rotation and one fetched after can both report the same
    /// <c>(serial, version)</c> while carrying different <c>signature.keyId</c> values — the
    /// rendered <c>dependably:signature-state</c> is unchanged (still <c>signed</c>) either way,
    /// which is the only signing fact this revision line tracks.
    ///
    /// <para>Mutant: fold <c>keyId</c> back into <c>ComputeContentFingerprint</c>'s input — this
    /// test's <c>Assert.Equal(version1, version2)</c> would then fail, since rotation would bump
    /// the revision the decision above says it must not. Verified by hand against this test; not
    /// committed as a mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task KeyRotation_DoesNotMoveRevision_SignatureKeyIdChangesAnyway()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-sig-rotate-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var (signer, keys) = TestSbomAuthorSigner.ConfiguredWithRepository(_fixture.Store, _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, signer);

        string first = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);
        using var doc1 = JsonDocument.Parse(first);
        string keyId1 = doc1.RootElement.GetProperty("signature").GetProperty("keyId").GetString()!;

        await keys.RotateAsync(orgId, CancellationToken.None);

        string second = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);
        using var doc2 = JsonDocument.Parse(second);
        string keyId2 = doc2.RootElement.GetProperty("signature").GetProperty("keyId").GetString()!;

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.NotEqual(keyId1, keyId2);
    }

    /// <summary>
    /// Two SIGNED renders of unchanged data share one revision identity, but are NOT
    /// byte-identical — <c>ECDsa.SignData</c> is randomized (no RFC 6979 in .NET), so
    /// <c>signature.value</c> differs between the two even though <c>serialNumber</c>/
    /// <c>version</c> do not. This is consistent with, not an exception carved out of,
    /// <c>ResolveRevisionAsync</c>'s own "indistinguishable, not merely similar" comment: that
    /// comment scopes to the identity triple it returns (serial/revision/changed_at), and several
    /// other rendered fields already vary unfingerprinted across two same-revision renders
    /// (coverage/freshness stamps, <c>dependably:last-scan-at</c>) — a signature is one more.
    ///
    /// <para>Mutant: fold <c>signature.value</c> itself into the content fingerprint — this
    /// test's OWN premise (two renders of unchanged data sharing a revision) would then be false
    /// whenever a real key is configured, since a randomized signature would bump <c>version</c>
    /// on every single render. Verified by hand against this test; not committed as a
    /// mutation-testing fixture.</para>
    /// </summary>
    [Fact]
    public async Task RepeatedSignedRenders_NoDataChange_SameRevision_DespiteDifferentSignatureBytes()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-sig-repeat-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        await InsertComponentAsync(orgId, versionId, "pkg:npm/left-pad@1.0.0", "left-pad");

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string first = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial1, version1, timestamp1) = Identity(first);
        using var doc1 = JsonDocument.Parse(first);
        string sigValue1 = doc1.RootElement.GetProperty("signature").GetProperty("value").GetString()!;

        _clock.Advance(TimeSpan.FromHours(1));

        string second = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var (serial2, version2, timestamp2) = Identity(second);
        using var doc2 = JsonDocument.Parse(second);
        string sigValue2 = doc2.RootElement.GetProperty("signature").GetProperty("value").GetString()!;

        Assert.Equal(serial1, serial2);
        Assert.Equal(version1, version2);
        Assert.Equal(timestamp1, timestamp2);
        Assert.NotEqual(sigValue1, sigValue2);
    }

    /// <summary>
    /// Mutant that turns this red: drop <c>DependencyKind</c>/<c>DependencyScope</c>/
    /// <c>HasInstallScript</c> from <c>VexVulnFingerprintFacts</c> — a standalone VEX document
    /// would then keep the SAME identity across a rendered priority change (the finding's
    /// <c>EffectivePriority</c> reads the referenced component's dependency scope), which is
    /// worse than the constant <c>version = 1</c> it replaces: a stable identity that no longer
    /// tracks what the document actually says. Verified by hand against this test; not committed
    /// as a mutation-testing fixture.
    /// </summary>
    [Fact]
    public async Task VexDocument_ReferencedComponentDependencyScopeChange_BumpsVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-vex-dep-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId);
        string purl = "pkg:npm/left-pad@1.0.0";
        string compId = await InsertComponentAsync(
            orgId, versionId, purl, "left-pad", dependencyScope: "dev");
        string vulnId = await InsertVulnerabilityAsync("CVE-2100-8003");
        await LinkAsync(compId, vulnId, _clock.GetUtcNow());
        string? purlKey = SbomPurlKey.ForComponent("npm", "left-pad", purl);
        Assert.NotNull(purlKey);
        await InsertAnalysisAsync(orgId, versionId, purlKey!, "CVE-2100-8003", "exploitable", _clock.GetUtcNow());

        string first = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial1, version1, _) = Identity(first);
        Assert.Equal(1, version1);

        // Neither the vulnerability nor its analysis changes at all — only the referenced
        // component's dependency_scope, which changes the rendered priority via EffectivePriority.
        _clock.Advance(TimeSpan.FromHours(2));
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE sbom_components SET dependency_scope = 'runtime' WHERE id = @compId",
                new { compId });
        }

        string second = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        var (serial2, version2, _) = Identity(second);

        Assert.Equal(serial1, serial2);
        Assert.Equal(2, version2);
    }
}
