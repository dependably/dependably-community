using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the raw JSON wire shape of <c>GET /api/v1/projects/{projectId}/versions/{versionId}/analysis</c>
/// — the response body the <c>dependably-mcp</c> server's <c>get_project_version</c> tool parses
/// as <c>AnalysisResponse</c>/<c>AnalysisItem</c>/<c>RegistryInfo</c>/<c>PolicyViolation</c>/
/// <c>Advisory</c>. <see cref="Dependably.Api.ApiContractTests"/> pins parameters and status codes
/// only; nothing else asserts a response field name against the value another project's client
/// code reads, so a renamed C# property here breaks the MCP client silently while every other
/// gate stays green.
///
/// <para>Every field is read with <see cref="JsonWire.Field"/>, which fails naming the absent
/// field and listing the siblings that are present — the same raw-JSON discipline
/// <c>EcosystemsApiTests</c> uses, and deliberately not a typed-DTO round-trip, which would
/// assert nothing about the wire.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProjectVersionAnalysisWireShapeTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public ProjectVersionAnalysisWireShapeTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task Analysis_TopLevelAndItemFields_MatchTheMcpWireContract()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();

        string orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");

        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', @projectName, 'application', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { projectId, orgId, projectName = $"wire-shape-{Guid.NewGuid():N}" });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { versionId, orgId, projectId });

        // One component that exercises every branch the MCP compactAnalysis() reads: a hosted
        // registry match (present/blocked/deprecated/latestVersion/outdated all non-null), one
        // materialized policy finding, and one advisory carrying a VEX statement.
        string componentId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_scope, dependency_kind, license_spdx, created_at)
            VALUES
                (@id, @orgId, @versionId, 'pkg:npm/lodash@4.17.21', 'npm', 'lodash', '4.17.21', 'lodash',
                 'library', 'required', 'runtime', 'direct', 'MIT', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = componentId, orgId, versionId });

        string packageId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, upstream_latest_version, created_at)
            VALUES (@id, @orgId, 'npm', 'lodash', 'lodash', '5.0.0', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = packageId, orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, manual_block_state, deprecated, created_at)
            VALUES
                (@id, @packageId, '4.17.21', 'pkg:npm/lodash@4.17.21', 'registry/npm/lodash/4.17.21/lodash-4.17.21.tgz',
                 'blocked', 'Use lodash-es instead.', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), packageId });

        string vulnId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, is_kev, fetched_at)
            VALUES (@id, 'CVE-2024-9999', 'npm', 'lodash', 'HIGH', 8.5, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = vulnId });
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });

        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source, reachability, updated_at)
            VALUES
                (@id, @orgId, @versionId, 'pkg:npm/lodash', 'CVE-2024-9999', 'exploitable', 'manual', 'reachable',
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId });

        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_policy_findings (id, org_id, project_version_id, component_id, arm, license_spdx, detail, created_at)
            VALUES
                (@id, @orgId, @versionId, @componentId, 'license', 'MIT', 'License requires manual review.',
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId, componentId });

        using var client = await AdminClient();
        using var resp = await client.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/analysis");
        resp.EnsureSuccessStatusCode();
        var body = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        // ── Top level ────────────────────────────────────────────────────────────────────────
        Assert.Equal(JsonValueKind.Object, body.Field("rollup").ValueKind);
        Assert.Equal(1, body.Field("page").GetInt32());
        Assert.Equal(SbomAnalysisProjection.DefaultPageSize, body.Field("limit").GetInt32());
        Assert.True(body.Field("total").GetInt32() >= 1);
        var items = body.Field("items");
        Assert.Equal(JsonValueKind.Array, items.ValueKind);
        Assert.Equal(JsonValueKind.Array, body.Field("orphanAnalysis").ValueKind);

        var item = items.EnumerateArray().Single(i => i.Field("componentId").GetString() == componentId);

        // ── Item fields ──────────────────────────────────────────────────────────────────────
        Assert.Equal("pkg:npm/lodash@4.17.21", item.Field("purl").GetString());
        Assert.Equal("lodash", item.Field("name").GetString());
        Assert.Equal("4.17.21", item.Field("version").GetString());
        Assert.Equal("npm", item.Field("ecosystem").GetString());
        Assert.Equal("runtime", item.Field("dependencyScope").GetString());
        Assert.True(item.Field("isProd").GetBoolean());
        Assert.Equal("direct", item.Field("dependencyKind").GetString());
        Assert.Equal("MIT", item.Field("licenseSpdx").GetString());

        // ── item.registry (non-empty, per the acceptance bar) ───────────────────────────────
        var registry = item.Field("registry");
        Assert.Equal(JsonValueKind.Object, registry.ValueKind);
        Assert.Equal("present", registry.Field("presence").GetString());
        Assert.Equal("version", registry.Field("blocked").GetString());
        Assert.Equal("version", registry.Field("deprecated").GetString());
        Assert.Equal("5.0.0", registry.Field("latestVersion").GetString());
        Assert.True(registry.Field("outdated").GetBoolean());

        // ── item.policyViolations[] (non-empty) ─────────────────────────────────────────────
        var violations = item.Field("policyViolations");
        Assert.Equal(JsonValueKind.Array, violations.ValueKind);
        var violation = Assert.Single(violations.EnumerateArray());
        Assert.Equal("license", violation.Field("arm").GetString());
        Assert.Equal("License requires manual review.", violation.Field("detail").GetString());

        // ── item.advisories[] (non-empty) ───────────────────────────────────────────────────
        var advisories = item.Field("advisories");
        Assert.Equal(JsonValueKind.Array, advisories.ValueKind);
        var advisory = Assert.Single(advisories.EnumerateArray());
        Assert.Equal("CVE-2024-9999", advisory.Field("vulnKey").GetString());
        Assert.Equal("CVE-2024-9999", advisory.Field("osvId").GetString());
        Assert.Equal("high", advisory.Field("severityBucket").GetString());
        Assert.Equal(8.5, advisory.Field("cvss").GetDouble());
        Assert.True(advisory.Field("isKev").GetBoolean());
        // IsKev alone floors the verdict at "act" regardless of every other signal.
        Assert.Equal("act", advisory.Field("effectivePriority").GetString());
        Assert.Equal("exploitable", advisory.Field("vexState").GetString());
        Assert.Equal("reachable", advisory.Field("reachability").GetString());
    }
}
