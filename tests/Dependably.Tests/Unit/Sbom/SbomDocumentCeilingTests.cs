using System.Data.Common;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Compliance;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The per-document entry ceilings and the batched write behind them.
///
/// <para>The byte cap on an upload bounds nothing useful on its own: minimal entries are cheap
/// to write and expensive to store, so a document comfortably inside it can declare hundreds of
/// thousands of statements or results. Each one became a row, a connection and a round trip on
/// the request thread, and the retraction sweep then re-read the whole set. The ceiling refuses
/// such a document the way the component ceiling already did, and the writer commits what is
/// left on one connection.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomDocumentCeilingTests
{
    // ── the ceilings ──────────────────────────────────────────────────────────

    [Fact]
    public void CycloneDx_RefusesMoreStatementsThanTheCeilingAdmits()
    {
        var ex = Assert.Throws<SbomParseException>(
            () => CycloneDxParser.Parse(Json(CycloneDxWithStatements(SbomDocumentLimits.MaxComponentStatements + 1))));

        Assert.Equal(SbomParseFailure.TooManyStatements, ex.Failure);
        Assert.Equal(SbomDocumentLimits.MaxComponentStatements.ToString(System.Globalization.CultureInfo.InvariantCulture), ex.Diagnostic);
    }

    [Fact]
    public void CycloneDx_AcceptsExactlyTheCeiling()
    {
        var document = CycloneDxParser.Parse(Json(CycloneDxWithStatements(SbomDocumentLimits.MaxComponentStatements)));

        Assert.Equal(SbomDocumentLimits.MaxComponentStatements, document.Statements.Count);
    }

    /// <summary>
    /// The shape counting parsed statements misses entirely. <c>affects[]</c> has no length limit
    /// of its own, so one statement can name any number of components — and every one of them is
    /// a row, a write and an entry in the retraction sweep's asserted set. Under a
    /// statement-count ceiling this document is a single statement and passes.
    /// </summary>
    [Fact]
    public void CycloneDx_RefusesOneStatementNamingMoreComponentsThanTheCeilingAdmits()
    {
        var ex = Assert.Throws<SbomParseException>(
            () => CycloneDxParser.Parse(Json(
                CycloneDxWithOneStatementNaming(SbomDocumentLimits.MaxComponentStatements + 1))));

        Assert.Equal(SbomParseFailure.TooManyStatements, ex.Failure);
    }

    [Fact]
    public void OpenVex_RefusesOneStatementNamingMoreComponentsThanTheCeilingAdmits()
    {
        var ex = Assert.Throws<SbomParseException>(
            () => OpenVexParser.Parse(Json(
                OpenVexWithOneStatementNaming(SbomDocumentLimits.MaxComponentStatements + 1))));

        Assert.Equal(SbomParseFailure.TooManyStatements, ex.Failure);
    }

    /// <summary>
    /// The charge is the product of the two array lengths, not either one alone: neither half of
    /// this document reaches the ceiling by itself.
    /// </summary>
    [Fact]
    public void CycloneDx_ChargesTheProductOfBothArrayLengths()
    {
        int half = SbomDocumentLimits.MaxComponentStatements / 2;

        // Two statements naming half the ceiling each is exactly the ceiling.
        var accepted = CycloneDxParser.Parse(Json(CycloneDxWithStatementsNaming(2, half)));
        Assert.Equal(2, accepted.Statements.Count);

        // One more component on each, and neither array is near the ceiling on its own.
        Assert.Throws<SbomParseException>(
            () => CycloneDxParser.Parse(Json(CycloneDxWithStatementsNaming(2, half + 1))));
    }

    /// <summary>
    /// A statement naming no component writes nothing, but charges one — otherwise a document of
    /// nothing but product-less statements would be admitted at any length.
    /// </summary>
    [Fact]
    public void CycloneDx_ChargesAStatementThatNamesNoComponent()
    {
        var ex = Assert.Throws<SbomParseException>(
            () => CycloneDxParser.Parse(Json(
                CycloneDxWithStatementsNaming(SbomDocumentLimits.MaxComponentStatements + 1, 0))));

        Assert.Equal(SbomParseFailure.TooManyStatements, ex.Failure);
    }

    [Fact]
    public void OpenVex_RefusesMoreStatementsThanTheCeilingAdmits()
    {
        var ex = Assert.Throws<SbomParseException>(
            () => OpenVexParser.Parse(Json(OpenVexWithStatements(SbomDocumentLimits.MaxComponentStatements + 1))));

        Assert.Equal(SbomParseFailure.TooManyStatements, ex.Failure);
    }

    [Fact]
    public void Sarif_RefusesMoreResultsThanTheCeilingAdmits()
    {
        var ex = Assert.Throws<SbomParseException>(
            () => SarifParser.Parse(Json(SarifWithResults(SbomDocumentLimits.MaxResults + 1))));

        Assert.Equal(SbomParseFailure.TooManyResults, ex.Failure);
        Assert.Equal(SbomDocumentLimits.MaxResults.ToString(System.Globalization.CultureInfo.InvariantCulture), ex.Diagnostic);
    }

    [Fact]
    public void Sarif_CountsResultsAcrossEveryRun()
    {
        // Split across two runs so a per-run counter would let the document through: the ceiling
        // bounds the rows one upload writes, and the producer chooses how many runs carry them.
        var ex = Assert.Throws<SbomParseException>(
            () => SarifParser.Parse(Json(SarifAcrossTwoRuns(SbomDocumentLimits.MaxResults + 1))));

        Assert.Equal(SbomParseFailure.TooManyResults, ex.Failure);
    }

    /// <summary>
    /// Every refusal a parser can raise names a localized message, in both catalogues. A failure
    /// with no key renders the enum name to an operator, which is the shape a new refusal is
    /// most likely to ship in.
    /// </summary>
    [Theory]
    [InlineData("error.sbom.tooManyComponents")]
    [InlineData("error.sbom.tooManyStatements")]
    [InlineData("error.sbom.tooManyResults")]
    public void EveryCeilingRefusal_NamesAMessageInEveryCatalogue(string key)
    {
        foreach (string file in new[] { "SharedResource.resx", "SharedResource.fr.resx" })
        {
            string resx = File.ReadAllText(Path.Combine(
                SourceRoots.RepoRoot(), "src", "Dependably.Core", "Resources", file));
            Assert.Contains($"\"{key}\"", resx, StringComparison.Ordinal);
        }
    }

    // ── the batched write ─────────────────────────────────────────────────────

    [Fact]
    public async Task ApplyingStatements_OpensTheSameNumberOfConnectionsWhateverTheStatementCount()
    {
        int forOne = await ConnectionsUsedApplyingVexAsync(statements: 1);
        int forMany = await ConnectionsUsedApplyingVexAsync(statements: 25);

        Assert.Equal(forOne, forMany);
    }

    [Fact]
    public async Task ApplyingResults_OpensTheSameNumberOfConnectionsWhateverTheResultCount()
    {
        int forOne = await ConnectionsUsedApplyingSarifAsync(results: 1);
        int forMany = await ConnectionsUsedApplyingSarifAsync(results: 25);

        Assert.Equal(forOne, forMany);
    }

    [Fact]
    public async Task ApplyingStatements_StillWritesEveryRow()
    {
        var (store, orgId, versionId) = await SeedAsync();
        await using var _ = store;

        var merge = new SbomMergeService(new SbomIngestRepository(store));
        var parsed = CycloneDxParser.Parse(Json(CycloneDxWithStatements(25)));
        var application = await merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, parsed.Statements, actorId: null, TestTime.KnownNow);

        Assert.Equal(25, application.Counts.Total);
        Assert.Equal(25, await AnalysisRowCountAsync(store, orgId, versionId));
    }

    // ── harness ───────────────────────────────────────────────────────────────

    private static JsonElement Json(string raw) => JsonDocument.Parse(raw).RootElement;

    private static async Task<int> ConnectionsUsedApplyingVexAsync(int statements)
    {
        var (store, orgId, versionId) = await SeedAsync();
        await using var _ = store;

        var merge = new SbomMergeService(new SbomIngestRepository(store));
        var parsed = CycloneDxParser.Parse(Json(CycloneDxWithStatements(statements)));

        store.ResetOpens();
        await merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, parsed.Statements, actorId: null, TestTime.KnownNow);
        return store.Opens;
    }

    private static async Task<int> ConnectionsUsedApplyingSarifAsync(int results)
    {
        var (store, orgId, versionId) = await SeedAsync();
        await using var _ = store;

        var merge = new SbomMergeService(new SbomIngestRepository(store));
        var parsed = SarifParser.Parse(Json(SarifWithResults(results)));

        store.ResetOpens();
        await merge.ApplySarifAsync(orgId, versionId, parsed, actorId: null, TestTime.KnownNow);
        return store.Opens;
    }

    private static async Task<(CountingMetadataStore Store, string OrgId, string VersionId)> SeedAsync()
    {
        var inner = new TestMetadataStore();
        await new SchemaInitializer(inner).InitializeAsync();
        var store = new CountingMetadataStore(inner);

        string orgId = await OrgSeeder.InsertAsync(inner, $"o-{Guid.NewGuid():N}");
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");

        await using var conn = await inner.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
            new { projectId, orgId, name = $"proj-{projectId[..8]}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
            new { versionId, orgId, projectId });
        return (store, orgId, versionId);
    }

    private static async Task<int> AnalysisRowCountAsync(
        CountingMetadataStore store, string orgId, string versionId)
    {
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId
            """,
            new { orgId, versionId });
    }

    /// <summary>Counts how many connections a code path opens, and otherwise delegates whole.</summary>
    private sealed class CountingMetadataStore : IMetadataStore, IAsyncDisposable
    {
        private readonly TestMetadataStore _inner;
        private int _opens;

        public CountingMetadataStore(TestMetadataStore inner) => _inner = inner;

        public int Opens => _opens;

        public DbProvider Provider => _inner.Provider;

        public void ResetOpens() => Interlocked.Exchange(ref _opens, 0);

        public Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            Interlocked.Increment(ref _opens);
            return _inner.OpenAsync(ct);
        }

        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }

    // ── fixtures ──────────────────────────────────────────────────────────────

    /// <summary>One CycloneDX document: <paramref name="statements"/> statements, each naming
    /// <paramref name="products"/> components.</summary>
    private static string CycloneDxWithStatementsNaming(int statements, int products)
    {
        var sb = new StringBuilder(
            """{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[""");
        for (int i = 0; i < statements; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append("{\"id\":\"CVE-2100-").Append(i).Append("\",\"affects\":[");
            for (int j = 0; j < products; j++)
            {
                if (j > 0)
                {
                    sb.Append(',');
                }

                sb.Append("{\"ref\":\"pkg:npm/dep-").Append(j).Append("@1.0.0\"}");
            }

            sb.Append("]}");
        }

        return sb.Append("]}").ToString();
    }

    private static string CycloneDxWithOneStatementNaming(int products) =>
        CycloneDxWithStatementsNaming(1, products);

    private static string OpenVexWithOneStatementNaming(int products)
    {
        var sb = new StringBuilder(
            """{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":"CVE-2100-0","status":"not_affected","products":[""");
        for (int j = 0; j < products; j++)
        {
            if (j > 0)
            {
                sb.Append(',');
            }

            sb.Append("{\"@id\":\"pkg:npm/dep-").Append(j).Append("@1.0.0\"}");
        }

        return sb.Append("]}]}").ToString();
    }

    private static string CycloneDxWithStatements(int count)
    {
        var sb = new StringBuilder(
            """{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[""");
        for (int i = 0; i < count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append("{\"id\":\"CVE-2100-").Append(i)
              .Append("\",\"affects\":[{\"ref\":\"pkg:npm/lodash@4.17.21\"}]}");
        }

        return sb.Append("]}").ToString();
    }

    private static string OpenVexWithStatements(int count)
    {
        var sb = new StringBuilder(
            """{"@context":"https://openvex.dev/ns/v0.2.0","statements":[""");
        for (int i = 0; i < count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append("{\"vulnerability\":\"CVE-2100-").Append(i)
              .Append("\",\"status\":\"not_affected\"}");
        }

        return sb.Append("]}").ToString();
    }

    private static string SarifWithResults(int count) =>
        $$"""{"version":"2.1.0","runs":[{"results":[{{ResultsJson(0, count)}}]}]}""";

    private static string SarifAcrossTwoRuns(int count) =>
        $$"""
          {"version":"2.1.0","runs":[
            {"results":[{{ResultsJson(0, count / 2)}}]},
            {"results":[{{ResultsJson(count / 2, count - (count / 2))}}]}
          ]}
          """;

    private static string ResultsJson(int start, int count)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append("{\"ruleId\":\"CVE-2100-").Append(start + i)
              .Append("\",\"properties\":{\"purl\":\"pkg:npm/lodash@4.17.21\"}}");
        }

        return sb.ToString();
    }
}
