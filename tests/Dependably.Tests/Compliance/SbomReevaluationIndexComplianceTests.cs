using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Compliance;

/// <summary>
/// The nightly SBOM policy re-evaluation's driver is a <c>SELECT DISTINCT sc.org_id,
/// sc.project_version_id FROM sbom_components sc …</c>. Neither <c>idx_sbom_components_pv</c>
/// (project_version_id alone) nor <c>idx_sbom_components_org_eco_name</c> (org_id, ecosystem,
/// purl_name) has that pair as a leading prefix, so without a covering index the sweep is a full
/// scan of every component row in the instance — millions of rows nightly at a modest catalogue
/// size, and a cost that grows with total history rather than with what changed.
///
/// <para>A missing index degrades silently: the query still returns the right answer, just slowly,
/// so nothing in the functional suite goes red. This gate is the thing that goes red instead —
/// declared in both provider schema files, and present on a database the initializer actually
/// built.</para>
/// </summary>
public sealed class SbomReevaluationIndexComplianceTests
{
    private const string IndexName = "idx_sbom_components_org_pv";

    [Trait("Category", "Schema")]
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BothProviderSchemas_DeclareTheCoveringIndex(bool sqlite)
    {
        string root = SchemaTestPaths.SourceRoot();
        string path = sqlite ? SchemaTestPaths.SqliteSchema(root) : SchemaTestPaths.PostgresSchema(root);
        string sql = File.ReadAllText(path);

        Assert.Contains(IndexName, sql, StringComparison.Ordinal);
        Assert.Contains("ON sbom_components(org_id, project_version_id)", sql, StringComparison.Ordinal);
    }

    /// <summary>
    /// The declaration-site half of the base-schema-vs-additive-migration ordering trap: an index
    /// naming a column that only exists after <c>RunAdditiveMigrationsAsync</c> cannot be declared
    /// in the schema files, because those run first. Both columns here come from the
    /// <c>sbom_components</c> CREATE TABLE block, so the schema-file declaration is correct — and
    /// this test proves the ordering empirically by building a database through the real
    /// initializer and reading the index back out.
    /// </summary>
    [Trait("Category", "Unit")]
    [Fact]
    public async Task InitializedDatabase_CarriesTheCoveringIndex()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        await using var conn = await db.OpenAsync();
        string? found = await conn.ExecuteScalarAsync<string?>(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = @name",
            new { name = IndexName });

        Assert.Equal(IndexName, found);
    }
}
