using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// Schema migration: <c>project_documents.signature_status</c> must permit the new 'unanchored'
/// value (<c>SbomSignatureVerdict.UnanchoredStatus</c>) on both fresh and existing databases.
/// Mirrors <see cref="BlockDeprecatedMigrationTests"/> — this column's CHECK is the nullable
/// shape (<c>CHECK (col IS NULL OR col IN (...))</c>), which is exactly what
/// <c>VerifyCheckAdmitsAsync</c>'s own bug (before this file existed to pin it) let a widen of
/// this specific column pass unverified: the wrong marker made the rewrite's own success check
/// unconditionally vacuous, so a stale literal or a stale stored-schema match would never have
/// been caught.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SignatureStatusCheckMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FreshSchema_AcceptsUnanchoredSignatureStatus()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES ('p1','o1','app')");
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES ('v1','o1','p1','1.0.0')");

        await conn.ExecuteAsync("""
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, sha256, blob_key, signature_status)
            VALUES
                ('d1', 'o1', 'v1', 'sbom', 'cyclonedx-json', 'x', 'x', 'unanchored')
            """);

        string? stored = await conn.ExecuteScalarAsync<string>(
            "SELECT signature_status FROM project_documents WHERE id = 'd1'");
        Assert.Equal("unanchored", stored);
    }

    [Fact]
    public async Task LegacySchemaWithOldThreeValueCheck_MigratedInPlace_WidensCheckToAdmitUnanchored()
    {
        // Simulate a database whose project_documents predates the 'unanchored' widen: recreate
        // it with the OLD nullable 3-value CHECK the SQLite rewrite targets, then re-run the
        // initializer. Additive ALTERs backfill the columns this minimal stand-in omits.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-legacy','legacy')");
            await setup.ExecuteAsync(
                "INSERT INTO projects (id, org_id, name) VALUES ('p-legacy','o-legacy','app')");
            await setup.ExecuteAsync(
                "INSERT INTO project_versions (id, org_id, project_id, version) VALUES ('v-legacy','o-legacy','p-legacy','1.0.0')");
            await setup.ExecuteAsync("DROP TABLE IF EXISTS project_documents");
            await setup.ExecuteAsync("""
                CREATE TABLE project_documents (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    project_version_id TEXT NOT NULL,
                    doc_type TEXT NOT NULL CHECK (doc_type IN ('sbom','vex','sarif')),
                    format TEXT NOT NULL CHECK (format IN ('cyclonedx-json','openvex-json','sarif-json','spdx-json')),
                    sha256 TEXT NOT NULL,
                    blob_key TEXT NOT NULL,
                    signature_status TEXT CHECK (signature_status IS NULL OR signature_status IN ('verified','failed','unsigned')),
                    UNIQUE (project_version_id, doc_type)
                )
                """);
            await setup.ExecuteAsync("""
                INSERT INTO project_documents
                    (id, org_id, project_version_id, doc_type, format, sha256, blob_key, signature_status)
                VALUES
                    ('d-legacy', 'o-legacy', 'v-legacy', 'sbom', 'cyclonedx-json', 'x', 'x', 'unsigned')
                """);

            // Mark the one-shot as not-yet-applied so re-init runs it.
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_signature_status_check_unanchored'");

            // Sanity: the legacy CHECK rejects the new value.
            var ex = await Assert.ThrowsAsync<SqliteException>(() => setup.ExecuteAsync(
                "UPDATE project_documents SET signature_status = 'unanchored' WHERE id = 'd-legacy'"));
            Assert.Contains("CHECK", ex.Message);
        }

        // Re-run initializer; the CHECK widen should apply and be verified.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();

        // The pre-existing row survives the rewrite untouched.
        string? untouched = await verify.ExecuteScalarAsync<string>(
            "SELECT signature_status FROM project_documents WHERE id = 'd-legacy'");
        Assert.Equal("unsigned", untouched);

        // Widened CHECK now accepts 'unanchored'.
        await verify.ExecuteAsync(
            "UPDATE project_documents SET signature_status = 'unanchored' WHERE id = 'd-legacy'");
        string? widened = await verify.ExecuteScalarAsync<string>(
            "SELECT signature_status FROM project_documents WHERE id = 'd-legacy'");
        Assert.Equal("unanchored", widened);
    }

    /// <summary>
    /// Pins <c>VerifyCheckAdmitsAsync</c>'s own verification specifically — not just the
    /// migration's end-to-end outcome (the test above), which the rewrite alone already
    /// satisfies whether or not verification does anything. The nullable-CHECK marker fix is
    /// what makes this test distinguish "the rewrite ran and actually widened the CHECK" from
    /// "the rewrite silently no-op'd and allowMissingCheck swallowed it" — before that fix,
    /// verification for `signature_status` could NEVER match (the marker only recognised the
    /// bare `CHECK (col IN (...))` shape, never the nullable one this column actually uses), so
    /// it fell through to allowMissingCheck and returned without checking anything, regardless of
    /// whether a real narrow CHECK — one the rewrite failed to widen — was still in force.
    ///
    /// <para>Simulated here by storing the OLD CHECK clause with different (but semantically
    /// identical) whitespace than <c>ExpandSignatureStatusCheckSqliteAsync</c>'s own literal
    /// `REPLACE` target — an exact-substring rewrite that therefore cannot match, leaving the
    /// narrow CHECK in force, exactly what a future edit to either the literal or Schema.sql's
    /// own formatting would produce by accident. `Flatten`-based verification (whitespace- and
    /// case-insensitive) still correctly recognises the nullable clause and must throw rather
    /// than silently accepting the untouched, still-narrow CHECK.</para>
    /// </summary>
    [Fact]
    public async Task RewriteThatFailsToMatchTheStoredCheckText_ThrowsRatherThanSilentlyPassingVerification()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS project_documents");
            // Same clause as the real old CHECK, but with a space after each comma — an exact
            // substring match against ExpandSignatureStatusCheckSqliteAsync's literal (no spaces)
            // therefore fails, so the REPLACE this migration issues touches nothing.
            await setup.ExecuteAsync("""
                CREATE TABLE project_documents (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    project_version_id TEXT NOT NULL,
                    doc_type TEXT NOT NULL CHECK (doc_type IN ('sbom','vex','sarif')),
                    format TEXT NOT NULL CHECK (format IN ('cyclonedx-json','openvex-json','sarif-json','spdx-json')),
                    sha256 TEXT NOT NULL,
                    blob_key TEXT NOT NULL,
                    signature_status TEXT CHECK (signature_status IS NULL OR signature_status IN ('verified', 'failed', 'unsigned')),
                    UNIQUE (project_version_id, doc_type)
                )
                """);
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_signature_status_check_unanchored'");
        }

        // The rewrite's own REPLACE cannot match this database's spacing, so the CHECK stays
        // narrow — verification must be the thing that notices and refuses to record the
        // migration as successfully applied.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new SchemaInitializer(_db).InitializeAsync());
        Assert.Contains("does not admit 'unanchored'", ex.Message, StringComparison.Ordinal);
    }
}
