using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit;

/// <summary>
/// The boot pass that folds stored <c>quarantine.purl</c> values for OCI onto the canonical form
/// <see cref="PurlNormalizer.Oci"/> derives.
///
/// <para>Fixing the write path leaves the rows already at rest on the interpolated spelling, and
/// nothing else rewrites them. <c>HasApprovedForPurlAsync</c> is what the block gate consults —
/// "an approved review row on the purl is the unblock signal" — so an operator who approved a
/// blocked image before the upgrade would keep a row the gate can no longer see: the image is
/// blocked again while the review UI still renders it approved. These cases therefore assert
/// through the real reader rather than only against the stored string.</para>
///
/// <para>The rows are seeded by hand because no writer produces the stale shape any more; it is
/// what a deployment holds after quarantining through the pre-fix controllers.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciQuarantinePurlMigrationTests : IAsyncLifetime
{
    private const string Repository = "library/alpine";
    private const string Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    // What the pre-fix OCI controllers interpolated.
    private const string StalePurl =
        "pkg:oci/library/alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111";

    private static string CanonicalPurl => PurlNormalizer.Oci(Repository, Digest);

    private readonly TestMetadataStore _db = new();
    private string _orgId = "";
    private QuarantineRepository _quarantine = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, $"ociqp-{Guid.NewGuid():N}");
        _quarantine = new QuarantineRepository(_db, TestTime.Frozen());
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ApprovalRecordedUnderTheStaleSpelling_IsFoundByTheGateAfterTheMigration()
    {
        await SeedQuarantineAsync(StalePurl, "approved");

        // The premise. If the gate could already find it, the migration would be untestable and
        // this whole pass unnecessary — so prove the gap exists before proving it is closed.
        Assert.False(
            await _quarantine.HasApprovedForPurlAsync(_orgId, CanonicalPurl),
            "pre-migration: the canonical spelling must NOT resolve, or this test proves nothing");

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.True(
            await _quarantine.HasApprovedForPurlAsync(_orgId, CanonicalPurl),
            "post-migration: the operator's approval must survive under the spelling the gate now asks with");
    }

    [Fact]
    public async Task StaleRowIsRewritten_NotDuplicated()
    {
        await SeedQuarantineAsync(StalePurl, "pending");

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var purls = (await conn.QueryAsync<string>(
            "SELECT purl FROM quarantine WHERE org_id = @orgId", new { orgId = _orgId })).ToList();

        Assert.Equal(new[] { CanonicalPurl }, purls);
    }

    /// <summary>
    /// <c>UNIQUE (org_id, purl)</c> refuses a rewrite onto an existing canonical row. The
    /// canonical row survives, but a decision recorded on the stale row is not reconstructible and
    /// must outrank that choice — otherwise the merge silently revokes an approval.
    /// </summary>
    [Fact]
    public async Task CollisionKeepsTheRecordedDecision_NotThePendingSurvivor()
    {
        await SeedQuarantineAsync(StalePurl, "approved");
        await SeedQuarantineAsync(CanonicalPurl, "pending");

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var rows = (await conn.QueryAsync<(string Purl, string State)>(
            "SELECT purl AS Purl, state AS State FROM quarantine WHERE org_id = @orgId",
            new { orgId = _orgId })).ToList();

        var (purl, state) = Assert.Single(rows);
        Assert.Equal(CanonicalPurl, purl);
        Assert.Equal("approved", state);
        Assert.True(await _quarantine.HasApprovedForPurlAsync(_orgId, CanonicalPurl));
    }

    /// <summary>An already-canonical row is left byte-identical — the pass is convergent.</summary>
    [Fact]
    public async Task AlreadyCanonicalRow_IsUntouched()
    {
        await SeedQuarantineAsync(CanonicalPurl, "approved");

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        string purl = await conn.ExecuteScalarAsync<string>(
            "SELECT purl FROM quarantine WHERE org_id = @orgId", new { orgId = _orgId }) ?? "";

        Assert.Equal(CanonicalPurl, purl);
    }

    [Theory]
    // The interpolated digest form is the one shape this pass rewrites.
    [InlineData("pkg:oci/library/alpine@sha256:abc", "pkg:oci/alpine@sha256%3Aabc?repository_url=library/alpine")]
    [InlineData("pkg:oci/unsloth/unsloth@sha256:def", "pkg:oci/unsloth@sha256%3Adef?repository_url=unsloth/unsloth")]
    [InlineData("pkg:oci/alpine@sha256:abc", "pkg:oci/alpine@sha256%3Aabc?repository_url=alpine")]
    public void InterpolatedForm_IsRewrittenToTheCanonicalSpelling(string stored, string expected)
        => Assert.Equal(expected, SchemaInitializer.TryCanonicalizeOciPurl(stored));

    [Theory]
    // Already canonical — carries the qualifier, so it is recognised and left alone.
    [InlineData("pkg:oci/alpine@sha256%3Aabc?repository_url=library/alpine")]
    // The tag-coordinate form the delete path used to write. It names no digest, so there is no
    // canonical PURL to fold it onto; guessing one would invent an identity.
    [InlineData("pkg:oci/library/alpine:3.20")]
    // Another ecosystem's purl must never be touched by an OCI pass.
    [InlineData("pkg:npm/left-pad@1.3.0")]
    // Malformed shapes are left exactly as stored rather than guessed at.
    [InlineData("pkg:oci/library/alpine@")]
    [InlineData("pkg:oci/@sha256:abc")]
    [InlineData("not-a-purl")]
    public void UnrecognisedShapes_AreLeftAlone(string stored)
        => Assert.Null(SchemaInitializer.TryCanonicalizeOciPurl(stored));

    private async Task SeedQuarantineAsync(string purl, string state)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO quarantine (id, org_id, ecosystem, purl, gate, state)
            VALUES (@id, @orgId, 'oci', @purl, 'malicious', @state)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId = _orgId, purl, state });
    }
}
