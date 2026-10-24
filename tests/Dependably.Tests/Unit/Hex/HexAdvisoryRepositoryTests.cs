using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The advisory projection behind the Hex <c>Package</c> resource, and the identity lookup behind
/// <c>GET /users/me</c>: grouping across owners, withdrawn exclusion, tolerant JSON parsing, and
/// the severity mapping onto the protocol enum.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexAdvisoryRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-1', 'org-1')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-2', 'org-2')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ListForOwners_NoOwnerIds_ReturnsEmptyWithoutQuerying()
    {
        var repo = new HexAdvisoryRepository(_db);

        var rows = await repo.ListForOwnersAsync(Array.Empty<string>());

        Assert.Empty(rows);
    }

    [Fact]
    public async Task ListForOwners_AdvisoryTouchingTwoOwners_GroupsIntoOneRowWithBothOwners()
    {
        string plug1 = await InsertCacheArtifactAsync("plug", "1.15.0");
        string plug2 = await InsertCacheArtifactAsync("plug", "1.15.1");
        await InsertVulnAsync("v-1", "GHSA-aaaa-bbbb-cccc", "Header injection", "HIGH", 7.5, "[\"CVE-2026-0001\"]", null);
        await LinkAsync("v-1", plug1);
        await LinkAsync("v-1", plug2);

        var rows = await new HexAdvisoryRepository(_db).ListForOwnersAsync(new List<string> { plug1, plug2 });

        var row = Assert.Single(rows);
        Assert.Equal("GHSA-aaaa-bbbb-cccc", row.OsvId);
        Assert.Equal("Header injection", row.Summary);
        Assert.Equal("HIGH", row.Severity);
        Assert.Equal(7.5, row.CvssScore);
        Assert.Equal(new[] { "CVE-2026-0001" }, row.Aliases);
        Assert.Equal(new[] { plug1, plug2 }.OrderBy(x => x, StringComparer.Ordinal), row.OwnerIds.OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public async Task ListForOwners_MixedAdvisories_DropsWithdrawnAndOutOfScope_AndOrdersByOsvId()
    {
        string jason = await InsertCacheArtifactAsync("jason", "1.4.1");
        string phoenix = await InsertCacheArtifactAsync("phoenix", "1.7.0");
        await InsertVulnAsync("v-z", "OSV-2026-0009", "Late id", "CRITICAL", 9.8, null, null);
        await InsertVulnAsync("v-a", "OSV-2026-0001", "Early id", "LOW", 2.0, "not json", "{\"id\":\"OSV-2026-0001\"}");
        await InsertVulnAsync("v-w", "OSV-2026-0005", "Retracted", "HIGH", 8.0, null, "{\"withdrawn\":\"2026-01-01T00:00:00Z\"}");
        await InsertVulnAsync("v-bad", "OSV-2026-0006", "Garbled detail", "MEDIUM", 5.0, null, "{ nope");
        await InsertVulnAsync("v-other", "OSV-2026-0007", "Unrequested owner", "HIGH", 8.0, null, null);
        await LinkAsync("v-z", jason);
        await LinkAsync("v-a", jason);
        await LinkAsync("v-w", jason);
        await LinkAsync("v-bad", phoenix);
        await LinkAsync("v-other", phoenix);

        var rows = await new HexAdvisoryRepository(_db).ListForOwnersAsync(new List<string> { jason });

        Assert.Equal(new[] { "OSV-2026-0001", "OSV-2026-0009" }, rows.Select(r => r.OsvId));
        Assert.Empty(rows[0].Aliases);
        Assert.Empty(rows[1].Aliases);

        var both = await new HexAdvisoryRepository(_db).ListForOwnersAsync(new List<string> { jason, phoenix });
        Assert.Equal(
            new[] { "OSV-2026-0001", "OSV-2026-0006", "OSV-2026-0007", "OSV-2026-0009" },
            both.Select(r => r.OsvId));
    }

    [Fact]
    public async Task ListForOwners_WithdrawnMarkerThatIsNotAString_IsNotTreatedAsWithdrawn()
    {
        string ecto = await InsertCacheArtifactAsync("ecto", "3.11.0");
        await InsertVulnAsync("v-n", "OSV-2026-0010", "Null withdrawn", "LOW", 3.0, null, "{\"withdrawn\":null}");
        await LinkAsync("v-n", ecto);

        var rows = await new HexAdvisoryRepository(_db).ListForOwnersAsync(new List<string> { ecto });

        Assert.Equal("OSV-2026-0010", Assert.Single(rows).OsvId);
    }

    [Fact]
    public async Task ListForOwners_AliasesJsonNull_YieldsNoAliases()
    {
        string cowboy = await InsertCacheArtifactAsync("cowboy", "2.12.0");
        await InsertVulnAsync("v-nl", "OSV-2026-0011", "Literal null aliases", "LOW", 3.0, "null", null);
        await LinkAsync("v-nl", cowboy);

        var rows = await new HexAdvisoryRepository(_db).ListForOwnersAsync(new List<string> { cowboy });

        Assert.Empty(Assert.Single(rows).Aliases);
    }

    [Fact]
    public void ToWire_ScoredAdvisoryWithAliases_CarriesOsvUrlsSeverityAndScore()
    {
        var row = new HexAdvisoryRow("GHSA-x y", "Open redirect", "MEDIUM", 6.1, new List<string> { "CVE-2026-1" }, new List<string> { "o" });

        var wire = HexAdvisoryRepository.ToWire(row);

        Assert.Equal("GHSA-x y", wire.Id);
        Assert.Equal("Open redirect", wire.Summary);
        Assert.Equal("https://osv.dev/vulnerability/GHSA-x%20y", wire.HtmlUrl);
        Assert.Equal("https://api.osv.dev/v1/vulns/GHSA-x%20y", wire.ApiUrl);
        Assert.Equal(HexAdvisorySeverity.Medium, wire.Severity);
        Assert.Equal(6.1f, wire.CvssScore);
        Assert.Equal(new[] { "CVE-2026-1" }, wire.Aliases);
    }

    [Fact]
    public void ToWire_UnscoredAdvisoryWithBlankSummary_FallsBackToIdAndOmitsOptionalFields()
    {
        var row = new HexAdvisoryRow("OSV-2026-0002", "   ", null, null, Array.Empty<string>(), new List<string>());

        var wire = HexAdvisoryRepository.ToWire(row);

        Assert.Equal("OSV-2026-0002", wire.Summary);
        Assert.Null(wire.Severity);
        Assert.Null(wire.CvssScore);
        Assert.Null(wire.Aliases);
    }

    [Theory]
    [InlineData("CRITICAL", HexAdvisorySeverity.Critical)]
    [InlineData("HIGH", HexAdvisorySeverity.High)]
    [InlineData("MEDIUM", HexAdvisorySeverity.Medium)]
    [InlineData("MODERATE", HexAdvisorySeverity.Medium)]
    [InlineData("LOW", HexAdvisorySeverity.Low)]
    [InlineData("NONE", HexAdvisorySeverity.None)]
    public void SeverityToWire_KnownBands_MapOntoTheProtocolEnum(string band, HexAdvisorySeverity expected) =>
        Assert.Equal(expected, HexAdvisoryRepository.SeverityToWire(band));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("UNKNOWN")]
    [InlineData("high")]
    public void SeverityToWire_UnrecognisedBand_CarriesNoBand(string? band) =>
        Assert.Null(HexAdvisoryRepository.SeverityToWire(band));

    [Fact]
    public async Task DisplayName_UserToken_ReturnsTheUsersEmail()
    {
        await InsertUserAsync("u-1", "org-1", "josevalim@example.com");
        var lookup = new HexIdentityLookup(_db);

        string? name = await lookup.DisplayNameForAsync("org-1", new TokenRecord { UserId = "u-1" });

        Assert.Equal("josevalim@example.com", name);
    }

    [Fact]
    public async Task DisplayName_ServiceTokenWithoutUser_ReturnsNull()
    {
        var lookup = new HexIdentityLookup(_db);

        Assert.Null(await lookup.DisplayNameForAsync("org-1", new TokenRecord { UserId = null }));
        Assert.Null(await lookup.DisplayNameForAsync("org-1", new TokenRecord { UserId = "" }));
    }

    [Fact]
    public async Task DisplayName_UserOfAnotherOrg_ReturnsNull()
    {
        await InsertUserAsync("u-2", "org-2", "chrismccord@example.com");
        var lookup = new HexIdentityLookup(_db);

        Assert.Null(await lookup.DisplayNameForAsync("org-1", new TokenRecord { UserId = "u-2" }));
        Assert.Null(await lookup.DisplayNameForAsync("org-1", new TokenRecord { UserId = "missing" }));
    }

    private async Task InsertUserAsync(string id, string orgId, string email)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @orgId, @email, 'x', 'admin')",
            new { id, orgId, email });
    }

    private async Task<string> InsertCacheArtifactAsync(string name, string version)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES
                (@id, 'hex', @name, @version, @filename, @blobKey, @contentHash, 0)
            """,
            new
            {
                id,
                name,
                version,
                filename = $"{name}-{version}.tar",
                blobKey = $"proxy/hex/{name}/{version}/{name}-{version}.tar",
                contentHash = $"sha256:{Guid.NewGuid():N}",
            });
        return id;
    }

    private async Task InsertVulnAsync(string id, string osvId, string summary, string severity, double cvss, string? aliases, string? osvJson)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, aliases, summary, severity, cvss_score, osv_json)
            VALUES (@id, @osvId, 'hex', 'pkg', @aliases, @summary, @severity, @cvss, @osvJson)
            """,
            new { id, osvId, aliases, summary, severity, cvss, osvJson });
    }

    private async Task LinkAsync(string vulnId, string cacheArtifactId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind)
            VALUES (@id, @cacheArtifactId, @vulnId, 'cache_artifact')
            """,
            new { id = Guid.NewGuid().ToString("N"), cacheArtifactId, vulnId });
    }
}
