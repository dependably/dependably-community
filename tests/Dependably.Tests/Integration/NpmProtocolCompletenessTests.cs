using System.Net;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for the npm protocol completeness features:
/// persisted dist-tags, dist-tag management routes, npm deprecate, npm unpublish,
/// and npm search — including org-isolation checks.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmProtocolCompletenessTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NpmProtocolCompletenessTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a second org and returns a push-capable token bound to it. The token is
    /// NOT valid for the default org, so using it against default-org routes should be
    /// rejected — exercising the token.OrgId != orgId cross-tenant guard.
    /// </summary>
    private async Task<string> CreateOtherOrgPushTokenAsync()
    {
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var other = await orgRepo.CreateOrgAsync($"npm-other-{Guid.NewGuid():N}"[..24]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            other.Id,
            $"npm-xtok-{Guid.NewGuid():N}"[..20],
            """["publish:*","read:artifact","read:metadata","yank:*"]""",
            expiresAt: null);
        return raw;
    }

    // Publish a package with an explicit dist-tag in the packument body.
    // Uses System.Text.Json.Nodes.JsonObject to serialize the hyphenated "dist-tags" key
    // (C# anonymous objects can't include hyphens in property names).
    private async Task PushWithTag(string name, string version, string tag)
    {
        string token = await _factory.CreateToken("push");
        var (tarball, _, integrity) = NpmFixtures.BuildTarball(name, version);
        string base64 = Convert.ToBase64String(tarball);
        string filename = $"{name}-{version}.tgz";

        var bodyNode = new System.Text.Json.Nodes.JsonObject
        {
            ["name"] = name,
            ["versions"] = new System.Text.Json.Nodes.JsonObject
            {
                [version] = new System.Text.Json.Nodes.JsonObject
                {
                    ["name"] = name,
                    ["version"] = version,
                    ["dist"] = new System.Text.Json.Nodes.JsonObject
                    {
                        ["tarball"] = $"https://reg/{filename}",
                        ["integrity"] = integrity
                    }
                }
            },
            ["dist-tags"] = new System.Text.Json.Nodes.JsonObject { [tag] = version },
            ["_attachments"] = new System.Text.Json.Nodes.JsonObject
            {
                [filename] = new System.Text.Json.Nodes.JsonObject
                {
                    ["content_type"] = "application/octet-stream",
                    ["data"] = base64,
                    ["length"] = tarball.Length
                }
            }
        };

        string body = bodyNode.ToJsonString();
        using var client = _factory.CreateClientWithBearer(token);
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/{name}", content);
        resp.EnsureSuccessStatusCode();
    }

    // ── Item 1: Persisted dist-tags ──────────────────────────────────────────────

    /// <summary>
    /// Publishing with --tag beta must NOT move the 'latest' tag. The 'latest' dist-tag
    /// should remain pointing at the stable version, not the newly-published beta.
    /// </summary>
    [Fact]
    public async Task Publish_BetaTag_DoesNotMoveLatesTag()
    {
        string pkg = $"disttag-beta-{Guid.NewGuid():N}"[..28].ToLowerInvariant();

        // Publish stable 1.0.0 first — gets 'latest'.
        await _factory.PushNpmPackage(pkg, "1.0.0");

        // Publish pre-release with explicit 'beta' tag.
        await PushWithTag(pkg, "2.0.0-beta.1", "beta");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(json);

        var distTags = doc.RootElement.GetProperty("dist-tags");

        // 'latest' must still be 1.0.0, not the beta.
        Assert.Equal("1.0.0", distTags.GetProperty("latest").GetString());
    }

    /// <summary>
    /// A beta publish with explicit tag should appear in the packument's dist-tags object.
    /// </summary>
    [Fact]
    public async Task Publish_WithExplicitTag_TagAppearsInPackument()
    {
        string pkg = $"disttag-explicit-{Guid.NewGuid():N}"[..28].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");
        await PushWithTag(pkg, "2.0.0-beta.1", "beta");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(json);
        var distTags = doc.RootElement.GetProperty("dist-tags");

        Assert.True(distTags.TryGetProperty("beta", out var betaEl));
        Assert.Equal("2.0.0-beta.1", betaEl.GetString());
    }

    // ── Item 2: dist-tag routes ──────────────────────────────────────────────────

    [Fact]
    public async Task GetDistTags_ExistingPackage_ReturnsTagMap()
    {
        string pkg = $"dt-get-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/-/package/{pkg}/dist-tags");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        // At minimum 'latest' should be present.
        Assert.True(doc.RootElement.TryGetProperty("latest", out _));
    }

    [Fact]
    public async Task PutDistTag_ValidVersion_SetsTag()
    {
        string pkg = $"dt-put-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Body must be a JSON string: the version number.
        using var content = new StringContent("\"1.0.0\"", Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/-/package/{pkg}/dist-tags/stable", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Verify by reading dist-tags.
        string json = await client.GetStringAsync($"/npm/-/package/{pkg}/dist-tags");
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("stable", out var stableEl));
        Assert.Equal("1.0.0", stableEl.GetString());
    }

    [Fact]
    public async Task PutDistTag_VersionDoesNotExist_Returns404()
    {
        string pkg = $"dt-put404-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        using var content = new StringContent("\"9.9.9\"", Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/-/package/{pkg}/dist-tags/nope", content);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task DeleteDistTag_NonLatestTag_Succeeds()
    {
        string pkg = $"dt-del-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // First set a 'beta' tag.
        using var putContent = new StringContent("\"1.0.0\"", Encoding.UTF8, "application/json");
        (await client.PutAsync($"/npm/-/package/{pkg}/dist-tags/beta", putContent)).EnsureSuccessStatusCode();

        // Now delete it.
        var deleteResp = await client.DeleteAsync($"/npm/-/package/{pkg}/dist-tags/beta");
        Assert.Equal(HttpStatusCode.NoContent, deleteResp.StatusCode);

        // Verify it's gone.
        string json = await client.GetStringAsync($"/npm/-/package/{pkg}/dist-tags");
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("beta", out _));
    }

    [Fact]
    public async Task DeleteDistTag_LatestTag_Returns400()
    {
        string pkg = $"dt-dellat-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.DeleteAsync($"/npm/-/package/{pkg}/dist-tags/latest");
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── Item 3: Deprecate ────────────────────────────────────────────────────────

    [Fact]
    public async Task Deprecate_SetsDeprecatedMessage_PackumentSurfacesIt()
    {
        string pkg = $"depr-set-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // npm deprecate shape: no _attachments, versions[version].deprecated set.
        string body = JsonSerializer.Serialize(new
        {
            name = pkg,
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = pkg, version = "1.0.0", deprecated = "Use new-pkg instead." }
            }
        });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/{pkg}", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Packument must contain the deprecated field on the version.
        string meta = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(meta);
        string? deprecated = doc.RootElement
            .GetProperty("versions").GetProperty("1.0.0")
            .TryGetProperty("deprecated", out var depEl) ? depEl.GetString() : null;
        Assert.Equal("Use new-pkg instead.", deprecated);
    }

    [Fact]
    public async Task Deprecate_EmptyMessage_ClearsDeprecation()
    {
        string pkg = $"depr-clr-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Set the deprecation first.
        string setBody = JsonSerializer.Serialize(new
        {
            name = pkg,
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = pkg, version = "1.0.0", deprecated = "old message" }
            }
        });
        (await client.PutAsync($"/npm/{pkg}", new StringContent(setBody, Encoding.UTF8, "application/json"))).EnsureSuccessStatusCode();

        // Clear it with an empty string.
        string clearBody = JsonSerializer.Serialize(new
        {
            name = pkg,
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = pkg, version = "1.0.0", deprecated = "" }
            }
        });
        (await client.PutAsync($"/npm/{pkg}", new StringContent(clearBody, Encoding.UTF8, "application/json"))).EnsureSuccessStatusCode();

        // Deprecated field should not appear in the packument.
        string meta = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(meta);
        Assert.False(
            doc.RootElement.GetProperty("versions").GetProperty("1.0.0").TryGetProperty("deprecated", out _),
            "deprecated field should be absent after clearing");
    }

    [Fact]
    public async Task Deprecate_MixedVersions_SomeSucceedSomeMissing()
    {
        string pkg = $"depr-mix-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");
        // Only 1.0.0 exists; 2.0.0 does not.

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Deprecate both versions — only 1.0.0 should apply.
        string body = JsonSerializer.Serialize(new
        {
            name = pkg,
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new { name = pkg, version = "1.0.0", deprecated = "msg" },
                ["2.0.0"] = new { name = pkg, version = "2.0.0", deprecated = "msg" }
            }
        });
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        // Should succeed (partial update, missing versions are skipped).
        var resp = await client.PutAsync($"/npm/{pkg}", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Verify 1.0.0 got deprecated.
        string meta = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(meta);
        Assert.True(
            doc.RootElement.GetProperty("versions").GetProperty("1.0.0").TryGetProperty("deprecated", out _));
        // 2.0.0 version row doesn't exist in our packument.
        Assert.False(
            doc.RootElement.GetProperty("versions").TryGetProperty("2.0.0", out _));
    }

    // ── Item 4: Unpublish ────────────────────────────────────────────────────────

    [Fact]
    public async Task Unpublish_ExistingUploadedVersion_Returns200AndVersionGone()
    {
        string pkg = $"unpub-ok-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.DeleteAsync($"/npm/{pkg}/-rev/1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Package should be gone entirely (no versions left → package row deleted).
        var getResp = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.NotFound, getResp.StatusCode);
    }

    [Fact]
    public async Task Unpublish_PackageNotFound_Returns404()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.DeleteAsync($"/npm/nosuchpkg-unpub/-rev/1.0.0");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Unpublish_WithoutYankCapability_Returns403()
    {
        string pkg = $"unpub-cap-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        // Create a pull-only token (no yank capability).
        string pullToken = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(pullToken);

        var resp = await client.DeleteAsync($"/npm/{pkg}/-rev/1.0.0");
        // Capability guard returns 403.
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    /// <summary>
    /// Unpublishing the version that 'latest' points at must re-anchor 'latest' to the
    /// highest remaining stable version. After the delete the packument's dist-tags must
    /// no longer reference the removed version, and npm-style resolution against 'latest'
    /// must resolve to a version that actually exists.
    /// </summary>
    [Fact]
    public async Task Unpublish_LatestVersion_ReanchorsLatestToHighestRemainingStable()
    {
        string pkg = $"unpub-retag-{Guid.NewGuid():N}"[..24].ToLowerInvariant();

        // Publish v1 (latest → v1 via default seeding), then publish v2 and explicitly
        // point 'latest' at it via the dist-tag management endpoint.
        await _factory.PushNpmPackage(pkg, "1.0.0");
        await _factory.PushNpmPackage(pkg, "2.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Explicitly set latest → v2 (bare publish does not auto-promote an existing tag).
        using var tagContent = new StringContent("\"2.0.0\"", Encoding.UTF8, "application/json");
        (await client.PutAsync($"/npm/-/package/{pkg}/dist-tags/latest", tagContent)).EnsureSuccessStatusCode();

        // Confirm the baseline: latest points at v2.
        string before = await client.GetStringAsync($"/npm/{pkg}");
        using var beforeDoc = JsonDocument.Parse(before);
        Assert.Equal("2.0.0", beforeDoc.RootElement.GetProperty("dist-tags").GetProperty("latest").GetString());

        // Unpublish v2 — this removes the version that 'latest' pointed at.
        var resp = await client.DeleteAsync($"/npm/{pkg}/-rev/2.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Package still exists (v1 remains). The packument's 'latest' must now be v1.
        string after = await client.GetStringAsync($"/npm/{pkg}");
        using var afterDoc = JsonDocument.Parse(after);
        var distTags = afterDoc.RootElement.GetProperty("dist-tags");
        Assert.Equal("1.0.0", distTags.GetProperty("latest").GetString());

        // v2 must not appear in versions.
        Assert.False(afterDoc.RootElement.GetProperty("versions").TryGetProperty("2.0.0", out _),
            "version 2.0.0 should be absent from the packument after unpublish");

        // v1 must still be present and resolvable.
        Assert.True(afterDoc.RootElement.GetProperty("versions").TryGetProperty("1.0.0", out _),
            "version 1.0.0 should remain in the packument");
    }

    /// <summary>
    /// Unpublishing a non-latest version must not disturb the 'latest' dist-tag.
    /// </summary>
    [Fact]
    public async Task Unpublish_NonLatestVersion_LeavesLatestUntouched()
    {
        string pkg = $"unpub-nonlat-{Guid.NewGuid():N}"[..24].ToLowerInvariant();

        await _factory.PushNpmPackage(pkg, "1.0.0");
        await _factory.PushNpmPackage(pkg, "2.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Explicitly set latest → v2 (bare publish does not auto-promote an existing tag).
        using var tagContent = new StringContent("\"2.0.0\"", Encoding.UTF8, "application/json");
        (await client.PutAsync($"/npm/-/package/{pkg}/dist-tags/latest", tagContent)).EnsureSuccessStatusCode();

        // Unpublish the older v1 — latest still points at v2.
        var resp = await client.DeleteAsync($"/npm/{pkg}/-rev/1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string after = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(after);
        Assert.Equal("2.0.0", doc.RootElement.GetProperty("dist-tags").GetProperty("latest").GetString());
    }

    /// <summary>
    /// Unpublishing the only remaining version removes the package row, and the cascade
    /// must leave no orphan dist-tag rows in npm_dist_tags.
    /// </summary>
    [Fact]
    public async Task Unpublish_OnlyVersion_NoOrphanTagRowsRemain()
    {
        string pkg = $"unpub-last-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Confirm 'latest' tag exists before unpublish.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        int tagsBefore = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM npm_dist_tags
            WHERE package_id = (
                SELECT id FROM packages WHERE ecosystem = 'npm' AND purl_name = @name LIMIT 1
            )
            """,
            new { name = pkg });
        Assert.True(tagsBefore > 0, "at least one tag row should exist before unpublish");

        var resp = await client.DeleteAsync($"/npm/{pkg}/-rev/1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // After deleting the only version the package row is removed; the FK cascade on
        // npm_dist_tags(package_id) removes all tag rows for that package.
        int tagsAfter = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM npm_dist_tags
            WHERE package_id = (
                SELECT id FROM packages WHERE ecosystem = 'npm' AND purl_name = @name LIMIT 1
            )
            """,
            new { name = pkg });
        Assert.Equal(0, tagsAfter);
    }

    // ── Item 3 (non-string deprecated guard) ────────────────────────────────────

    /// <summary>
    /// The npm deprecate endpoint must not 500 when a version object carries a non-string
    /// 'deprecated' value (e.g. a boolean false). Non-string values are silently ignored and
    /// the existing deprecation state of the version is left unchanged.
    /// </summary>
    [Fact]
    public async Task Deprecate_NonStringDeprecatedValue_IgnoredWithout500()
    {
        string pkg = $"depr-nstr-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        // Send "deprecated": false — a non-string value that previously caused a throw in
        // GetValue<string>(). The endpoint must return 200, not 500.
        string body = """{"name":""" + $"\"{pkg}\"" + ""","versions":{"1.0.0":{"deprecated":false}}}""";
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/{pkg}", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // The existing (null) deprecation state must be unchanged.
        string meta = await client.GetStringAsync($"/npm/{pkg}");
        using var doc = JsonDocument.Parse(meta);
        Assert.False(
            doc.RootElement.GetProperty("versions").GetProperty("1.0.0").TryGetProperty("deprecated", out _),
            "deprecated field must be absent when the PUT body carried a boolean false");
    }

    // ── Item 5: Search ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Search_ReturnsPackagesMatchingText()
    {
        string unique = Guid.NewGuid().ToString("N")[..10].ToLowerInvariant();
        string pkg = $"srch-{unique}";
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/-/v1/search?text={pkg}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("objects", out var objects));
        Assert.True(doc.RootElement.TryGetProperty("total", out _));
        Assert.True(objects.GetArrayLength() >= 1);

        // Verify the package is in the result.
        bool found = objects.EnumerateArray()
            .Any(o => o.TryGetProperty("package", out var p)
                   && p.TryGetProperty("name", out var n)
                   && n.GetString() == pkg);
        Assert.True(found, $"Package '{pkg}' not found in search results.");
    }

    [Fact]
    public async Task Search_NoText_ReturnsAllPackages()
    {
        // Just ensure the endpoint works with no text filter.
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/-/v1/search?size=10");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("objects", out _));
    }

    /// <summary>
    /// CRITICAL: Search results are scoped to the requesting org. A cross-org token (bound
    /// to a different org than the request target) must be refused — the token.OrgId guard
    /// prevents token holders from one org accessing another org's search results.
    /// </summary>
    [Fact]
    public async Task Search_CrossOrgToken_Returns401()
    {
        // Push a package into the default org.
        string pkg = $"srch-iso-{Guid.NewGuid():N}"[..24].ToLowerInvariant();
        await _factory.PushNpmPackage(pkg, "1.0.0");

        // Token bound to a different org.
        string otherToken = await CreateOtherOrgPushTokenAsync();
        using var client = _factory.CreateClientWithBearer(otherToken);

        // Using a cross-org token on the default-org search endpoint. The cross-tenant
        // guard coerces the token to null (token.OrgId != default-org), so with
        // anonymous pull off the search returns 401.
        var resp = await client.GetAsync($"/npm/-/v1/search?text={pkg}");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    /// <summary>
    /// Search with no auth and anonymous pull off must return 401.
    /// </summary>
    [Fact]
    public async Task Search_NoToken_AnonymousPullOff_Returns401()
    {
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync("/npm/-/v1/search?text=anything");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
