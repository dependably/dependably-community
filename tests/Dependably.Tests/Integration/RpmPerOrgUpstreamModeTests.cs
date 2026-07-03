using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for the per-org RPM hosted-publishing mode override (rpm_upstream_mode).
/// Proves the operator can enable hosted RPM publishing for one org from the management API
/// (Settings → Proxy) and have it take effect without an instance restart, and that the per-org
/// override composes with the instance <c>Rpm:UpstreamMode</c> env value as an override — not a
/// floor — in EITHER direction: an org can opt into 'merged' on a passthrough instance, or opt
/// out to 'passthrough' on a merged instance. An unset (null) org override always inherits the
/// instance env value.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RpmPerOrgUpstreamModeTests
{
    private static async Task<(DependablyFactory Factory, HttpClient Admin)> NewAsync(string? instanceRpmUpstreamMode = null)
    {
        // Fresh factory per test for isolation — the upstream registry and mode toggles mutate
        // org state that would otherwise bleed across cases sharing a class fixture.
        var f = new DependablyFactory { RpmUpstreamMode = instanceRpmUpstreamMode };
        using (var boot = f.CreateClient())
        {
            await boot.GetAsync("/health");
        }

        string jwt = await f.CreateAdminJwt();
        var admin = f.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return (f, admin);
    }

    [Fact]
    public async Task RpmUpstreamMode_PerOrgToggle_GatesHostedPublish_WithoutRestart()
    {
        // Instance env is unset (production default 'passthrough').
        var (f, admin) = await NewAsync();
        await using var _f = f;
        using var _a = admin;

        // Configure an rpm upstream registry so the passthrough publish guard engages for this org.
        var add = await admin.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "rpm", url = "https://rpm.example.test/repo" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        // No per-org override (null) inherits the instance default 'passthrough' → 409.
        using (var r1 = await f.UploadRpm())
        {
            Assert.Equal(HttpStatusCode.Conflict, r1.StatusCode);
        }

        // Operator flips the org to 'merged' from the UI — no instance restart.
        var toMerged = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = "merged" });
        Assert.Equal(HttpStatusCode.NoContent, toMerged.StatusCode);

        // The setting is reflected in the org settings payload (camelCase, frontend contract).
        var settings = await admin.GetFromJsonAsync<System.Text.Json.JsonElement>("/api/v1/settings");
        Assert.Equal("merged", settings.GetProperty("rpmUpstreamMode").GetString());
        Assert.Equal("merged", settings.GetProperty("rpmUpstreamModeEffective").GetString());
        Assert.Equal("passthrough", settings.GetProperty("rpmUpstreamModeInstanceDefault").GetString());

        // Hosted publish now succeeds against the same running instance.
        using (var r2 = await f.UploadRpm())
        {
            Assert.True(r2.IsSuccessStatusCode,
                $"expected success after switching to merged, got {(int)r2.StatusCode}");
        }

        // Flipping back to 'passthrough' re-arms the 409 — again without restart.
        var toPass = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = "passthrough" });
        Assert.Equal(HttpStatusCode.NoContent, toPass.StatusCode);

        using var r3 = await f.UploadRpm();
        Assert.Equal(HttpStatusCode.Conflict, r3.StatusCode);
    }

    [Fact]
    public async Task RpmUpstreamMode_InstanceMerged_OrgOverridesToPassthrough_Returns409()
    {
        // Pins the override-not-floor composition end-to-end: the instance env is 'merged', yet
        // the operator explicitly sets this org's override to 'passthrough'. The explicit org
        // value must win — hosted publish is refused even though the instance-wide default is
        // merged. Under the old OR-floor composition this would succeed (env=merged always won),
        // which is exactly the defect this test guards against.
        var (f, admin) = await NewAsync(instanceRpmUpstreamMode: "merged");
        await using var _f = f;
        using var _a = admin;

        var add = await admin.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "rpm", url = "https://rpm.example.test/repo" });
        Assert.Equal(HttpStatusCode.Created, add.StatusCode);

        // No override yet: inherits the merged instance default → publish succeeds.
        using (var r1 = await f.UploadRpm())
        {
            Assert.True(r1.IsSuccessStatusCode, $"expected success (inherit merged), got {(int)r1.StatusCode}");
        }

        // Explicit org override to 'passthrough' downgrades below the merged instance default.
        var toPass = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = "passthrough" });
        Assert.Equal(HttpStatusCode.NoContent, toPass.StatusCode);

        var settings = await admin.GetFromJsonAsync<System.Text.Json.JsonElement>("/api/v1/settings");
        Assert.Equal("passthrough", settings.GetProperty("rpmUpstreamMode").GetString());
        Assert.Equal("passthrough", settings.GetProperty("rpmUpstreamModeEffective").GetString());
        Assert.Equal("merged", settings.GetProperty("rpmUpstreamModeInstanceDefault").GetString());

        using var r2 = await f.UploadRpm();
        Assert.Equal(HttpStatusCode.Conflict, r2.StatusCode);

        // Clearing the override (back to null) re-inherits the merged instance default.
        var toInherit = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = (string?)null });
        Assert.Equal(HttpStatusCode.NoContent, toInherit.StatusCode);

        using var r3 = await f.UploadRpm();
        Assert.True(r3.IsSuccessStatusCode, $"expected success after clearing to inherit, got {(int)r3.StatusCode}");
    }

    [Fact]
    public async Task RpmUpstreamMode_NoUpstreamConfigured_MergedAndPassthroughBothPublish()
    {
        // With no rpm upstream registry configured, the passthrough guard never engages regardless
        // of mode — hosted publish is always allowed (nothing to shadow). This isolates the guard's
        // "AND the org has ≥1 rpm registry" clause from the mode itself.
        var (f, admin) = await NewAsync();
        await using var _f = f;
        using var _a = admin;

        using (var r1 = await f.UploadRpm())
        {
            Assert.True(r1.IsSuccessStatusCode, $"expected success, got {(int)r1.StatusCode}");
        }

        var toMerged = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = "merged" });
        Assert.Equal(HttpStatusCode.NoContent, toMerged.StatusCode);

        using var r2 = await f.UploadRpm();
        Assert.True(r2.IsSuccessStatusCode, $"expected success, got {(int)r2.StatusCode}");
    }

    [Fact]
    public async Task RpmUpstreamMode_InvalidValue_Returns422()
    {
        var (f, admin) = await NewAsync();
        await using var _f = f;
        using var _a = admin;

        var bad = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = "bogus" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, bad.StatusCode);
    }

    [Fact]
    public async Task RpmUpstreamMode_NullValue_ClearsOverrideToInherit()
    {
        var (f, admin) = await NewAsync();
        await using var _f = f;
        using var _a = admin;

        var toMerged = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = "merged" });
        Assert.Equal(HttpStatusCode.NoContent, toMerged.StatusCode);

        var toInherit = await admin.PutAsJsonAsync("/api/v1/rpm-upstream-mode", new { mode = (string?)null });
        Assert.Equal(HttpStatusCode.NoContent, toInherit.StatusCode);

        var settings = await admin.GetFromJsonAsync<System.Text.Json.JsonElement>("/api/v1/settings");
        Assert.Equal(System.Text.Json.JsonValueKind.Null, settings.GetProperty("rpmUpstreamMode").ValueKind);
        Assert.Equal("passthrough", settings.GetProperty("rpmUpstreamModeEffective").GetString());
    }
}
