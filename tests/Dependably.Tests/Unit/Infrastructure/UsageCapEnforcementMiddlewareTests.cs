using System.Reflection;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The usage-cap arm of <see cref="TenantStatusEnforcementMiddleware"/> and its response shapes in
/// <see cref="TenantNotReadyResponseWriter"/>. Each refusal has an admitted twin — the same request
/// under a normal posture, or a DELETE/read/management request under the capped one — so a gate
/// that refuses nothing, or everything, fails.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UsageCapEnforcementMiddlewareTests
{
    private const string InfoUrl = "https://billing.example.com/usage?ref=cap";

    private static TenantStatusEnforcementMiddleware Build(RequestDelegate next, string? infoUrl = null) =>
        new(next, new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["USAGE_CAP_INFO_URL"] = infoUrl })
            .Build());

    // The routed endpoint, as UseRouting leaves it: the gate classifies the protocol plane by the
    // controller a request routed to, not by its path. /api/v1/ and /saml/ paths route to
    // management controllers; everything else here routes to a protocol controller.
    private static DefaultHttpContext Request(
        string method, string path, string posture, string status = "active", Type? controller = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Response.Body = new MemoryStream();
        ctx.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("org-1", "acme", status, posture);
        controller ??= path.StartsWith("/api/v1/", StringComparison.Ordinal) || path.StartsWith("/saml/", StringComparison.Ordinal)
            ? typeof(Dependably.Api.SamlController)
            : typeof(Dependably.Api.NpmController);
        ctx.SetEndpoint(new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new ControllerActionDescriptor { ControllerTypeInfo = controller.GetTypeInfo() }),
            "test"));
        return ctx;
    }

    // The routed endpoint built from a real controller action, as MVC builds it: the action
    // descriptor plus every attribute the action declares, so a test exercises the markers the
    // action actually carries rather than a hand-built one. controller overrides the descriptor's
    // controller type (the action's declaring type by default).
    private static DefaultHttpContext Request(
        string method, string path, string posture, string status, MethodInfo action, Type? controller = null)
    {
        var ctx = Request(method, path, posture, status);
        var metadata = new List<object>
        {
            new ControllerActionDescriptor
            {
                ControllerTypeInfo = (controller ?? action.DeclaringType!).GetTypeInfo(),
                MethodInfo = action,
            },
        };
        metadata.AddRange(action.GetCustomAttributes(inherit: true));
        ctx.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(metadata), "test"));
        return ctx;
    }

    private static MethodInfo NpmAction(string name) =>
        typeof(Dependably.Api.NpmController).GetMethod(name)
        ?? throw new InvalidOperationException($"NpmController.{name} not found");

    private static async Task<(bool Reached, DefaultHttpContext Ctx)> RunAsync(DefaultHttpContext ctx, string? infoUrl = null)
    {
        bool reached = false;
        var middleware = Build(_ =>
        {
            reached = true;
            return Task.CompletedTask;
        }, infoUrl);
        await middleware.InvokeAsync(ctx, NullLogger<TenantStatusEnforcementMiddleware>.Instance);
        return (reached, ctx);
    }

    private static JsonElement Body(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return JsonDocument.Parse(ctx.Response.Body).RootElement.Clone();
    }

    [Theory]
    [InlineData("POST", "/pypi/legacy/")]
    [InlineData("PUT", "/npm/left-pad")]
    [InlineData("PATCH", "/v2/team/app/blobs/uploads/abc")]
    public async Task Protocol_writes_are_refused_under_uploads_refused(string method, string path)
    {
        var (reached, ctx) = await RunAsync(Request(method, path, UsagePostures.UploadsRefused));

        Assert.False(reached);
        Assert.NotEqual(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData("POST", "/pypi/legacy/")]
    [InlineData("PUT", "/npm/left-pad")]
    [InlineData("PATCH", "/v2/team/app/blobs/uploads/abc")]
    public async Task The_same_writes_are_admitted_under_a_normal_posture(string method, string path)
    {
        var (reached, _) = await RunAsync(Request(method, path, UsagePostures.Normal));

        Assert.True(reached);
    }

    [Fact]
    public async Task Writes_are_refused_under_downloads_throttled_too()
    {
        var (reached, ctx) = await RunAsync(Request("PUT", "/npm/left-pad", UsagePostures.DownloadsThrottled));

        Assert.False(reached);
        Assert.Equal(StatusCodes.Status402PaymentRequired, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData("DELETE", "/nuget/publish/pkg/1.0.0")]
    [InlineData("DELETE", "/v2/team/app/manifests/sha256:abc")]
    [InlineData("GET", "/npm/left-pad")]
    [InlineData("HEAD", "/v2/team/app/blobs/sha256:abc")]
    [InlineData("POST", "/api/v1/tokens")]
    [InlineData("PUT", "/api/v1/org-settings")]
    public async Task Deletes_reads_and_the_management_plane_are_admitted_at_the_cap(string method, string path)
    {
        var (reached, _) = await RunAsync(Request(method, path, UsagePostures.DownloadsThrottled));

        Assert.True(reached);
    }

    [Theory]
    [InlineData("/npm/-/npm/v1/security/advisories/bulk")]
    [InlineData("/NPM/-/npm/v1/security/advisories/bulk/")]
    public async Task The_npm_bulk_advisory_query_is_admitted_at_the_cap(string path)
    {
        var (reached, _) = await RunAsync(Request("POST", path, UsagePostures.DownloadsThrottled));

        Assert.True(reached);
    }

    [Theory]
    [InlineData("POST", "/npm/-/npm/v1/security/advisories/bulk/extra")]
    [InlineData("POST", "/npm/-/npm/v1/security/advisories")]
    [InlineData("PUT", "/npm/-/npm/v1/security/advisories/bulk")]
    [InlineData("POST", "/npm/left-pad")]
    public async Task Only_the_exact_query_route_is_admitted_and_only_for_POST(string method, string path)
    {
        var (reached, ctx) = await RunAsync(Request(method, path, UsagePostures.UploadsRefused));

        Assert.False(reached);
        Assert.Equal(StatusCodes.Status402PaymentRequired, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData(UsagePostures.UploadsRefused, "active")]
    [InlineData(UsagePostures.DownloadsThrottled, "active")]
    [InlineData(UsagePostures.Normal, "read_only")]
    [InlineData(UsagePostures.UploadsRefused, "read_only")]
    public async Task Saml_sign_in_is_admitted_under_a_cap_and_under_read_only(string posture, string status)
    {
        // /saml/acs routes outside /api/v1/, so a path-prefix test would call it protocol plane
        // and lock SSO users out of the UI they need to bring usage back down.
        var (reached, _) = await RunAsync(Request("POST", "/saml/acs", posture, status));

        Assert.True(reached);
    }

    [Theory]
    [InlineData(UsagePostures.UploadsRefused, "active", StatusCodes.Status402PaymentRequired)]
    [InlineData(UsagePostures.Normal, "read_only", StatusCodes.Status423Locked)]
    public async Task The_same_POST_routed_to_a_protocol_controller_is_refused(string posture, string status, int expected)
    {
        var (reached, ctx) = await RunAsync(Request("POST", "/pypi/legacy/", posture, status));

        Assert.False(reached);
        Assert.Equal(expected, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task A_write_that_routed_to_no_controller_is_not_the_protocol_plane()
    {
        var ctx = Request("POST", "/no-such-route", UsagePostures.UploadsRefused, "read_only");
        ctx.SetEndpoint(null);

        var (reached, _) = await RunAsync(ctx);

        Assert.True(reached);
    }

    [Fact]
    public async Task A_non_active_status_wins_over_the_usage_posture()
    {
        var (reached, ctx) = await RunAsync(Request("PUT", "/npm/left-pad", UsagePostures.UploadsRefused, status: "read_only"));

        Assert.False(reached);
        Assert.Equal(StatusCodes.Status423Locked, ctx.Response.StatusCode);
        Assert.Equal("ReadOnlyWrite", Body(ctx).GetProperty("reason").GetString());
    }

    [Theory]
    [InlineData(nameof(Dependably.Api.NpmController.UnpublishRevPut), "/npm/left-pad/-rev/3-abc")]
    [InlineData(nameof(Dependably.Api.NpmController.UnpublishRevPutScoped), "/npm/@acme/left-pad/-rev/3-abc")]
    public async Task The_npm_unpublish_prune_PUT_is_admitted_under_uploads_refused(string action, string path)
    {
        var (reached, _) = await RunAsync(Request("PUT", path, UsagePostures.UploadsRefused, "active", NpmAction(action)));

        Assert.True(reached);
    }

    [Theory]
    [InlineData(nameof(Dependably.Api.NpmController.UnpublishRevPut), "/npm/left-pad/-rev/3-abc")]
    [InlineData(nameof(Dependably.Api.NpmController.UnpublishRevPutScoped), "/npm/@acme/left-pad/-rev/3-abc")]
    public async Task The_npm_unpublish_prune_PUT_is_admitted_under_downloads_throttled_too(string action, string path)
    {
        var (reached, _) = await RunAsync(Request("PUT", path, UsagePostures.DownloadsThrottled, "active", NpmAction(action)));

        Assert.True(reached);
    }

    [Theory]
    [InlineData(nameof(Dependably.Api.NpmController.Publish), "/npm/left-pad")]
    [InlineData(nameof(Dependably.Api.NpmController.PublishScoped), "/npm/@acme/left-pad")]
    public async Task An_ordinary_npm_publish_PUT_built_from_its_real_action_stays_refused(string action, string path)
    {
        var (reached, ctx) = await RunAsync(Request("PUT", path, UsagePostures.UploadsRefused, "active", NpmAction(action)));

        Assert.False(reached);
        Assert.Equal(StatusCodes.Status402PaymentRequired, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData(nameof(Dependably.Api.NpmController.UnpublishRevPut), "/npm/left-pad/-rev/3-abc", UsagePostures.Normal)]
    [InlineData(nameof(Dependably.Api.NpmController.UnpublishRevPutScoped), "/npm/@acme/left-pad/-rev/3-abc", UsagePostures.UploadsRefused)]
    public async Task The_npm_unpublish_prune_PUT_is_still_refused_under_read_only(string action, string path, string posture)
    {
        // read_only refuses deletes as well as uploads, so the usage-cap admission does not reach it.
        var (reached, ctx) = await RunAsync(Request("PUT", path, posture, "read_only", NpmAction(action)));

        Assert.False(reached);
        Assert.Equal(StatusCodes.Status423Locked, ctx.Response.StatusCode);
        Assert.Equal("ReadOnlyWrite", Body(ctx).GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Apex_requests_are_never_capped()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = "/npm/left-pad";
        ctx.Items[TenantContext.HttpItemsKey] = TenantContext.Apex;

        var (reached, _) = await RunAsync(ctx);

        Assert.True(reached);
    }

    [Fact]
    public async Task Refusal_is_402_problem_json_with_about_blank_when_no_info_url_is_set()
    {
        var (_, ctx) = await RunAsync(Request("PUT", "/npm/left-pad", UsagePostures.UploadsRefused));

        Assert.Equal(StatusCodes.Status402PaymentRequired, ctx.Response.StatusCode);
        Assert.Equal("application/problem+json", ctx.Response.ContentType);
        Assert.False(ctx.Response.Headers.ContainsKey("Link"));
        var body = Body(ctx);
        Assert.Equal("about:blank", body.GetProperty("type").GetString());
        Assert.Equal("Usage cap reached", body.GetProperty("title").GetString());
        Assert.Equal(402, body.GetProperty("status").GetInt32());
        Assert.Equal("UsageCapReached", body.GetProperty("reason").GetString());
        Assert.Contains("usage cap", body.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Refusal_links_to_the_configured_info_url()
    {
        var (_, ctx) = await RunAsync(Request("PUT", "/npm/left-pad", UsagePostures.UploadsRefused), InfoUrl);

        Assert.Equal(InfoUrl, Body(ctx).GetProperty("type").GetString());
        Assert.Equal($"<{InfoUrl}>; rel=\"help\"", ctx.Response.Headers.Link.ToString());
    }

    [Fact]
    public async Task Oci_refusal_is_denied_with_the_info_url_in_detail()
    {
        var (_, ctx) = await RunAsync(Request("POST", "/v2/team/app/blobs/uploads/", UsagePostures.UploadsRefused), InfoUrl);

        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        Assert.Equal("application/json", ctx.Response.ContentType);
        var error = Body(ctx).GetProperty("errors")[0];
        Assert.Equal("DENIED", error.GetProperty("code").GetString());
        Assert.Equal("Organization has reached a usage cap; uploads are refused.", error.GetProperty("message").GetString());
        Assert.Equal(InfoUrl, error.GetProperty("detail").GetProperty("infoUrl").GetString());
    }

    [Fact]
    public async Task Oci_refusal_without_an_info_url_carries_no_detail()
    {
        var (_, ctx) = await RunAsync(Request("POST", "/v2/team/app/blobs/uploads/", UsagePostures.UploadsRefused));

        var error = Body(ctx).GetProperty("errors")[0];
        Assert.Equal("DENIED", error.GetProperty("code").GetString());
        Assert.True(!error.TryGetProperty("detail", out var detail) || detail.ValueKind == JsonValueKind.Null);
    }

    [Fact]
    public async Task The_info_url_never_decorates_another_reason()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/npm/left-pad";
        ctx.Response.Body = new MemoryStream();

        await TenantNotReadyResponseWriter.WriteAsync(ctx, TenantNotReadyReason.ReadOnlyWrite, InfoUrl);

        Assert.Equal("about:blank", Body(ctx).GetProperty("type").GetString());
        Assert.False(ctx.Response.Headers.ContainsKey("Link"));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("/usage", null)]
    [InlineData("javascript:alert(1)", null)]
    [InlineData("ftp://example.com/usage", null)]
    [InlineData(" https://example.com/usage ", "https://example.com/usage")]
    [InlineData("http://example.com/u", "http://example.com/u")]
    public void Only_an_absolute_web_url_is_accepted(string? configured, string? expected)
    {
        Assert.Equal(expected, TenantNotReadyResponseWriter.ParseUsageCapInfoUrl(configured));
    }
}
