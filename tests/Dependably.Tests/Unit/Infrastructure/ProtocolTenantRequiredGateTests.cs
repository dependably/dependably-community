using System.Reflection;
using System.Text.Json;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Edge;
using Dependably.Storage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The no-tenant arm of <see cref="TenantStatusEnforcementMiddleware"/>: a request routed to a
/// protocol controller whose host resolved no tenant (apex, uninitialized, or no context at all)
/// is answered 404 and never reaches the controller. Each refusal has an admitted twin — the same
/// context on the management plane or an unrouted path, or a resolved tenant on the protocol
/// plane — so a gate that refuses everything fails as well as one that refuses nothing. Also pins
/// the backstop behind the gate in <see cref="OrgCacheEpochStore"/>: a blank org id is rejected
/// by name. (<c>OrgScopedControllerBaseTests</c> pins the other backstop, the tenant read.)
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProtocolTenantRequiredGateTests
{
    // Every kept protocol surface, read from the classification itself so a newly added protocol
    // controller is covered without editing this list.
    public static TheoryData<Type> ProtocolControllers()
    {
        var data = new TheoryData<Type>();
        foreach (var type in typeof(OrgScopedControllerBase).Assembly.GetTypes()
                     .Where(t => !t.IsAbstract && typeof(ControllerBase).IsAssignableFrom(t))
                     .Where(EdgeProtocolSurface.IsProtocol))
        {
            data.Add(type);
        }

        return data;
    }

    public static TheoryData<string> UnresolvedContexts() => new() { "apex", "uninitialized", "missing" };

    private static TenantContext? Context(string kind) => kind switch
    {
        "apex" => TenantContext.Apex,
        "uninitialized" => TenantContext.Uninitialized,
        "missing" => null,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static DefaultHttpContext Request(string path, TenantContext? tenant, Type? controller)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = path;
        ctx.Response.Body = new MemoryStream();
        if (tenant is not null)
        {
            ctx.Items[TenantContext.HttpItemsKey] = tenant;
        }

        if (controller is not null)
        {
            ctx.SetEndpoint(new Endpoint(
                _ => Task.CompletedTask,
                new EndpointMetadataCollection(new ControllerActionDescriptor { ControllerTypeInfo = controller.GetTypeInfo() }),
                "test"));
        }

        return ctx;
    }

    private static async Task<bool> RunAsync(DefaultHttpContext ctx)
    {
        bool reached = false;
        var middleware = new TenantStatusEnforcementMiddleware(
            _ =>
            {
                reached = true;
                return Task.CompletedTask;
            },
            new ConfigurationBuilder().Build());
        await middleware.InvokeAsync(ctx, NullLogger<TenantStatusEnforcementMiddleware>.Instance);
        return reached;
    }

    private static JsonElement Body(DefaultHttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return JsonDocument.Parse(ctx.Response.Body).RootElement.Clone();
    }

    [Fact]
    public void The_protocol_surface_list_is_not_empty()
    {
        Assert.True(ProtocolControllers().Count >= 9);
    }

    [Theory]
    [MemberData(nameof(ProtocolControllers))]
    public async Task Every_protocol_controller_is_refused_on_the_apex(Type controller)
    {
        var ctx = Request("/maven/org/example/maven-metadata.xml", TenantContext.Apex, controller);

        Assert.False(await RunAsync(ctx));
        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
    }

    [Theory]
    [MemberData(nameof(UnresolvedContexts))]
    public async Task Protocol_request_without_a_tenant_is_a_404_problem(string kind)
    {
        var ctx = Request("/npm/left-pad", Context(kind), typeof(NpmController));

        Assert.False(await RunAsync(ctx));
        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
        Assert.Equal("application/problem+json", ctx.Response.ContentType);
        var body = Body(ctx);
        Assert.Equal(404, body.GetProperty("status").GetInt32());
        Assert.Equal(nameof(TenantNotReadyReason.NotFound), body.GetProperty("reason").GetString());
        Assert.False(body.TryGetProperty("detail", out _));
    }

    [Theory]
    [MemberData(nameof(UnresolvedContexts))]
    public async Task Oci_request_without_a_tenant_gets_the_oci_error_envelope(string kind)
    {
        var ctx = Request("/v2/", Context(kind), typeof(OciController));

        Assert.False(await RunAsync(ctx));
        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
        Assert.Equal("application/json", ctx.Response.ContentType);
        Assert.Equal(
            "NAME_UNKNOWN",
            Body(ctx).GetProperty("errors")[0].GetProperty("code").GetString());
    }

    [Theory]
    [MemberData(nameof(UnresolvedContexts))]
    public async Task Management_plane_without_a_tenant_is_admitted(string kind)
    {
        // The apex's own surfaces (system admin, login, bootstrap) route to management controllers.
        var ctx = Request("/api/v1/system/tenants", Context(kind), typeof(SamlController));

        Assert.True(await RunAsync(ctx));
    }

    [Theory]
    [MemberData(nameof(UnresolvedContexts))]
    public async Task Unrouted_request_without_a_tenant_is_admitted(string kind)
    {
        // The SPA fallback and static files carry no controller endpoint.
        var ctx = Request("/system/tenants", Context(kind), controller: null);

        Assert.True(await RunAsync(ctx));
    }

    [Fact]
    public async Task Protocol_request_on_a_resolved_tenant_is_admitted()
    {
        var ctx = Request("/npm/left-pad", TenantContext.ForTenant("org-1", "acme"), typeof(NpmController));

        Assert.True(await RunAsync(ctx));
    }

    [Fact]
    public async Task A_tenant_context_with_a_blank_id_is_still_refused()
    {
        var ctx = Request("/npm/left-pad", TenantContext.ForTenant("", "acme"), typeof(NpmController));

        Assert.False(await RunAsync(ctx));
        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
    }

    // Every controller method named CurrentTenantId — the base's, and any a controller that does
    // not derive from OrgScopedControllerBase declares for itself — is invoked under an apex
    // context and must throw, not hand back a null org id. Behavioural rather than a source scan,
    // so a future shadow with the raw `.TenantId!` body fails here however it is spelled.
    [Fact]
    public void Every_controller_tenant_read_throws_without_a_resolved_tenant()
    {
        var readers = new[] { typeof(OrgScopedControllerBase).Assembly, typeof(SamlController).Assembly }
            .SelectMany(a => a.GetTypes())
            .Where(t => !t.IsAbstract && !t.ContainsGenericParameters && typeof(ControllerBase).IsAssignableFrom(t))
            .Select(t => (Type: t, Method: t.GetMethod(
                "CurrentTenantId",
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                Type.EmptyTypes)))
            .Where(x => x.Method is not null && x.Method.ReturnType == typeof(string))
            .ToList();

        // The three protocol controllers that read the tenant without deriving from the base.
        Assert.Contains(readers, r => r.Type == typeof(NpmController));
        Assert.Contains(readers, r => r.Type == typeof(NuGetController));
        Assert.Contains(readers, r => r.Type == typeof(PyPiController));

        var returnedNull = new List<string>();
        foreach (var (type, method) in readers)
        {
            var controller = (ControllerBase)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(type);
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = Request("/npm/x", TenantContext.Apex, controller: null),
            };

            var thrown = Record.Exception(() => method!.Invoke(controller, null));
            if (thrown is not TargetInvocationException { InnerException: InvalidOperationException })
            {
                returnedNull.Add($"{type.Name} ({thrown?.GetType().Name ?? "returned without throwing"})");
            }
        }

        Assert.True(returnedNull.Count == 0, "Tenant reads that do not throw: " + string.Join(", ", returnedNull));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Epoch_store_rejects_a_blank_org_id_by_name(string? orgId)
    {
        var store = new OrgCacheEpochStore();

        var getToken = Assert.Throws<ArgumentException>(() => store.GetToken(orgId!));
        Assert.Equal("orgId", getToken.ParamName);
        Assert.Throws<ArgumentException>(() => store.Invalidate(orgId!));
    }

    [Fact]
    public void Epoch_store_still_binds_and_expires_a_real_org()
    {
        var store = new OrgCacheEpochStore();
        var token = store.GetToken("org-1");

        Assert.False(token.HasChanged);
        store.Invalidate("org-1");
        Assert.True(token.HasChanged);
    }
}
