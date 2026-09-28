using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Infrastructure.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class RowLevelSecurityUnitTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    [Theory]
    [InlineData(null, RowLevelSecurityMode.Off)]
    [InlineData("", RowLevelSecurityMode.Off)]
    [InlineData("off", RowLevelSecurityMode.Off)]
    [InlineData("enforce", RowLevelSecurityMode.Enforce)]
    [InlineData(" Enforce ", RowLevelSecurityMode.Enforce)]
    public void Options_ParseMode(string? value, RowLevelSecurityMode expected)
    {
        var options = RowLevelSecurityOptions.FromConfiguration(Config(("DB_ROW_LEVEL_SECURITY", value)));

        Assert.Equal(expected, options.Mode);
        Assert.Equal("dependably_rls", options.RoleName);
    }

    [Theory]
    [InlineData("postgres", "multi", null, RowLevelSecurityMode.Enforce, false)]
    [InlineData("postgres", "header", null, RowLevelSecurityMode.Enforce, false)]
    [InlineData("postgres", "multi", "off", RowLevelSecurityMode.Off, true)]
    [InlineData("postgres", "multi", "enforce", RowLevelSecurityMode.Enforce, false)]
    [InlineData("postgres", "single", null, RowLevelSecurityMode.Off, false)]
    [InlineData("postgres", "bound", null, RowLevelSecurityMode.Off, false)]
    [InlineData("sqlite", "multi", null, RowLevelSecurityMode.Off, false)]
    [InlineData(null, null, null, RowLevelSecurityMode.Off, false)]
    public void Options_DefaultFollowsTheDeployment(
        string? provider, string? deploymentMode, string? mode, RowLevelSecurityMode expected, bool disabledWarning)
    {
        var options = RowLevelSecurityOptions.FromConfiguration(Config(
            ("DB_PROVIDER", provider), ("DEPLOYMENT_MODE", deploymentMode), ("DB_ROW_LEVEL_SECURITY", mode)));

        Assert.Equal(expected, options.Mode);
        Assert.Equal(disabledWarning, options.DisabledOnMultiTenantPostgres);
        Assert.Equal(mode is not null, options.Explicit);
    }

    [Theory]
    [InlineData("on")]
    [InlineData("true")]
    [InlineData("enforced")]
    public void Options_UnknownMode_FailsInsteadOfFallingBackToOff(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => RowLevelSecurityOptions.FromConfiguration(Config(("DB_ROW_LEVEL_SECURITY", value))));
        Assert.Contains("DB_ROW_LEVEL_SECURITY", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("app_tenant", true)]
    [InlineData("_rls1", true)]
    [InlineData("Upper", false)]
    [InlineData("has-dash", false)]
    [InlineData("x\"; DROP ROLE postgres; --", false)]
    [InlineData("1leading_digit", false)]
    public void Options_RoleName_MustBeAPlainIdentifier(string role, bool valid)
    {
        var config = Config(("DB_ROW_LEVEL_SECURITY", "enforce"), ("DB_ROW_LEVEL_SECURITY_ROLE", role));

        if (valid)
        {
            Assert.Equal(role, RowLevelSecurityOptions.FromConfiguration(config).RoleName);
        }
        else
        {
            Assert.Throws<InvalidOperationException>(() => RowLevelSecurityOptions.FromConfiguration(config));
        }
    }

    [Fact]
    public void TenantDbScope_FromTenantContext_BindsOnlyAResolvedTenant()
    {
        Assert.Equal("org-1", TenantDbScope.FromTenantContext(TenantContext.ForTenant("org-1", "acme")).OrgId);
        Assert.Throws<InvalidOperationException>(() => TenantDbScope.FromTenantContext(TenantContext.Apex));
        Assert.Throws<InvalidOperationException>(() => TenantDbScope.FromTenantContext(TenantContext.Uninitialized));
        Assert.Throws<ArgumentException>(() => TenantDbScope.ForOrgIteration(" "));
    }

    [Fact]
    public void AmbientScope_ReadsTheHostResolvedTenantContext()
    {
        var accessor = new HttpContextAccessor();
        var scope = new HttpContextAmbientTenantScope(accessor);
        Assert.Equal(AmbientTenant.None, scope.Current);

        accessor.HttpContext = new DefaultHttpContext();
        Assert.Equal(AmbientTenant.None, scope.Current);

        accessor.HttpContext.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant("org-1", "acme");
        Assert.Equal(new AmbientTenant(AmbientTenantKind.Tenant, "org-1"), scope.Current);

        accessor.HttpContext.Items[TenantContext.HttpItemsKey] = TenantContext.Apex;
        Assert.Equal(AmbientTenantKind.Apex, scope.Current.Kind);

        // An uninitialized installation is not the apex: it must bind no tenant, never the bypass.
        accessor.HttpContext.Items[TenantContext.HttpItemsKey] = TenantContext.Uninitialized;
        Assert.Equal(AmbientTenant.None, scope.Current);
    }

    [Fact]
    public void NpgsqlStore_RefusesMultiplexingUnderEnforcement()
    {
        var enforce = new RowLevelSecurityOptions(RowLevelSecurityMode.Enforce, "dependably_rls") { Explicit = true };

        Assert.Throws<InvalidOperationException>(
            () => new NpgsqlMetadataStore("Host=db;Database=d;Multiplexing=true", enforce, null));
        _ = new NpgsqlMetadataStore("Host=db;Database=d;Multiplexing=true", RowLevelSecurityOptions.Disabled, null);

        // A defaulted enforce never blocks startup: it falls back to owner sessions and says why.
        var defaulted = new NpgsqlMetadataStore(
            "Host=db;Database=d;Multiplexing=true", enforce with { Explicit = false }, null);
        Assert.False(defaulted.RowLevelSecurity.Enforced);
        Assert.Contains("Multiplexing", defaulted.RowLevelSecurityFallbackReason, StringComparison.Ordinal);
    }

    [Fact]
    public void Startup_EnforceWithSqlite_FailsBoot()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["DB_ROW_LEVEL_SECURITY"] = "enforce";

        var ex = Assert.Throws<InvalidOperationException>(() => builder.AddDependablyMetadataStore());
        Assert.Contains("DB_PROVIDER=postgres", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DbScope_NestsRestoresAndFlowsIntoChildTasks()
    {
        Assert.Null(DbScope.Declared);

        using (DbScope.ForOrg("org-a"))
        {
            Assert.Equal(new AmbientTenant(AmbientTenantKind.Tenant, "org-a"), DbScope.Declared);

            using (DbScope.CrossTenant("test: nested sweep"))
            {
                Assert.Equal(AmbientTenantKind.Apex, DbScope.Declared?.Kind);
            }

            Assert.Equal("org-a", DbScope.Declared?.OrgId);
            Assert.Equal("org-a", await Task.Run(() => DbScope.Declared?.OrgId));
        }

        Assert.Null(DbScope.Declared);
    }

    [Fact]
    public void DbScope_RefusesABlankTenantOrReason()
    {
        Assert.Throws<ArgumentException>(() => DbScope.ForOrg(" "));
        Assert.Throws<ArgumentException>(() => DbScope.CrossTenant(""));
    }

    [Theory]
    [InlineData("DR001", "whatever", "no_tenant_context")]
    [InlineData("DR002", "whatever", "session_mismatch")]
    [InlineData("42501", "new row violates row-level security policy for table \"packages\"", "policy_violation")]
    [InlineData("42501", "permission denied for table packages", "insufficient_privilege")]
    [InlineData("23505", "duplicate key value violates unique constraint", null)]
    public void Violations_ClassifyBySqlState(string sqlState, string message, string? expected)
    {
        var pg = new PostgresException(message, "ERROR", "ERROR", sqlState);

        Assert.Equal(expected, RowLevelSecurityViolations.Classify(pg));
        Assert.Equal(expected, RowLevelSecurityViolations.Classify(new InvalidOperationException("wrapped", pg)));
        Assert.Null(RowLevelSecurityViolations.Classify(new InvalidOperationException("unrelated")));
    }

    // The expected scope is passed as its parts, which xUnit can serialize per row; null kind means
    // no scope is declared.
    public static TheoryData<string, AmbientTenantKind?, string?> RequestScopes => new()
    {
        { "tenant", AmbientTenantKind.Tenant, "org-a" },
        { "apex", AmbientTenantKind.Apex, null },
        { "uninitialized", null, null },
    };

    [Theory]
    [MemberData(nameof(RequestScopes))]
    public async Task SubdomainTenantMiddleware_DeclaresTheResolvedSurfaceAsTheRequestScope(
        string surface, AmbientTenantKind? expectedKind, string? expectedOrgId)
    {
        AmbientTenant? expected = expectedKind is { } kind ? new AmbientTenant(kind, expectedOrgId) : null;
        var resolved = surface switch
        {
            "tenant" => TenantContext.ForTenant("org-a", "org-a-slug"),
            "apex" => TenantContext.Apex,
            _ => TenantContext.Uninitialized,
        };
        AmbientTenant? seen = null;
        bool reached = false;
        var middleware = new SubdomainTenantMiddleware(_ =>
        {
            reached = true;
            seen = DbScope.Declared;
            return Task.CompletedTask;
        });
        var http = new DefaultHttpContext();

        await middleware.InvokeAsync(http, new FixedTenantResolver(resolved));

        Assert.True(reached);
        Assert.Equal(expected, seen);
        Assert.Same(resolved, http.Items[TenantContext.HttpItemsKey]);
        Assert.Null(DbScope.Declared);
    }

    private sealed class FixedTenantResolver(TenantContext resolved) : ITenantResolver
    {
        public Task<TenantContext> ResolveAsync(HttpContext context, CancellationToken ct = default) =>
            Task.FromResult(resolved);
    }
}
