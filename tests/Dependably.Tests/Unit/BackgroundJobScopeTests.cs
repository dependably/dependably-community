using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for <see cref="BackgroundJobScope"/> — the per-tick observability scope
/// for hosted background jobs. Exercises the outcome recorders and the fire-and-forget
/// run-history persistence on dispose (which is silently skipped when no service provider
/// or no repository is available).
/// </summary>
[Trait("Category", "Unit")]
[Collection("BackgroundJobScope")] // Serialize: the test mutates the static Services hook.
public sealed class BackgroundJobScopeTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private IServiceProvider? _savedServices;

    public async Task InitializeAsync()
    {
        _savedServices = BackgroundJobScope.Services;
        await new SchemaInitializer(_db).InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        BackgroundJobScope.Services = _savedServices;
        await _db.DisposeAsync();
    }

    [Fact]
    public void Begin_SetsIdentityFields()
    {
        using var scope = BackgroundJobScope.Begin("reaper", "audit.reap", TimeProvider.System);
        Assert.Equal("reaper", scope.JobName);
        Assert.Equal("audit.reap", scope.Operation);
        Assert.False(string.IsNullOrWhiteSpace(scope.JobRunId));
    }

    [Fact]
    public void Complete_SuccessAndCustomOutcome_DoNotThrow()
    {
        var ex = Record.Exception(() =>
        {
            using (var ok = BackgroundJobScope.Begin("j", "op", TimeProvider.System))
            {
                ok.Complete(); // default "success" — records the success counter
            }

            using var noop = BackgroundJobScope.Begin("j", "op", TimeProvider.System);
            noop.Complete("noop"); // non-success branch
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Fail_WithAndWithoutException_DoNotThrow()
    {
        var ex = Record.Exception(() =>
        {
            using (var s1 = BackgroundJobScope.Begin("j", "op", TimeProvider.System))
            {
                s1.Fail();
            }

            using var s2 = BackgroundJobScope.Begin("j", "op", TimeProvider.System);
            s2.Fail(new InvalidOperationException("boom"), "server_error");
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Dispose_WithoutServices_SkipsPersistence()
    {
        BackgroundJobScope.Services = null;
        // Disposing must not throw even though no provider is wired to persist the run.
        var ex = Record.Exception(() =>
        {
            using var scope = BackgroundJobScope.Begin("j", "op", TimeProvider.System);
            scope.Complete();
        });
        Assert.Null(ex);
    }

    [Fact]
    public async Task Dispose_WithProviderLackingRepository_SkipsPersistence()
    {
        BackgroundJobScope.Services = new ServiceCollection().BuildServiceProvider();
        // The fire-and-forget write resolves the repo to null and returns — the repo-null
        // branch must complete without throwing. Give the background write a beat to run.
        var ex = await Record.ExceptionAsync(async () =>
        {
            using (var scope = BackgroundJobScope.Begin("orphan", "op", TimeProvider.System))
            {
                scope.Complete();
            }

            await Task.Delay(150);
        });
        Assert.Null(ex);
    }

    [Fact]
    public async Task Dispose_WithRepository_PersistsRunRow()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new BackgroundJobRunRepository(_db));
        BackgroundJobScope.Services = services.BuildServiceProvider();

        using (var scope = BackgroundJobScope.Begin("persisted", "op.persist", TimeProvider.System))
        {
            scope.Complete();
        }

        Assert.True(await WaitForRowAsync("persisted"), "expected a background_job_runs row to be written");
    }

    [Fact]
    public async Task Dispose_WithRepository_PersistsErrorMessageOnFailure()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new BackgroundJobRunRepository(_db));
        BackgroundJobScope.Services = services.BuildServiceProvider();

        using (var scope = BackgroundJobScope.Begin("failing", "op.fail", TimeProvider.System))
        {
            scope.Fail(new InvalidOperationException("kaboom"));
        }

        Assert.True(await WaitForRowAsync("failing"), "expected a failed-run row to be written");
        await using var conn = await _db.OpenAsync();
        string? msg = await conn.ExecuteScalarAsync<string?>(
            "SELECT error_message FROM background_job_runs WHERE job_name = 'failing'");
        Assert.Equal("kaboom", msg);
    }

    private async Task<bool> WaitForRowAsync(string jobName)
    {
        for (int i = 0; i < 60; i++)
        {
            await using var conn = await _db.OpenAsync();
            long count = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM background_job_runs WHERE job_name = @jobName", new { jobName });
            if (count > 0)
            {
                return true;
            }

            await Task.Delay(50);
        }
        return false;
    }
}

[CollectionDefinition("BackgroundJobScope", DisableParallelization = true)]
public sealed class BackgroundJobScopeCollection { }
