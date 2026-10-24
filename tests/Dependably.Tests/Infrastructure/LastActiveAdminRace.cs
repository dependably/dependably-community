using System.Security.Claims;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Drives two operators changing each other's account status at the same moment through the real
/// <see cref="SystemController"/> and <see cref="SystemAdminRepository"/>, on whichever store the
/// caller supplies (in-memory SQLite, a file-backed production SQLite store, or Postgres). The
/// admin repository sits behind a <see cref="LockstepOpenStore"/>, so a guard that reads and writes
/// on separate connections is forced into the read-read-write-write interleaving that loses the
/// last active admin; everything else (audit, tokens) uses the store directly.
/// </summary>
internal static class LastActiveAdminRace
{
    /// <summary>One request's result: HTTP status and, for a problem response, its <c>reason</c>.</summary>
    public readonly record struct Response(int Status, string? Reason);

    /// <summary>
    /// <paramref name="adminA"/> sets <paramref name="adminB"/> to <paramref name="statusForB"/>
    /// while <paramref name="adminB"/> sets <paramref name="adminA"/> to <paramref name="statusForA"/>.
    /// </summary>
    public static async Task<(Response ByA, Response ByB)> MutualAsync(
        IMetadataStore db, string adminA, string adminB, string statusForB, string statusForA)
    {
        var lockstep = new LockstepOpenStore(db);
        var byA = Controller(lockstep, db, actorId: adminA);
        var byB = Controller(lockstep, db, actorId: adminB);

        var first = lockstep.RunAsAsync(0, () => byA.SetAdminAccountStatus(
            adminB, new SetAdminAccountStatusRequest(statusForB), CancellationToken.None));
        var second = lockstep.RunAsAsync(1, () => byB.SetAdminAccountStatus(
            adminA, new SetAdminAccountStatusRequest(statusForA), CancellationToken.None));
        var results = await Task.WhenAll(first, second);
        return (Describe(results[0]), Describe(results[1]));
    }

    /// <summary>A controller acting as <paramref name="actorId"/> with its admin repository on <paramref name="adminStore"/>.</summary>
    public static SystemController Controller(IMetadataStore adminStore, IMetadataStore db, string actorId)
    {
        var clock = TestTime.Frozen();
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, actorId),
                    new Claim("sub", actorId),
                    new Claim("scope", "system"),
                ],
                authenticationType: "test")),
        };
        return new SystemController(
            new OrgRepository(db),
            new SystemAdminRepository(adminStore, clock),
            new SystemTokenRepository(db, clock),
            db,
            new AuditRepository(db),
            TestProblems.Create(),
            new ConfigurationBuilder().Build(),
            clock,
            TestEnvelope.Unconfigured(),
            NullLogger<SystemController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    public static Response Describe(IActionResult result) => result switch
    {
        ObjectResult { Value: ProblemDetails problem } obj => new(
            obj.StatusCode ?? problem.Status ?? 0,
            problem.Extensions.TryGetValue("reason", out object? reason) ? reason?.ToString() : null),
        ObjectResult obj => new(obj.StatusCode ?? StatusCodes.Status200OK, null),
        IStatusCodeActionResult status => new(status.StatusCode ?? 0, null),
        _ => throw new InvalidOperationException($"Unexpected action result {result.GetType().Name}."),
    };

    public static async Task<List<string>> ActiveIdsAsync(IMetadataStore db)
    {
        await using var conn = await db.OpenAsync();
        return (await conn.QueryAsync<string>(
            "SELECT id FROM system_admins WHERE account_status = 'active'")).AsList();
    }

    /// <summary>Takes every existing admin out of the active set, so a test starts from a known count.</summary>
    public static async Task DisableAllAsync(IMetadataStore db)
    {
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync("UPDATE system_admins SET account_status = 'disabled'");
    }
}
