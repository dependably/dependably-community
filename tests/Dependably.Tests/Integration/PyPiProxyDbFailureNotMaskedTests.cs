using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression test for the PyPI proxy first-fetch error-handling contract: a metadata-store
/// failure during first-fetch recording must NOT be masked as a 404.
///
/// <see cref="Dependably.Api.PyPiProtocol.PyPiProxyFetcher"/> ends its fetch path with a
/// blanket <c>catch { return NotFoundResult(); }</c>. Inside the try,
/// <c>ProxyFetchService.RecordAndScanAsync</c> → <c>ProxyVersionRecorder.RecordAsync</c> issues
/// direct DB writes (the per-tenant <c>packages</c> row, the global cache facts) that run
/// synchronously on the request thread and are NOT wrapped by <c>CacheAccessRecorder</c>'s
/// swallow-to-null. A raw provider exception there (DB locked, disk full, corrupt) reached the
/// blanket catch and became a 404 — so pip reported a real, existing package as nonexistent
/// during an infrastructure outage.
///
/// The fix adds a <c>catch (DbException) { throw; }</c> arm (matching npm/NuGet) so the failure
/// propagates to a 5xx instead. This test installs a <c>BEFORE INSERT</c> trigger on
/// <c>packages</c> that aborts the insert — forcing a <c>SqliteException</c> from
/// <c>PackageRepository.GetOrCreateAsync</c>, the first synchronous write inside
/// <c>RecordAsync</c> — then asserts the response is a server error and specifically NOT a 404.
/// It fails on the pre-fix code (404) and passes after.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiProxyDbFailureNotMaskedTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public PyPiProxyDbFailureNotMaskedTests(DependablyFactory factory) => _factory = factory;

    private void StubWheelUpstream(string name, string filename, byte[] wheelBytes, string sha256Hex)
    {
        string mockBase = _factory.MockUpstream.Urls[0];
        string simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{filename}#sha256={sha256Hex}">{filename}</a>
            </body></html>
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(simpleHtml));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(wheelBytes));
    }

    [Fact]
    public async Task ProxyFirstFetch_DbFailureDuringRecording_IsNotMaskedAs404()
    {
        // Boot the app (schema init + first-boot) before touching the DB directly.
        using (var bootClient = _factory.CreateClient())
        {
            await bootClient.GetAsync("/health");
        }

        string name = $"pypi-dbfail-{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-1.0.0-py3-none-any.whl";
        var (wheelBytes, sha256Hex) = PyPiFixtures.BuildWheel(name, "1.0.0");

        StubWheelUpstream(name, filename, wheelBytes, sha256Hex);

        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        try
        {
            // Force a metadata-store failure inside ProxyVersionRecorder.RecordAsync: its first
            // synchronous global-plane write is the per-tenant packages GetOrCreate INSERT. A
            // BEFORE INSERT trigger that aborts makes that INSERT throw SqliteException — a
            // DbException the fetch path must not mask as a 404.
            await conn.ExecuteAsync(
                """
                CREATE TRIGGER __test_fail_packages_insert BEFORE INSERT ON packages
                BEGIN
                    SELECT RAISE(ABORT, 'injected db failure');
                END
                """);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            // The artefact exists upstream; the failure is pure infrastructure. Pre-fix code swallowed
            // it and returned 404 (package reported nonexistent). The fix rethrows the DbException, so
            // it must NOT be a 404: either it surfaces as a 5xx, or — under the TestServer pipeline,
            // which has no catch-all exception handler and rethrows unhandled exceptions to the
            // caller — the send itself throws. Both outcomes prove the failure is no longer masked.
            HttpResponseMessage? resp = null;
            Exception? thrown = null;
            try
            {
                resp = await client.GetAsync($"/packages/{filename}");
            }
            catch (Exception ex)
            {
                thrown = ex;
            }

            if (thrown is not null)
            {
                // The propagated exception must be the injected metadata-store failure, not some
                // unrelated fault — walk the chain for the DbException / abort message.
                bool isInjectedDbFailure = false;
                for (var e = thrown; e is not null; e = e.InnerException)
                {
                    if (e is System.Data.Common.DbException ||
                        e.Message.Contains("injected db failure", StringComparison.Ordinal))
                    {
                        isInjectedDbFailure = true;
                        break;
                    }
                }

                Assert.True(isInjectedDbFailure,
                    $"Expected the injected DbException to propagate, got {thrown.GetType().Name}: {thrown.Message}");
            }
            else
            {
                Assert.NotEqual(HttpStatusCode.NotFound, resp!.StatusCode);
                Assert.True((int)resp.StatusCode >= 500,
                    $"Expected a server error, got {(int)resp.StatusCode} {resp.StatusCode}.");
            }
        }
        finally
        {
            // Drop the trigger so sibling tests on the shared factory are unaffected.
            await conn.ExecuteAsync("DROP TRIGGER IF EXISTS __test_fail_packages_insert");
        }
    }
}
