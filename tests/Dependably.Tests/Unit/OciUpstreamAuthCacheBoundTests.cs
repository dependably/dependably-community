using System.Reflection;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dependably.Tests.Unit;

/// <summary>
/// The token and per-key lock maps are keyed partly on the client-requested repository path,
/// so a pull-capable (or anonymous, with AnonymousPull) client can mint unlimited distinct
/// keys against any org with a matching upstream prefix. Both structures must stay bounded so
/// hostile enumeration cannot grow the singleton's memory without limit: the token cache is
/// size-capped with eviction, and the semaphore map is a fixed striped array.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciUpstreamAuthCacheBoundTests
{
    private static OciUpstreamAuthService BuildService()
    {
        var factory = new StubHttpClientFactory();
        return new OciUpstreamAuthService(
            factory,
            Options.Create(new OciOptions()),
            new StubAirGap(),
            NullLogger<OciUpstreamAuthService>.Instance,
            TestTime.Frozen());
    }

    private static int ConstInt(string name) =>
        (int)typeof(OciUpstreamAuthService)
            .GetField(name, BindingFlags.NonPublic | BindingFlags.Static)!
            .GetRawConstantValue()!;

    [Fact]
    public void TokenCache_StaysBounded_WhenClientMintsUnlimitedRepositoryKeys()
    {
        var svc = BuildService();
        var storeToken = typeof(OciUpstreamAuthService)
            .GetMethod("StoreToken", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var tokensField = typeof(OciUpstreamAuthService)
            .GetField("_tokens", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var cachedTokenType = typeof(OciUpstreamAuthService)
            .GetNestedType("CachedToken", BindingFlags.NonPublic)!;
        int cap = ConstInt("MaxCachedTokens");

        // Enumerate three times the cap of distinct repository keys under one upstream.
        for (int i = 0; i < cap * 3; i++)
        {
            var key = ("org1", "registry-1.docker.io", $"library/repo-{i}", "pull");
            object token = Activator.CreateInstance(cachedTokenType, $"tok-{i}", TestTime.KnownNow.AddHours(1))!;
            storeToken.Invoke(svc, new[] { (object)key, token });
        }

        var tokens = (System.Collections.ICollection)tokensField.GetValue(svc)!;
        Assert.True(tokens.Count <= cap,
            $"token cache must stay bounded at {cap}, but held {tokens.Count} entries");
    }

    [Fact]
    public void SemaphoreMap_IsFixedSize_RegardlessOfDistinctKeys()
    {
        var svc = BuildService();
        var sems = (Array)typeof(OciUpstreamAuthService)
            .GetField("_sems", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(svc)!;

        // The per-key semaphore map is replaced by a fixed striped array with no per-key growth
        // surface — its length equals StripeCount no matter how many keys a client requests.
        Assert.Equal(ConstInt("StripeCount"), sems.Length);
        foreach (object? s in sems)
        {
            Assert.IsType<SemaphoreSlim>(s);
        }
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new FakeHttpHandler());
    }
}
