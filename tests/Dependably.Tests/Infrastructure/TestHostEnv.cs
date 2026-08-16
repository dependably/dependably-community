using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Makes a hand-rolled test host hermetic against the developer's shell.
///
/// <para>Both composition roots call <c>.AddEnvironmentVariables()</c>, and an integration test
/// boots that same builder through <c>WebApplicationFactory&lt;Program&gt;</c>. Every OS
/// environment variable therefore flows into every test host's configuration. Most of it is
/// harmless — the fixtures substitute <c>IMetadataStore</c> and <c>IBlobStore</c> outright, so a
/// developer's <c>DB_PATH</c> or <c>LOCAL_STORAGE_PATH</c> can never reach a real store. What
/// leaks is configuration consumed at <em>service-registration</em> time, which a later DI
/// substitution cannot undo.</para>
///
/// <para><c>DEPLOYMENT_MODE</c> is the case that bites: it selects the tenant-resolver strategy
/// while services are being registered, and in <c>multi</c> the host seeds no <c>default</c> org.
/// A developer who keeps <c>DEPLOYMENT_MODE=multi</c> exported for a local instance — a supported,
/// deliberate setup — then watches a chunk of the integration suite fail with
/// <c>"Default org not found"</c>, an error that points at the org rather than at the mode.</para>
///
/// <para><b>Call this between <c>WebApplication.CreateBuilder()</c> and
/// <c>Program.ConfigureBuilder(builder)</c>.</b> The ordering is the whole point and is not
/// stylistic: after <c>ConfigureBuilder</c> the resolver is already bound, so the widespread
/// <c>builder.WebHost.UseSetting("DEPLOYMENT_MODE", …)</c> form is inert for this key however
/// correct it looks. It works for keys read at runtime (<c>AIR_GAPPED</c>, <c>OSV_MODE</c>), which
/// is why the mistake is easy to make by copying a neighbouring line.
/// <see cref="Dependably.Tests.Compliance.TestHostAmbientEnvComplianceTests"/> enforces both the
/// presence and the ordering.</para>
///
/// <para>Scope is deliberately one key. The environment provider is left in place, because booting
/// the real builder — env provider included — is precisely what an integration test is for; a test
/// host that read no environment would stop resembling production. This pins the one value proven
/// to break hermeticity, and is the single place to add another if one is found.</para>
/// </summary>
public static class TestHostEnv
{
    /// <summary>The mode the fixtures assume: first boot seeds the <c>default</c> org.</summary>
    public const string DefaultDeploymentMode = "single";

    /// <summary>
    /// Pins <c>DEPLOYMENT_MODE</c> so an ambient value cannot select a different tenant resolver.
    /// Added as a configuration source rather than through the indexer: a source outranks the
    /// environment-variable provider and survives the provider reload during <c>Build()</c>, which
    /// a plain indexer assignment does not.
    /// </summary>
    /// <param name="builder">The builder, freshly returned by <c>WebApplication.CreateBuilder()</c>.</param>
    /// <param name="deploymentMode">
    /// Mode to pin. Defaults to <see cref="DefaultDeploymentMode"/>; pass <c>multi</c>, <c>header</c>
    /// or <c>edge</c> for a fixture that deliberately exercises one of those.
    /// </param>
    public static void PinAmbient(WebApplicationBuilder builder, string deploymentMode = DefaultDeploymentMode)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = deploymentMode,
        });
    }
}
