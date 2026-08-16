using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the hosted-service registration order that <see cref="Program.ConfigureBuilder"/> wires up.
/// <c>IHost</c> starts hosted services in registration order, and the framework's DataProtection
/// hosted service eagerly loads the key ring from the <c>data_protection_keys</c> table at startup.
/// <see cref="CoreStartupService"/> runs the schema migration that creates that table, so it must be
/// registered — and therefore started and completed — before the DataProtection hosted service, or
/// the key-ring load races the migration on a fresh database.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HostedServiceBootOrderTests
{
    [Fact]
    public void ConfigureBuilder_RegistersCoreStartupServiceBeforeDataProtectionHostedService()
    {
        var builder = WebApplication.CreateBuilder();

        // Pin before ConfigureBuilder: the tenant resolver is selected from
        // DEPLOYMENT_MODE at service-registration time, so a UseSetting after this
        // line is inert. See TestHostEnv.
        TestHostEnv.PinAmbient(builder);
        Program.ConfigureBuilder(builder);

        var hostedServiceDescriptors = builder.Services
            .Where(d => d.ServiceType == typeof(IHostedService))
            .ToList();

        int coreStartupIndex = hostedServiceDescriptors.FindIndex(
            d => d.ImplementationType == typeof(CoreStartupService));
        int dataProtectionIndex = hostedServiceDescriptors.FindIndex(IsDataProtectionHostedService);

        Assert.True(coreStartupIndex >= 0,
            "CoreStartupService must be registered as an IHostedService.");
        Assert.True(dataProtectionIndex >= 0,
            "The framework DataProtection hosted service must be registered as an IHostedService " +
            "(AddDataProtection() is expected to have run).");
        Assert.True(coreStartupIndex < dataProtectionIndex,
            "CoreStartupService (schema init, creates data_protection_keys) must be registered — and "
            + "therefore start — before the DataProtection hosted service (which eagerly loads the key "
            + $"ring on startup). Got CoreStartupService at index {coreStartupIndex}, DataProtection "
            + $"hosted service at index {dataProtectionIndex}.");
    }

    // Matches the framework's DataProtectionHostedService by implementation-type name rather than a
    // direct type reference: it lives in an internal namespace under Microsoft.AspNetCore.DataProtection
    // and is not part of the public API surface this project can reference directly.
    private static bool IsDataProtectionHostedService(ServiceDescriptor descriptor) =>
        descriptor.ImplementationType?.FullName?.Contains(
            "DataProtectionHostedService", StringComparison.Ordinal) == true;
}
