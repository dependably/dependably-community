using Dependably.Infrastructure.Caching;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The full-host composition root registers exactly one <see cref="IMetadataInvalidationBus"/>.
/// Core registers the no-op bus and the management wiring swaps in the Redis one when
/// <c>REDIS_CONNECTION_STRING</c> is set. Two descriptors would still resolve the Redis bus for a
/// single-service lookup (the last registration wins), but an enumeration would also surface the
/// no-op, and which one a lookup returns would hang on registration order rather than on intent.
/// The collection is inspected, not built, so no broker is needed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MetadataInvalidationBusRegistrationTests : IDisposable
{
    private readonly string _dataDir =
        Path.Combine(Path.GetTempPath(), "dependably-bus-registration-" + Guid.NewGuid().ToString("N"));

    [Theory]
    [InlineData("redis.invalid:6379", typeof(RedisMetadataInvalidationBus))]
    [InlineData("", typeof(NullMetadataInvalidationBus))]
    public void FullHost_RegistersOneInvalidationBus(string redisConnectionString, Type expected)
    {
        var builder = WebApplication.CreateBuilder();
        TestHostEnv.PinAmbient(builder);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            // Pinned in both directions so an ambient value in the developer's shell cannot flip
            // the case under test.
            ["REDIS_CONNECTION_STRING"] = redisConnectionString,
            ["DB_PATH"] = Path.Combine(_dataDir, "dependably.db"),
            ["LOCAL_STORAGE_PATH"] = Path.Combine(_dataDir, "blobs"),
        });

        Program.ConfigureBuilder(builder);

        var descriptor = Assert.Single(builder.Services, d => d.ServiceType == typeof(IMetadataInvalidationBus));
        Assert.Equal(expected, descriptor.ImplementationType);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dataDir, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
            // Nothing was written.
        }
    }
}
