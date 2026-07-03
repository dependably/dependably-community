using Dependably.Infrastructure;
using Dependably.Protocol;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for a real <see cref="BlockGateService"/> wired over an in-memory metadata store,
/// so controller-construction test helpers do not each re-assemble its dependency graph.
/// </summary>
public static class TestBlockGate
{
    public static BlockGateService Create(IMetadataStore db, TimeProvider clock) =>
        new(
            new VulnerabilityRepository(db, clock),
            new AuditRepository(db),
            new QuarantineRepository(db, clock),
            new InstallScriptAllowlistService(db, new MemoryCache(new MemoryCacheOptions()), clock),
            NullLogger<BlockGateService>.Instance,
            clock);
}
