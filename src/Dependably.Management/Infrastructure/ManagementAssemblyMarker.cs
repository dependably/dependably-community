namespace Dependably.Infrastructure;

/// <summary>
/// Anchor type for reflection against the Dependably.Management assembly. Used where MVC needs
/// the management assembly by type rather than by <c>typeof(Program)</c>: the management
/// controllers live here, not in the composition-root assembly, and the full root registers this
/// assembly as an MVC application part via <c>typeof(ManagementAssemblyMarker).Assembly</c>.
/// The SPA/swagger static assets are Content items published into the root's output and served
/// by the physical file provider; this assembly carries no embedded-files manifest.
/// </summary>
public static class ManagementAssemblyMarker
{
}
