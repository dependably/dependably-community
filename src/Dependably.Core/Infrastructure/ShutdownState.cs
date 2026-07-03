namespace Dependably.Infrastructure;

/// <summary>
/// Singleton that tracks whether the process is in the pre-stop drain window.
/// /ready returns 503 while IsShuttingDown is true so the ALB stops routing new traffic.
/// </summary>
public sealed class ShutdownState
{
    private volatile bool _isShuttingDown;
    public bool IsShuttingDown => _isShuttingDown;
    public void MarkShuttingDown() => _isShuttingDown = true;
}
