using System;

namespace VirusTotalDirectoryScanner.Services;

public class RateLimitService : IRateLimitService
{
    private readonly DateTime _windowStart;
    private readonly TimeSpan _windowDuration = TimeSpan.FromMinutes(1);

    public event EventHandler<TimeSpan>? RateLimitHit;

    public RateLimitService()
    {
        // Assuming the window starts when the service (and thus the limiter) is created.
        _windowStart = DateTime.UtcNow;
    }

    public void NotifyRateLimitHit(TimeSpan waitTime)
    {
        RateLimitHit?.Invoke(this, waitTime);
    }

    public TimeSpan GetTimeUntilReset()
    {
        var now = DateTime.UtcNow;
        var elapsed = now - _windowStart;
        var windowsPassed = (long)(elapsed.Ticks / _windowDuration.Ticks);
        var currentWindowStart = _windowStart.AddTicks(windowsPassed * _windowDuration.Ticks);
        var nextReset = currentWindowStart.Add(_windowDuration);

        var remaining = nextReset - now;
        return remaining < TimeSpan.Zero ? TimeSpan.Zero : remaining;
    }
}
