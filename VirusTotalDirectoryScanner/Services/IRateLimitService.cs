using System;

namespace VirusTotalDirectoryScanner.Services;

public interface IRateLimitService
{
    event EventHandler<TimeSpan> RateLimitHit;
    event EventHandler RateLimitResolved;
    void NotifyRateLimitHit(TimeSpan waitTime);
    void NotifyRateLimitResolved();
    TimeSpan GetTimeUntilReset();
}
