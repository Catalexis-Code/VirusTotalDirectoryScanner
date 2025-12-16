using System;

namespace VirusTotalDirectoryScanner.Services;

public interface IRateLimitService
{
    event EventHandler<TimeSpan> RateLimitHit;
    void NotifyRateLimitHit(TimeSpan waitTime);
    TimeSpan GetTimeUntilReset();
}
