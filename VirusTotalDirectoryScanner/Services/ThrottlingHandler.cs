using System.Net.Http;
using System.Threading.RateLimiting;

namespace VirusTotalDirectoryScanner.Services;

internal sealed class ThrottlingHandler : DelegatingHandler
{
    private readonly RateLimiter _limiter;
    private readonly IRateLimitService _rateLimitService;

    public ThrottlingHandler(RateLimiter limiter, IRateLimitService rateLimitService)
        : base(new HttpClientHandler())
    {
        _limiter = limiter;
        _rateLimitService = rateLimitService;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        if (_limiter.GetStatistics()?.CurrentAvailablePermits == 0)
        {
            _rateLimitService.NotifyRateLimitHit(_rateLimitService.GetTimeUntilReset());
        }

        using var lease = await _limiter.AcquireAsync(1, ct);
        if (!lease.IsAcquired)
            return new HttpResponseMessage(System.Net.HttpStatusCode.TooManyRequests);

        _rateLimitService.NotifyRateLimitResolved();

        return await base.SendAsync(request, ct);
    }
}
