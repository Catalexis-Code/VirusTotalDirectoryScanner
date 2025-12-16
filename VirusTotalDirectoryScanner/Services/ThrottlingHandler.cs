using System.Net.Http;
using System.Threading.RateLimiting;

namespace VirusTotalDirectoryScanner.Services;

internal sealed class ThrottlingHandler : DelegatingHandler
{
    private readonly RateLimiter _limiter;

    public ThrottlingHandler(RateLimiter limiter)
        : base(new HttpClientHandler()) => _limiter = limiter;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        using var lease = await _limiter.AcquireAsync(1, ct);
        if (!lease.IsAcquired)
            return new HttpResponseMessage(System.Net.HttpStatusCode.TooManyRequests);

        return await base.SendAsync(request, ct);
    }
}
