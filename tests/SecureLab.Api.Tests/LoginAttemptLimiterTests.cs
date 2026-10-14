using Microsoft.Extensions.Caching.Memory;
using SecureLab.Api.Application.Authentication;

namespace SecureLab.Api.Tests;

public sealed class LoginAttemptLimiterTests
{
    [Fact]
    public void FailedAttempts_ArePartitionedAndExpireAtTheWindowBoundary()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new LoginAttemptLimiter(cache, clock);

        for (var attempt = 0; attempt < LoginAttemptLimiter.MaximumFailedAttempts; attempt++)
        {
            limiter.RecordFailure("192.0.2.10");
        }

        Assert.True(limiter.IsBlocked("192.0.2.10"));
        Assert.False(limiter.IsBlocked("192.0.2.11"));

        clock.Advance(LoginAttemptLimiter.Window);

        Assert.False(limiter.IsBlocked("192.0.2.10"));
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset utcNow = now;

        public override DateTimeOffset GetUtcNow() => utcNow;

        public void Advance(TimeSpan elapsed) => utcNow += elapsed;
    }
}
