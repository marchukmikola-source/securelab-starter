using Microsoft.Extensions.Caching.Memory;

namespace SecureLab.Api.Application.Authentication;

public sealed class LoginAttemptLimiter(
    IMemoryCache cache,
    TimeProvider timeProvider)
{
    public const int MaximumFailedAttempts = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(2);

    private readonly object sync = new();

    public bool IsBlocked(string partitionKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partitionKey);

        lock (sync)
        {
            var attempts = GetActiveAttempts(partitionKey);
            return attempts.Count >= MaximumFailedAttempts;
        }
    }

    public void RecordFailure(string partitionKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partitionKey);

        lock (sync)
        {
            var attempts = GetActiveAttempts(partitionKey);
            attempts.Add(timeProvider.GetUtcNow());

            cache.Set(
                GetCacheKey(partitionKey),
                attempts,
                new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = Window
                });
        }
    }

    private List<DateTimeOffset> GetActiveAttempts(string partitionKey)
    {
        var cacheKey = GetCacheKey(partitionKey);
        var attempts = cache.Get<List<DateTimeOffset>>(cacheKey) ?? [];
        var cutoff = timeProvider.GetUtcNow() - Window;

        attempts.RemoveAll(attempt => attempt <= cutoff);

        if (attempts.Count == 0)
        {
            cache.Remove(cacheKey);
        }

        return attempts;
    }

    private static string GetCacheKey(string partitionKey) =>
        $"failed-login-attempts:{partitionKey}";
}
