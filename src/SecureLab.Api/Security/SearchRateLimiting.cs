using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace SecureLab.Api.Security;

public sealed class SearchRateLimitOptions
{
    public int PermitLimit { get; set; } = 30;
    public int WindowSeconds { get; set; } = 10;
}

public static class SearchRateLimiting
{
    public const string PolicyName = "incident-search";

    public static void AddSearchRateLimiting(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<SearchRateLimitOptions>()
            .Bind(builder.Configuration.GetSection("RateLimiting:Search"))
            .Validate(options => options.PermitLimit is >= 1 and <= 1000
                && options.WindowSeconds is >= 1 and <= 3600, "Invalid search rate limit configuration.")
            .ValidateOnStart();
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                await Results.Problem(title: "Забагато запитів пошуку.", statusCode: 429)
                    .ExecuteAsync(context.HttpContext);
            };
            options.AddPolicy(PolicyName, context =>
            {
                var settings = context.RequestServices.GetRequiredService<IOptions<SearchRateLimitOptions>>().Value;
                // Authentication and authorization run first. Client headers/query never select a partition.
                var subject = context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "missing-subject";
                return RateLimitPartition.GetFixedWindowLimiter(subject, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = settings.PermitLimit,
                    Window = TimeSpan.FromSeconds(settings.WindowSeconds),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
            });
        });
    }
}
