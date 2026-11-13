using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Security;

public static class SessionRevocation
{
    public const string Path = "/api/me/sessions/revoke-all";
    public const string LogCategory = "SecureLab.Api.Audit.SessionRevocation";

    public static void MapSessionRevocation(this WebApplication app)
    {
        app.MapPost(Path, RevokeAsync)
            .RequireAuthorization()
            .AddEndpointFilter<AntiforgeryFilter>()
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
    }

    private static async Task<IResult> RevokeAsync(RevokeSessionsRequest input,
        HttpContext context, UserManager<ApplicationUser> users,
        SignInManager<ApplicationUser> signIn, RevocationAttemptLimiter limiter,
        ILoggerFactory loggerFactory, TimeProvider clock)
    {
        var subject = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(subject, out var userId)) return Results.Unauthorized();
        var logger = loggerFactory.CreateLogger(LogCategory);
        void Audit(string result) => logger.LogInformation(new EventId(4201, "sessions.revoke_all"),
            "{EventName} {Subject} {Action} {Resource} {Result} {Time} {TraceId}",
            "sessions.revoke_all", userId, "revoke-all", "self/sessions", result,
            clock.GetUtcNow(), System.Diagnostics.Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier);

        // Atomic admission bounds expensive password checks, including concurrent attempts.
        // Only the authenticated subject selects the partition; no persistent account lockout.
        if (!limiter.TryAcquire(userId))
        {
            Audit("rate_limited");
            return Results.Problem(title: "Забагато спроб підтвердження пароля.", statusCode: 429);
        }
        if (string.IsNullOrEmpty(input.CurrentPassword) || input.CurrentPassword.Length > 1024)
        {
            Audit("failure");
            return Results.Problem(title: "Укажіть поточний пароль.", statusCode: 400);
        }
        var user = await users.GetUserAsync(context.User);
        if (user is null) return Results.Unauthorized();
        if (!await users.CheckPasswordAsync(user, input.CurrentPassword))
        {
            Audit("failure");
            return Results.Problem(title: "Підтвердження пароля не пройдено.", statusCode: 403);
        }
        var result = await users.UpdateSecurityStampAsync(user);
        if (!result.Succeeded)
        {
            Audit("failure");
            throw new InvalidOperationException("Session revocation could not be persisted.");
        }
        await signIn.SignOutAsync();
        Audit("success");
        return Results.NoContent();
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record RevokeSessionsRequest(string? CurrentPassword);

public sealed class RevocationAttemptLimiter(IMemoryCache cache, TimeProvider clock)
{
    public const int PermitLimit = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(2);
    private readonly object sync = new();

    public bool TryAcquire(Guid subject)
    {
        lock (sync)
        {
            var key = (typeof(RevocationAttemptLimiter), subject);
            var now = clock.GetUtcNow();
            if (!cache.TryGetValue<Attempts>(key, out var state) || state is null || now >= state.End)
                state = new Attempts(now.Add(Window), 0);
            if (state.Count >= PermitLimit) return false;
            cache.Set(key, state with { Count = state.Count + 1 }, Window);
            return true;
        }
    }

    private sealed record Attempts(DateTimeOffset End, int Count);
}
