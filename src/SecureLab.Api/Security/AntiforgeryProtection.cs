using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Cors;

namespace SecureLab.Api.Security;

public static class AntiforgeryProtection
{
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string TokenPath = "/api/auth/csrf";

    public static void AddCookieAntiforgery(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IAntiforgeryAdditionalDataProvider, StampBoundAntiforgeryData>();
        builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = HeaderName;
            options.Cookie.Name = "SecureLab.Antiforgery";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        });
    }

    public static void MapAntiforgeryToken(this WebApplication app)
    {
        app.MapGet(TokenPath, (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Ok(new AntiforgeryTokenResponse(tokens.RequestToken!, HeaderName));
        })
            .RequireAuthorization()
            .WithMetadata(new DisableCorsAttribute())
            .Produces<AntiforgeryTokenResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized);
    }
}

public sealed record AntiforgeryTokenResponse(string RequestToken, string HeaderName);

// JSON and DELETE routes use this explicit standard validation before the handler can mutate state.
public sealed class AntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(title: "CSRF-перевірку не пройдено.",
                statusCode: StatusCodes.Status400BadRequest,
                extensions: new Dictionary<string, object?> { ["code"] = "csrf_validation_failed" });
        }
        return await next(context);
    }
}
