using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using SecureLab.Api.Application.Authentication;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public const string AuthenticationLogCategory = "SecureLab.Api.Authentication";
    private const int UserNameMaxLength = 256;
    private const int EmailMaxLength = 256;
    private const int DisplayNameMaxLength = 120;
    private static readonly EmailAddressAttribute EmailAddressValidator = new();

    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                return WriteAuthenticationProblemAsync(
                    context.HttpContext,
                    StatusCodes.Status401Unauthorized,
                    "Потрібна автентифікація.");
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                return WriteAuthenticationProblemAsync(
                    context.HttpContext,
                    StatusCodes.Status403Forbidden,
                    "Доступ заборонено.");
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", RegisterAsync)
            .Produces<RegisteredUserResponse>(StatusCodes.Status201Created)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .ProducesValidationProblem(StatusCodes.Status409Conflict);
        app.MapPost("/api/auth/login", LoginAsync);
        app.MapPost("/api/auth/logout", async (
            SignInManager<ApplicationUser> signIn,
            ILoggerFactory loggerFactory) =>
        {
            await signIn.SignOutAsync();
            loggerFactory.CreateLogger(AuthenticationLogCategory)
                .LogInformation("Authentication event: logout completed.");
            return Results.NoContent();
        })
            .Produces(StatusCodes.Status204NoContent);
        app.MapGet("/api/me", GetCurrentUserAsync)
            .RequireAuthorization()
            .Produces<CurrentUserResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized);
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static async Task<IResult> LoginAsync(
        LoginInput input,
        HttpContext context,
        SignInManager<ApplicationUser> signIn,
        LoginAttemptLimiter loginAttempts,
        ILoggerFactory loggerFactory)
    {
        var logger = loggerFactory.CreateLogger(AuthenticationLogCategory);
        // IP-based partitioning treats all account names identically. This
        // avoids letting user-controlled names influence the limiter or logs.
        var partitionKey = context.Connection.RemoteIpAddress?.ToString() ?? "unknown-client";

        if (loginAttempts.IsBlocked(partitionKey))
        {
            logger.LogWarning("Authentication event: login rate limited.");
            return Results.Problem(
                title: "Забагато спроб входу.",
                statusCode: StatusCodes.Status429TooManyRequests);
        }

        var succeeded = !string.IsNullOrWhiteSpace(input.UserName)
            && !string.IsNullOrEmpty(input.Password)
            && (await signIn.PasswordSignInAsync(
                input.UserName,
                input.Password,
                isPersistent: false,
                lockoutOnFailure: false)).Succeeded;

        if (succeeded)
        {
            logger.LogInformation("Authentication event: login succeeded.");
            return Results.NoContent();
        }

        loginAttempts.RecordFailure(partitionKey);
        logger.LogWarning("Authentication event: login failed.");
        return Results.Unauthorized();
    }

    private static async Task<IResult> GetCurrentUserAsync(
        HttpContext context,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        // The identity comes only from the authenticated cookie principal.
        // Request headers and client-supplied identifiers are deliberately ignored.
        var principalId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(principalId, out var userId))
        {
            return Results.Unauthorized();
        }

        var profile = await db.Users
            .AsNoTracking()
            .Where(user => user.Id == userId)
            .Select(user => new CurrentUserResponse(
                user.Id,
                user.UserName!,
                user.DisplayName))
            .SingleOrDefaultAsync(cancellationToken);

        return profile is null ? Results.Unauthorized() : Results.Ok(profile);
    }

    private static Task WriteAuthenticationProblemAsync(
        HttpContext context,
        int statusCode,
        string title)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";

        var payload = JsonSerializer.Serialize(
            new ProblemDetails
            {
                Status = statusCode,
                Title = title
            },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        return context.Response.WriteAsync(payload);
    }

    private static async Task<IResult> RegisterAsync(
        RegisterUserRequest input,
        UserManager<ApplicationUser> users)
    {
        // The contract defines trimming for public profile fields only. A
        // password is deliberately passed to Identity unchanged.
        var userName = input.UserName?.Trim();
        var email = input.Email?.Trim();
        var displayName = input.DisplayName?.Trim();

        var validationErrors = ValidateRegistration(
            userName,
            email,
            displayName,
            input.Password);

        if (validationErrors.Count > 0)
        {
            return Results.ValidationProblem(validationErrors);
        }

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = userName!,
            Email = email!,
            DisplayName = displayName!
        };

        var createResult = await users.CreateAsync(user, input.Password!);
        if (!createResult.Succeeded)
        {
            return CreateIdentityFailureResult(createResult);
        }

        var roleResult = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
        if (!roleResult.Succeeded)
        {
            // Do not leave a partially registered account if the fixed,
            // server-owned default role was not available.
            await users.DeleteAsync(user);
            throw new InvalidOperationException("Default role assignment failed.");
        }

        var response = new RegisteredUserResponse(
            user.Id,
            user.UserName,
            user.DisplayName);

        return Results.Created("/api/me", response);
    }

    private static Dictionary<string, string[]> ValidateRegistration(
        string? userName,
        string? email,
        string? displayName,
        string? password)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(userName))
        {
            errors["userName"] = ["Ім’я користувача є обов’язковим."];
        }
        else if (userName.Length > UserNameMaxLength)
        {
            errors["userName"] = [$"Ім’я користувача не може бути довшим за {UserNameMaxLength} символів."];
        }
        else if (!HasAllowedUserNameCharacters(userName))
        {
            errors["userName"] = ["Допустимі лише латинські літери, цифри та символи -._@+."];
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            errors["email"] = ["Email є обов’язковим."];
        }
        else if (email.Length > EmailMaxLength)
        {
            errors["email"] = [$"Email не може бути довшим за {EmailMaxLength} символів."];
        }
        else if (!EmailAddressValidator.IsValid(email))
        {
            errors["email"] = ["Email має коректний формат."];
        }

        if (string.IsNullOrWhiteSpace(displayName))
        {
            errors["displayName"] = ["Ім’я профілю є обов’язковим."];
        }
        else if (displayName.Length > DisplayNameMaxLength)
        {
            errors["displayName"] = [$"Ім’я профілю не може бути довшим за {DisplayNameMaxLength} символів."];
        }

        if (string.IsNullOrEmpty(password))
        {
            errors["password"] = ["Пароль є обов’язковим."];
        }

        return errors;
    }

    private static bool HasAllowedUserNameCharacters(string userName)
    {
        foreach (var character in userName)
        {
            var isAsciiLetter = character is >= 'A' and <= 'Z' or >= 'a' and <= 'z';
            var isDigit = character is >= '0' and <= '9';
            var isAllowedPunctuation = character is '-' or '.' or '_' or '@' or '+';

            if (!isAsciiLetter && !isDigit && !isAllowedPunctuation)
            {
                return false;
            }
        }

        return true;
    }

    private static IResult CreateIdentityFailureResult(IdentityResult result)
    {
        var codes = result.Errors
            .Select(error => error.Code)
            .ToHashSet(StringComparer.Ordinal);

        if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
        {
            var errors = new Dictionary<string, string[]>();

            if (codes.Contains("DuplicateUserName"))
            {
                errors["userName"] = ["Це ім’я користувача вже зайняте."];
            }

            if (codes.Contains("DuplicateEmail"))
            {
                errors["email"] = ["Цей email уже використовується."];
            }

            return Results.ValidationProblem(
                errors,
                statusCode: StatusCodes.Status409Conflict);
        }

        if (codes.Overlaps(
            [
                "PasswordTooShort",
                "PasswordRequiresDigit",
                "PasswordRequiresLower",
                "PasswordRequiresUpper",
                "PasswordRequiresNonAlphanumeric"
            ]))
        {
            return Results.ValidationProblem(
                new Dictionary<string, string[]>
                {
                    ["password"] = ["Пароль не відповідає налаштованим вимогам."]
                });
        }

        return Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
                ["registration"] = ["Дані реєстрації некоректні."]
            });
    }
}

public sealed record LoginInput(string? UserName, string? Password);
