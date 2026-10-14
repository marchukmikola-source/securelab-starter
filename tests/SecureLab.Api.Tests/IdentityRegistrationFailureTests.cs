using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class IdentityRegistrationFailureTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Theory]
    [InlineData("InvalidUserName", "userName")]
    [InlineData("InvalidEmail", "email")]
    [InlineData("UnexpectedValidationFailure", "registration")]
    public async Task Register_WithIdentityValidationFailure_ReturnsSafeFieldError(
        string code,
        string expectedField)
    {
        var publicName = $"reg{Guid.NewGuid():N}"[..24];
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddScoped<IUserValidator<ApplicationUser>>(_ => new RejectingUserValidator(publicName, code))));
        using var client = host.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = publicName,
            email = $"{publicName}@example.test",
            displayName = "Identity validation verification",
            password = Environment.GetEnvironmentVariable("SeedUsers__Password")
                ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.")
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        var errors = json.RootElement.GetProperty("errors");
        var errorFields = errors.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal([expectedField], errorFields);
        Assert.False(body.Contains("internal-validation-detail", StringComparison.Ordinal));
        Assert.False(body.Contains(code, StringComparison.Ordinal));

        using var scope = host.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        Assert.False(await users.FindByNameAsync(publicName) is not null,
            "Failed Identity validation must not persist the account.");
    }

    private sealed class RejectingUserValidator(string publicName, string code) : IUserValidator<ApplicationUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user) =>
            Task.FromResult(user.UserName == publicName
                ? IdentityResult.Failed(new IdentityError
                {
                    Code = code,
                    Description = "internal-validation-detail must never appear in the response"
                })
                : IdentityResult.Success);
    }
}
