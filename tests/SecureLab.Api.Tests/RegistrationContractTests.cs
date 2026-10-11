using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class RegistrationContractTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Register_WithValidInput_ReturnsSafeResponseAndAssignsReporterRole()
    {
        var userName = NewUserName();
        var email = $"{userName}@example.test";

        try
        {
            using var client = factory.CreateClient();
            using var response = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = $"  {userName}  ",
                email = $"  {email}  ",
                displayName = "  Тестовий користувач  ",
                password = GetLocalStudyPassword()
            });

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

            var body = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;

            var responseFields = root.EnumerateObject()
                .Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(["displayName", "id", "userName"], responseFields);
            Assert.Equal(userName, root.GetProperty("userName").GetString());
            Assert.Equal("Тестовий користувач", root.GetProperty("displayName").GetString());
            Assert.NotEqual(Guid.Empty, root.GetProperty("id").GetGuid());
            Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("securityStamp", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("cookie", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("token", body, StringComparison.OrdinalIgnoreCase);
            Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));

            using var scope = factory.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var registeredUser = await users.FindByNameAsync(userName);

            Assert.NotNull(registeredUser);
            Assert.True(await users.IsInRoleAsync(registeredUser, DbSeeder.ReporterRole));
            Assert.False(await users.IsInRoleAsync(registeredUser, DbSeeder.AdministratorRole));
        }
        finally
        {
            await DeleteUserAsync(userName);
        }
    }

    [Fact]
    public async Task Register_WithUnexpectedServerManagedField_Returns400WithoutCreatingAccount()
    {
        var userName = NewUserName();

        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"{userName}@example.test",
            displayName = "Перевірка зайвого поля",
            password = GetLocalStudyPassword(),
            role = "Administrator"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        Assert.Null(await users.FindByNameAsync(userName));
    }

    [Fact]
    public async Task Register_WithDuplicateUserName_Returns409ValidationProblem()
    {
        var userName = NewUserName();

        try
        {
            using var client = factory.CreateClient();
            using (var firstResponse = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName,
                email = $"{userName}@example.test",
                displayName = "Перший користувач",
                password = GetLocalStudyPassword()
            }))
            {
                Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);
            }

            using var duplicateResponse = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName,
                email = $"second-{userName}@example.test",
                displayName = "Повторний користувач",
                password = GetLocalStudyPassword()
            });

            Assert.Equal(HttpStatusCode.Conflict, duplicateResponse.StatusCode);
            Assert.Equal("application/problem+json", duplicateResponse.Content.Headers.ContentType?.MediaType);

            var body = await duplicateResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(body);
            var errors = document.RootElement.GetProperty("errors");

            Assert.True(errors.TryGetProperty("userName", out _));
            Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("passwordhash", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("securitystamp", body, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await DeleteUserAsync(userName);
        }
    }

    [Fact]
    public async Task Register_WithDuplicateEmail_Returns409ValidationProblem()
    {
        var firstUserName = NewUserName();
        var secondUserName = NewUserName();
        var email = $"{firstUserName}@example.test";

        try
        {
            using var client = factory.CreateClient();
            using (var firstResponse = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = firstUserName,
                email,
                displayName = "Перший користувач",
                password = GetLocalStudyPassword()
            }))
            {
                Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);
            }

            using var duplicateResponse = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = secondUserName,
                email,
                displayName = "Повторний користувач",
                password = GetLocalStudyPassword()
            });

            Assert.Equal(HttpStatusCode.Conflict, duplicateResponse.StatusCode);
            Assert.Equal("application/problem+json", duplicateResponse.Content.Headers.ContentType?.MediaType);

            using var document = JsonDocument.Parse(await duplicateResponse.Content.ReadAsStringAsync());
            Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("email", out _));
        }
        finally
        {
            await DeleteUserAsync(firstUserName);
            await DeleteUserAsync(secondUserName);
        }
    }

    [Fact]
    public async Task Register_WithPasswordThatFailsIdentityPolicy_ReturnsSafe400()
    {
        var userName = NewUserName();

        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"{userName}@example.test",
            displayName = "Перевірка policy",
            password = new string('a', 10)
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);

        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("password", out _));
        Assert.DoesNotContain("PasswordRequires", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PasswordTooShort", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Register_WithInvalidContractFields_Returns400ValidationProblem()
    {
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = "invalid user name",
            email = "not-an-email",
            displayName = new string('d', 121),
            password = string.Empty
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var errors = document.RootElement.GetProperty("errors");

        Assert.True(errors.TryGetProperty("userName", out _));
        Assert.True(errors.TryGetProperty("email", out _));
        Assert.True(errors.TryGetProperty("displayName", out _));
        Assert.True(errors.TryGetProperty("password", out _));
    }

    private static string NewUserName() => $"reg{Guid.NewGuid():N}"[..24];

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private async Task DeleteUserAsync(string userName)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);

        if (user is not null)
        {
            var result = await users.DeleteAsync(user);
            Assert.True(result.Succeeded, "Не вдалося прибрати тимчасового користувача тесту.");
        }
    }
}
