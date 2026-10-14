using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
            Assert.Equal("/api/me", response.Headers.Location?.OriginalString);
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
            Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));
            using var profileWithoutLogin = await client.GetAsync("/api/me");
            Assert.Equal(HttpStatusCode.Unauthorized, profileWithoutLogin.StatusCode);

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

    [Theory]
    [InlineData("role")]
    [InlineData("id")]
    [InlineData("ownerUserId")]
    [InlineData("passwordHash")]
    [InlineData("securityStamp")]
    public async Task Register_WithUnexpectedServerManagedField_Returns400WithoutCreatingAccount(string field)
    {
        var userName = NewUserName();

        using var client = factory.CreateClient();
        var request = new Dictionary<string, object?>
        {
            ["userName"] = userName,
            ["email"] = $"{userName}@example.test",
            ["displayName"] = "Перевірка зайвого поля",
            ["password"] = GetLocalStudyPassword(),
            [field] = field switch
            {
                "role" => DbSeeder.AdministratorRole,
                "id" or "ownerUserId" => DbSeeder.AdminId,
                _ => "untrusted-client-value"
            }
        };
        using var response = await client.PostAsJsonAsync("/api/auth/register", request);

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
            Assert.False(body.Contains("password", StringComparison.OrdinalIgnoreCase));
            Assert.False(body.Contains("securitystamp", StringComparison.OrdinalIgnoreCase));
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

    [Theory]
    [InlineData("tooShort")]
    [InlineData("missingDigit")]
    [InlineData("missingLower")]
    [InlineData("missingUpper")]
    [InlineData("missingSymbol")]
    public async Task Register_WithPasswordThatFailsIdentityPolicy_ReturnsSafe400(string rule)
    {
        var userName = NewUserName();

        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"{userName}@example.test",
            displayName = "Перевірка policy",
            password = CreatePasswordMissingRule(rule)
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);

        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("password", out _));
        Assert.False(body.Contains("PasswordRequires", StringComparison.OrdinalIgnoreCase));
        Assert.False(body.Contains("PasswordTooShort", StringComparison.OrdinalIgnoreCase));

        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        Assert.Null(await users.FindByNameAsync(userName));
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

    [Theory]
    [InlineData("userName", 256)]
    [InlineData("email", 256)]
    [InlineData("displayName", 120)]
    public async Task Register_AtLengthLimit_CreatesAccount(string field, int limit)
    {
        var publicName = NewUserName();
        var request = CreateValidRequest(publicName);
        request[field] = field switch
        {
            "userName" => publicName.PadRight(limit, 'a'),
            "email" => CreateEmailAtLength(publicName, limit),
            _ => new string('d', limit)
        };
        var registeredName = (string)request["userName"]!;
        try
        {
            using var client = factory.CreateClient();
            using var response = await client.PostAsJsonAsync("/api/auth/register", request);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(registeredName);
        }
    }

    [Theory]
    [InlineData("userName", 257)]
    [InlineData("email", 257)]
    [InlineData("displayName", 121)]
    public async Task Register_AboveLengthLimit_Returns400WithoutCreatingAccount(string field, int length)
    {
        var publicName = NewUserName();
        var request = CreateValidRequest(publicName);
        request[field] = field switch
        {
            "userName" => publicName.PadRight(length, 'a'),
            "email" => CreateEmailAtLength(publicName, length),
            _ => new string('d', length)
        };

        await AssertRejectedRequestAsync(request, field);
    }

    [Theory]
    [InlineData("userName", null)]
    [InlineData("email", null)]
    [InlineData("displayName", null)]
    [InlineData("password", null)]
    [InlineData("userName", "   ")]
    [InlineData("email", "   ")]
    [InlineData("displayName", "   ")]
    [InlineData("password", "")]
    public async Task Register_WithMissingRequiredField_Returns400WithoutCreatingAccount(string field, string? value)
    {
        var request = CreateValidRequest(NewUserName());
        request[field] = value;
        await AssertRejectedRequestAsync(request, field);
    }

    [Theory]
    [InlineData("userName", "invalid user name")]
    [InlineData("userName", "імя")]
    [InlineData("email", "not-an-email")]
    public async Task Register_WithInvalidFieldFormat_ReturnsFieldValidationError(string field, string value)
    {
        var request = CreateValidRequest(NewUserName());
        request[field] = value;
        await AssertRejectedRequestAsync(request, field);
    }

    [Fact]
    public async Task Register_DoesNotTrimPasswordAndStoresOnlyIdentityHash()
    {
        var publicName = NewUserName();
        // One-off test credentials and their hash remain in memory/the test store.
        var password = $"  A{Guid.NewGuid():N}z!9  ";
        var request = CreateValidRequest(publicName);
        request["password"] = password;
        try
        {
            using var client = factory.CreateClient();
            using var response = await client.PostAsJsonAsync("/api/auth/register", request);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            using var scope = factory.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByNameAsync(publicName);
            Assert.NotNull(user);
            Assert.False(string.IsNullOrEmpty(user.PasswordHash));
            Assert.False(string.Equals(user.PasswordHash, password, StringComparison.Ordinal));
            Assert.True(await users.CheckPasswordAsync(user, password));
            Assert.False(await users.CheckPasswordAsync(user, password.Trim()));
        }
        finally
        {
            await DeleteUserAsync(publicName);
        }
    }

    [Fact]
    public async Task Register_WithMalformedJson_Returns400InsteadOf500()
    {
        using var client = factory.CreateClient();
        using var content = new StringContent("{", Encoding.UTF8, "application/json");
        using var response = await client.PostAsync("/api/auth/register", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static Dictionary<string, object?> CreateValidRequest(string publicName) => new()
    {
        ["userName"] = publicName,
        ["email"] = $"{publicName}@example.test",
        ["displayName"] = "Тестовий користувач",
        ["password"] = GetLocalStudyPassword()
    };

    private async Task AssertRejectedRequestAsync(Dictionary<string, object?> request, string expectedField)
    {
        using var client = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var userCountBefore = await users.Users.CountAsync();
        using var response = await client.PostAsJsonAsync("/api/auth/register", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.GetProperty("errors").TryGetProperty(expectedField, out _));

        Assert.Equal(userCountBefore, await users.Users.CountAsync());
    }

    private static string CreateEmailAtLength(string publicName, int length)
    {
        var hostLength = length - publicName.Length - 1 - ".example.test".Length;
        var labels = new List<string>();
        while (hostLength > 63)
        {
            labels.Add(new string('e', 63));
            hostLength -= 64;
        }
        labels.Add(new string('e', hostLength));
        return $"{publicName}@{string.Join('.', labels)}.example.test";
    }

    private static string CreatePasswordMissingRule(string rule) => rule switch
    {
        "tooShort" => new string('a', 3),
        "missingDigit" => new string('a', 10) + "A!",
        "missingLower" => new string('A', 10) + "1!",
        "missingUpper" => new string('a', 10) + "1!",
        "missingSymbol" => new string('a', 10) + "A1",
        _ => throw new ArgumentOutOfRangeException(nameof(rule))
    };

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
