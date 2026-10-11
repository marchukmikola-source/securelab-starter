using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class CurrentUserEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Me_WithoutCookie_Returns401ProblemWithoutRedirectOrChallenge()
    {
        using var client = CreateCookieClient();
        using var response = await client.GetAsync("/api/me");

        await AssertUnauthorizedProblemAsync(response);
    }

    [Fact]
    public async Task Login_FailuresForUnknownUserAndIncorrectPasswordHaveTheSameExternalResult()
    {
        using var client = CreateCookieClient();
        var password = GetLocalStudyPassword();

        using var unknownUserResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = $"unknown{Guid.NewGuid():N}",
            password
        });
        using var wrongPasswordResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice",
            password = password + "-incorrect"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, unknownUserResponse.StatusCode);
        Assert.Equal(unknownUserResponse.StatusCode, wrongPasswordResponse.StatusCode);
        Assert.Equal(
            unknownUserResponse.Content.Headers.ContentType?.MediaType,
            wrongPasswordResponse.Content.Headers.ContentType?.MediaType);

        var unknownUserBody = await unknownUserResponse.Content.ReadAsStringAsync();
        var wrongPasswordBody = await wrongPasswordResponse.Content.ReadAsStringAsync();
        using var unknownUserProblem = JsonDocument.Parse(unknownUserBody);
        using var wrongPasswordProblem = JsonDocument.Parse(wrongPasswordBody);

        Assert.Equal(
            unknownUserProblem.RootElement.GetProperty("status").GetInt32(),
            wrongPasswordProblem.RootElement.GetProperty("status").GetInt32());
        Assert.Equal(
            unknownUserProblem.RootElement.GetProperty("title").GetString(),
            wrongPasswordProblem.RootElement.GetProperty("title").GetString());
        Assert.DoesNotContain("password", unknownUserBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", wrongPasswordBody, StringComparison.OrdinalIgnoreCase);
        Assert.Null(unknownUserResponse.Headers.Location);
        Assert.Null(wrongPasswordResponse.Headers.Location);
        Assert.Empty(unknownUserResponse.Headers.WwwAuthenticate);
        Assert.Empty(wrongPasswordResponse.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task Login_CreatesCookieWithExpectedSecurityAttributes()
    {
        using var client = CreateCookieClient();
        using var response = await LoginAsAliceAsync(client);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var setCookies = response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.ToArray()
            : [];

        var applicationCookie = Assert.Single(setCookies, value =>
            value.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal));

        Assert.Contains("httponly", applicationCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", applicationCookie, StringComparison.OrdinalIgnoreCase);
        // The test client uses HTTPS, so Development's SameAsRequest policy
        // must emit Secure on the application cookie.
        Assert.Contains("secure", applicationCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Me_AfterAliceLogin_IgnoresForeignDemoHeaderAndReturnsOnlyAliceProfile()
    {
        using var client = CreateCookieClient();
        using var login = await LoginAsAliceAsync(client);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Empty(response.Headers.WwwAuthenticate);

        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);
        var profile = document.RootElement;
        var fields = profile.EnumerateObject()
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["displayName", "id", "userName"], fields);
        Assert.Equal(DbSeeder.AliceId, profile.GetProperty("id").GetGuid());
        Assert.Equal("alice", profile.GetProperty("userName").GetString());
        Assert.Equal("Аліса Коваль", profile.GetProperty("displayName").GetString());
        Assert.DoesNotContain("email", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("securityStamp", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Logout_RemovesCookieAndMakesSubsequentMeRequestUnauthorized()
    {
        using var client = CreateCookieClient();
        using var login = await LoginAsAliceAsync(client);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

        using (var beforeLogout = await client.GetAsync("/api/me"))
        {
            Assert.Equal(HttpStatusCode.OK, beforeLogout.StatusCode);
        }

        using var logout = await client.PostAsync("/api/auth/logout", null);

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var setCookies = logout.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.ToArray()
            : [];

        Assert.Contains(setCookies, value =>
            value.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal)
            && value.Contains("expires=", StringComparison.OrdinalIgnoreCase));

        using var afterLogout = await client.GetAsync("/api/me");
        await AssertUnauthorizedProblemAsync(afterLogout);
    }

    private HttpClient CreateCookieClient() => factory.CreateClient(
        new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static Task<HttpResponseMessage> LoginAsAliceAsync(HttpClient client) =>
        client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice",
            password = GetLocalStudyPassword()
        });

    private static async Task AssertUnauthorizedProblemAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);

        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);
        Assert.Equal(401, document.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain("stack trace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
    }
}
