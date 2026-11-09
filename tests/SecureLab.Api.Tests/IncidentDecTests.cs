using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentDecTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Details_ReporterOwner_IsAllowed()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<HttpClient> LoginAsync(string userName)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        using var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName,
            password = GetLocalStudyPassword()
        });

        if (login.StatusCode != HttpStatusCode.NoContent)
        {
            client.Dispose();
            throw new InvalidOperationException(
                $"Login for '{userName}' failed with HTTP {(int)login.StatusCode}.");
        }

        return client;
    }

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException(
            "Set SeedUsers__Password outside Git before running tests.");
}
