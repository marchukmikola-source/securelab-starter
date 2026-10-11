using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentOwnershipSecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Create_WithoutAuthentication_Returns401ProblemWithoutRedirect()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var response = await client.PostAsJsonAsync("/api/incidents", CreateValidRequest());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task Create_WithoutOwner_AssignsOwnerFromAuthenticatedPrincipal()
    {
        var incidentId = await CreateAsBobAsync(CreateValidRequest());

        try
        {
            await AssertOwnerAsync(incidentId, DbSeeder.BobId);
        }
        finally
        {
            await DeleteIncidentAsync(incidentId);
        }
    }

    [Fact]
    public async Task Create_WithForeignOwnerUserId_IgnoresItAndUsesAuthenticatedPrincipal()
    {
        var incidentId = await CreateAsBobAsync(new
        {
            title = $"Foreign owner ignored {Guid.NewGuid():N}",
            description = "Власник має визначатися лише перевіреним сервером principal.",
            severity = "Medium",
            occurredAtUtc = DateTimeOffset.UtcNow,
            ownerUserId = DbSeeder.AliceId
        });

        try
        {
            await AssertOwnerAsync(incidentId, DbSeeder.BobId);
        }
        finally
        {
            await DeleteIncidentAsync(incidentId);
        }
    }

    private async Task<Guid> CreateAsBobAsync(object request)
    {
        using var client = await factory.LoginAsync("bob", GetLocalStudyPassword());
        using var response = await client.PostAsJsonAsync("/api/incidents", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var responseFields = document.RootElement.EnumerateObject()
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            ["createdAtUtc", "id", "occurredAtUtc", "severity", "status", "title"],
            responseFields);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));

        return document.RootElement.GetProperty("id").GetGuid();
    }

    private async Task AssertOwnerAsync(Guid incidentId, Guid expectedOwnerId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        var ownerId = await db.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == incidentId)
            .Select(incident => incident.OwnerUserId)
            .SingleAsync();

        Assert.Equal(expectedOwnerId, ownerId);
    }

    private async Task DeleteIncidentAsync(Guid incidentId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        await db.Incidents
            .Where(incident => incident.Id == incidentId)
            .ExecuteDeleteAsync();
    }

    private static object CreateValidRequest() => new
    {
        title = $"Authenticated create {Guid.NewGuid():N}",
        description = "Коректний опис для перевірки захищеного створення інциденту.",
        severity = "Medium",
        occurredAtUtc = DateTimeOffset.UtcNow
    };

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
}
