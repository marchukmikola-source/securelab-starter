using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task GetList_ReturnsSeededIncidents()
    {
        using var client = await factory.LoginAsync("alice", GetLocalStudyPassword());
        var incidents = await client.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var client = await factory.LoginAsync("alice", GetLocalStudyPassword());
        using var response = await client.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Інцидент не знайдено", body);
        Assert.DoesNotContain("Npgsql", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("stack trace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var client = await factory.LoginAsync("alice", GetLocalStudyPassword());
        using var response = await client.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        using var client = factory.CreateClient();
        var script = await client.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
}
