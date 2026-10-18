using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class IncidentAuthorizationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Details_EnforcesAuthenticationOwnershipAndAnalystReadContract()
    {
        using var anonymous = factory.CreateClient();
        using var unauthenticated = await anonymous.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        Assert.Null(unauthenticated.Headers.Location);

        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");
        using var morgan = await LoginAsync("morgan");
        using var own = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        var ownerJson = JsonNode.Parse(await own.Content.ReadAsStringAsync())!.AsObject();
        Assert.DoesNotContain(ownerJson["comments"]!.AsArray(), comment =>
            comment!["id"]!.GetValue<Guid>() == DbSeeder.AliceInternalCommentId);

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, foreign.Content.Headers.ContentType?.MediaType);
        Assert.Equal(await NormalizeProblemAsync(unknown), await NormalizeProblemAsync(foreign));

        using var analysis = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, analysis.StatusCode);
        var analysisJson = JsonNode.Parse(await analysis.Content.ReadAsStringAsync())!.AsObject();
        Assert.Contains(analysisJson["comments"]!.AsArray(), comment =>
            comment!["id"]!.GetValue<Guid>() == DbSeeder.AliceInternalCommentId);
    }

    [Fact]
    public async Task ListSearchAndSummary_AreScopedBeforeProjectionAndAggregation()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        using var admin = await LoginAsync("admin");

        var aliceList = await alice.GetFromJsonAsync<JsonArray>("/api/incidents");
        Assert.NotNull(aliceList);
        Assert.DoesNotContain(aliceList, row => row!["id"]!.GetValue<Guid>() == DbSeeder.BobIncidentId);
        var analystList = await morgan.GetFromJsonAsync<JsonArray>("/api/incidents");
        Assert.Contains(analystList!, row => row!["id"]!.GetValue<Guid>() == DbSeeder.BobIncidentId);
        using var denied = await admin.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var query = Uri.EscapeDataString("Невідома спроба входу");
        var aliceSearch = await alice.GetFromJsonAsync<JsonArray>("/api/incidents/search?q=" + query);
        Assert.Empty(aliceSearch!);
        var analystSearch = await morgan.GetFromJsonAsync<JsonArray>("/api/incidents/search?q=" + query);
        Assert.Contains(analystSearch!, row => row!["id"]!.GetValue<Guid>() == DbSeeder.BobIncidentId);

        var aliceSummary = await alice.GetFromJsonAsync<JsonArray>("/api/incidents/severity-summary");
        var analystSummary = await morgan.GetFromJsonAsync<JsonArray>("/api/incidents/severity-summary");
        Assert.Equal(3, aliceSummary!.Sum(row => row!["count"]!.GetValue<int>()));
        Assert.Equal(5, analystSummary!.Sum(row => row!["count"]!.GetValue<int>()));
    }

    [Fact]
    public async Task Update_EnforcesTheSameOwnerDecisionAsDetails()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");
        var before = JsonNode.Parse(await bob.GetStringAsync($"/api/incidents/{DbSeeder.BobIncidentId}"))!;
        var payload = new { title = "Нова назва, яку Alice не може встановити", description = new string('x', 50) };
        using var foreignUpdate = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}", payload);
        Assert.Equal(HttpStatusCode.NotFound, foreignUpdate.StatusCode);
        Assert.Equal(before.ToJsonString(), (await JsonNode.ParseAsync(await bob.GetStreamAsync($"/api/incidents/{DbSeeder.BobIncidentId}")))!.ToJsonString());
    }

    [Fact]
    public async Task Update_AllowsOnlyReporterOwnerAndRejectsProtectedRequestFields()
    {
        var id = Guid.NewGuid();
        await AddTestIncidentAsync(id);
        try
        {
            using var alice = await LoginAsync("alice");
            using var morgan = await LoginAsync("morgan");
            var valid = new
            {
                title = "Reporter owner update " + id,
                description = "Only the Reporter owner may change these two content fields."
            };
            using var allowed = await alice.PutAsJsonAsync($"/api/incidents/{id}", valid);
            Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
            var changed = JsonNode.Parse(await alice.GetStringAsync($"/api/incidents/{id}"))!.AsObject();
            Assert.Equal(valid.title, changed["title"]!.GetValue<string>());

            using var analystDenied = await morgan.PutAsJsonAsync($"/api/incidents/{id}", valid);
            Assert.Equal(HttpStatusCode.Forbidden, analystDenied.StatusCode);
            using var forged = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                valid.title, valid.description, ownerUserId = DbSeeder.BobId, status = "Closed"
            });
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
            var afterForged = JsonNode.Parse(await alice.GetStringAsync($"/api/incidents/{id}"))!.AsObject();
            Assert.Equal(valid.title, afterForged["title"]!.GetValue<string>());
            Assert.Equal("New", afterForged["status"]!.GetValue<string>());
        }
        finally
        {
            await RemoveTestIncidentAsync(id);
        }
    }

    [Fact]
    public async Task Create_DeniesAdministratorWithoutPublishedCreateRight()
    {
        using var admin = await LoginAsync("admin");
        using var response = await admin.PostAsJsonAsync("/api/incidents", new
        {
            title = "Administrator must not create an incident",
            description = "This request uses a valid contract but no published Administrator right.",
            severity = "Low", occurredAtUtc = DateTimeOffset.UtcNow
        });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private Task<HttpClient> LoginAsync(string user) => factory.LoginAsync(user, Password());

    private async Task AddTestIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.Incidents.Add(new Incident
        {
            Id = id, OwnerUserId = DbSeeder.AliceId, Title = "Authorization test " + id,
            Description = "Synthetic incident used only by the authorization integration test.",
            Severity = IncidentSeverity.Low, Status = IncidentStatus.New,
            OccurredAtUtc = now, CreatedAtUtc = now, UpdatedAtUtc = now
        });
        await db.SaveChangesAsync();
    }

    private async Task RemoveTestIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(row => row.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(row => row.Id == id).ExecuteDeleteAsync();
    }

    private static async Task<string> NormalizeProblemAsync(HttpResponseMessage response)
    {
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        body.Remove("traceId");
        body.Remove("requestId");
        return body.ToJsonString();
    }

    private static string Password() => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
}
