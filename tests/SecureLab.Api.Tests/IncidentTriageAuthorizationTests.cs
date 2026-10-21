using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class IncidentTriageAuthorizationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Triage_EnforcesRoleResourceAndCurrentStatusBeforeMutation()
    {
        var id = Guid.NewGuid();
        await AddTestIncidentAsync(factory, id);
        try
        {
            using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
            });
            using var anonymousResponse = await anonymous.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);
            Assert.Null(anonymousResponse.Headers.Location);

            using var alice = await LoginAsync(factory, "alice");
            using var bob = await LoginAsync(factory, "bob");
            using var morgan = await LoginAsync(factory, "morgan");
            using var admin = await LoginAsync(factory, "admin");

            // A-06: a Reporter cannot obtain the privileged action by claiming a role in JSON.
            using var reporterDenied = await alice.PostAsJsonAsync($"/api/incidents/{id}/triage", new
            {
                role = "Analyst", ownerUserId = DbSeeder.MorganId,
                status = "Triaged", isTransitionAllowed = true
            });
            Assert.Equal(HttpStatusCode.Forbidden, reporterDenied.StatusCode);
            await AssertStatusAsync(alice, id, "New");

            using var foreignReporterDenied = await bob.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.NotFound, foreignReporterDenied.StatusCode);
            await AssertStatusAsync(alice, id, "New");

            using var administratorDenied = await admin.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.Forbidden, administratorDenied.StatusCode);
            await AssertStatusAsync(alice, id, "New");

            // A-07: only the verified Analyst may make the server-chosen transition.
            using var analystAllowed = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.NoContent, analystAllowed.StatusCode);
            await AssertStatusAsync(morgan, id, "Triaged");
            await AssertSingleTransitionAsync(factory, id, DbSeeder.MorganId);

            using var invalidState = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.Conflict, invalidState.StatusCode);
            await AssertStatusAsync(morgan, id, "Triaged");
            await AssertSingleTransitionAsync(factory, id, DbSeeder.MorganId);
        }
        finally
        {
            await RemoveTestIncidentAsync(factory, id);
        }
    }

    [Fact]
    public async Task Triage_Denial_ProducesSafeStructuredAuditEventWithResponseTrace()
    {
        var collector = new TriageAuditCollector();
        using var auditFactory = new AuditLogApiFactory(collector);
        using var alice = await LoginAsync(auditFactory, "alice");
        using var denied = await alice.PostAsJsonAsync(
            $"/api/incidents/{DbSeeder.SafeTextIncidentId}/triage",
            new { role = "Analyst", ownerUserId = DbSeeder.MorganId, status = "Triaged" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);

        var problem = JsonNode.Parse(await denied.Content.ReadAsStringAsync())!.AsObject();
        var responseTraceId = problem["traceId"]!.GetValue<string>();
        var entry = Assert.Single(collector.Entries, item =>
            item.Category == IncidentTriageAudit.LogCategory);

        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(IncidentTriageAudit.DeniedEventName, entry.Fields["EventName"]);
        Assert.Equal("Incident.Triage", entry.Fields["Operation"]);
        Assert.Equal(DbSeeder.AliceId, entry.Fields["ActorUserId"]);
        Assert.Equal(DbSeeder.SafeTextIncidentId, entry.Fields["IncidentId"]);
        Assert.Equal("Denied", entry.Fields["Result"]);
        Assert.IsType<DateTimeOffset>(entry.Fields["OccurredAtUtc"]);
        Assert.Equal(responseTraceId, entry.Fields["TraceId"]);

        var allowedKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            "EventName", "Operation", "ActorUserId", "IncidentId", "Result",
            "OccurredAtUtc", "TraceId", "{OriginalFormat}"
        };
        Assert.All(entry.Fields.Keys, key => Assert.Contains(key, allowedKeys));
        Assert.DoesNotContain(entry.Fields.Values, value =>
            value?.ToString()?.Contains("Analyst", StringComparison.Ordinal) == true);
        await AssertStatusAsync(alice, DbSeeder.SafeTextIncidentId, "New");
    }

    private static async Task<HttpClient> LoginAsync(WebApplicationFactory<Program> factory, string user)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = user, password = GetLocalStudyPassword()
        });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        return client;
    }

    private static async Task AssertStatusAsync(HttpClient client, Guid id, string expectedStatus)
    {
        var details = JsonNode.Parse(await client.GetStringAsync($"/api/incidents/{id}"))!.AsObject();
        Assert.Equal(expectedStatus, details["status"]!.GetValue<string>());
    }

    private static async Task AddTestIncidentAsync(SecureLabApiFactory factory, Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.Incidents.Add(new Incident
        {
            Id = id, OwnerUserId = DbSeeder.AliceId, Title = "Triage authorization test " + id,
            Description = "Synthetic Incident used only for the triage authorization integration test.",
            Severity = IncidentSeverity.Low, Status = IncidentStatus.New,
            OccurredAtUtc = now, CreatedAtUtc = now, UpdatedAtUtc = now
        });
        await db.SaveChangesAsync();
    }

    private static async Task RemoveTestIncidentAsync(SecureLabApiFactory factory, Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(row => row.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(row => row.Id == id).ExecuteDeleteAsync();
    }

    private static async Task AssertSingleTransitionAsync(
        SecureLabApiFactory factory, Guid id, Guid expectedActorId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var history = await db.IncidentStatusHistory.Where(row => row.IncidentId == id).ToListAsync();
        var transition = Assert.Single(history);
        Assert.Equal(expectedActorId, transition.ChangedByUserId);
        Assert.Equal(IncidentStatus.New, transition.OldStatus);
        Assert.Equal(IncidentStatus.Triaged, transition.NewStatus);
    }

    private static string GetLocalStudyPassword() => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private sealed class AuditLogApiFactory(TriageAuditCollector collector)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureLogging(logging => logging.AddProvider(collector));
        }
    }

    private sealed class TriageAuditCollector : ILoggerProvider
    {
        private readonly ConcurrentQueue<TriageAuditEntry> entries = new();

        public IReadOnlyCollection<TriageAuditEntry> Entries => entries.ToArray();

        public ILogger CreateLogger(string categoryName) => new TriageAuditLogger(categoryName, entries);

        public void Dispose()
        {
        }

        private sealed class TriageAuditLogger(
            string category, ConcurrentQueue<TriageAuditEntry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
                Exception? exception, Func<TState, Exception?, string> formatter)
            {
                var fields = state is IEnumerable<KeyValuePair<string, object?>> values
                    ? values.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal)
                    : new Dictionary<string, object?>();
                entries.Enqueue(new TriageAuditEntry(category, logLevel, fields));
            }
        }
    }

    private sealed record TriageAuditEntry(
        string Category, LogLevel Level, IReadOnlyDictionary<string, object?> Fields);
}
