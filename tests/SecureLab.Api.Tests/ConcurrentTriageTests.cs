using System.Data.Common;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using Xunit.Abstractions;

namespace SecureLab.Api.Tests;

public sealed class ConcurrentTriageTests(SecureLabApiFactory factory, ITestOutputHelper output)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task SimultaneousTriage_ExactlyOneTransitionAndOneHistoryRecord()
    {
        var incidentId = Guid.NewGuid();
        var barrier = new TwoReadersBarrier(incidentId);
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddDbContext<SecureLabDbContext>(options => options.AddInterceptors(barrier))));
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.Incidents.Add(new Incident {
            Id = incidentId, OwnerUserId = Guid.Parse("10000000-0000-0000-0000-000000000001"),
            Title = "Concurrent triage regression", Description = "Disposable incident for atomic workflow verification.",
            Severity = IncidentSeverity.Low, Status = IncidentStatus.New,
            OccurredAtUtc = now, CreatedAtUtc = now, UpdatedAtUtc = now
        });
        await db.SaveChangesAsync();
        try
        {
            var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
                ?? throw new InvalidOperationException("Local study credential required (value omitted).");
            using var first = await host.LoginAsync("morgan", password);
            using var second = await host.LoginAsync("morgan", password);
            var responses = await Task.WhenAll(first.PostAsync($"/api/incidents/{incidentId}/triage", null),
                second.PostAsync($"/api/incidents/{incidentId}/triage", null));
            var statuses = responses.Select(response => (int)response.StatusCode).Order().ToArray();
            foreach (var response in responses) response.Dispose();
            var historyCount = await db.IncidentStatusHistory.CountAsync(row => row.IncidentId == incidentId);
            var status = await db.Incidents.Where(row => row.Id == incidentId).Select(row => row.Status).SingleAsync();
            output.WriteLine("LAB06_TRIAGE " + JsonSerializer.Serialize(new {
                scenario = "simultaneous-triage", barrier = "two completed SELECTs before either handler continues",
                barrierReaders = barrier.Readers, statuses, historyCount, finalStatus = status.ToString(), sensitiveValues = "omitted" }));
            Assert.True(barrier.Readers >= 2, "Both concurrent readers must reach the test barrier.");
            Assert.Equal(new[] { (int)HttpStatusCode.NoContent, (int)HttpStatusCode.Conflict }, statuses);
            Assert.Equal(1, historyCount);
            Assert.Equal(IncidentStatus.Triaged, status);
        }
        finally
        {
            await db.IncidentStatusHistory.Where(row => row.IncidentId == incidentId).ExecuteDeleteAsync();
            await db.Incidents.Where(row => row.Id == incidentId).ExecuteDeleteAsync();
        }
    }

    // Test-only scheduling control; no endpoint or production bypass is introduced.
    private sealed class TwoReadersBarrier(Guid target) : DbCommandInterceptor
    {
        private readonly TaskCompletionSource ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int readers;
        public int Readers => readers;
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command,
            CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("SELECT", StringComparison.Ordinal)
                && command.CommandText.Contains("FROM incidents", StringComparison.Ordinal)
                && command.Parameters.Cast<DbParameter>().Any(parameter => parameter.Value is Guid value && value == target))
            {
                var number = Interlocked.Increment(ref readers);
                if (number == 2) ready.TrySetResult();
                if (number <= 2) await ready.Task.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            }
            return result;
        }
    }
}
