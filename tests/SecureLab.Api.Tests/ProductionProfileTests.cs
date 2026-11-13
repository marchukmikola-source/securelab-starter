using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class ProductionProfileTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyConnection =>
        Environment.GetEnvironmentVariable("ConnectionStrings__SecureLab")
        ?? "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;"
            + "Password=local-study-password;Include Error Detail=false";

    private WebApplicationFactory<Program> Production(string? connection = null) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab", connection ?? StudyConnection);
        });

    [Fact]
    public async Task Production_UsesExplicitConfigurationAndPreservesProtectedErrorContracts()
    {
        using var production = Production();
        Assert.Equal("Production", production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);
        var configuration = production.Services.GetRequiredService<IConfiguration>();
        Assert.False(configuration.GetValue<bool>("Database:ApplyMigrationsOnStartup"));
        Assert.False(configuration.GetValue<bool>("Database:AllowReset"));
        Assert.True(configuration.GetConnectionString("SecureLab") == StudyConnection,
            "Production must receive its explicit connection setting (value omitted).");

        using var client = await production.LoginAsync("alice", StudyPassword());
        using var allowed = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        foreach (var (route, status) in new[]
        {
            ("/api/incidents?status=Unknown", HttpStatusCode.BadRequest),
            ("/api/incidents/99999999-9999-9999-9999-999999999999", HttpStatusCode.NotFound),
            ("/api/incidents/search?sortBy=Unknown", HttpStatusCode.BadRequest),
            ("/openapi/v1.json", HttpStatusCode.NotFound)
        })
        {
            using var response = await client.GetAsync(route);
            Assert.Equal(status, response.StatusCode);
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            AssertSafe(await response.Content.ReadAsStringAsync());
        }

        using var fallback = await client.GetAsync("/scalar/v1");
        Assert.Equal(HttpStatusCode.OK, fallback.StatusCode);
        Assert.Equal("text/html", fallback.Content.Headers.ContentType?.MediaType);
        var fallbackHtml = await fallback.Content.ReadAsStringAsync();
        using var index = await client.GetAsync("/");
        Assert.Equal(await index.Content.ReadAsStringAsync(), fallbackHtml);
        Assert.DoesNotContain("scalar-api-reference", fallbackHtml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Production_AuthenticationCookieRetainsSecureHttpOnlyAndSameSiteFlags()
    {
        using var production = Production();
        using var client = production.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var login = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword() });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        var cookie = Assert.Single(login.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal));
        // Boolean assertions deliberately avoid including the cookie value in failure output.
        Assert.True(cookie.Contains("; secure", StringComparison.OrdinalIgnoreCase));
        Assert.True(cookie.Contains("; httponly", StringComparison.OrdinalIgnoreCase));
        Assert.True(cookie.Contains("; samesite=lax", StringComparison.OrdinalIgnoreCase));
        using var token = await client.GetAsync(SecureLab.Api.Security.AntiforgeryProtection.TokenPath);
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        var antiforgeryCookie = Assert.Single(token.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith("SecureLab.Antiforgery=", StringComparison.Ordinal));
        Assert.True(antiforgeryCookie.Contains("; secure", StringComparison.OrdinalIgnoreCase));
        Assert.True(antiforgeryCookie.Contains("; httponly", StringComparison.OrdinalIgnoreCase));
        Assert.True(antiforgeryCookie.Contains("; samesite=strict", StringComparison.OrdinalIgnoreCase));
        using var session = await client.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, session.StatusCode);
    }

    [Fact]
    public async Task ProductionReset_IsRejectedWithoutChangingStudyRows()
    {
        using var production = Production();
        using var scope = production.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var before = await db.Incidents.AsNoTracking().OrderBy(x => x.Id)
            .Select(x => new { x.Id, x.Title, x.Status, x.UpdatedAtUtc }).ToListAsync();
        var userCount = await db.Users.CountAsync();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => DatabaseBootstrap.InitializeAsync(
            production.Services, production.Services.GetRequiredService<IConfiguration>(),
            production.Services.GetRequiredService<IHostEnvironment>(), resetRequested: true));
        Assert.Contains("Development", error.Message, StringComparison.Ordinal);
        var after = await db.Incidents.AsNoTracking().OrderBy(x => x.Id)
            .Select(x => new { x.Id, x.Title, x.Status, x.UpdatedAtUtc }).ToListAsync();
        Assert.Equal(before, after);
        Assert.Equal(userCount, await db.Users.CountAsync());
    }

    [Fact]
    public async Task UnexpectedDatabaseFailure_ReturnsSafeProblemLinkedToExceptionLog()
    {
        var collector = new ExceptionTraceCollector();
        using var production = Production(
            "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
            + "Password=unreachable-study-value;Include Error Detail=false;Timeout=2;Command Timeout=2")
            .WithWebHostBuilder(builder => builder.ConfigureLogging(logging => logging.AddProvider(collector)));
        using var client = production.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "NotARealPassword1!" });
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        BrowserHardeningTests.AssertSecurityHeaders(response);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        AssertSafe(body);
        using var document = JsonDocument.Parse(body);
        var problem = document.RootElement;
        Assert.Equal(500, problem.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("title").GetString()));
        var traceParent = problem.GetProperty("traceId").GetString()!;
        Assert.Matches("^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$", traceParent);
        Assert.Contains(traceParent.Split('-')[1], collector.TraceIds);
    }

    private static string StudyPassword() => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set SeedUsers__Password outside Git.");

    private static void AssertSafe(string body)
    {
        foreach (var forbidden in new[]
        {
            "Npgsql", "System.InvalidOperationException", "StackTrace", "SELECT ", "Host=", "Password=",
            "NotARealPassword1!", "unreachable-study-value", "F:\\", "C:\\", StudyPassword()
        })
        {
            Assert.False(body.Contains(forbidden, StringComparison.OrdinalIgnoreCase),
                "HTTP problem exposed an internal or sensitive value (value omitted).");
        }
    }

    private sealed class ExceptionTraceCollector : ILoggerProvider
    {
        public ConcurrentBag<string> TraceIds { get; } = [];
        public ILogger CreateLogger(string categoryName) => new TraceLogger(categoryName, TraceIds);
        public void Dispose() { }

        private sealed class TraceLogger(string category, ConcurrentBag<string> traces) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Error;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (category == "Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware"
                    && logLevel >= LogLevel.Error && Activity.Current is { } activity)
                    traces.Add(activity.TraceId.ToString());
            }
        }
    }
}
