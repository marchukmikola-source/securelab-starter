using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Application.Authentication;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationProtectionTests
{
    [Fact]
    public async Task Login_AfterMaximumFailedAttempts_Returns429AndRecoversAfterWindow()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        using var factory = new RateLimitApiFactory(clock);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        var invalidPassword = $"invalid-{Guid.NewGuid():N}";
        var invalidRequest = new
        {
            userName = "rate-limit-test-user",
            password = invalidPassword
        };
        var validRequest = new
        {
            userName = "alice",
            password = GetLocalStudyPassword()
        };

        for (var attempt = 0; attempt < LoginAttemptLimiter.MaximumFailedAttempts; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/api/auth/login", invalidRequest);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        using (var blockedResponse = await client.PostAsJsonAsync("/api/auth/login", invalidRequest))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, blockedResponse.StatusCode);
            Assert.Equal("application/problem+json", blockedResponse.Content.Headers.ContentType?.MediaType);
            Assert.Null(blockedResponse.Headers.Location);
            Assert.Empty(blockedResponse.Headers.WwwAuthenticate);

            var body = await blockedResponse.Content.ReadAsStringAsync();
            Assert.False(body.Contains("rate-limit-test-user", StringComparison.Ordinal));
            Assert.False(body.Contains("password", StringComparison.OrdinalIgnoreCase));
        }

        // The IP partition also blocks valid credentials until the window
        // expires; changing the account name cannot bypass the policy.
        using (var blockedValidResponse = await client.PostAsJsonAsync("/api/auth/login", validRequest))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, blockedValidResponse.StatusCode);
        }

        clock.Advance(LoginAttemptLimiter.Window.Add(TimeSpan.FromSeconds(1)));

        using var recoveredResponse = await client.PostAsJsonAsync("/api/auth/login", validRequest);
        Assert.Equal(HttpStatusCode.NoContent, recoveredResponse.StatusCode);

        using var profileResponse = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, profileResponse.StatusCode);
    }

    [Fact]
    public async Task AuthenticationEvents_ContainOnlySafeOutcomeInformation()
    {
        var collector = new AuthenticationEventCollector();
        using var factory = new AuditLogApiFactory(collector);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        var invalidPassword = $"invalid-{Guid.NewGuid():N}";

        using (var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice",
            password = GetLocalStudyPassword()
        }))
        {
            Assert.Equal(HttpStatusCode.NoContent, loginResponse.StatusCode);
        }

        using (var failedResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "audit-test-unknown-user",
            password = invalidPassword
        }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, failedResponse.StatusCode);
        }

        for (var attempt = 1; attempt < LoginAttemptLimiter.MaximumFailedAttempts; attempt++)
        {
            using var failedAttempt = await client.PostAsJsonAsync("/api/auth/login", new
            {
                userName = "audit-test-unknown-user",
                password = invalidPassword
            });
            Assert.Equal(HttpStatusCode.Unauthorized, failedAttempt.StatusCode);
        }

        using (var rateLimitedResponse = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "audit-test-unknown-user",
            password = invalidPassword
        }))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, rateLimitedResponse.StatusCode);
        }

        using (var logoutResponse = await client.PostAsync("/api/auth/logout", null))
        {
            Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);
        }

        var events = collector.Entries
            .Where(entry => entry.Category == Lab03Identity.AuthenticationLogCategory)
            .Select(entry => entry.Message)
            .ToArray();

        var allowedEvents = new HashSet<string>(StringComparer.Ordinal)
        {
            "Authentication event: login succeeded.",
            "Authentication event: login failed.",
            "Authentication event: login rate limited.",
            "Authentication event: logout completed."
        };
        foreach (var requiredEvent in allowedEvents)
        {
            Assert.True(events.Contains(requiredEvent),
                $"Missing auth outcome '{requiredEvent}' (observed messages omitted).");
        }
        Assert.True(events.All(allowedEvents.Contains),
            "Auth events must contain only approved outcomes (messages omitted).");
    }

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private sealed class RateLimitApiFactory(MutableTimeProvider clock)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(clock);
            });
        }
    }

    private sealed class AuditLogApiFactory(AuthenticationEventCollector collector)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureLogging(logging => logging.AddProvider(collector));
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset utcNow = now;

        public override DateTimeOffset GetUtcNow() => utcNow;

        public void Advance(TimeSpan elapsed) => utcNow += elapsed;
    }

    private sealed class AuthenticationEventCollector : ILoggerProvider
    {
        private readonly ConcurrentQueue<AuthenticationEvent> entries = new();

        public IReadOnlyCollection<AuthenticationEvent> Entries => entries.ToArray();

        public ILogger CreateLogger(string categoryName) => new EventLogger(categoryName, entries);

        public void Dispose()
        {
        }

        private sealed class EventLogger(
            string category,
            ConcurrentQueue<AuthenticationEvent> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                entries.Enqueue(new AuthenticationEvent(category, formatter(state, exception)));
            }
        }
    }

    private sealed record AuthenticationEvent(string Category, string Message);
}
