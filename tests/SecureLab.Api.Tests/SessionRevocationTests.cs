using System.Collections.Concurrent;
using System.Data.Common;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureLab.Api.Data;
using SecureLab.Api.Security;
using Xunit.Abstractions;

namespace SecureLab.Api.Tests;

public sealed class SessionRevocationTests(SecureLabApiFactory factory, ITestOutputHelper output)
    : IClassFixture<SecureLabApiFactory>
{
    private static string Password() => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Local study credential is required (value omitted).");

    private static WebApplicationFactoryClientOptions ClientOptions(bool cookies = true) => new()
    {
        BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = cookies
    };

    private static async Task AssertAlive(HttpClient client)
    {
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task AssertRevoked(HttpClient client)
    {
        using var response = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RevokeAll_RejectsBadProofs_RevokesBothAliceSessionsAndReplay_LeavesBobAndFreshLoginWorking()
    {
        var audit = new AuditCollector();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.AddSingleton<ILoggerProvider>(audit)));
        using var alice1 = await host.LoginAsync("alice", Password());
        using var alice2 = await host.LoginAsync("alice", Password());
        using var bob = await host.LoginAsync("bob", Password());
        using var anonymous = host.CreateClient(ClientOptions());
        await AssertAlive(alice1); await AssertAlive(alice2); await AssertAlive(bob);
        var originalToken = alice1.DefaultRequestHeaders.GetValues(AntiforgeryProtection.HeaderName).Single();
        using var renewed = await alice1.GetAsync("/api/me");
        var oldCookie = string.Join("; ", renewed.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal))
            .Select(value => value.Split(';')[0]));
        Assert.True(oldCookie.Length > 0, "Old authenticated cookie captured only in memory.");
        using var replay = host.CreateClient(ClientOptions(false));
        replay.DefaultRequestHeaders.Add("Cookie", oldCookie);
        using (var denied = await anonymous.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() }))
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        alice1.DefaultRequestHeaders.Remove(AntiforgeryProtection.HeaderName);
        foreach (var invalid in new[] { false, true })
        {
            if (invalid) alice1.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, "invalid-study-token");
            using var denied = await alice1.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() });
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
            await AssertAlive(alice1); await AssertAlive(alice2); await AssertAlive(replay);
        }
        await alice1.AddAntiforgeryTokenAsync();
        using (var denied = await alice1.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = "wrong-study-value" }))
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        await AssertAlive(alice1); await AssertAlive(alice2); await AssertAlive(replay);
        using (var excessField = await alice1.PostAsJsonAsync(SessionRevocation.Path,
                   new { currentPassword = Password(), userId = Guid.Parse("10000000-0000-0000-0000-000000000002") }))
            Assert.Equal(HttpStatusCode.BadRequest, excessField.StatusCode);
        using (var revoked = await alice1.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() }))
            Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
        await AssertRevoked(alice1); await AssertRevoked(alice2); await AssertRevoked(replay);
        await AssertAlive(bob);
        using (var login = await alice1.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password = Password() }))
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        await AssertAlive(alice1);
        alice1.DefaultRequestHeaders.Remove(AntiforgeryProtection.HeaderName);
        alice1.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, originalToken);
        using (var stale = await alice1.PostAsync("/api/auth/logout", null))
            Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
        await AssertAlive(alice1);
        await alice1.AddAntiforgeryTokenAsync();
        using (var fresh = await alice1.PostAsync("/api/auth/logout", null))
            Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);

        var events = audit.Events.ToArray();
        Assert.Contains(events, item => Equals(item["Result"], "failure"));
        Assert.Contains(events, item => Equals(item["Result"], "success"));
        foreach (var item in events)
        {
            Assert.Equal(new[] { "Action", "EventName", "Resource", "Result", "Subject", "Time", "TraceId", "{OriginalFormat}" },
                item.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray());
            Assert.True(!string.IsNullOrEmpty(item["TraceId"]?.ToString()));
            Assert.False(JsonSerializer.Serialize(item).Contains(Password(), StringComparison.Ordinal));
        }
        output.WriteLine("LAB06_ADVANCED " + JsonSerializer.Serialize(new {
            scenario = "two-alice-bob-replay", initial = "3 x 200", anonymous = 401,
            missingCsrf = 400, invalidCsrf = 400, wrongPassword = 403, extraTargetField = 400,
            unchangedAfterDenials = true, revoke = 204, aliceSessions = "2 x 401", replay = 401,
            bob = 200, newAliceLogin = 204, oldAntiforgery = 400, freshAntiforgery = 204,
            audit = events, sensitiveValues = "omitted" }));
    }

    [Fact]
    public async Task BobSelfRevocation_CannotTargetAlice()
    {
        using var host = factory.WithWebHostBuilder(_ => { });
        using var alice1 = await host.LoginAsync("alice", Password());
        using var alice2 = await host.LoginAsync("alice", Password());
        using var bob1 = await host.LoginAsync("bob", Password());
        using var bob2 = await host.LoginAsync("bob", Password());
        using (var response = await bob1.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() }))
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        await AssertRevoked(bob1); await AssertRevoked(bob2);
        await AssertAlive(alice1); await AssertAlive(alice2);
        output.WriteLine("LAB06_ADVANCED {\"scenario\":\"bob-self-only\",\"bob\":\"2 x 401\",\"alice\":\"2 x 200\"}");
    }

    [Fact]
    public async Task PasswordChecks_AreBoundedBySubject_429DoesNotRevoke_RecoversAfterWindow()
    {
        var clock = new TestClock();
        var audit = new AuditCollector();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services => {
            services.RemoveAll<TimeProvider>(); services.AddSingleton<TimeProvider>(clock);
            services.AddSingleton<ILoggerProvider>(audit);
        }));
        using var alice = await host.LoginAsync("alice", Password());
        using var second = await host.LoginAsync("alice", Password());
        using var bob = await host.LoginAsync("bob", Password());
        for (var attempt = 0; attempt < RevocationAttemptLimiter.PermitLimit; attempt++)
        {
            using var denied = await alice.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = "wrong-study-value" });
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }
        using (var denied = await second.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() }))
            Assert.Equal(HttpStatusCode.TooManyRequests, denied.StatusCode);
        await AssertAlive(alice); await AssertAlive(second); await AssertAlive(bob);
        using (var bobAttempt = await bob.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = "wrong-study-value" }))
            Assert.Equal(HttpStatusCode.Forbidden, bobAttempt.StatusCode);
        clock.Advance(RevocationAttemptLimiter.Window + TimeSpan.FromSeconds(1));
        using (var valid = await alice.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() }))
            Assert.Equal(HttpStatusCode.NoContent, valid.StatusCode);
        await AssertRevoked(second); await AssertAlive(bob);
        Assert.Equal(6, audit.Events.Count(item => Equals(item["Result"], "failure")));
        Assert.Contains(audit.Events, item => Equals(item["Result"], "rate_limited"));
        output.WriteLine("LAB06_ADVANCED {\"scenario\":\"password-rate-limit\",\"failed\":\"5 x 403\",\"sameSubjectSecondClient\":429,\"sessionsUnchanged\":true,\"bobIndependent\":403,\"afterWindow\":204,\"failureAuditCount\":6}");
    }

    [Theory]
    [InlineData(false, HttpStatusCode.NoContent)]
    [InlineData(true, HttpStatusCode.BadRequest)]
    public async Task SameUserOldAntiforgery_AfterStampRotationAndRelogin_BeforeAfterProvider(
        bool stampBinding, HttpStatusCode expected)
    {
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services => {
            if (!stampBinding) {
                services.RemoveAll<IAntiforgeryAdditionalDataProvider>();
                services.AddAntiforgery(); // Restore the framework's unextended default provider, test host only.
            }
        }));
        using var client = await host.LoginAsync("alice", Password());
        using (var revoked = await client.PostAsJsonAsync(SessionRevocation.Path, new { currentPassword = Password() }))
            Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
        using (var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = "alice", password = Password() }))
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        using (var old = await client.PostAsync("/api/auth/logout", null))
            Assert.Equal(expected, old.StatusCode);
        if (stampBinding) {
            await AssertAlive(client); await client.AddAntiforgeryTokenAsync();
            using var fresh = await client.PostAsync("/api/auth/logout", null);
            Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
        }
        output.WriteLine("LAB06_ADVANCED " + JsonSerializer.Serialize(new {
            scenario = "same-user-old-antiforgery", stampBinding, status = (int)expected,
            sessionUnchangedOnRejection = stampBinding, freshTokenStatus = 204 }));
    }

    [Fact]
    public async Task AnonymousAntiforgery_UsesStandardRoundTripWithoutDatabaseLookup()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var antiforgery = scope.ServiceProvider.GetRequiredService<IAntiforgery>();
        var issue = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        issue.Request.Scheme = "https";
        var tokens = antiforgery.GetAndStoreTokens(issue);
        var cookie = issue.Response.Headers.SetCookie.Single()!.Split(';')[0];
        var validate = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        validate.Request.Scheme = "https";
        validate.Request.Method = "POST";
        validate.Request.Headers.Cookie = cookie;
        validate.Request.Headers[AntiforgeryProtection.HeaderName] = tokens.RequestToken;
        await antiforgery.ValidateRequestAsync(validate);
        // Neither principal contains userId/stamp; this is also the pre-login principal shape.
        Assert.False(validate.User.Identity?.IsAuthenticated ?? false);
    }

    [Fact]
    public void AdditionalData_HandlesAnonymousAndRejectsIncompleteAuthenticatedPrincipal()
    {
        var provider = new StampBoundAntiforgeryData(Options.Create(new IdentityOptions()));
        var anonymous = new DefaultHttpContext();
        var data = provider.GetAdditionalData(anonymous);
        Assert.True(provider.ValidateAdditionalData(anonymous, data));
        var incomplete = new DefaultHttpContext {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "alice")], "test"))
        };
        Assert.False(provider.ValidateAdditionalData(incomplete, data));
        Assert.Throws<InvalidOperationException>(() => provider.GetAdditionalData(incomplete));
    }

    [Theory]
    [InlineData(30)]
    [InlineData(0)]
    public async Task ValidationCost_MeasuresDatabaseReadsLatencyAndProductionCookieRenewal(int intervalMinutes)
    {
        var counter = new CommandCounter();
        using var host = factory.WithWebHostBuilder(builder => {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab", Environment.GetEnvironmentVariable("ConnectionStrings__SecureLab")
                ?? "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;Password=local-study-password;Include Error Detail=false");
            builder.ConfigureServices(services => {
                services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.FromMinutes(intervalMinutes));
                services.AddDbContext<SecureLabDbContext>(options => options.AddInterceptors(counter));
            });
        });
        using var client = await host.LoginAsync("alice", Password());
        await AssertAlive(client);
        counter.Count = 0;
        var renewed = 0;
        const int requests = 10;
        var elapsed = new List<double>();
        for (var index = 0; index < requests; index++)
        {
            var timer = Stopwatch.StartNew();
            using var response = await client.GetAsync("/api/me");
            elapsed.Add(timer.Elapsed.TotalMilliseconds);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
                foreach (var cookie in cookies.Where(value => value.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal)))
                {
                    renewed++;
                    Assert.True(cookie.Contains("secure", StringComparison.OrdinalIgnoreCase), "Secure retained (value omitted).");
                    Assert.True(cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase), "HttpOnly retained (value omitted).");
                    Assert.True(cookie.Contains("samesite=lax", StringComparison.OrdinalIgnoreCase), "SameSite retained (value omitted).");
                }
        }
        if (intervalMinutes == 0) {
            Assert.Equal(requests, renewed); Assert.True(counter.Count > requests);
        } else { Assert.Equal(0, renewed); Assert.Equal(requests, counter.Count); }
        output.WriteLine("LAB06_ADVANCED " + JsonSerializer.Serialize(new {
            scenario = "validation-cost", profile = "Production", intervalMinutes, requests,
            databaseCommands = counter.Count, renewedResponses = renewed,
            meanMs = Math.Round(elapsed.Average(), 3), maxMs = Math.Round(elapsed.Max(), 3),
            flags = "Secure; HttpOnly; SameSite=Lax", cookieValues = "omitted",
            scope = "local sequential warm /api/me requests, not a load benchmark" }));
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan span) => now += span;
    }

    private sealed class CommandCounter : DbCommandInterceptor
    {
        public int Count;
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref Count); return ValueTask.FromResult(result); }
    }

    private sealed class AuditCollector : ILoggerProvider
    {
        public ConcurrentQueue<Dictionary<string, object?>> Events { get; } = new();
        public ILogger CreateLogger(string categoryName) => new AuditLogger(categoryName, Events);
        public void Dispose() { }
        private sealed class AuditLogger(string category, ConcurrentQueue<Dictionary<string, object?>> events) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => category == SessionRevocation.LogCategory;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(logLevel) && state is IEnumerable<KeyValuePair<string, object?>> fields)
                    events.Enqueue(fields.ToDictionary(pair => pair.Key, pair => pair.Value));
            }
        }
    }
}
