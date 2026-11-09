using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public sealed class BrowserHardeningTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string Password() => Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set SeedUsers__Password outside Git.");

    private async Task<HttpClient> RawLoginAsync(string user = "alice")
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName = user, password = Password() });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return client;
    }

    [Fact]
    public async Task RegCsrf01_RealCookieDenialPreservesStateThenTokenAllowsMutation()
    {
        using var client = await RawLoginAsync();
        var path = $"/api/incidents/{DbSeeder.SafeTextIncidentId}";
        var before = await client.GetStringAsync(path);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var original = await db.Incidents.AsNoTracking().SingleAsync(x => x.Id == DbSeeder.SafeTextIncidentId);
        var title = "CSRF regression " + Guid.NewGuid().ToString("N");
        var mutation = new { title, description = "Legitimate content change after explicit antiforgery token validation." };
        try
        {
            using var missing = await client.PutAsJsonAsync(path, mutation);
            await AssertCsrfDeniedAsync(missing);
            Assert.True(before == await client.GetStringAsync(path), "Missing-token request changed the resource.");
            client.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, "invalid-study-token");
            using var invalid = await client.PutAsJsonAsync(path, mutation);
            await AssertCsrfDeniedAsync(invalid);
            Assert.True(before == await client.GetStringAsync(path), "Invalid-token request changed the resource.");
            await client.AddAntiforgeryTokenAsync();
            using var allowed = await client.PutAsJsonAsync(path, mutation);
            Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
            using var after = JsonDocument.Parse(await client.GetStringAsync(path));
            Assert.Equal(title, after.RootElement.GetProperty("title").GetString());
            Assert.Equal(mutation.description, after.RootElement.GetProperty("description").GetString());
        }
        finally
        {
            await db.Incidents.Where(x => x.Id == original.Id).ExecuteUpdateAsync(set => set
                .SetProperty(x => x.Title, original.Title).SetProperty(x => x.Description, original.Description)
                .SetProperty(x => x.UpdatedAtUtc, original.UpdatedAtUtc));
        }
    }

    [Theory]
    [InlineData("POST", "/api/incidents", false)]
    [InlineData("POST", "/api/incidents", true)]
    [InlineData("PUT", "/api/incidents/20000000-0000-0000-0000-000000000003", false)]
    [InlineData("PUT", "/api/incidents/20000000-0000-0000-0000-000000000003", true)]
    [InlineData("DELETE", "/api/incidents/20000000-0000-0000-0000-000000000003", false)]
    [InlineData("DELETE", "/api/incidents/20000000-0000-0000-0000-000000000003", true)]
    [InlineData("POST", "/api/incidents/20000000-0000-0000-0000-000000000003/triage", false)]
    [InlineData("POST", "/api/incidents/20000000-0000-0000-0000-000000000003/triage", true)]
    [InlineData("POST", "/api/auth/logout", false)]
    [InlineData("POST", "/api/auth/logout", true)]
    [InlineData("POST", "/api/me/sessions/revoke-all", false)]
    [InlineData("POST", "/api/me/sessions/revoke-all", true)]
    public async Task EveryCookieMutation_RejectsMissingOrInvalidTokenWithoutChangingState(
        string method, string path, bool invalidToken)
    {
        using var client = await RawLoginAsync(path.EndsWith("/triage", StringComparison.Ordinal) ? "morgan" : "alice");
        var before = await SnapshotAsync();
        if (invalidToken) client.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, "invalid-study-token");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (method != "DELETE" && path != "/api/auth/logout")
            request.Content = JsonContent.Create(new
            {
                title = "Rejected mutation " + Guid.NewGuid().ToString("N"),
                description = "This request must not change the stored resource.",
                severity = "Low", occurredAtUtc = DateTimeOffset.UtcNow
            });
        // PUT has a strict DTO; use only its allowed fields so CSRF is the rejecting control.
        if (method == "PUT") request.Content = JsonContent.Create(new { title = "Rejected update", description = "Unchanged state." });
        if (path == SessionRevocation.Path) request.Content = JsonContent.Create(new { currentPassword = Password() });
        using var response = await client.SendAsync(request);
        await AssertCsrfDeniedAsync(response);
        Assert.True(before == await SnapshotAsync(), "Denied request changed stored incident/history state.");
        using var session = await client.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, session.StatusCode);
    }

    [Fact]
    public async Task TokenPair_IsBoundToCookieAndPrincipal_AndFreshLoginTokenRestoresLegitimateFlow()
    {
        using var alice = await RawLoginAsync();
        var oldToken = await alice.GetFromJsonAsync<AntiforgeryTokenResponse>(AntiforgeryProtection.TokenPath);
        Assert.NotNull(oldToken);
        using var bob = await RawLoginAsync("bob");
        bob.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, oldToken.RequestToken);
        using var wrongCookie = await bob.PostAsync("/api/auth/logout", null);
        await AssertCsrfDeniedAsync(wrongCookie);
        await bob.AddAntiforgeryTokenAsync();
        bob.DefaultRequestHeaders.Remove(AntiforgeryProtection.HeaderName);
        bob.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, oldToken.RequestToken);
        using var wrongPair = await bob.PostAsync("/api/auth/logout", null);
        await AssertCsrfDeniedAsync(wrongPair);
        await alice.AddAntiforgeryTokenAsync();
        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var login = await alice.PostAsJsonAsync("/api/auth/login", new { userName = "bob", password = Password() });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        using var stale = await alice.PostAsync("/api/auth/logout", null);
        await AssertCsrfDeniedAsync(stale);
        await alice.AddAntiforgeryTokenAsync();
        using var fresh = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }

    [Fact]
    public async Task TokenIssuance_RequiresSessionAndDisablesCorsAndCaching()
    {
        using var anonymous = factory.CreateClient();
        using var denied = await anonymous.GetAsync(AntiforgeryProtection.TokenPath);
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        using var client = await RawLoginAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, AntiforgeryProtection.TokenPath);
        request.Headers.Add("Origin", "http://localhost:4173");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith("SecureLab.Antiforgery=", StringComparison.Ordinal));
        Assert.True(cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase));
        Assert.True(cookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task SecurityHeaders_CoverStaticSuccessValidationAndNotFound()
    {
        using var client = await factory.LoginAsync("alice", Password());
        foreach (var (path, expected) in new[]
        {
            ("/", HttpStatusCode.OK),
            ($"/api/incidents/{DbSeeder.AliceIncidentId}", HttpStatusCode.OK),
            ("/api/incidents?status=Unknown", HttpStatusCode.BadRequest),
            ("/api/incidents/99999999-9999-9999-9999-999999999999", HttpStatusCode.NotFound)
        })
        {
            using var response = await client.GetAsync(path);
            Assert.Equal(expected, response.StatusCode);
            AssertSecurityHeaders(response);
        }
    }

    [Theory]
    [InlineData("http://localhost:4173", true)]
    [InlineData("http://localhost:4174", false)]
    public async Task Cors_OnlyPermitsTheExactDevelopmentReadOrigin(string origin, bool allowed)
    {
        using var client = await factory.LoginAsync("alice", Password());
        using var request = new HttpRequestMessage(HttpMethod.Options, "/api/incidents");
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "X-Lab-Cors-Probe");
        using var response = await client.SendAsync(request);
        Assert.Equal(allowed, response.Headers.Contains("Access-Control-Allow-Origin"));
        if (allowed)
        {
            Assert.Equal(origin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
            Assert.Equal("true", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Credentials")));
        }
    }

    internal static void AssertSecurityHeaders(HttpResponseMessage response)
    {
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        Assert.Equal("default-src 'self'; frame-ancestors 'none'",
            Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
    }

    private static async Task AssertCsrfDeniedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("csrf_validation_failed", problem.RootElement.GetProperty("code").GetString());
    }

    private async Task<string> SnapshotAsync()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return JsonSerializer.Serialize(new
        {
            incidents = await db.Incidents.AsNoTracking().OrderBy(x => x.Id)
                .Select(x => new { x.Id, x.Title, x.Description, x.Status, x.UpdatedAtUtc }).ToListAsync(),
            history = await db.IncidentStatusHistory.CountAsync()
        });
    }
}
