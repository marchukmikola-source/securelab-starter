using System.Net;
using Microsoft.AspNetCore.Hosting;

namespace SecureLab.Api.Tests;

public sealed class SearchRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Search_EnforcesQuotaIsolatesVerifiedSubjectsAndRecoversWithoutGrantingAccess()
    {
        using var host = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:Search:PermitLimit", "2");
            builder.UseSetting("RateLimiting:Search:WindowSeconds", "2");
        });
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set SeedUsers__Password outside Git.");
        using var alice = await host.LoginAsync("alice", password);
        using var bob = await host.LoginAsync("bob", password);
        const string search = "/api/incidents/search?q=USB";
        using var first = await alice.GetAsync(search);
        using var second = await alice.GetAsync(search);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        using var blocked = await alice.GetAsync(search);
        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
        Assert.Equal("application/problem+json", blocked.Content.Headers.ContentType?.MediaType);
        alice.DefaultRequestHeaders.Add("X-Demo-UserId", "different-partition");
        using var forged = await alice.GetAsync(search + "&client=another");
        Assert.Equal(HttpStatusCode.TooManyRequests, forged.StatusCode);
        using var isolated = await bob.GetAsync(search);
        Assert.Equal(HttpStatusCode.OK, isolated.StatusCode);
        using var foreign = await alice.GetAsync("/api/incidents/20000000-0000-0000-0000-000000000002");
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        using var anonymous = host.CreateClient();
        using var unauthenticated = await anonymous.GetAsync(search);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        await Task.Delay(TimeSpan.FromMilliseconds(2300));
        using var recovered = await alice.GetAsync(search);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }
}
