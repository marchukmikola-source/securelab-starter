using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    public static async Task<HttpClient> LoginAsync(this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        await client.AddAntiforgeryTokenAsync();
        return client;
    }

    public static async Task AddAntiforgeryTokenAsync(this HttpClient client)
    {
        var token = await client.GetFromJsonAsync<AntiforgeryTokenResponse>(AntiforgeryProtection.TokenPath)
            ?? throw new InvalidOperationException("Antiforgery token response missing (value omitted).");
        client.DefaultRequestHeaders.Remove(AntiforgeryProtection.HeaderName);
        client.DefaultRequestHeaders.Add(AntiforgeryProtection.HeaderName, token.RequestToken);
    }
}
