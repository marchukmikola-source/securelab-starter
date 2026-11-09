using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace SecureLab.Api.Security;

// The standard antiforgery system protects this additional data inside the token.
// Reading the authenticated claim adds no database query of its own.
public sealed class StampBoundAntiforgeryData(IOptions<IdentityOptions> identityOptions)
    : IAntiforgeryAdditionalDataProvider
{
    public string GetAdditionalData(HttpContext context) => Binding(context.User)
        ?? throw new InvalidOperationException("Authenticated principal lacks session binding claims.");

    public bool ValidateAdditionalData(HttpContext context, string additionalData)
    {
        var expected = Binding(context.User);
        return expected is not null && CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(additionalData));
    }

    private string? Binding(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true) return "anonymous:v1";
        var claims = identityOptions.Value.ClaimsIdentity;
        var subject = principal.FindFirstValue(claims.UserIdClaimType);
        var stamp = principal.FindFirstValue(claims.SecurityStampClaimType);
        if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(stamp)) return null;
        return "stamp:v1:" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{subject.Length}:{subject}{stamp.Length}:{stamp}")));
    }
}
