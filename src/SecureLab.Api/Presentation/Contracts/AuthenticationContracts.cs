using System.Text.Json.Serialization;

namespace SecureLab.Api.Presentation.Contracts;

// The client may provide only registration data. Roles, identifiers and
// Identity-managed fields are intentionally absent from this input contract.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record RegisterUserRequest(
    string? UserName,
    string? Email,
    string? DisplayName,
    string? Password);

// Data-minimised representation returned after successful registration.
public sealed record RegisteredUserResponse(
    Guid Id,
    string UserName,
    string DisplayName);

// Safe profile exposed only for the authenticated principal.
public sealed record CurrentUserResponse(
    Guid Id,
    string UserName,
    string DisplayName);
