using System.Text.Json;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class RegistrationRequestSerializationTests
{
    [Fact]
    public void RegisterRequest_RejectsUnmappedServerManagedFields()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<RegisterUserRequest>("""
                { "role": "Administrator" }
                """));
    }
}
