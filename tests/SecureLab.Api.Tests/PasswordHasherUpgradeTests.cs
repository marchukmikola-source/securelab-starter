using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class PasswordHasherUpgradeTests
{
    [Fact]
    public void VerifyHash_WithLowerWorkFactor_RequestsRehashAndAcceptsUpgradedHash()
    {
        // This one-off value and both hashes exist only in this test's memory.
        // The assertions expose verification outcomes, never their inputs.
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            DisplayName = "Hasher upgrade verification"
        };
        var originalHasher = CreateHasher(iterationCount: 10_000);
        var upgradedHasher = CreateHasher(iterationCount: 20_000);
        var originalHash = originalHasher.HashPassword(user, password);

        Assert.Equal(
            PasswordVerificationResult.Success,
            originalHasher.VerifyHashedPassword(user, originalHash, password));
        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            upgradedHasher.VerifyHashedPassword(user, originalHash, password));

        var upgradedHash = upgradedHasher.HashPassword(user, password);

        Assert.Equal(
            PasswordVerificationResult.Success,
            upgradedHasher.VerifyHashedPassword(user, upgradedHash, password));
        Assert.Equal(
            PasswordVerificationResult.Failed,
            upgradedHasher.VerifyHashedPassword(user, upgradedHash, password + "-incorrect"));
    }

    private static PasswordHasher<ApplicationUser> CreateHasher(int iterationCount) =>
        new(Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
            IterationCount = iterationCount
        }));
}
