using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class IdentityStoreContractTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public void IdentityModel_UsesGuidIdentityAndDomainForeignKeysWithoutLegacyStore()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        Assert.True(typeof(IdentityUser<Guid>).IsAssignableFrom(typeof(ApplicationUser)));
        var user = db.Model.FindEntityType(typeof(ApplicationUser));
        Assert.NotNull(user);
        Assert.Equal("identity_users", user.GetTableName());
        Assert.Equal(120, user.FindProperty(nameof(ApplicationUser.DisplayName))?.GetMaxLength());
        Assert.Equal(256, user.FindProperty(nameof(ApplicationUser.UserName))?.GetMaxLength());
        Assert.Equal(256, user.FindProperty(nameof(ApplicationUser.Email))?.GetMaxLength());
        Assert.DoesNotContain(db.Model.GetEntityTypes(), entity => entity.GetTableName() == "study_users");

        foreach (var (entityType, propertyName) in new[]
        {
            (typeof(Incident), nameof(Incident.OwnerUserId)),
            (typeof(IncidentComment), nameof(IncidentComment.AuthorUserId)),
            (typeof(IncidentStatusHistory), nameof(IncidentStatusHistory.ChangedByUserId))
        })
        {
            var entity = db.Model.FindEntityType(entityType);
            Assert.NotNull(entity);
            var foreignKey = Assert.Single(entity.GetForeignKeys(), key =>
                key.Properties.Count == 1 && key.Properties[0].Name == propertyName);
            Assert.Equal(typeof(Guid), foreignKey.Properties[0].ClrType);
            Assert.Equal(typeof(ApplicationUser), foreignKey.PrincipalEntityType.ClrType);
        }
    }

    [Fact]
    public async Task Seed_PreservesFixedAccountsRolesAndAliceBobOwnership()
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        foreach (var (id, name, role) in new[]
        {
            (DbSeeder.AliceId, "alice", DbSeeder.ReporterRole),
            (DbSeeder.BobId, "bob", DbSeeder.ReporterRole),
            (DbSeeder.MorganId, "morgan", DbSeeder.AnalystRole),
            (DbSeeder.AdminId, "admin", DbSeeder.AdministratorRole)
        })
        {
            var user = await users.FindByIdAsync(id.ToString());
            Assert.NotNull(user);
            Assert.Equal(name, user.UserName);
            Assert.True(await users.IsInRoleAsync(user, role));
        }

        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        foreach (var (incidentId, ownerId) in new[]
        {
            (DbSeeder.AliceIncidentId, DbSeeder.AliceId),
            (DbSeeder.BobIncidentId, DbSeeder.BobId)
        })
        {
            var actualOwner = await db.Incidents.AsNoTracking()
                .Where(incident => incident.Id == incidentId)
                .Select(incident => incident.OwnerUserId)
                .SingleAsync();
            Assert.Equal(ownerId, actualOwner);
        }
    }

    [Fact]
    public async Task Seed_IncludesFixedInternalCommentByMorganForAliceIncident()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        var comment = await db.IncidentComments.AsNoTracking()
            .Where(item => item.Id == DbSeeder.AliceInternalCommentId)
            .Select(item => new
            {
                item.Id,
                item.IncidentId,
                item.AuthorUserId,
                item.IsInternal,
                OwnerUserId = item.Incident.OwnerUserId
            })
            .SingleOrDefaultAsync();

        Assert.NotNull(comment);
        Assert.Equal(Guid.Parse("30000000-0000-0000-0000-000000000003"), comment.Id);
        Assert.Equal(DbSeeder.AliceIncidentId, comment.IncidentId);
        Assert.Equal(DbSeeder.AliceId, comment.OwnerUserId);
        Assert.Equal(DbSeeder.MorganId, comment.AuthorUserId);
        Assert.True(comment.IsInternal);
    }
}
