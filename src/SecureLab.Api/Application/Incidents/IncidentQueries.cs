using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    // 1. Метод для списку інцидентів
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        IncidentReadScope scope,
        Guid subjectId,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();
        if (scope == IncidentReadScope.Owned)
        {
            query = query.Where(incident => incident.OwnerUserId == subjectId);
        }
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    // 2. Метод для деталей інциденту
    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id, bool includeInternalComments, CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternalComments || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    // 3. Метод для підсумку за severity з підтримкою фільтру status (ДЛЯ ДОБРОГО РІВНЯ)
    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentStatus? status,
        IncidentReadScope scope,
        Guid subjectId,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Generating severity summary with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();
        if (scope == IncidentReadScope.Owned)
        {
            query = query.Where(incident => incident.OwnerUserId == subjectId);
        }

        // 2. ДОДАЛИ ФІЛЬТРАЦІЮ ПЕРЕД ГРУПУВАННЯМ
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        var existingGroups = await query
            .GroupBy(incident => incident.Severity)
            .Select(group => new IncidentSeveritySummaryResponse(
                group.Key.ToString(),
                group.Count()))
            .ToListAsync(cancellationToken);

        var countsBySeverity = existingGroups
            .ToDictionary(item => item.Severity, item => item.Count);

        var allLevels = Enum.GetValues<IncidentSeverity>();

        var completeSummary = allLevels
            .Select(level => new IncidentSeveritySummaryResponse(
                level.ToString(),
                countsBySeverity.GetValueOrDefault(level.ToString(), 0)))
            .ToList();

        var orderedSummary = completeSummary
            .OrderBy(item => GetSeverityRank(item.Severity))
            .ToList();

        logger.LogInformation(
            "Severity summary generated with {GroupCount} severity levels",
            orderedSummary.Count);

        return orderedSummary;
    }

    public Task<IncidentAccessTarget?> GetAccessTargetAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.Incidents.AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentAccessTarget(incident.OwnerUserId))
            .SingleOrDefaultAsync(cancellationToken);

    private static int GetSeverityRank(string severity) => severity switch
    {
        nameof(IncidentSeverity.Critical) => 0,
        nameof(IncidentSeverity.High) => 1,
        nameof(IncidentSeverity.Medium) => 2,
        nameof(IncidentSeverity.Low) => 3,
        _ => int.MaxValue,
    };
}

public sealed record IncidentAccessTarget(Guid OwnerUserId);
