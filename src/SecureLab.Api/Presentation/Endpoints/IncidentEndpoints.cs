using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static RouteGroupBuilder MapIncidentEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/incidents");

        // 1. Отримання списку інцидентів з можливістю фільтрації за status
        group.MapGet("/", GetListAsync)
            .Produces<IReadOnlyList<IncidentListItemResponse>>(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        // 2. Отримання деталей інциденту за GUID
        group.MapGet("/{id:guid}", GetDetailsAsync)
            .Produces<IncidentDetailsResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        // 3. Отримання підсумку за severity з підтримкою фільтру status (Добрий рівень)
        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        // LR04 step 4: controlled vulnerable state for the local synthetic PoC.
        // Login is required, but the resource ownership decision is deliberately
        // missing here. Step 6 must add it before this state is considered fixed.
        group.MapPut("/{id:guid}", UpdateContentAsync)
            .RequireAuthorization()
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        return group;
    }

    private static async Task<IResult> UpdateContentAsync(
        Guid id, UpdateIncidentContentRequest request,
        SecureLabDbContext db, CancellationToken cancellationToken)
    {
        // Tracked entity: SaveChanges must persist the controlled test mutation.
        var incident = await db.Incidents.SingleOrDefaultAsync(
            item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(title: "Інцидент не знайдено",
                detail: "Запитаний інцидент відсутній.", statusCode: 404);
        }

        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title) || request.Title.Length > 160)
            errors["title"] = ["Title є обов’язковим і містить не більше 160 символів."];
        if (string.IsNullOrWhiteSpace(request.Description) || request.Description.Length > 4000)
            errors["description"] = ["Description є обов’язковим і містить не більше 4000 символів."];
        var title = request.Title?.Trim() ?? string.Empty;
        var description = request.Description?.Trim() ?? string.Empty;
        if (!errors.ContainsKey("description")
            && incident.Severity is IncidentSeverity.High or IncidentSeverity.Critical
            && description.Length < 40)
            errors["description"] = ["Для рівнів High і Critical опис має містити щонайменше 40 символів."];
        if (errors.Count == 0 && title == description)
            errors["description"] = ["Опис інциденту не може дублювати його заголовок."];
        if (errors.Count > 0)
            return Results.ValidationProblem(errors);

        if (await db.Incidents.AnyAsync(item => item.Id != id
            && item.Status != IncidentStatus.Closed && item.Title.Trim() == title,
            cancellationToken))
            return Results.Problem(title: "Інцидент уже існує",
                detail: "Активний інцидент із такою назвою вже зареєстровано.", statusCode: 409);

        // Intentionally missing owner/policy check: the defect demonstrated by PoC.
        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> GetListAsync(
        [FromQuery] IncidentStatus? status,
        IncidentQueries incidentQueries,
        CancellationToken cancellationToken)
    {
        var incidents = await incidentQueries.GetListAsync(status, cancellationToken);
        return Results.Ok(incidents);
    }

    private static async Task<IResult> GetDetailsAsync(
        [FromRoute] Guid id,
        IncidentQueries incidentQueries,
        CancellationToken cancellationToken)
    {
        var incident = await incidentQueries.GetDetailsAsync(id, cancellationToken);
        return incident is not null
            ? Results.Ok(incident)
            : Results.Problem(
                title: "Інцидент не знайдено",
                detail: "Запитаний інцидент відсутній.",
                statusCode: StatusCodes.Status404NotFound);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        [FromQuery] IncidentStatus? status,
        IncidentQueries incidentQueries,
        CancellationToken cancellationToken)
    {
        var summary = await incidentQueries.GetSeveritySummaryAsync(status, cancellationToken);
        return Results.Ok(summary);
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateIncidentContentRequest(string? Title, string? Description);
