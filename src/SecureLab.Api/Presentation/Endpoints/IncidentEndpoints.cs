using System.Diagnostics;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static RouteGroupBuilder MapIncidentEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/incidents").RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .Produces<IReadOnlyList<IncidentListItemResponse>>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);
        group.MapGet("/{id:guid}", GetDetailsAsync)
            .Produces<IncidentDetailsResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);
        group.MapPut("/{id:guid}", UpdateContentAsync)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest);
        group.MapDelete("/{id:guid}", DeleteAsync)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        group.MapPost("/{id:guid}/triage", TriageAsync)
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        routes.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .RequireAuthorization()
            .Produces<IncidentCommentResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        return group;
    }

    private static async Task<IResult> GetListAsync(
        [FromQuery] IncidentStatus? status, HttpContext httpContext,
        IncidentAccessRules accessRules, IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        var scope = accessRules.ReadScope(context);
        if (scope == IncidentReadScope.Forbidden) return Forbidden();
        return Results.Ok(await queries.GetListAsync(status, scope, context.SubjectId, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        [FromRoute] Guid id, HttpContext httpContext, IncidentAccessRules accessRules,
        IncidentQueries queries, CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        if (accessRules.ReadScope(context) == IncidentReadScope.Forbidden) return Forbidden();
        var target = await queries.GetAccessTargetAsync(id, cancellationToken);
        if (target is null) return NotFound();
        var decision = accessRules.Read(context, target.OwnerUserId);
        if (decision != IncidentAccessDecision.Allow) return Denied(decision);
        var incident = await queries.GetDetailsAsync(id, context.IsAnalyst, cancellationToken);
        return incident is null ? NotFound() : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        [FromQuery] IncidentStatus? status, HttpContext httpContext,
        IncidentAccessRules accessRules, IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        var scope = accessRules.ReadScope(context);
        if (scope == IncidentReadScope.Forbidden) return Forbidden();
        return Results.Ok(await queries.GetSeveritySummaryAsync(
            status, scope, context.SubjectId, cancellationToken));
    }

    private static async Task<IResult> UpdateContentAsync(
        Guid id, UpdateIncidentContentRequest request, HttpContext httpContext,
        IncidentAccessRules accessRules, SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        if (!context.IsReporter) return Forbidden();
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null) return NotFound();
        var decision = accessRules.Update(context, incident.OwnerUserId);
        if (decision != IncidentAccessDecision.Allow) return Denied(decision);

        var errors = ValidateContent(request, incident.Severity);
        if (errors.Count > 0) return Results.ValidationProblem(errors);
        var title = request.Title!.Trim();
        var description = request.Description!.Trim();
        if (await db.Incidents.AnyAsync(item => item.Id != id
            && item.Status != IncidentStatus.Closed && item.Title.Trim() == title, cancellationToken))
        {
            return Results.Problem(title: "Інцидент уже існує",
                detail: "Активний інцидент із такою назвою вже зареєстровано.", statusCode: 409);
        }

        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id, HttpContext httpContext, IncidentAccessRules accessRules,
        IncidentQueries queries, CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        if (!context.IsReporter) return Forbidden();
        var target = await queries.GetAccessTargetAsync(id, cancellationToken);
        if (target is null) return NotFound();
        return Denied(accessRules.Delete(context, target.OwnerUserId));
    }

    private static async Task<IResult> TriageAsync(
        Guid id, HttpContext httpContext, IncidentAccessRules accessRules,
        SecureLabDbContext db, ILoggerFactory loggerFactory, CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        if (!context.IsAnalyst && !context.IsReporter) return Forbidden();
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null) return NotFound();
        var decision = accessRules.Triage(context, incident.OwnerUserId, incident.Status);
        if (decision != IncidentAccessDecision.Allow)
        {
            LogDeniedTriage(loggerFactory, httpContext, context.SubjectId, id);
            return Denied(decision);
        }

        var oldStatus = incident.Status;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(), IncidentId = incident.Id, ChangedByUserId = context.SubjectId,
            OldStatus = oldStatus, NewStatus = IncidentStatus.Triaged,
            Note = "Triage completed.", CreatedAtUtc = incident.UpdatedAtUtc
        });
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id, HttpContext httpContext, IncidentAccessRules accessRules,
        IncidentQueries queries, CancellationToken cancellationToken)
    {
        var context = accessRules.From(httpContext.User);
        if (accessRules.ReadScope(context) == IncidentReadScope.Forbidden) return Forbidden();
        var target = await queries.GetCommentAccessTargetAsync(id, cancellationToken);
        if (target is null) return NotFound();
        var decision = accessRules.ReadComment(context, target.IncidentOwnerUserId, target.IsInternal);
        return decision == IncidentAccessDecision.Allow ? Results.Ok(target.Response) : Denied(decision);
    }

    private static Dictionary<string, string[]> ValidateContent(
        UpdateIncidentContentRequest request, IncidentSeverity severity)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title) || request.Title.Length > 160)
            errors["title"] = ["Title є обов’язковим і містить не більше 160 символів."];
        if (string.IsNullOrWhiteSpace(request.Description) || request.Description.Length > 4000)
            errors["description"] = ["Description є обов’язковим і містить не більше 4000 символів."];
        var title = request.Title?.Trim() ?? string.Empty;
        var description = request.Description?.Trim() ?? string.Empty;
        if (!errors.ContainsKey("description")
            && severity is IncidentSeverity.High or IncidentSeverity.Critical && description.Length < 40)
            errors["description"] = ["Для рівнів High і Critical опис має містити щонайменше 40 символів."];
        if (errors.Count == 0 && title == description)
            errors["description"] = ["Опис інциденту не може дублювати його заголовок."];
        return errors;
    }

    private static void LogDeniedTriage(
        ILoggerFactory loggerFactory, HttpContext httpContext, Guid subjectId, Guid resourceId)
    {
        var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;
        loggerFactory.CreateLogger("SecureLab.Api.Authorization").LogWarning(
            "authorization.denied {SubjectId} {Action} {ResourceId} {Result} {OccurredAtUtc} {TraceId}",
            subjectId, "Incident.Triage", resourceId, "denied", DateTimeOffset.UtcNow, traceId);
    }

    private static IResult Denied(IncidentAccessDecision decision) =>
        decision == IncidentAccessDecision.NotFound ? NotFound() : Forbidden();

    private static IResult NotFound() => Results.Problem(title: "Інцидент не знайдено",
        detail: "Запитаний інцидент відсутній.", statusCode: StatusCodes.Status404NotFound);

    private static IResult Forbidden() => Results.Problem(title: "Доступ заборонено",
        detail: "Операція не дозволена для поточного користувача.", statusCode: StatusCodes.Status403Forbidden);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateIncidentContentRequest(string? Title, string? Description);
