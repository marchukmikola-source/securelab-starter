using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02.
// Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        // ============================================================
        // GET /api/incidents/search
        // ============================================================
        app.MapGet(
            "/api/incidents/search",
            async (
                string? q,
                string? sortBy,
                SecureLabDbContext db,
                CancellationToken ct) =>
            {
                // Literal substring:
                // %, _ та \ з q не повинні працювати як LIKE metacharacters.
                var escapedQuery = EscapeLike(q ?? string.Empty);
                var pattern = $"%{escapedQuery}%";

                var found = db.Incidents
                    .AsNoTracking()
                    .Where(item =>
                        EF.Functions.ILike(
                            item.Title,
                            pattern,
                            "\\")
                        ||
                        EF.Functions.ILike(
                            item.Description,
                            pattern,
                            "\\"));

                // sortBy визначає структуру SQL,
                // тому використовуємо лише server-side allowlist.
                IQueryable<Incident>? ordered = sortBy switch
                {
                    null or "" or "createdAtUtc" => found
                        .OrderByDescending(
                            item => item.CreatedAtUtc)
                        .ThenBy(
                            item => item.Id),

                    // Critical -> High -> Medium -> Low
                    "severity" => found
                        .OrderBy(item =>
                            item.Severity
                                == IncidentSeverity.Critical ? 0 :
                            item.Severity
                                == IncidentSeverity.High ? 1 :
                            item.Severity
                                == IncidentSeverity.Medium ? 2 :
                            3)
                        .ThenBy(
                            item => item.Id),

                    // New -> Triaged -> InProgress -> Resolved -> Closed
                    "status" => found
                        .OrderBy(item =>
                            item.Status
                                == IncidentStatus.New ? 0 :
                            item.Status
                                == IncidentStatus.Triaged ? 1 :
                            item.Status
                                == IncidentStatus.InProgress ? 2 :
                            item.Status
                                == IncidentStatus.Resolved ? 3 :
                            4)
                        .ThenBy(
                            item => item.Id),

                    _ => null
                };

                if (ordered is null)
                {
                    return Results.ValidationProblem(
                        new Dictionary<string, string[]>
                        {
                            ["sortBy"] =
                            [
                                "Допустимі значення: createdAtUtc, severity, status."
                            ]
                        });
                }

                var rows = await ordered
                    .Take(50)
                    .Select(row => new
                    {
                        row.Id,
                        row.Title,
                        row.Description,
                        Severity = row.Severity.ToString(),
                        Status = row.Status.ToString(),
                        row.CreatedAtUtc
                    })
                    .ToListAsync(ct);

                return Results.Ok(rows);
            });

        // ============================================================
        // POST /api/incidents
        // ============================================================
        app.MapPost(
            "/api/incidents",
            async (
                CreateIncidentRequest request,
                HttpContext httpContext,
                SecureLabDbContext db,
                CancellationToken ct) =>
            {
                // Поточний UTC-час фіксуємо один раз.
                var now = DateTimeOffset.UtcNow;

                var errors =
                    new Dictionary<string, string[]>();

                IncidentSeverity severity = default;

                // ----------------------------------------------------
                // 1. Title
                //
                // required — за змістом;
                // max 160 — до Trim().
                // ----------------------------------------------------
                if (string.IsNullOrWhiteSpace(
                        request.Title))
                {
                    errors["title"] =
                    [
                        "Title є обов’язковим."
                    ];
                }
                else if (request.Title.Length > 160)
                {
                    errors["title"] =
                    [
                        "Title не може бути довшим за 160 символів."
                    ];
                }

                // ----------------------------------------------------
                // 2. Description
                //
                // required — за змістом;
                // max 4000 — до Trim().
                // ----------------------------------------------------
                if (string.IsNullOrWhiteSpace(
                        request.Description))
                {
                    errors["description"] =
                    [
                        "Description є обов’язковим."
                    ];
                }
                else if (request.Description.Length > 4000)
                {
                    errors["description"] =
                    [
                        "Description не може бути довшим за 4000 символів."
                    ];
                }

                // ----------------------------------------------------
                // 3. Severity
                //
                // Потрібні і TryParse, і IsDefined.
                // ----------------------------------------------------
                var severityIsValid =
                    !string.IsNullOrWhiteSpace(
                        request.Severity)
                    &&
                    Enum.TryParse<IncidentSeverity>(
                        request.Severity,
                        ignoreCase: true,
                        out severity)
                    &&
                    Enum.IsDefined(severity)
                    &&
                    // Enum.TryParse accepts comma-separated names even for
                    // a non-[Flags] enum. The HTTP contract accepts exactly
                    // one declared severity name, never a composite or a
                    // numeric representation.
                    string.Equals(
                        request.Severity,
                        Enum.GetName(severity),
                        StringComparison.OrdinalIgnoreCase);

                if (!severityIsValid)
                {
                    errors["severity"] =
                    [
                        "Допустимі значення: Low, Medium, High, Critical."
                    ];
                }

                // ----------------------------------------------------
                // 4. OccurredAtUtc
                //
                // required;
                // максимум now + 5 хв.
                // ----------------------------------------------------
                if (request.OccurredAtUtc is null)
                {
                    errors["occurredAtUtc"] =
                    [
                        "OccurredAtUtc є обов’язковим."
                    ];
                }
                else if (
                    request.OccurredAtUtc.Value
                    > now.AddMinutes(5))
                {
                    errors["occurredAtUtc"] =
                    [
                        "OccurredAtUtc не може бути більш ніж на 5 хвилин у майбутньому."
                    ];
                }

                // ----------------------------------------------------
                // 5. Нормалізація
                // ----------------------------------------------------
                var title =
                    request.Title?.Trim()
                    ?? string.Empty;

                var description =
                    request.Description?.Trim()
                    ?? string.Empty;

                // ----------------------------------------------------
                // 6. T-09
                //
                // High/Critical -> description >= 40 після Trim().
                // ----------------------------------------------------
                if (severityIsValid
                    && !errors.ContainsKey("description")
                    && severity is
                        IncidentSeverity.High
                        or IncidentSeverity.Critical
                    && description.Length < 40)
                {
                    errors["description"] =
                    [
                        "Для рівнів High і Critical опис має містити щонайменше 40 символів."
                    ];
                }

                // ----------------------------------------------------
                // 7. T-10 — додаткове правило відмінного рівня
                //
                // description після Trim()
                // не може повністю дорівнювати title після Trim().
                // ----------------------------------------------------
                if (!errors.ContainsKey("title")
                    && !errors.ContainsKey("description")
                    && string.Equals(
                        title,
                        description,
                        StringComparison.Ordinal))
                {
                    errors["description"] =
                    [
                        "Опис інциденту не може дублювати його заголовок."
                    ];
                }

                // Усі validation errors повертаємо
                // до будь-якого доступу до БД.
                if (errors.Count > 0)
                {
                    return Results.ValidationProblem(
                        errors);
                }

                // The resource owner is server-controlled. Authentication has
                // already established this principal from the application
                // cookie; no client field or request header participates.
                var principalId = httpContext.User
                    .FindFirst(ClaimTypes.NameIdentifier)
                    ?.Value;

                if (!Guid.TryParse(principalId, out var ownerUserId))
                {
                    return Results.Unauthorized();
                }

                // ----------------------------------------------------
                // 8. T-03 — duplicate active title
                //
                // після Trim();
                // case-sensitive;
                // Closed не блокує.
                // ----------------------------------------------------
                var blockingStatuses = new[]
                {
                    IncidentStatus.New,
                    IncidentStatus.Triaged,
                    IncidentStatus.InProgress,
                    IncidentStatus.Resolved
                };

                var hasDuplicateTitle =
                    await db.Incidents.AnyAsync(
                        item =>
                            blockingStatuses.Contains(
                                item.Status)
                            &&
                            item.Title.Trim() == title,
                        ct);

                if (hasDuplicateTitle)
                {
                    return Results.Problem(
                        title: "Інцидент уже існує",
                        detail:
                            "Активний інцидент із такою назвою вже зареєстровано.",
                        statusCode:
                            StatusCodes.Status409Conflict);
                }

                // ----------------------------------------------------
                // 9. Entity
                //
                // server-managed:
                // Id,
                // OwnerUserId,
                // Status,
                // CreatedAtUtc,
                // UpdatedAtUtc.
                // ----------------------------------------------------
                var occurredAtUtc =
                    request.OccurredAtUtc!
                        .Value
                        .ToUniversalTime();

                var incident = new Incident
                {
                    Id = Guid.NewGuid(),

                    OwnerUserId = ownerUserId,

                    Title = title,

                    Description = description,

                    Severity = severity,

                    Status =
                        IncidentStatus.New,

                    OccurredAtUtc =
                        occurredAtUtc,

                    CreatedAtUtc = now,

                    UpdatedAtUtc = now
                };

                db.Incidents.Add(incident);

                await db.SaveChangesAsync(ct);

                // ----------------------------------------------------
                // 10. Safe response DTO
                // ----------------------------------------------------
                var response =
                    new CreatedIncidentResponse(
                        incident.Id,
                        incident.Title,
                        incident.Severity.ToString(),
                        incident.Status.ToString(),
                        incident.OccurredAtUtc,
                        incident.CreatedAtUtc);

                return Results.Created(
                    $"/api/incidents/{incident.Id}",
                    response);
            })
            .Produces<CreatedIncidentResponse>(
                StatusCodes.Status201Created)
            .ProducesValidationProblem(
                StatusCodes.Status400BadRequest)
            .ProducesProblem(
                StatusCodes.Status409Conflict)
            .ProducesProblem(
                StatusCodes.Status401Unauthorized)
            .RequireAuthorization();
    }

    // ================================================================
    // Literal LIKE / ILIKE escaping.
    //
    // Спочатку екрануємо escape character,
    // потім "_" і "%".
    // ================================================================
    private static string EscapeLike(
        string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("_", "\\_")
            .Replace("%", "\\%");
    }
}

// ====================================================================
// Request DTO
//
// Клієнт може керувати лише цими 4 полями.
// Id, OwnerUserId, Status,
// CreatedAtUtc та UpdatedAtUtc — server-managed.
// ====================================================================
public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);
