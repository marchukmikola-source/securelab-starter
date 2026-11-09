using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Application.Incidents;

public static class IncidentTriageAudit
{
    public const string LogCategory = "SecureLab.Api.Audit.IncidentTriage";
    public const string DeniedEventName = "incident.triage.denied";
    public const string AllowedEventName = "incident.triage.allowed";

    private static readonly EventId DeniedEvent = new(4101, "IncidentTriageDenied");

    public static void Allowed(ILoggerFactory loggerFactory, Guid actorUserId, Guid incidentId,
        DateTimeOffset occurredAtUtc, string traceId)
    {
        loggerFactory.CreateLogger(LogCategory).LogInformation(new EventId(4102, "IncidentTriageAllowed"),
            "{EventName} {Operation} {ActorUserId} {IncidentId} {Result} {OccurredAtUtc} {TraceId}",
            AllowedEventName, "Incident.Triage", actorUserId, incidentId, "Allowed", occurredAtUtc, traceId);
    }

    public static void Denied(
        ILoggerFactory loggerFactory, Guid actorUserId, Guid incidentId,
        DateTimeOffset occurredAtUtc, string traceId)
    {
        loggerFactory.CreateLogger(LogCategory).LogWarning(DeniedEvent,
            "{EventName} {Operation} {ActorUserId} {IncidentId} {Result} {OccurredAtUtc} {TraceId}",
            DeniedEventName, "Incident.Triage", actorUserId, incidentId, "Denied",
            occurredAtUtc, traceId);
    }
}
