using System.Security.Claims;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

public enum IncidentAccessDecision
{
    Allow,
    NotFound,
    Forbidden
}

public enum IncidentReadScope
{
    Owned,
    All,
    Forbidden
}

public readonly record struct IncidentAccessContext(
    Guid SubjectId,
    bool IsReporter,
    bool IsAnalyst,
    bool IsAdministrator)
{
    public bool HasSubject => SubjectId != Guid.Empty;
}

// One server-side decision point for existing Incident operations.
// It accepts only the verified Identity principal plus state loaded from the DB.
public sealed class IncidentAccessRules
{
    public IncidentAccessContext From(ClaimsPrincipal principal)
    {
        var subject = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(subject, out var subjectId)
            ? new IncidentAccessContext(
                subjectId,
                principal.IsInRole("Reporter"),
                principal.IsInRole("Analyst"),
                principal.IsInRole("Administrator"))
            : default;
    }

    public IncidentReadScope ReadScope(IncidentAccessContext context) => context switch
    {
        { HasSubject: true, IsAnalyst: true } => IncidentReadScope.All,
        { HasSubject: true, IsReporter: true } => IncidentReadScope.Owned,
        _ => IncidentReadScope.Forbidden
    };

    public IncidentAccessDecision Read(IncidentAccessContext context, Guid ownerUserId) =>
        context switch
        {
            { HasSubject: true, IsAnalyst: true } => IncidentAccessDecision.Allow,
            { HasSubject: true, IsReporter: true, SubjectId: var subjectId } when subjectId == ownerUserId
                => IncidentAccessDecision.Allow,
            { HasSubject: true, IsReporter: true } => IncidentAccessDecision.NotFound,
            _ => IncidentAccessDecision.Forbidden
        };

    public IncidentAccessDecision Update(IncidentAccessContext context, Guid ownerUserId) =>
        context switch
        {
            { HasSubject: true, IsReporter: true, SubjectId: var subjectId } when subjectId == ownerUserId
                => IncidentAccessDecision.Allow,
            // An Analyst can see the record but has no content-update right.
            { HasSubject: true, IsAnalyst: true } => IncidentAccessDecision.Forbidden,
            { HasSubject: true, IsReporter: true } => IncidentAccessDecision.NotFound,
            _ => IncidentAccessDecision.Forbidden
        };

    // Delete is deliberately narrower than read: only the Reporter who owns
    // the incident receives this mutating right. A foreign Reporter receives
    // the same concealment decision as for details and update.
    public IncidentAccessDecision Delete(IncidentAccessContext context, Guid ownerUserId) =>
        context switch
        {
            { HasSubject: true, IsReporter: true, SubjectId: var subjectId } when subjectId == ownerUserId
                => IncidentAccessDecision.Allow,
            { HasSubject: true, IsReporter: true } => IncidentAccessDecision.NotFound,
            _ => IncidentAccessDecision.Forbidden
        };

    // Triage is a privileged operation: ownership never substitutes for the
    // Analyst role. A foreign Reporter receives the same concealment decision
    // as for details and update.
    public IncidentAccessDecision Triage(IncidentAccessContext context, Guid ownerUserId) =>
        context switch
        {
            { HasSubject: true, IsAnalyst: true } => IncidentAccessDecision.Allow,
            { HasSubject: true, IsReporter: true, SubjectId: var subjectId } when subjectId != ownerUserId
                => IncidentAccessDecision.NotFound,
            _ => IncidentAccessDecision.Forbidden
        };

    public bool MayCreate(IncidentAccessContext context) =>
        context.HasSubject && (context.IsReporter || context.IsAnalyst);
}
