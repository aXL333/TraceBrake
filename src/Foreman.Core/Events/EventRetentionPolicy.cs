using Foreman.Core.Models;

namespace Foreman.Core.Events;

/// <summary>Shared provenance-aware retention rules for operator-visible in-memory event stores.</summary>
public static class EventRetentionPolicy
{
    public static bool IsAgentReported(ForemanEvent evt) =>
        evt.Origin == EventOrigin.Agent;

    public static IEnumerable<ForemanEvent> SelectVictims(
        IReadOnlyCollection<ForemanEvent> events,
        int count,
        string? protectedArrivalId = null)
    {
        if (count <= 0) return [];
        var candidates = events.Where(e => !string.Equals(e.Id, protectedArrivalId, StringComparison.Ordinal));
        return candidates
            .OrderBy(static e => e.Acknowledged ? 0 : 1)
            .ThenByDescending(IsAgentReported)
            .ThenBy(static e => e.Severity)
            .ThenBy(static e => e.Timestamp)
            .Take(count)
            .ToList();
    }

    public static IEnumerable<ForemanEvent> SelectAgentQuotaVictims(
        IReadOnlyCollection<ForemanEvent> events,
        int agentQuota)
    {
        var agentEvents = events.Where(IsAgentReported).ToList();
        return SelectVictims(agentEvents, Math.Max(0, agentEvents.Count - agentQuota));
    }
}
