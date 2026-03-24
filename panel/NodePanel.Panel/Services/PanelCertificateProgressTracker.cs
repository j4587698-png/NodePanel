using System.Collections.Concurrent;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelCertificateProgressTracker
{
    private readonly ConcurrentDictionary<string, PanelCertificateProgressSnapshot> _snapshots = new(StringComparer.Ordinal);

    public PanelCertificateProgressSnapshot GetSnapshot(string certificateId)
    {
        var normalizedCertificateId = certificateId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedCertificateId))
        {
            return new PanelCertificateProgressSnapshot();
        }

        return _snapshots.TryGetValue(normalizedCertificateId, out var snapshot)
            ? snapshot
            : new PanelCertificateProgressSnapshot { CertificateId = normalizedCertificateId };
    }

    public void Start(string certificateId, string triggerSource, string stage, int currentStep, int totalSteps)
        => Update(certificateId, triggerSource, stage, currentStep, totalSteps);

    public void Update(string certificateId, string triggerSource, string stage, int currentStep, int totalSteps)
    {
        var normalizedCertificateId = certificateId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedCertificateId))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        _snapshots.AddOrUpdate(
            normalizedCertificateId,
            static (_, state) => new PanelCertificateProgressSnapshot
            {
                CertificateId = state.CertificateId,
                IsRunning = true,
                TriggerSource = state.TriggerSource,
                Stage = state.Stage,
                CurrentStep = state.CurrentStep,
                TotalSteps = state.TotalSteps,
                StartedAt = state.Now,
                UpdatedAt = state.Now
            },
            static (_, current, state) => current with
            {
                IsRunning = true,
                TriggerSource = state.TriggerSource,
                Stage = state.Stage,
                CurrentStep = state.CurrentStep,
                TotalSteps = state.TotalSteps,
                StartedAt = current.StartedAt == default ? state.Now : current.StartedAt,
                UpdatedAt = state.Now
            },
            new TrackerState
            {
                CertificateId = normalizedCertificateId,
                TriggerSource = NormalizeTriggerSource(triggerSource),
                Stage = stage?.Trim() ?? string.Empty,
                CurrentStep = Math.Max(0, currentStep),
                TotalSteps = Math.Max(0, totalSteps),
                Now = now
            });
    }

    public void Complete(string certificateId)
    {
        var normalizedCertificateId = certificateId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedCertificateId))
        {
            return;
        }

        _snapshots.TryRemove(normalizedCertificateId, out _);
    }

    private static string NormalizeTriggerSource(string triggerSource)
        => string.IsNullOrWhiteSpace(triggerSource) ? string.Empty : triggerSource.Trim().ToLowerInvariant();

    private sealed record TrackerState
    {
        public string CertificateId { get; init; } = string.Empty;

        public string TriggerSource { get; init; } = string.Empty;

        public string Stage { get; init; } = string.Empty;

        public int CurrentStep { get; init; }

        public int TotalSteps { get; init; }

        public DateTimeOffset Now { get; init; }
    }
}
