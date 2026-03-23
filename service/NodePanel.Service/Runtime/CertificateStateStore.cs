using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Service.Runtime;

public sealed class CertificateStateStore
{
    private readonly object _sync = new();
    private TaskCompletionSource<int> _assetSignal = CreateSignal();
    private CertificateRuntimeSnapshot _snapshot = new();

    public CertificateRuntimeSnapshot GetSnapshot() => Volatile.Read(ref _snapshot);

    public void Report(CertificateRuntimeSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        lock (_sync)
        {
            var current = _snapshot;
            var assetChanged = HasAssetChanged(current, snapshot);
            var normalized = snapshot with
            {
                AssetVersion = assetChanged ? current.AssetVersion + 1 : current.AssetVersion
            };

            _snapshot = normalized;

            if (!assetChanged)
            {
                return;
            }

            var completed = _assetSignal;
            _assetSignal = CreateSignal();
            completed.TrySetResult(normalized.AssetVersion);
        }
    }

    public Task WaitForAssetChangeAsync(int knownAssetVersion, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_snapshot.AssetVersion != knownAssetVersion)
            {
                return Task.CompletedTask;
            }

            return _assetSignal.Task.WaitAsync(cancellationToken);
        }
    }

    private static bool HasAssetChanged(CertificateRuntimeSnapshot current, CertificateRuntimeSnapshot next)
        => current.Available != next.Available ||
           !string.Equals(current.PfxPath, next.PfxPath, StringComparison.Ordinal) ||
           !string.Equals(current.Thumbprint, next.Thumbprint, StringComparison.Ordinal) ||
           current.NotBefore != next.NotBefore ||
           current.NotAfter != next.NotAfter;

    private static TaskCompletionSource<int> CreateSignal()
        => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

public sealed record CertificateRuntimeSnapshot
{
    public int AssetVersion { get; init; }

    public string Mode { get; init; } = CertificateModes.ManualPfx;

    public bool Available { get; init; }

    public string PfxPath { get; init; } = string.Empty;

    public string Domain { get; init; } = string.Empty;

    public string Thumbprint { get; init; } = string.Empty;

    public DateTimeOffset? NotBefore { get; init; }

    public DateTimeOffset? NotAfter { get; init; }

    public DateTimeOffset? LastAttemptAt { get; init; }

    public DateTimeOffset? LastSuccessAt { get; init; }

    public string LastError { get; init; } = string.Empty;

    public CertificateStatusPayload ToPayload()
        => new()
        {
            Mode = Mode,
            Available = Available,
            SourcePath = string.IsNullOrWhiteSpace(PfxPath) ? null : PfxPath,
            Domain = string.IsNullOrWhiteSpace(Domain) ? null : Domain,
            Thumbprint = string.IsNullOrWhiteSpace(Thumbprint) ? null : Thumbprint,
            NotBefore = NotBefore,
            NotAfter = NotAfter,
            LastAttemptAt = LastAttemptAt,
            LastSuccessAt = LastSuccessAt,
            Error = string.IsNullOrWhiteSpace(LastError) ? null : LastError
        };
}
