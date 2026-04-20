namespace NodePanel.Service.Runtime;

public sealed class AppliedRuntimeSnapshotStore
{
    private NodeRuntimeSnapshot _snapshot = NodeRuntimeSnapshot.Empty;

    public NodeRuntimeSnapshot GetSnapshot() => Volatile.Read(ref _snapshot);

    public void MarkApplied(NodeRuntimeSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        Volatile.Write(
            ref _snapshot,
            snapshot with
            {
                Revision = Math.Max(0, snapshot.Revision)
            });
    }
}
