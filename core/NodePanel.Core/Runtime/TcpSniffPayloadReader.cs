namespace NodePanel.Core.Runtime;

internal static class TcpSniffPayloadReader
{
    private const int ProbeBytes = 4096;
    private const int MaxNoClueAttempts = 2;
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromMilliseconds(200);

    public static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var buffer = new byte[ProbeBytes];
        var totalRead = 0;
        var noClueAttempts = 0;
        var session = new RuntimeSniffProbeSession(DispatchNetwork.Tcp);
        using var sniffCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        sniffCts.CancelAfter(ProbeTimeout);

        try
        {
            while (totalRead < buffer.Length && session.HasCandidates)
            {
                var read = await stream.ReadAsync(
                    buffer.AsMemory(totalRead, buffer.Length - totalRead),
                    sniffCts.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                totalRead += read;
                switch (session.Advance(buffer.AsSpan(0, totalRead)))
                {
                    case SniffContentProbeState.Matched:
                    case SniffContentProbeState.Rejected:
                        return buffer.AsSpan(0, totalRead).ToArray();
                    case SniffContentProbeState.NoClue:
                        noClueAttempts++;
                        if (noClueAttempts >= MaxNoClueAttempts)
                        {
                            return buffer.AsSpan(0, totalRead).ToArray();
                        }

                        break;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        return totalRead == 0 ? Array.Empty<byte>() : buffer.AsSpan(0, totalRead).ToArray();
    }

    private sealed class RuntimeSniffProbeSession
    {
        private readonly DispatchNetwork _network;
        private List<string> _candidates;

        public RuntimeSniffProbeSession(DispatchNetwork network)
        {
            _network = network;
            _candidates = RuntimeSniffingEvaluator.GetProbeProtocols(network).ToList();
        }

        public bool HasCandidates => _candidates.Count > 0;

        public SniffContentProbeState Advance(ReadOnlySpan<byte> payload)
        {
            if (_candidates.Count == 0)
            {
                return SniffContentProbeState.Rejected;
            }

            List<string>? pendingCandidates = null;
            for (var index = 0; index < _candidates.Count; index++)
            {
                var protocol = _candidates[index];
                switch (RuntimeSniffingEvaluator.ProbeProtocol(protocol, payload, _network))
                {
                    case SniffContentProbeState.Matched:
                        _candidates = [protocol];
                        return SniffContentProbeState.Matched;
                    case SniffContentProbeState.NeedMoreData:
                        _candidates = [protocol];
                        return SniffContentProbeState.NeedMoreData;
                    case SniffContentProbeState.NoClue:
                        pendingCandidates ??= [];
                        pendingCandidates.Add(protocol);
                        break;
                }
            }

            if (pendingCandidates is { Count: > 0 })
            {
                _candidates = pendingCandidates;
                return SniffContentProbeState.NoClue;
            }

            _candidates.Clear();
            return SniffContentProbeState.Rejected;
        }
    }
}
