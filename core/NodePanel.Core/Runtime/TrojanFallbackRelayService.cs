namespace NodePanel.Core.Runtime;

public sealed class TrojanFallbackRelayService
{
    private readonly RuntimeFallbackRelayService _inner;

    public TrojanFallbackRelayService(
        IRuntimeRelayService relayService,
        IDnsResolver? dnsResolver = null)
    {
        _inner = new RuntimeFallbackRelayService(relayService, dnsResolver);
    }

    public Task<bool> TryHandleAsync(
        Stream clientStream,
        byte[] initialPayload,
        ITrojanInboundConnectionOptions options,
        CancellationToken cancellationToken)
        => _inner.TryHandleAsync(clientStream, initialPayload, options, cancellationToken);
}
