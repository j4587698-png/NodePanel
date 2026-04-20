namespace NodePanel.Core.Runtime;

internal static class Http2ConnectTunnel
{
    public static async ValueTask<Stream> OpenAsync(
        Stream transportStream,
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connectHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        var session = await Http2TunnelSession.CreateAsync(transportStream, cancellationToken).ConfigureAwait(false);
        try
        {
            return await session
                .OpenConnectStreamAsync(
                    connectHeaders,
                    destination,
                    initialPayload,
                    cancellationToken,
                    disposeSessionOnClose: true)
                .ConfigureAwait(false);
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
