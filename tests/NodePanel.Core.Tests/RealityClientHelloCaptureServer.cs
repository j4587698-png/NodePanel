using System.Net.Sockets;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

internal sealed record RealityClientHelloCapture(
    byte[] ClientHello,
    RuntimeTlsClientHelloMetadata? Metadata);

internal static class RealityClientHelloCaptureServer
{
    public static async Task<RealityClientHelloCapture> AcceptOnceAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        var metadata = RuntimeTlsClientHelloParser.TryParse(clientHello, out var parsed)
            ? parsed
            : null;
        return new RealityClientHelloCapture(clientHello, metadata);
    }
}
