using System.Net;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

public enum TrojanClientTransportType
{
    Tcp = 0,
    Tls = 1,
    Ws = 2,
    Wss = 3
}

public sealed record TrojanClientOptions
{
    public EndPoint? SourceEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string ServerHost { get; init; } = string.Empty;

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public TrojanClientTransportType Transport { get; init; } = TrojanClientTransportType.Tls;

    public string WebSocketPath { get; init; } = "/ws";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketEarlyDataBytes { get; init; }

    public int WebSocketHeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public string Password { get; init; } = string.Empty;

    public Protocol.TrojanCommand Command { get; init; } = Protocol.TrojanCommand.Connect;

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; } = 443;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public bool SkipCertificateValidation { get; init; }

    public RemoteCertificateValidationCallback? CertificateValidationCallback { get; init; }

    public SslProtocols EnabledSslProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; init; }
}

public sealed class TrojanClientConnection : IAsyncDisposable
{
    private readonly Stream _transportStream;
    private readonly WebSocket? _webSocket;

    internal TrojanClientConnection(
        Stream transportStream,
        Stream applicationStream,
        SslStream? sslStream,
        WebSocket? webSocket)
    {
        _transportStream = transportStream;
        Stream = applicationStream;
        SslStream = sslStream;
        _webSocket = webSocket;
    }

    public Stream Stream { get; }

    public SslStream? SslStream { get; }

    public X509Certificate2? RemoteCertificate
        => SslStream?.RemoteCertificate is null
            ? null
            : SslStream.RemoteCertificate as X509Certificate2 ?? new X509Certificate2(SslStream.RemoteCertificate);

    public async ValueTask DisposeAsync()
    {
        if (!ReferenceEquals(Stream, _transportStream))
        {
            await Stream.DisposeAsync().ConfigureAwait(false);
        }

        _webSocket?.Dispose();

        await _transportStream.DisposeAsync().ConfigureAwait(false);
    }
}
