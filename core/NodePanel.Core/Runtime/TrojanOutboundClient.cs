using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Runtime;

public sealed class TrojanOutboundClient
{
    private const string DefaultChromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";

    private readonly IDnsResolver _dnsResolver;
    private readonly TrojanHandshakeWriter _trojanHandshakeWriter;

    public TrojanOutboundClient()
        : this(new TrojanHandshakeWriter(), dnsResolver: null)
    {
    }

    public TrojanOutboundClient(
        TrojanHandshakeWriter trojanHandshakeWriter,
        IDnsResolver? dnsResolver = null)
    {
        _trojanHandshakeWriter = trojanHandshakeWriter;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public async Task<TrojanClientConnection> ConnectAsync(
        TrojanClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);

        var handshakePayload = _trojanHandshakeWriter.Build(
            options.Password,
            options.Command,
            options.TargetHost,
            options.TargetPort);
        var webSocketEarlyData = ResolveWebSocketEarlyData(options, handshakePayload);

        var transportConnection = await OpenTransportAsync(options, webSocketEarlyData, cancellationToken).ConfigureAwait(false);
        try
        {
            if (webSocketEarlyData is null)
            {
                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));
                await transportConnection.Stream.WriteAsync(handshakePayload.AsMemory(0, handshakePayload.Length), handshakeCts.Token).ConfigureAwait(false);
                await transportConnection.Stream.FlushAsync(handshakeCts.Token).ConfigureAwait(false);
            }

            return transportConnection;
        }
        catch
        {
            await transportConnection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task<TrojanClientConnection> OpenTransportAsync(
        TrojanClientOptions options,
        byte[]? webSocketEarlyData,
        CancellationToken cancellationToken)
    {
        Stream? baseStream = null;
        try
        {
            if (options.TransportStreamFactory is not null)
            {
                baseStream = await options.TransportStreamFactory(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(TimeSpan.FromSeconds(options.ConnectTimeoutSeconds));
                var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
                    options.ServerHost,
                    options.ServerPort,
                    AddressFamily.Unspecified,
                    _dnsResolver,
                    connectCts.Token).ConfigureAwait(false);
                baseStream = await OutboundSocketDialer.OpenTcpStreamAsync(
                    new DispatchContext
                    {
                        SourceEndPoint = options.SourceEndPoint,
                        LocalEndPoint = options.LocalEndPoint
                    },
                    options.Via,
                    options.ViaCidr,
                    endPoints,
                    connectCts.Token).ConfigureAwait(false);
            }

            SslStream? sslStream = null;
            Stream transportStream = baseStream;
            WebSocket? webSocket = null;

            if (RequiresTls(options.Transport))
            {
                sslStream = new SslStream(
                    baseStream,
                    leaveInnerStreamOpen: false,
                    (sender, certificate, chain, errors) => ValidateServerCertificate(options, certificate, chain, errors));

                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));
                await sslStream
                    .AuthenticateAsClientAsync(BuildSslClientAuthenticationOptions(options), handshakeCts.Token)
                    .ConfigureAwait(false);

                transportStream = sslStream;
            }

            Stream applicationStream = transportStream;
            if (RequiresWebSocket(options.Transport))
            {
                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));
                webSocket = await OpenWebSocketAsync(transportStream, options, webSocketEarlyData, handshakeCts.Token).ConfigureAwait(false);
                applicationStream = new WebSocketDuplexStream(webSocket);
            }

            return new TrojanClientConnection(transportStream, applicationStream, sslStream, webSocket);
        }
        catch
        {
            if (baseStream is not null)
            {
                await baseStream.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static SslClientAuthenticationOptions BuildSslClientAuthenticationOptions(TrojanClientOptions options)
    {
        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = GetServerName(options),
            EnabledSslProtocols = options.EnabledSslProtocols,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

        var applicationProtocols = ResolveApplicationProtocols(options);
        if (applicationProtocols.Count > 0)
        {
            sslOptions.ApplicationProtocols = applicationProtocols
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => new SslApplicationProtocol(value))
                .ToList();
        }

        return sslOptions;
    }

    private static IReadOnlyList<string> ResolveApplicationProtocols(TrojanClientOptions options)
        => options.Transport switch
        {
            TrojanClientTransportType.Tls => options.ApplicationProtocols,
            TrojanClientTransportType.Wss => ["http/1.1"],
            _ => Array.Empty<string>()
        };

    private static bool ValidateServerCertificate(
        TrojanClientOptions options,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors errors)
    {
        if (options.CertificateValidationCallback is not null)
        {
            return options.CertificateValidationCallback(options, certificate, chain, errors);
        }

        if (options.SkipCertificateValidation)
        {
            return true;
        }

        return errors == SslPolicyErrors.None;
    }

    private static async Task<WebSocket> OpenWebSocketAsync(
        Stream transportStream,
        TrojanClientOptions options,
        byte[]? webSocketEarlyData,
        CancellationToken cancellationToken)
    {
        var webSocketKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var request = BuildWebSocketRequest(options, webSocketKey, webSocketEarlyData);

        await transportStream.WriteAsync(Encoding.ASCII.GetBytes(request), cancellationToken).ConfigureAwait(false);
        await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var statusLine = await ReadHttpLineAsync(transportStream, cancellationToken).ConfigureAwait(false);
        if (!statusLine.StartsWith("HTTP/1.1 101", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unexpected WebSocket response status: {statusLine}");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await ReadHttpLineAsync(transportStream, cancellationToken).ConfigureAwait(false);
            if (line.Length == 0)
            {
                break;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        if (!headers.TryGetValue("Sec-WebSocket-Accept", out var acceptValue))
        {
            throw new InvalidOperationException("WebSocket response is missing Sec-WebSocket-Accept.");
        }

        var expectedAccept = ComputeWebSocketAccept(webSocketKey);
        if (!string.Equals(acceptValue, expectedAccept, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("WebSocket Sec-WebSocket-Accept validation failed.");
        }

        return WebSocket.CreateFromStream(
            transportStream,
            isServer: false,
            subProtocol: null,
            keepAliveInterval: options.WebSocketHeartbeatPeriodSeconds > 0
                ? TimeSpan.FromSeconds(options.WebSocketHeartbeatPeriodSeconds)
                : Timeout.InfiniteTimeSpan);
    }

    private static string BuildWebSocketRequest(TrojanClientOptions options, string webSocketKey, byte[]? webSocketEarlyData)
    {
        var reservedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Upgrade",
            "Connection",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "User-Agent"
        };

        var hostHeader = BuildHostHeader(options);
        var userAgent = BuildUserAgentHeader(options);

        var builder = new StringBuilder(512);
        builder.Append("GET ");
        builder.Append(NormalizeWebSocketPath(options.WebSocketPath));
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(hostHeader);
        builder.Append("\r\n");
        builder.Append("Upgrade: websocket\r\n");
        builder.Append("Connection: Upgrade\r\n");
        builder.Append("Sec-WebSocket-Key: ");
        builder.Append(webSocketKey);
        builder.Append("\r\n");
        builder.Append("Sec-WebSocket-Version: 13\r\n");
        builder.Append("User-Agent: ");
        builder.Append(userAgent);
        builder.Append("\r\n");
        if (webSocketEarlyData is not null)
        {
            builder.Append("Sec-WebSocket-Protocol: ");
            builder.Append(Convert.ToBase64String(webSocketEarlyData)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_'));
            builder.Append("\r\n");
        }

        foreach (var (name, value) in options.WebSocketHeaders)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                string.IsNullOrWhiteSpace(value) ||
                reservedHeaders.Contains(name) ||
                string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            builder.Append(name.Trim());
            builder.Append(": ");
            builder.Append(value.Trim());
            builder.Append("\r\n");
        }

        builder.Append("\r\n");
        return builder.ToString();
    }

    private static async Task<string> ReadHttpLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(128);
        var oneByte = new byte[1];

        while (buffer.Length < 8 * 1024)
        {
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF during WebSocket handshake.");
            }

            if (oneByte[0] == '\n')
            {
                var bytes = buffer.ToArray();
                if (bytes.Length > 0 && bytes[^1] == '\r')
                {
                    Array.Resize(ref bytes, bytes.Length - 1);
                }

                return Encoding.ASCII.GetString(bytes);
            }

            buffer.WriteByte(oneByte[0]);
        }

        throw new InvalidOperationException("WebSocket handshake line exceeded the configured limit.");
    }

    private static string ComputeWebSocketAccept(string key)
    {
        const string webSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var input = Encoding.ASCII.GetBytes(key + webSocketGuid);
        return Convert.ToBase64String(SHA1.HashData(input));
    }

    private static string NormalizeWebSocketPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        return value.StartsWith("/", StringComparison.Ordinal) ? value.Trim() : "/" + value.Trim();
    }

    private static string BuildHostHeader(TrojanClientOptions options)
    {
        if (options.WebSocketHeaders.TryGetValue("Host", out var requestedHost) &&
            !string.IsNullOrWhiteSpace(requestedHost))
        {
            return requestedHost.Trim();
        }

        return RequiresTls(options.Transport)
            ? GetServerName(options)
            : options.ServerHost.Trim();
    }

    private static string BuildUserAgentHeader(TrojanClientOptions options)
        => options.WebSocketHeaders.TryGetValue("User-Agent", out var requestedUserAgent) &&
           !string.IsNullOrWhiteSpace(requestedUserAgent)
            ? requestedUserAgent.Trim()
            : DefaultChromeUserAgent;

    private static string GetServerName(TrojanClientOptions options)
        => string.IsNullOrWhiteSpace(options.ServerName) ? options.ServerHost.Trim() : options.ServerName.Trim();

    private static byte[]? ResolveWebSocketEarlyData(TrojanClientOptions options, byte[] handshakePayload)
    {
        if (!RequiresWebSocket(options.Transport) || options.WebSocketEarlyDataBytes <= 0)
        {
            return null;
        }

        return handshakePayload.Length <= options.WebSocketEarlyDataBytes ? handshakePayload : null;
    }

    private static bool RequiresTls(TrojanClientTransportType transport)
        => transport is TrojanClientTransportType.Tls or TrojanClientTransportType.Wss;

    private static bool RequiresWebSocket(TrojanClientTransportType transport)
        => transport is TrojanClientTransportType.Ws or TrojanClientTransportType.Wss;

    private static void ValidateOptions(TrojanClientOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ServerHost);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Password);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.TargetHost);

        if (options.ServerPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ServerPort, "Server port must be between 1 and 65535.");
        }

        if (options.TargetPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.TargetPort, "Target port must be between 1 and 65535.");
        }

        if (options.ConnectTimeoutSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ConnectTimeoutSeconds, "Connect timeout must be greater than zero.");
        }

        if (options.HandshakeTimeoutSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.HandshakeTimeoutSeconds, "Handshake timeout must be greater than zero.");
        }

        if (options.WebSocketEarlyDataBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.WebSocketEarlyDataBytes, "WebSocket early data bytes must be zero or greater.");
        }

        if (options.WebSocketHeartbeatPeriodSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.WebSocketHeartbeatPeriodSeconds, "WebSocket heartbeat period must be zero or greater.");
        }
    }
}
